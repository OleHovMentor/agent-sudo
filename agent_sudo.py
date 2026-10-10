#!/usr/bin/env python3
"""agent-sudo: a safety wrapper for shell commands run by AI agents.

Zero dependencies, one file, Python 3.9+. Point your agent at
`agent-sudo run -- <command>` instead of a raw shell and you get:

  * policy: dangerous commands are blocked (deny rules) or only a known set
    is allowed (allow rules)
  * redaction: secrets never reach the model's context (keys, tokens, and the
    literal values of secret-looking environment variables)
  * snapshots: back up paths before a risky command, roll back in one command
  * audit log: every decision as one JSON line
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import time
from pathlib import Path

__version__ = "0.1.0"

STATE_DIR = Path(os.environ.get("AGENT_SUDO_DIR", ".agent-sudo"))
POLICY_FILE = "agent-sudo.toml"
REDACTED = "[REDACTED]"
EXIT_BLOCKED = 126

# (rule id, regex). Matched against the whole command and each pipeline segment.
DEFAULT_DENY: list[tuple[str, str]] = [
    ("rm-root", r"\brm\s+(-[a-zA-Z]*\s+)*(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|~|\$HOME|/\*|\*)(\s|$)"),
    ("disk-wipe", r"\b(mkfs(\.\w+)?|dd\s+[^|;]*of=/dev/|wipefs|shred\s+/dev/)"),
    ("fork-bomb", r":\(\)\s*\{"),
    ("pipe-to-shell", r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
    ("read-secrets", r"\b(cat|less|more|head|tail|cp|scp|base64|xxd|strings)\b[^|;]*"
                      r"(\.env\b|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.pypirc|\.netrc)"),
    ("dump-env", r"(^|[;&|]\s*)(env|printenv|export\s+-p)\s*($|[;&|])"),
    ("chmod-777-root", r"\bchmod\s+(-\w+\s+)*0?777\s+/(\s|$)"),
    ("power", r"\b(shutdown|reboot|halt|poweroff|init\s+0)\b"),
    ("git-force-push", r"\bgit\s+push\b[^|;]*(--force\b|\s-f\b|--force-with-lease)"),
    ("git-destroy", r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|branch\s+-D)\b"),
    ("sql-destroy", r"\b(drop\s+(table|database|schema)|truncate\s+table)\b"),
    ("firewall", r"\b(ufw\s+(disable|reset)|iptables\s+-F|nft\s+flush)\b"),
    ("ssh-config", r"(>|>>|tee)\s*\S*(authorized_keys|sshd_config)"),
]

SECRET_VALUE_PATTERNS: list[re.Pattern] = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
]
KV_RE = re.compile(
    r"(?i)(\b\w*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\w*)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
SECRET_ENV_NAME_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)")
MIN_SECRET_LEN = 6


# --------------------------------------------------------------------- policy
class Policy:
    def __init__(self, deny=None, allow=None, snapshot=None, timeout=120, max_output=200_000):
        self.deny = [(rid, re.compile(rx, re.I)) for rid, rx in (deny if deny is not None else DEFAULT_DENY)]
        self.allow = [re.compile(a) for a in (allow or [])]
        self.snapshot = list(snapshot or [])
        self.timeout = timeout
        self.max_output = max_output

    @classmethod
    def load(cls, path: str | None = None) -> "Policy":
        p = Path(path or POLICY_FILE)
        if not p.exists():
            return cls()
        try:
            import tomllib  # py3.11+
        except ImportError:  # pragma: no cover
            try:
                import tomli as tomllib  # type: ignore
            except ImportError:
                sys.exit("agent-sudo: reading %s needs Python 3.11+ (or `pip install tomli`)" % p)
        data = tomllib.loads(p.read_text())
        deny = list(DEFAULT_DENY)
        if data.get("replace_default_deny"):
            deny = []
        deny += [(f"custom-{i}", rx) for i, rx in enumerate(data.get("deny", []))]
        return cls(
            deny=deny,
            allow=data.get("allow", []),
            snapshot=data.get("snapshot", []),
            timeout=int(data.get("timeout", 120)),
            max_output=int(data.get("max_output", 200_000)),
        )

    def check(self, command: str) -> tuple[bool, str]:
        """Return (allowed, rule). Rule explains the decision."""
        for rid, rx in self.deny:
            if rx.search(command):
                return False, f"deny:{rid}"
        if self.allow:
            for seg in split_segments(command):
                if not any(a.search(seg) for a in self.allow):
                    return False, f"not-in-allowlist:{seg.strip()[:60]}"
        return True, "allowed"


def split_segments(command: str) -> list[str]:
    """Split a command line on ; && || | and newlines (outside of quotes)."""
    segs, buf, quote, i = [], [], "", 0
    while i < len(command):
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in ";\n|&":
            segs.append("".join(buf))
            buf = []
            while i + 1 < len(command) and command[i + 1] in "|&":
                i += 1
        else:
            buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


# ------------------------------------------------------------------ redaction
def secret_env_values(env=None) -> list[str]:
    env = os.environ if env is None else env
    vals = {v for k, v in env.items() if SECRET_ENV_NAME_RE.search(k) and len(v) >= MIN_SECRET_LEN}
    return sorted(vals, key=len, reverse=True)


def redact(text: str, env=None) -> str:
    for v in secret_env_values(env):
        text = text.replace(v, REDACTED)
    for rx in SECRET_VALUE_PATTERNS:
        text = rx.sub(lambda m: (m.group(1) + REDACTED) if m.groups() else REDACTED, text)
    return KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


# ------------------------------------------------------------------ snapshots
def _snap_dir() -> Path:
    d = STATE_DIR / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def snapshot(paths: list[str]) -> str | None:
    existing = [p for p in paths if Path(p).exists()]
    if not existing:
        return None
    sid = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
    with tarfile.open(_snap_dir() / f"{sid}.tar.gz", "w:gz") as tar:
        for p in existing:
            tar.add(p)
    (_snap_dir() / f"{sid}.json").write_text(json.dumps({"id": sid, "paths": existing}))
    return sid


def list_snapshots() -> list[str]:
    return sorted(p.stem for p in _snap_dir().glob("*.json"))


def rollback(sid: str | None = None) -> str:
    ids = list_snapshots()
    if not ids:
        raise SystemExit("agent-sudo: no snapshots to roll back to")
    sid = sid or ids[-1]
    archive = _snap_dir() / f"{sid}.tar.gz"
    if not archive.exists():
        raise SystemExit(f"agent-sudo: unknown snapshot {sid}")
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():  # refuse path traversal / absolute escapes
            if m.name.startswith("/") or ".." in Path(m.name).parts:
                raise SystemExit(f"agent-sudo: refusing unsafe path in snapshot: {m.name}")
        tar.extractall(".")
    return sid


# ---------------------------------------------------------------------- audit
def audit(entry: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
    entry["command"] = redact(entry.get("command", ""))
    with open(STATE_DIR / "audit.jsonl", "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ------------------------------------------------------------------------ run
def run_command(command: str, policy: Policy, dry_run=False, no_snapshot=False) -> int:
    allowed, rule = policy.check(command)
    if not allowed:
        audit({"command": command, "decision": "blocked", "rule": rule})
        print(f"agent-sudo: BLOCKED ({rule})\n  command: {redact(command)}", file=sys.stderr)
        return EXIT_BLOCKED
    if dry_run:
        audit({"command": command, "decision": "dry-run", "rule": rule})
        print(f"agent-sudo: would run (policy ok): {redact(command)}")
        return 0
    sid = None
    if policy.snapshot and not no_snapshot:
        sid = snapshot(policy.snapshot)
        if sid:
            print(f"agent-sudo: snapshot {sid} (undo: agent-sudo rollback {sid})", file=sys.stderr)
    try:
        proc = subprocess.run(
            ["bash", "-c", command], capture_output=True, text=True, timeout=policy.timeout, errors="replace"
        )
        out, err, rc = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as e:
        out, err, rc = (e.stdout or ""), f"agent-sudo: timeout after {policy.timeout}s", 124
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
    out, err = redact(out), redact(err)
    if len(out) > policy.max_output:
        out = out[: policy.max_output] + "\n[agent-sudo: output truncated]"
    sys.stdout.write(out)
    sys.stderr.write(err)
    audit({"command": command, "decision": "ran", "rule": rule, "rc": rc, "snapshot": sid})
    return rc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent-sudo", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--policy", help=f"path to policy file (default ./{POLICY_FILE})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a command through the policy")
    r.add_argument("--dry-run", action="store_true", help="only check the policy, don't execute")
    r.add_argument("--no-snapshot", action="store_true")
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- <command ...>")

    c = sub.add_parser("check", help="exit 0 if allowed, 126 if blocked (no execution)")
    c.add_argument("command", nargs=argparse.REMAINDER)

    s = sub.add_parser("snapshot", help="back up paths now")
    s.add_argument("paths", nargs="+")
    b = sub.add_parser("rollback", help="restore the latest (or given) snapshot")
    b.add_argument("id", nargs="?")
    sub.add_parser("snapshots", help="list snapshots")
    t = sub.add_parser("log", help="show recent audit entries")
    t.add_argument("-n", type=int, default=20)
    sub.add_parser("init", help=f"write a starter {POLICY_FILE}")

    a = ap.parse_args(argv)
    if a.cmd in ("run", "check"):
        words = a.command[1:] if a.command and a.command[0] == "--" else a.command
        if not words:
            ap.error("no command given (usage: agent-sudo run -- <command>)")
        command = words[0] if len(words) == 1 else shlex.join(words)
        policy = Policy.load(a.policy)
        if a.cmd == "check":
            ok, rule = policy.check(command)
            print(("allowed" if ok else "blocked") + f" ({rule})")
            return 0 if ok else EXIT_BLOCKED
        return run_command(command, policy, a.dry_run, a.no_snapshot)
    if a.cmd == "snapshot":
        sid = snapshot(a.paths)
        print(sid or "nothing to snapshot")
        return 0
    if a.cmd == "rollback":
        print("restored", rollback(a.id))
        return 0
    if a.cmd == "snapshots":
        print("\n".join(list_snapshots()) or "(none)")
        return 0
    if a.cmd == "log":
        f = STATE_DIR / "audit.jsonl"
        lines = f.read_text().splitlines()[-a.n:] if f.exists() else []
        print("\n".join(lines) or "(empty)")
        return 0
    if a.cmd == "init":
        if Path(POLICY_FILE).exists():
            print(f"{POLICY_FILE} already exists")
            return 1
        Path(POLICY_FILE).write_text(STARTER_POLICY)
        print(f"wrote {POLICY_FILE}")
        return 0
    return 2


STARTER_POLICY = '''# agent-sudo policy. Built-in deny rules (rm -rf /, curl|sh, cat .env, force push...)
# are always on unless you set replace_default_deny = true.

# Extra regexes to block:
deny = [
  "\\\\bkubectl\\\\s+delete\\\\b",
]

# Optional strict mode: when non-empty, EVERY segment of a command must match one of these.
# allow = ["^(ls|cat|grep|git (status|log|diff)|systemctl (status|restart) myapp)\\\\b"]

# Paths backed up before every run; restore with `agent-sudo rollback`.
snapshot = ["config", "app.db"]

timeout = 120
'''

if __name__ == "__main__":
    sys.exit(main())
