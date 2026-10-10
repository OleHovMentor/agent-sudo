# agent-sudo

**Let AI agents run shell commands without handing them the keys to production.**

One file. Zero dependencies. Python 3.9+. Wrap whatever your agent runs
(Claude Code, Codex, Aider, a custom MCP tool, a cron script) with
`agent-sudo run --` and get four things:

| | |
|---|---|
| **Policy** | `rm -rf /`, `curl … \| sh`, `cat .env`, `git push --force`, `DROP TABLE` and friends are blocked before they run. Or switch to a strict allowlist. |
| **Redaction** | Keys, tokens, JWTs, private keys, and the *literal values* of secret-looking env vars never reach the model's context. |
| **Snapshots** | Back up the paths you care about before every run. `agent-sudo rollback` undoes a bad command. |
| **Audit log** | Every decision (allowed / blocked / dry-run) as a JSON line in `.agent-sudo/audit.jsonl`. |

```console
$ agent-sudo run -- cat .env
agent-sudo: BLOCKED (deny:read-secrets)
  command: cat .env                                   # exit 126

$ agent-sudo run -- rm -rf /
agent-sudo: BLOCKED (deny:rm-root)                    # exit 126

$ export STRIPE_SECRET_KEY=demo_secret_value_123456
$ agent-sudo run -- 'echo "key: $STRIPE_SECRET_KEY"'
key: [REDACTED]

$ agent-sudo run -- 'echo oops > app.db'              # app.db is snapshotted first
agent-sudo: snapshot 20261010-155106-439 (undo: agent-sudo rollback 20261010-155106-439)
$ agent-sudo rollback
restored 20261010-155106-439
```

Want to see it live? `bash demo/demo.sh`

## Install

```bash
pip install git+https://github.com/OleHovMentor/agent-sudo      # or just copy agent_sudo.py
```

## Claude Code: one command

```bash
pip install git+https://github.com/OleHovMentor/agent-sudo
agent-sudo install-hook            # this project (./.claude/settings.json); add --global for all projects
```

That registers a `PreToolUse` hook. From now on every `Bash` call is checked against the policy, and
`Read`/`Edit`/`Write` of `.env`, `~/.ssh/*`, `~/.aws/*` and friends is denied. The agent gets a clear
reason and is told not to work around it. Safe calls pass through silently and your normal permission
prompts still apply. Every decision lands in `.agent-sudo/audit.jsonl`.

Hook mode checks calls *before* they run; it cannot rewrite output or take snapshots. For redaction and
rollback, have the agent run commands through `agent-sudo run --`.

## Any other agent

Tell the agent to run every shell command through the wrapper, for example in
`CLAUDE.md` / `AGENTS.md`:

```markdown
Run shell commands only as: agent-sudo run -- <command>
Exit code 126 means the command was blocked by policy. Do not try to work around it; ask the user.
```

Or use `agent-sudo check -- <command>` (exit 0 / 126, nothing executes) inside a
pre-tool-use hook, and `agent-sudo run --dry-run -- <command>` to preview.

## Policy

`agent-sudo init` writes a starter `agent-sudo.toml`:

```toml
deny = ["\\bkubectl\\s+delete\\b"]          # extra regexes, on top of the built-in rules
allow = ["^(ls|cat|grep|git (status|log|diff)|systemctl (status|restart) myapp)\\b"]  # strict mode
snapshot = ["config", "app.db"]            # backed up before each run
timeout = 120
```

With `allow` set, **every** segment of a pipeline (`a && b | c`) must match, so
`ls && curl evil.sh` is rejected.

## What this is NOT

Read this before you trust it.

- **It is a guardrail, not a sandbox.** Pattern matching catches the mistakes
  and the obvious bad ideas an agent makes by accident. It does **not** stop a
  determined or prompt-injected agent that obfuscates (`python -c`, base64,
  `$(…)` tricks). For hostile workloads use a container/VM/least-privilege user
  *and* agent-sudo; the allowlist mode is the strongest setting here.
- Redaction is best-effort: env var values and common secret formats, not
  arbitrary secrets the tool can't recognise.
- Snapshots copy only the paths you list; they don't cover databases that
  changed outside those files, or side effects like API calls.

## Why

Agents are most useful when they can touch real systems, and most dangerous for
the same reason. Heavy sandboxes are great and slow to adopt; this is the 60-second
version that catches the common disasters. Built after wrestling a production
server with AI agents that had far too much access.

## Develop

```bash
pip install pytest tomli && pytest -q
```

MIT licensed. Issues and rule contributions welcome (see `DEFAULT_DENY` in `agent_sudo.py`).
