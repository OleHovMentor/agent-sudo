#!/usr/bin/env bash
# Scripted terminal demo. Record with:
#   asciinema rec -c "bash demo/demo.sh" demo.cast      (then: agg demo.cast demo.gif)
# Run from the repo root.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"; cd "$W"
agent-sudo() { python3 "$ROOT/agent_sudo.py" "$@"; }
export STRIPE_SECRET_KEY=demo_secret_value_123456
echo "important data" > app.db
printf 'snapshot = ["app.db"]\n' > agent-sudo.toml

type_cmd() {
  printf '\033[1;32m$\033[0m '
  for ((i=0;i<${#1};i++)); do printf '%s' "${1:$i:1}"; sleep 0.03; done
  echo; sleep 0.4
}
say() { printf '\n\033[2m# %s\033[0m\n' "$1"; sleep 1; }

say "Your AI agent decides to read secrets..."
type_cmd "agent-sudo run -- cat .env"
agent-sudo run -- cat .env; sleep 1.2

say "...or wipe the server"
type_cmd "agent-sudo run -- rm -rf /"
agent-sudo run -- rm -rf /; sleep 1.2

say "Secrets never reach the model's context"
type_cmd 'agent-sudo run -- echo "key: $STRIPE_SECRET_KEY"'
agent-sudo run -- 'echo "key: $STRIPE_SECRET_KEY"'; sleep 1.2

say "A bad edit? Snapshot was taken automatically."
type_cmd "agent-sudo run -- 'echo oops > app.db'"
agent-sudo run -- 'echo oops > app.db'; cat app.db; sleep 0.8
type_cmd "agent-sudo rollback"
agent-sudo rollback; cat app.db; sleep 1.5
