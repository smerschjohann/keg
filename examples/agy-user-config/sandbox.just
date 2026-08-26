# sandbox.just — Delegation pattern for running host-only tasks from inside keg

in_sandbox := env_var_or_default("KEG_RUNNER", env_var_or_default("KEG_DELEGATION", env_var_or_default("CODE_SANDBOX", "0")))

set positional-arguments := true

# Delegate a task to the host runner
[private]
delegate *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{in_sandbox}}" != "1" ]; then
        echo "✗ 'just delegate' can only be executed inside an active sandbox." >&2
        exit 1
    fi
    exec keg delegate "$@"
