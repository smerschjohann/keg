# Keg (Kernel-isolated Execution with Gateways) Agent Prompt & Repository Setup Guide

You are setting up a software repository to run securely inside **keg**, an isolated bubblewrap sandbox with zero-trust network egress and host delegation. Create valid defaults but inform the user of possible shortcomings and give a list of things you want to delegate before actually doing it.

---

## 1. Architecture & Security Principles

* **Strict Isolation:** Sandboxes run in unprivileged Linux user/mount/pid/net namespaces (`bwrap --unshare-all`). Only the repository root and explicit mounts are available.
* **Zero-Trust Network Egress (Deny-by-default):** The sandbox has only loopback network access (`127.0.0.1`).
  * HTTP/HTTPS traffic goes through the internal proxy on `127.0.0.1:18081` (whitelisted via `network.sni_domains`).
  * DNS resolution is handled by the internal DNS server on `127.0.0.1:53` (whitelisted + static `hosts` mappings).
  * Dev services running in the sandbox can expose ports to the host via `ports` back-channels.
* **Host Delegation:** Host-dependent tasks (e.g. Playwright browser tests, Podman container builds, Git commits in linked worktrees) are delegated transparently to the host via `just delegate <task> [args...]` or `keg delegate <task> [args...]`.
* **Offline Caching:** Language templates (`go`, `java`, `node`, `python`) mount host warm-caches read-write into the sandbox so builds run offline without internet access.

---

## 2. Justfile Delegation Pattern

To enable seamless execution both inside the sandbox and directly on the host, use the **`sandbox.just`** pattern:

### Step 1: Create `sandbox.just`
Place this file in the repository root (or generate via `keg agent sandbox-just > sandbox.just`):

```just
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
```

### Step 2: Configure your `justfile`
Import `sandbox.just` at the top of your `justfile` and wrap host-delegated recipes:

```just
import 'sandbox.just'

default:
    @just --list

# ── In-Sandbox Tasks (Offline builds, tests) ───────────────────
test:
    #!/usr/bin/env bash
    set -euo pipefail
    go test -v ./...

build:
    #!/usr/bin/env bash
    set -euo pipefail
    go build -o bin/app .

# ── Delegated Tasks (Host-only, e.g. Playwright, Podman) ───────
test-playwright test_file="" port="8080":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{in_sandbox}}" = "1" ]; then
        echo "[Sandbox] Delegating 'test-playwright' to host runner..."
        just delegate test-playwright "{{test_file}}" "{{port}}"
        exit $?
    fi

    echo "Running Playwright on host against port {{port}}..."
    npx playwright test {{test_file}}

container-build tag="latest":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{in_sandbox}}" = "1" ]; then
        just delegate container-build "{{tag}}"
        exit $?
    fi

    podman build -t "myapp:{{tag}}" .
```

---

## 3. Repository Configuration (`.keg.yaml`)

Create `.keg.yaml` in the root of the repository:

```yaml
version: "1"

# Language templates for toolchain env and cache binds (go, java, node, python)
templates:
  - go

# Environment variable configuration
env:
  inherit:
    - MY_VAR_FROM_HOST
  set:
    APP_ENV: test

# Secrets required by the sandbox (resolved from host user config to /run/secrets/<name>)
secrets:
  - name: ai_token          # dynamic secret from user config secret_sources
    env: AI_TOKEN_FILE      # sets AI_TOKEN_FILE=/run/secrets/ai_token
  - name: github_pat        # static host-file secret from user config secrets map

# Port back-channel exposing sandbox services to host loopback (for Playwright, etc.)
ports:
  - "8080"

# Zero-trust network egress policy
network:
  mode: proxy # proxy | transparent | both
  sni_domains:
    - maven.repo.company.tld
  dns:
    enabled: true
    hosts:
      db.local.test: "127.0.0.1"

# Whitelist of tasks allowed to execute on the host
delegated_tasks:
  exact:
    - container-build
  prefixes:
    - test-playwright
  raw:
    - cmd: git
      # here we typically don't want to have push rights.
      subcommands: [add, branch, checkout, commit, diff, fetch, log, merge, rebase, reset, show, stash, status, switch]
      opts_with_value: ["-c", "-C", "--git-dir", "--work-tree"]
      flags: ["--no-pager", "--paginate", "--no-paginate"]
      allow_opt_value_form: true
      forbidden_args_matching:
        - "https://*"
        - "http://*"
        - "git@*"
        - "ssh://*"
```

---

## 4. User Machine Configuration (`~/.config/keg/config.yaml`)

Machine-local paths and secret provider mechanisms live in user config:

```yaml
paths:
  storage_base: /var/lib/containers/storage/sandbox
  tmp_base: /tmp

# Dynamic secrets: fetched/refreshed periodically via host command
secret_sources:
  ai_token:
    cmd: ["op", "read", "op://Vault/AI/token"]
    interval: 5m
    timeout: 10s
    on_refresh_error: keep

# Static host file secrets: bind-mounted read-only to /run/secrets/<name> (~/$VAR expanded)
secrets:
  github_pat: "~/.config/gh/hosts.yml"

runner:
  extra_prefixes:
    - agy

security:
  landlock: auto
```

---

## 5. Helpful Commands

* `keg agent prompt` — Show this setup prompt.
* `keg agent schema repo` — Query JSON schema for `.keg.yaml`.
* `keg agent schema user` — Query JSON schema for user `config.yaml`.
* `keg agent sandbox-just` — Output `sandbox.just` delegation helper snippet.
* `keg run` — Start interactive sandbox.
* `keg run --ephemeral -- just test` — Run tests in throwaway tmpfs overlay.
* `keg run --disk-overlay <name>` — Run in persistent diff-able on-disk layer.
