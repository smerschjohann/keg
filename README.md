# keg — Kernel-isolated Execution with Gateways

Isolated development sandbox powered by **bubblewrap** (`bwrap`) with zero-trust egress — a single, robust Go binary instead of error-prone shell scripts.

---

## 1. Overview & Architecture

`keg` isolates untested or AI-agent-generated code in a hermetic sandbox. Isolation is enforced at the kernel level using unprivileged Linux namespaces (`--unshare-all`) and optional **Landlock LSM** filesystem restrictions.

### Communication Channels (FD Map & Zero-Trust)

All communication between the sandbox and host occurs strictly through controlled file descriptors:

```
┌───────────────────────────── HOST ─────────────────────────────┐
│ keg (Host Orchestrator)                                        │
│  ├─► Channel A (FD 3): Egress HTTP/HTTPS Proxy (CONNECT Whitelist) │
│  ├─► Channel B (FD 4): Whitelist DNS (:53, loopback resolv.conf) │
│  ├─► Channel C (FD 5): Host Delegation Runner (Whitelisted Tasks)│
│  ├─► Channel D (FD 6): Control / Guest Agent (RPC & Streaming) │
│  ├─► Channel E (FD 7): Reverse Port Forwarding (KEG_PORT_*)    │
│  └─► /run/secrets:     Dynamic Secrets (0400 ro-bind, Refresh) │
└──────────────────────────────┬─────────────────────────────────┘
                               │ bwrap socketpairs
┌──────────────────────────────▼─────────────────────────────────┐
│ SANDBOX (PID / IPC / Net / User / Mount / UTS Namespaces)      │
│  ├─► Workload / Agent / Compiler                               │
│  ├─► Loopback Interface (no default gateway, no raw network)   │
│  └─► Landlock LSM (syscall restrictions for rootfs & mounts)   │
└────────────────────────────────────────────────────────────────┘
```

| Channel | FD | Protocol | Purpose |
|---|---|---|---|
| **Channel A (Proxy)** | `FD 3` | `muxado` Session | HTTP/HTTPS proxy with strict SNI and domain whitelisting. |
| **Channel B (DNS)** | `FD 4` | RFC 1035 TCP Framing | Filtering DNS server on loopback `:53`, static hosts & wildcards. |
| **Channel C (Delegation)** | `FD 5` | Length-Prefixed JSON | Secure execution of allowed host tasks (`just delegate`). |
| **Channel D (Control)** | `FD 6` | `muxado` Session | Control channel & RPC for library / daemon modes. |
| **Channel E (Ports)** | `FD 7` | `muxado` Session | Reverse port back-channel from host into sandbox (`KEG_PORT_<NAME>`). |

---

## 2. Installation & CLI Usage

### Prerequisites & System Requirements

* **Linux Kernel:** ≥ 5.11 with unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone = 1` / `user.max_user_namespaces > 0`).
* **util-linux:** `unshare` utility available on `PATH`.
* **Bubblewrap (`bwrap`):** **`bwrap ≥ 0.11.0`** is required for `--ephemeral` and disk overlay mounts (`--overlay-src`, `--tmp-overlay`).

#### Note for Ubuntu LTS (24.04 / 22.04) and Debian 12 (Bookworm)

Distribution package repositories in older LTS releases only provide older versions of bubblewrap (e.g., Ubuntu 24.04 LTS ships `bwrap 0.9.0`, Debian 12 ships `0.8.0`), which lack overlay mount support.

To build and install `bwrap 0.11.0` on Ubuntu 24.04 LTS / Debian:

```bash
# 1. Install build dependencies
sudo apt-get update && sudo apt-get install -y \
  git make gcc meson ninja-build libcap-dev libseccomp-dev pkg-config

# 2. Clone and build bwrap 0.11.0 (compiles in ~2 seconds)
git clone --depth 1 --branch v0.11.0 https://github.com/containers/bubblewrap.git /tmp/bwrap
cd /tmp/bwrap && meson setup _build --prefix=/usr && ninja -C _build && sudo ninja -C _build install

# 3. Verify installed version (must be >= 0.11.0)
bwrap --version
```

*(Modern distributions such as Fedora 40+, Debian Trixie/Sid, and Ubuntu 24.10+ already provide `bwrap ≥ 0.11.0` in their default package repositories).*

### Building

```bash
make build          # -> bin/keg
```

### Commands

#### 1. Starting a Sandbox (`keg run`)

```bash
# Interactive shell in current repository:
bin/keg run

# Run command directly inside isolation:
bin/keg run -- go test ./...

# Ephemeral run (repository untouched via tmpfs upper overlay):
bin/keg run --ephemeral -- just build

# Persistent disk overlay (changes persist across sandbox exits):
bin/keg run --disk-overlay agent-feature -- bash

# Cache isolation for Go/toolchain caches (read warm cache, write tmpfs):
bin/keg run --isolate-caches -- go build ./...

# Parallel sandbox instances with deterministic name:
bin/keg run --name worker-1 -- just test

# Pass through or set environment variables in sandbox:
bin/keg run -e LANG -e COLORTERM -e CUSTOM_VAR=value -- bash

# Set or override template variables on invocation:
bin/keg run --var token_ttl=1800 -V custom_greeting=hello -- bash

# Pass through all host environment variables (except denied credentials/proxies):
bin/keg run --inherit-all -- bash

# Combine: Pass through all host variables plus explicitly allowed sensitive vars:
bin/keg run --inherit-all -e AWS_SESSION_TOKEN -e HTTP_PROXY -- bash
```

#### 2. Repository Approval & Trust (`keg trust`)

Non-empty `.keg.yaml` files and associated trust anchors (e.g. `trust_anchors:` or referenced `justfiles` in delegated tasks) are subject to the repository trust gate:

```bash
# Approve / trust current repository configuration:
bin/keg trust

# Check approval status (TRUSTED, CHANGED, NONE):
bin/keg trust --status

# Revoke repository approval:
bin/keg trust --revoke
```

#### 3. Layer Management (`keg list`, `clean`, `clean-cache`)

```bash
# List all persistent disk and cache layers:
bin/keg list

# Delete specific repository overlay layer:
bin/keg clean agent-feature

# Delete specific cache layer:
bin/keg clean-cache agent-feature

# Clean all layers with interactive confirmation:
bin/keg clean --all
```

#### 4. Host Delegation (`keg delegate`)

Inside the sandbox, approved tasks can be delegated to the host runner:

```bash
# Transparently delegates 'test-playwright' to the host:
bin/keg delegate test-playwright login.spec.ts 8080

# Run allowed Git commands on host:
bin/keg delegate git commit -m "feat: new feature"
```

#### 5. Background Daemon (`keg serve`)

Starts the RPC daemon for daemon and remote control:

```bash
# Standard Unix socket (0660, SO_PEERCRED audit):
bin/keg serve --listen unix:///run/keg/api.sock

# TCP listener (requires authentication token):
bin/keg serve --listen 127.0.0.1:7777 --auth token --token "my-secret-token"
```

---

## 3. Go Library API (`pkg/keg`)

`keg` can be imported directly as a Go library:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/smerschjohann/keg/pkg/keg"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sb, err := keg.Launch(ctx, "/path/to/repo",
		keg.WithEphemeral(),
		keg.WithName("agent-task"),
		keg.WithCommand("go", "test", "./..."),
	)
	if err != nil {
		log.Fatalf("Launch: %v", err)
	}
	defer sb.Close()

	// Query sandbox path to mounted dynamic secrets
	secretPath := sb.SecretPath("ai_secret_key") // -> "/run/secrets/ai_secret_key"
	fmt.Printf("Secret mounted at: %s (Host PID: %d)\n", secretPath, sb.Pid())

	// Wait for completion
	exitCode, err := sb.Wait()
	if err != nil {
		log.Fatalf("Wait: %v", err)
	}
	fmt.Printf("Sandbox exited with code: %d\n", exitCode)
}
```

---

## 4. Configuration

### Repository Configuration (`.keg.yaml`)

Located in the root directory of the repository:

```yaml
version: "1"

# Predefined toolchain presets (golang, rust, python, node)
templates:
  - golang

# Additional PATH directories in sandbox (prepended / appended to $PATH)
paths:
  prepend:
    - node_modules/.bin
    - vendor/bin
  append:
    - /opt/fallback/bin


# Environment variable controls (Deny-by-default)

env:
  inherit:
    - LANG
    - COLORTERM
  set:
    LOG_FORMAT: json

# Dynamic secrets (0400 read-only under /run/secrets/<name>)
secrets:
  - name: ai_secret_key
    env: AI_SECRET_KEY

# Network and egress policies
network:
  mode: proxy
  dns:
    enabled: true
    hosts:
      db.internal: 10.0.0.5
  sni_domains:
    - api.anthropic.com
    - api.openai.com
    - proxy.golang.org

# Port back-channel: Forward host connections into sandbox (§4.9)
#
# A dev server runs INSIDE the sandbox (e.g. :3000). To allow host access
# (Browser, Playwright, curl), the repo declares the ports.
# keg binds host listeners and tunnels connections over Channel E into sandbox.
ports:
  - "3000"              # Sandbox 127.0.0.1:3000 -> Host 127.0.0.1:3000
  - "5432:15432"        # Sandbox :5432 -> custom host port 15432
  - name: dev-server
    port: 8080
    dynamic: true       # collision-free host port, available in sandbox as
                        # $KEG_PORT_DEV_SERVER
```

**How Port Forwarding Works (Host → Internal Sandbox Port):**

1. The service runs **inside** the sandbox and binds `127.0.0.1:<guest>` — unreachable from outside since the sandbox only possesses its own loopback.
2. When exposed, the host binds the port: declarations without separator (`"3000"`) use the same host port; `"<guest>:<host>"` selects a custom host port; `dynamic: true` conflict-freely reserves an available host port and sets `$KEG_PORT_<NAME>` in sandbox environment (normalized to `[A-Z0-9_]`).
3. `keg` connects on each connection over **Channel E** into the sandbox; the guest forwarder dials the target on sandbox loopback. The sandbox gains **no** outgoing path — it only receives forwarded connections.
4. Security: The host exclusively binds `127.0.0.1`, never `0.0.0.0`; guest forwarder strictly dials declared targets (deny-by-default). Details and invariants: `CONCEPT.md` §4.9 and `THREAT_MODEL.md` §5.8.

```yaml
# Whitelist for host delegation
delegated_tasks:
  exact:
    - build
    - test
  prefixes:
    - "test-playwright"
  raw:
    - cmd: git
      subcommands: [status, diff, log, add, commit]
```

### User Configuration (`~/.config/keg/config.yaml`)

Machine- and user-specific settings:

```yaml
paths:
  storage_base: "/var/lib/containers/storage/sandbox"
  tmp_base: "/tmp"

# Host secret sources with automatic refresh (supports Go templates: .Vars.instance, .Vars.token_ttl, .Vars.secret_name)
secret_sources:
  ai_secret_key:
    cmd: ["genkey", '{{ .Vars.instance | default "keg" }}', '{{ .Vars.token_ttl | default "60" }}']
    interval: 30s
    timeout: 5s
    on_refresh_error: keep
    # always: true   # optional: inject secret into EVERY sandbox
    # async: true    # optional: fetch asynchronously in background without blocking launch

# Expose existing host files as secrets (ro-bind to /run/secrets/<name>; ~ and $VAR expanded).
# The repo declares requirements via secrets: — allowing multiple sandboxes to share files without copies.
secrets:
  github_pat: "~/.config/gh/hosts.yml"

# Additional per-target-repo secret requirements (merged with repo .keg.yaml):
repos:
  "/home/code/agent-repo":
    secrets:
      - name: ai_secret_key
        env: AI_SECRET_KEY

# Security & LSM settings
security:
  landlock: auto # auto | on | off

# Central audit logging
log:
  audit_file: "~/.config/keg/audit.log"
```

### Activating Secrets (Three Ways)

Providing a secret (provider mechanism) and requesting one (requirement) are strictly separated. A secret defined in user configuration is only mounted (`/run/secrets/<name>`) when requested by one of the following sources:

1. **Repo `.keg.yaml`** (portable, version-controlled):
   ```yaml
   secrets:
     - name: ai_secret_key
       env: AI_SECRET_KEY
   ```
2. **`repos[<match>].secrets` in User Configuration** (specific to target repo, leaving repo untouched) — merged with repo declarations:
   ```yaml
   repos:
     "/home/code/agent-repo":
       secrets:
         - name: ai_secret_key
           env: AI_SECRET_KEY
   ```
3. **`always: true` in `secret_sources`** (globally for **every** sandbox):
   ```yaml
   secret_sources:
     ai_secret_key:
       cmd: ["genkey", "keg", "1500"]
       interval: 10m
       always: true        # -> /run/secrets/ai_secret_key in EVERY sandbox
   ```

The `name` must exist in `secret_sources` or the `secrets:` map of user configuration; otherwise launch fails immediately. `env:` additionally sets `<ENV> = /run/secrets/<name>`.

---

## 5. Examples

- **[`examples/pi-agent`](file:///home/coder/dev/jailbox/examples/pi-agent/README.md):** Complete AI agent example featuring `golang` preset, dynamic `genkey` secret generation to `/run/secrets/ai_secret_key`, and `just test-playwright` delegation.
- **[`examples/agy`](file:///home/coder/dev/jailbox/examples/agy/README.md):** **Project Configuration (In-Sandbox):** Running `agy` inside sandbox; all mounts and network policies (`mode: transparent`, DNS forwarding, TCP endpoints) declared in `.keg.yaml`.
- **[`examples/agy-user-sandbox`](file:///home/coder/dev/jailbox/examples/agy-user-sandbox/README.md):** **User Configuration (In-Sandbox):** Clean repository without Google endpoints; user enables `agy` in their `user_config.yaml` (`~/.config/keg/config.yaml`) via additive mounts and zero-trust network rules. `agy` runs **fully isolated and sandboxed**.
- **[`examples/agy-user-config`](file:///home/coder/dev/jailbox/examples/agy-user-config/README.md):** **User Configuration (Host Delegation):** Clean repository; `agy` runs on host and delegates over Channel C (`runner.extra_prefixes: ["agy"]`).

---

## 6. Development & Testing

```bash
make lint            # golangci-lint (must pass with 0 warnings)
make test            # all unit tests with -race
make integration     # bwrap integration tests (tag: integration)
make tidy            # go mod tidy (must remain diff-free)
```

---

## 7. Documentation

- [`CONCEPT.md`](CONCEPT.md) — Detailed architecture, data flows, and design decisions.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — Threat model and security invariants (§8).
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — Milestones M1–M9 and status.
- [`docs/container-requirements.md`](docs/container-requirements.md) — Minimum requirements for running in Docker / Podman / Kubernetes.
- [`docs/errors.md`](docs/errors.md) — Error catalog and exit codes.
