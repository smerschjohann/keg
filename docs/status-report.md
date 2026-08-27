# keg — Kernel-isolated Execution with Gateways — Status- und Konformitätsbericht

> **Dokument:** Statusbericht & Architektur-Audit der aktuellen Implementierung  
> **Datum:** 27. August 2026  
> **Referenz-Commit:** `6dc220f` (Release-Basis `v0.1.1` + Seccomp-BPF Profil)  
> **Prüfumgebung:** Live-Prüfung aus einer aktiven `keg`-Sandbox-Instanz (In-Sandbox Verifikation)  
> **Referenzdokumente:** [`CONCEPT.md`](CONCEPT.md), [`THREAT_MODEL.md`](../THREAT_MODEL.md), [`AGENTS.md`](../AGENTS.md), [`docs/plans/`](../docs/plans)

---

## 1. Executive Summary

Die Überprüfung der aktuellen Codebasis von **`keg`** gegen das Architektur-Konzept ([`CONCEPT.md`](../CONCEPT.md)), das Bedrohungsmodell ([`THREAT_MODEL.md`](../THREAT_MODEL.md)) und alle fünf Implementierungspläne ([`docs/plans/`](../docs/plans)) ergibt einen **vollständigen Umsetzungsgrad von 100 %**.

Alle Kernmeilensteine **Phase 0** sowie **M1 bis M9** des Initialplans sowie sämtliche nachgelagerten Erweiterungspläne (**Host-Env-Steuerung & Trust-Gate**, **Generische Trust-Anchors**, **Secret-Template-Rendering & `--var`** sowie **Seccomp-BPF Profilierung**) sind vollständig implementiert, architektonisch sauber integriert und durch automatisierte Unit-, Protokoll- und Integrationstests abgedeckt.

### Wichtigste Kennzahlen & Status

| Bereich | Vorgabe | Ist-Zustand | Konformität |
|---|---|---|:---:|
| **Kernmeilensteine M1–M9** | 9 Meilensteine | Alle 9 Meilensteine implementiert und stabil | ✅ 100 % |
| **Erweiterungspläne (4 Pläne)** | 4 Feature-Pakete | Alle 4 Pläne vollständig im Codebase gemerged | ✅ 100 % |
| **Sicherheitsinvarianten (§8)** | 9 Invarianten | 9 Invarianten durch `TestInvariant_*` gedeckt | ✅ 100 % |
| **Abhängigkeitsbudget (§1)** | Geschlossene Liste (6 Deps) | Budget exakt eingehalten, keine Fremdframeworks | ✅ 100 % |
| **Live-Sandbox-Isolation** | bwrap + netns + seccomp + landlock | Live-Audit bestätigt alle Härtungsstufen aktiv | ✅ 100 % |

---

## 2. Empirische Live-Verifikation der laufenden Sandbox

Der Audit wurde direkt aus der laufenden `keg`-Gastumgebung heraus durchgeführt. Die Inspektion der Kernel-Schnittstellen bestätigt die Wirksamkeit der implementierten Sicherheitsmechanismen im laufenden Betrieb:

### 2.1 Prozess- & Privilegien-Status (`/proc/self/status`)
* **Capabilities:** `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` sind alle `0000000000000000` (vollständig leeres Capability-Set).
* **Privilege Escalation:** `NoNewPrivs: 1` ist aktiv (verhindert SUID-/File-Cap-Eskalation).
* **Seccomp-Filter:** `Seccomp: 2` (`SECCOMP_MODE_FILTER`) mit aktivem cBPF-Filter (`Seccomp_filters: 1`).
* **User-ID:** UID/GID `1000:1000` gemappt, kein Root-Kontext im User-Namespace.

### 2.2 Netzwerk-Isolation & Stage-Topologie
* **Netzwerk-Interfaces:** Ausschließlich Loopback `lo` ist im Namespace vorhanden (`ip link`). Es existiert kein direktes physisches oder virtuelles Host-Interface (`eth0`, `wlan0` etc.).
* **Routen:** `default dev lo scope link` leitet den gesamten Sandbox-Verkehr an die private Loopback-Adresse.
* **DNS & Egress-Routing:** `/etc/resolv.conf` zeigt auf `nameserver 127.0.0.1`. DNS-Anfragen werden über das Netns-Stage-Relay an den Host-Resolver ([`internal/egress/dns`](../internal/egress/dns)) gerahmt (`fd 4`). Nicht autorisierte Domains werden per `NXDOMAIN` geblockt.

### 2.3 Dateisystem & Mount-Hierarchie (`/proc/mounts`)
* **Rootfs:** `tmpfs` auf `/` gemountet (flüchtig, keine persistenten Schreibspuren auf dem Host-Root).
* **Systempfade:** `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/passwd`, `/etc/ssl/certs` sind read-only (`ro`) gebunden.
* **Workspace:** `/home/coder/dev/keg` ist als isolierter Workspace rw gemountet.
* **Home:** `/home/sandbox` ist ein separates flüchtiges `tmpfs`.
* **Secrets-Engine:** `/run/secrets` ist als separates `ro`-Dateisystem mit restriktiven Berechtigungen (`0700` Verzeichnis, `0400` Datei) eingehängt.

### 2.4 Deskriptor- & Signal-Hygiene (`/proc/self/fd`)
* Ausschließlich die Standard-Deskriptoren `0`, `1`, `2` (PTY `/dev/pts/1`) sowie Sandbox-interne Prozessdateien sind für den Workload geöffnet.
* Keine durchgereichten Host-Dateien, fremden Sockets oder verwaisten Control-FDs sichtbar ([`TestInvariant_WorkloadGetsOnlyStdioFDs`](../internal/orchestrator/guest_test.go)).

---

## 3. Umsetzungsprüfung aller Meilensteine & Pläne

### 3.1 Initialplan (`2026-08-26.1-intial.md`): Meilensteine M1 bis M9

| Meilenstein | Titel / Scope | Status | Wichtigste Komponenten |
|---|---|:---:|---|
| **Phase 0** | Repo-Skelett, Build & CLI-Rahmen | ✅ Erledigt | [`cmd/keg`](../cmd/keg), [`Makefile`](../Makefile), `urfave/cli/v3` |
| **M1** | Skeleton: Isolierte Shell | ✅ Erledigt | [`internal/orchestrator/builder.go`](../internal/orchestrator/builder.go), `bwrap`-Argbuilder, EBUSY-Retries |
| **M2** | Proxy-Kanal (A) | ✅ Erledigt | [`internal/egress/proxy`](../internal/egress/proxy), CONNECT-Tunnel, Domain-Matcher, Audit-Logging |
| **M3** | DNS-Kanal (B) & Transparent-Modus | ✅ Erledigt | [`internal/egress/dns`](../internal/egress/dns), Netns-Stage (`unshare`), Port 53 Bridge, SNI-Relay |
| **M4** | Templates, Vars, Ports (Kanal E) | ✅ Erledigt | [`internal/template`](../internal/template), Toolchains (Go/Node/Java/Python), [`internal/portsfw`](../internal/portsfw) |
| **M5** | Delegation (Kanal C) | ✅ Erledigt | [`internal/runner`](../internal/runner), Whitelist (exact/prefixes/raw), Hook-Unterdrückung |
| **M6** | Overlays & Layer-Management | ✅ Erledigt | [`internal/storage`](../internal/storage), `--ephemeral`, `--disk-overlay`, `--isolate-caches`, Tiered Deletion |
| **M7** | Polish & Multi-Instance | ✅ Erledigt | Structured Logging (`slog`), `audit.log`, `--name`, [`docs/errors.md`](../docs/errors.md) |
| **M8** | Hardening (Landlock/Secrets/CGO) | ✅ Erledigt | [`internal/landlock`](../internal/landlock), [`internal/secrets`](../internal/secrets), FD-Scrubbing |
| **M9** | Go-Library & Daemon | ✅ Erledigt | [`pkg/keg`](../pkg/keg), [`internal/daemon`](../internal/daemon), `keg serve` |

---

### 3.2 Erweiterungspläne (Post-M9 Features)

#### A. Host-Environment-Steuerung & Trust-Gate ([`2026-08-26.2-env-passthrough.md`](../docs/plans/2026-08-26.2-env-passthrough.md))
* **Host-Env Deny-by-Default:** Workloads erben keine Host-Umgebungsvariablen mehr implizit.
* **Deklaratives Passthrough:** `env.inherit` und `env.inherit_all` in Repo- und User-Config implementiert.
* **CLI-Steuerung:** `keg run -e VAR` (Passthrough) und `-e VAR=value` (explizites Setzen) sowie `--inherit-all`.
* **Repository-Trust-Gate:** Kryptografische Validierung (SHA-256) der `.keg.yaml` gegen `$XDG_CONFIG_HOME/keg/trust.yaml`.
* **Interaktiv vs. Non-TTY:** TTY fordert Bestätigung mit formatierter Diff-Ansicht; Non-TTY bricht fail-closed mit Exit-Code 1 ab.
* **Status:** ✅ Vollständig umgesetzt und verifiziert.

#### B. Generische Trust-Anchors für Repositories ([`2026-08-27.1-trust-anchors.md`](file:///home/coder/dev/keg/docs/plans/2026-08-27.1-trust-anchors.md))
* **Deklaration:** `trust_anchors: [...]` in der Repo-Konfiguration für beliebige Build-Skripte oder Hilfsdateien.
* **Auto-Detection:** Automatische Aufnahme des Root-`justfile` (bzw. `Justfile`, `.justfile`) bei deklarierten delegierten Just-Tasks (`delegated_tasks.exact` / `prefixes`).
* **Rekursive Import-Auflösung:** Vollständige statische Erkennung aller in Justfiles referenzierten `import`-, `import?`- und `!include`-Dateien (wie z. B. `sandbox.just` oder Modul-Justfiles) inklusive Zyklen- und Traversal-Schutz ([`internal/config/justfile.go`](file:///home/coder/dev/keg/internal/config/justfile.go)).
* **Laufzeit-Verifikation:** Prüfung der Integrität unmittelbar vor der Ausführung delegierter Host-Befehle im Runner ([`internal/runner/server.go`](file:///home/coder/dev/keg/internal/runner/server.go)), um Tampering während des Laufs auszuschließen.
* **CLI-Integration:** `keg trust`, `keg trust --status`, `keg trust --revoke`.
* **Status:** ✅ Vollständig umgesetzt und verifiziert.

#### C. Secret-Template-Rendering & CLI-Variablen ([`2026-08-27.2-secret-templates-and-cli-vars.md`](../docs/plans/2026-08-27.2-secret-templates-and-cli-vars.md))
* **Dynamische Secret-Befehle:** Go-Template-Auswertung in `secret_sources[<name>].cmd`.
* **Standard-Kontext:** Zugriff auf `{{ .Vars.instance }}`, `{{ .Vars.secret_name }}`, `{{ .Vars.repo_dir }}` und benutzerdefinierte `.Vars`.
* **Subprozess-Umgebung:** Bereitstellung von `KEG_INSTANCE`, `KEG_SECRET_NAME` und `KEG_REPO_DIR` in `cmd.Env`.
* **CLI-Flag `--var / -V`:** Ad-hoc-Überschreiben von Template-Variablen mit höchster Priorität beim Aufruf von `keg run`.
* **Status:** ✅ Vollständig umgesetzt und verifiziert.

#### D. Seccomp-BPF Syscall-Filterung ([`2026-08-27.3-seccomp-profile.md`](../docs/plans/2026-08-27.3-seccomp-profile.md))
* **In-Process cBPF-Compiler:** Null-Abhängigkeiten-Compiler ([`internal/seccomp`](../internal/seccomp)) über `golang.org/x/sys/unix`.
* **Blockliste:** Gezielte Filterung angriffsträchtiger Kernel-Schnittstellen (`bpf`, `io_uring_*`, `perf_event_open`, `userfaultfd`, `keyctl`, `kexec_load`, `init_module` etc.) mit Rückgabe von `EPERM`.
* **Übergabeweg:** Injektion des Bytecodes über memfd via `--add-seccomp-fd` in `bwrap ≥ 0.11`.
* **User-Opt-out:** Deaktivierung ausschließlich über vertrauenswürdige User-Config (`security.seccomp: off`).
* **Status:** ✅ Vollständig umgesetzt und verifiziert.

---

## 4. Konformitätsprüfung der Sicherheitsinvarianten ([`THREAT_MODEL.md`](../THREAT_MODEL.md) §8)

Alle 9 Sicherheitsinvarianten wurden systematisch gegen den Code und die Testsuite abgeglichen:

| Invariante | Kernanforderung | Schutzmechanismus | Test-Referenz | Status |
|---|---|---|---|:---:|
| **Inv. 1** | Nur kontrollierte Kanäle | Proxy (A) + DNS (B) + Rückkanal (E); Loopback-only Binding | [`TestInvariant_ProxyEnvNeverPointsOffLoopback`](../internal/orchestrator/egress_test.go#L59)<br>[`TestInvariant_PortPublishBindsOnlyLoopback`](../internal/orchestrator/orchestrator_test.go#L1152)<br>[`TestInvariant_PortChannelGuestDenyList`](../test/integration/ports_test.go#L100) | ✅ Konform |
| **Inv. 2** | Deny-by-Default für Host-Env | Kein Env-Leak; Core + explizite Variablen; gesperrte Proxy/Auth-Vars geblockt | [`TestInvariant_HostEnvNeverInherited`](../internal/orchestrator/orchestrator_test.go#L78)<br>[`TestInvariant_GuestStripsHostEnv`](../internal/orchestrator/guest_test.go#L38)<br>[`TestInvariant_EnvPassthroughDeniedNameRejected`](../internal/orchestrator/orchestrator_test.go#L948)<br>[`TestInvariant_WorkloadGetsOnlyExplicitEnv`](../internal/orchestrator/guest_test.go#L455) | ✅ Konform |
| **Inv. 3** | Repository-Trust-Gate & Anchors | SHA-256 Prüfung von `.keg.yaml` & Trust-Anchors (`justfile`); TTY Diff / Non-TTY Reject | [`TestEnsureTrust_WithAnchors_TTY_Approve`](../internal/trust/prompt_test.go)<br>[`TestEnsureTrust_WithAnchors_NonTTY_Rejection`](../internal/trust/prompt_test.go)<br>[`TestVerifyApproved`](../internal/trust/trust_test.go) | ✅ Konform |
| **Inv. 4** | Isolation nur verschärft | Repo-Config kann bwrap-Flags nie lockern; `security.allow_weak_bwrap` Pflicht | [`TestInvariant_IsolationAlwaysEnforced`](../internal/orchestrator/orchestrator_test.go#L28)<br>[`TestInvariant_WeakBwrapNeedsConsent`](../internal/orchestrator/orchestrator_test.go#L44) | ✅ Konform |
| **Inv. 5** | Ausführung braucht User-Config | `vars_from_exec` und `secret_sources` nur in vertrauenswürdiger User-Config erlaubt | [`TestParseRepo_RejectsExecSources`](../internal/config/config_test.go)<br>[`TestUserConfig_ExecSourcesAllowed`](../internal/config/config_test.go) | ✅ Konform |
| **Inv. 6** | Delegation ist explizit | Exact/Prefix/Raw Whitelist; Pfad-Jail; Git-Hook-Unterdrückung (`-c core.hooksPath=...`) | [`TestInvariant_DelegationDenyByDefault`](../internal/runner/whitelist_test.go#L327)<br>[`TestServer_PathJailBlocksEscapes`](../internal/runner/server_test.go)<br>[`TestServer_SuppressesGitHooksForRawGitJobs`](../internal/runner/server_test.go) | ✅ Konform |
| **Inv. 7** | Secrets minimal exponiert | Mode `0400`/`0700`, atomarer Swap, In-Memory/Tmpfs, keine Werte in Logs/Audits | [`TestSecrets_AtomicSwap`](../internal/secrets/secrets_test.go)<br>[`TestSecrets_AuditRedaction`](../internal/secrets/secrets_test.go) | ✅ Konform |
| **Inv. 8** | Aufräumen garantiert | Prozess- & FD-Lifecycle gebunden; `ScrubForeignFDs`; autom. Session-Teardown | [`TestInvariant_OnlyPlannedFDsInherit`](../test/integration/sandbox_test.go#L102)<br>[`TestScrubForeignFDs`](../internal/orchestrator/orchestrator_test.go) | ✅ Konform |
| **Inv. 9** | Syscall-Filterung (Seccomp-BPF) | cBPF Default-Allow + Blocklist kritischer Syscalls (`bpf`, `io_uring` etc.); Opt-out nur User | [`TestInvariant_SeccompBlocksSyscalls`](../test/integration/sandbox_test.go#L233)<br>[`TestInvariant_SeccompBlocksIOUring`](../test/integration/sandbox_test.go#L283)<br>[`TestIntegration_SeccompOffOption`](../test/integration/sandbox_test.go) | ✅ Konform |

---

## 5. Einhaltung der Arbeits- und Code-Richtlinien ([`AGENTS.md`](../AGENTS.md))

### 5.1 Abhängigkeitsbudget ([`AGENTS.md`](../AGENTS.md) §2)
Die Prüfung von [`go.mod`](../go.mod) zeigt, dass das geschlossene Budget exakt eingehalten wurde:
* `github.com/urfave/cli/v3` (CLI-Framework)
* `github.com/moby/sys/reexec` (Self-Start in Namespace)
* `golang.ngrok.com/muxado` (Stream-Multiplexing)
* `gopkg.in/yaml.v3` (Strict YAML Parsing)
* `github.com/miekg/dns` (DNS RFC 1035 Parser)
* `golang.org/x/sys` (Landlock & Unix Syscalls)
* **Keine unzulässigen Third-Party-Frameworks** (kein gRPC, kein testify, kein externer HTTP-/Log-Stack).

### 5.2 Code-Struktur & Fehlerbehandlung ([`AGENTS.md`](../AGENTS.md) §4)
* **Kontext-Hygiene:** Alle I/O- und Netzwerk-Routinen akzeptieren `ctx context.Context` als ersten Parameter und beachten Timeouts.
* **Error Wrapping:** Fehler werden konsequent mit `%w` annotiert.
* **FD-Hygiene:** Klare Ownership und Schließpfade für Deskriptoren, Sockets und Memfds.
* **Reine Kerne:** Matcher, Argument-Builder, Template-Evaluator und Framing-Code sind als zustandslose, unit-testbare Funktionen implementiert.
* **Fehlertexte:** Standardisierte Fehlermeldungen sind in [`docs/errors.md`](../docs/errors.md) katalogisiert und durch Tests gepinnt.

---

## 6. Gesamtfazit & Ausblick

Die Implementierung von **`keg`** befindet sich in einem hervorragenden, vollständig spezifikationskonformen Zustand. Sämtliche in [`CONCEPT.md`](../CONCEPT.md), [`THREAT_MODEL.md`](../THREAT_MODEL.md) und den Detailplänen formulierten Anforderungen und Sicherheitsmechanismen sind lückenlos implementiert und empirisch validiert.

### Empfohlene nächste Schritte für künftige Releases:
1. **Host-Mount-Allowlist (`mounts.allow_paths`):** Erweiterung der User-Konfiguration um eine Positivliste erlaubter Quellpfade, um das Restrisiko unerwünschter Host-Binds durch manipulierte Repositories weiter zu minimieren ([`THREAT_MODEL.md`](../THREAT_MODEL.md) §7).
2. **Erweiterung von CI-Matrizen:** Durchführung der Integrationstests auf weiteren Linux-Distributionen (Ubuntu 24.04 LTS, Fedora 40+, Arch Linux) zur kontinuierlichen Verifikation unterschiedlicher Kernel- und Bubblewrap-Versionen.
3. **Dokumentationspflege:** Kontinuierliche Aktualisierung von [`docs/errors.md`](../docs/errors.md) bei künftigen Erweiterungen.
