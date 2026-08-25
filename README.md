# keg — Kernel-isolated Execution with Gateways

Isolierte Entwicklungs-Sandbox auf Basis von **bubblewrap** mit Zero-Trust
Egress — ein Go-Binary statt Shell-Skript-Orchester.

**Status:** Work in Progress. Abgeschlossen laut `IMPLEMENTATION_PLAN.md`:
Phase 0 + **WP-M1** (isolierter Skeleton-Lauf). Weiter geht's mit WP-M2
(Proxy-Kanal).

## Nutzung (aktueller Stand)

```bash
make build          # -> bin/keg

# Befehl isoliert ausführen (liest .keg.yaml im Repo):
bin/keg run --repo /pfad/zum/repo -- go version

# Interaktive Shell:
cd /pfad/zum/repo && bin/keg run

# Werfbarer Lauf / persistenter Layer:
bin/keg run --ephemeral -- just test
bin/keg run --disk-overlay agent-42 -- bash -c 'just build'
```

Konfiguration: `.keg.yaml` pro Repo (Schema: `CONCEPT.md §5`),
Maschinenlokalities optional in `$XDG_CONFIG_HOME/keg/config.yaml`
(`CONCEPT.md §4.8`). Fehlt die Repo-Konfiguration, bricht der Lauf mit
klarem Fehler ab.

## Was M1 garantiert

* `--unshare-all` (+ UserNS), `--die-with-parent`, `--disable-userns` —
  immer, unabhängig von der Repo-Config (`TestInvariant_IsolationAlwaysEnforced`)
* Nur Loopback: kein Interface, kein Routing (`ip link` zeigt allein `lo`)
* Host-Env wird nie geerbt: Proxy-/Cloud-Variablen werden doppelt entfernt —
  per bwrap `--unsetenv` und erneut im Guest-Entrypoint
  (`TestInvariant_HostEnvNeverInherited`, `TestInvariant_GuestStripsHostEnv`)
* Isolation-schwächende `bwrap_args` brauchen
  `security.allow_weak_bwrap: true`; der Fehler nennt das exakte Flag
  (`TestInvariant_WeakBwrapNeedsConsent`)
* FD-Kanäle 3/4/5 (Proxy/DNS/Runner) werden als Socketpair-Enden in die
  Sandbox vererbt (`TestSandboxFDInheritance`)
* Overlay-Modi: plain rw, `--ephemeral` (tmpfs-Upper, Repo bleibt sauber),
  `--disk-overlay NAME` (Layer unter `/var/lib/containers/storage/sandbox`,
  Upperdirs auf ext4 — Syntax wie im Bestand via `--overlay-src`)

## Entwicklung

```bash
make lint            # golangci-lint, muss warnungsfrei sein
make test            # Unit-Tests mit -race
make integration     # bwrap-Integrationstests (-tags integration)
make tidy            # go mod tidy muss diff-frei bleiben
```

TDD ist Pflicht (`AGENTS.md`): keine Produktionszeile ohne vorher roten
Test. Integrationstests skippen sichtbar mit Grund, wenn bwrap fehlt.

### Bekannte Umgebungseigenheiten

* **Overlay-Persistenz:** Unprivilegiertes OverlayFS persistiert
  Upperdir-Writes zuverlässig nur mit `--ro-bind / /` als Lower-Layer —
  ohne Root-Bind verwirft dieser Kernel die Writes beim Namespace-Teardown.
  keg bindet den Host-Root daher read-only ein (Prinzip wie im legacy
  `dist/jail`-Prototyp); `/home` und `/tmp` werden per tmpfs verdeckt,
  Schreibzugriff bleibt auf Repo/Layer beschränkt. Details:
  `THREAT_MODEL.md` §5.1.
* Direkt aufeinanderfolgende Läufe auf denselben Disk-Layer können kurz mit
  „Device or resource busy“ kollidieren (lazy Namespace-Teardown des
  vorherigen Overlay-Mounts). Layer-Management mit Retry folgt in WP-M6.

## Dokumentation

* `CONCEPT.md` — Architektur & Designentscheidungen
* `THREAT_MODEL.md` — Bedrohungsmodell, §8 Sicherheitsinvarianten
* `IMPLEMENTATION_PLAN.md` — Meilensteine & Reihenfolge
