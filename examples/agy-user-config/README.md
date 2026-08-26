# Google Antigravity (`agy`) — Nutzer-Konfiguration (Host-Delegation)

Dieses Beispiel demonstriert die Ausführung von `agy` über eine **reine Benutzer-Konfiguration**, ohne das Git-Repository zu verändern:

- **Im Repository ([`.keg.yaml`](file:///home/coder/dev/keg/examples/agy-user-config/.keg.yaml)):**
  Das Projekt ist sauber und hermetisch isoliert — es enthält **weder** Mounts für `~/.gemini` **noch** Google-Netzwerkfreigaben.
- **In der Benutzer-Konfiguration ([`user_config.yaml`](file:///home/coder/dev/keg/examples/agy-user-config/user_config.yaml) bzw. `~/.config/keg/config.yaml`):**
  Der Benutzer autorisiert auf seinem Host die Ausführung von `agy` für die Sandbox über den Runner (`runner.extra_prefixes: ["agy"]`).

---

## 1. Konfiguration

### Im Projekt ([`.keg.yaml`](file:///home/coder/dev/keg/examples/agy-user-config/.keg.yaml))
```yaml
version: "1"

# Standard-Freigaben des Repos (kein agy, kein Internet)
delegated_tasks:
  exact:
    - build
    - test
```

### In der Nutzer-Konfiguration ([`user_config.yaml`](file:///home/coder/dev/keg/examples/agy-user-config/user_config.yaml))
```yaml
paths:
  storage_base: "/var/lib/containers/storage/sandbox"
  tmp_base: "/tmp"

runner:
  # Erlaubt der Sandbox, das just-Rezept 'agy' auf dem Host auszuführen:
  extra_prefixes:
    - "agy"

security:
  landlock: auto
```

---

## 2. Ablauf & Aufruf

1. Der Agent oder Workflow führt in der Sandbox `just agy "sag hi"` aus.
2. `sandbox.just` erkennt, dass der Prozess in der Sandbox läuft (`KEG_RUNNER=1`), und delegiert den Aufruf per `keg delegate agy "sag hi"` über **Kanal C (Delegation-Socket)** an den Host-Runner.
3. Der Host prüft die Whitelist aus der `user_config.yaml`, führt `agy` mit den vollen Host-Rechten/Credentials aus und streamt das Ergebnis zurück in die Sandbox.

---

## 3. Demo ausführen

```bash
# 1. Aus dem Root-Verzeichnis bauen
make build

# 2. agy über Host-Delegation aus der Sandbox heraus aufrufen:
./bin/keg run --repo examples/agy-user-config --user-config examples/agy-user-config/user_config.yaml -- just agy "sag hi"

# 3. Test mit benutzerdefiniertem Prompt:
./bin/keg run --repo examples/agy-user-config --user-config examples/agy-user-config/user_config.yaml -- just agy "antworte nur mit TEST_OK"
```
