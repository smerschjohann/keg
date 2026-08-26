# pi-agent Beispiel

Dieses Beispiel demonstriert einen typischen KI-Coding-Agenten (`pi-agent`) innerhalb einer isolierten **keg**-Sandbox mit:

1. **Golang Toolchain Preset (`templates: [golang]`):**
   - Bindet Go-Modul- und Build-Caches isoliert ein.
   - Ermöglicht Offline-Kompilierung und performante Toolchain-Nutzung.

2. **Dynamische Secrets Engine (`/run/secrets/ai_secret_key`):**
   - In `.keg.yaml` wird `secrets` konfiguriert:
     ```yaml
     secrets:
       - name: ai_secret_key
         env: AI_SECRET_KEY
     ```
   - In `user_config.yaml` (`~/.config/keg/config.yaml`) wird die Host-Quelle definiert:
     ```yaml
     secret_sources:
       ai_secret_key:
         cmd: ["./genkey", "pi-agent", "30"]
         interval: 10s
         timeout: 5s
         on_refresh_error: keep
     ```
   - Beim Start ruft der Host `genkey <instance_name> <ttl_seconds>` auf und bindet den Token schreibgeschützt (Mode `0400`) nach `/run/secrets/ai_secret_key` ein.
   - Der Hintergrund-Refresher aktualisiert das Secret atomar alle 10 Sekunden.

3. **Host-Task-Delegation (`just test-playwright`):**
   - In `.keg.yaml` ist `test-playwright` freigegeben:
     ```yaml
     delegated_tasks:
       prefixes:
         - "test-playwright"
     ```
   - Beim Ausführen von `just test-playwright` in der Sandbox wird der Task transparent an den Host-Runner delegiert:
     ```bash
     just test-playwright login.spec.ts 8080
     ```

## Sandbox starten

```bash
# 1. Aus dem keg-Root bauen
make build

# 2. pi-agent Sandbox starten
./bin/keg run --repo examples/pi-agent --user-config examples/pi-agent/user_config.yaml

# 3. Oder als werfbaren / isolierten Lauf
./bin/keg run --repo examples/pi-agent --user-config examples/pi-agent/user_config.yaml --ephemeral -- just run
```
