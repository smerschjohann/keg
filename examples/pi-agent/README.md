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
   - In `user_config.yaml` (`~/.config/keg/config.yaml`) wird die Host-Quelle mit beliebigem Refresh-Intervall definiert:
     ```yaml
     secret_sources:
       ai_secret_key:
         cmd: ["examples/pi-agent/genkey", "pi-agent", "10"]
         interval: 5s         # ⏱️ Refresh-Intervall (z. B. 5s, 30s, 15m, 1h, oder 0s für statisch)
         timeout: 5s          # ⏱️ Timeout für den Befehl
         on_refresh_error: keep # 'keep' (alten Token behalten) oder 'fail' (Sandbox stoppen)
     ```
   - Beim Start ruft der Host `genkey <instance_name> <ttl_seconds>` auf und bindet den Token schreibgeschützt (Mode `0400`) nach `/run/secrets/ai_secret_key` ein.
   - Der Hintergrund-Refresher aktualisiert das Secret atomar nach dem konfigurierten `interval` (z. B. alle 5 Sekunden).

3. **Konfiguration verschiedener Refresh-Zeiten (`interval`):**
   - `interval: 5s` — Schnelles Rolling für Tests & Demos.
   - `interval: 30s` — Kurzlebige STS- / Session-Tokens.
   - `interval: 15m` oder `1h` — OAuth- / OIDC-Tokens.
   - `interval: 0s` (oder weglassen) — Statisches Secret: wird nur einmalig beim Start geholt.

4. **Host-Task-Delegation (`just test-playwright`):**
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

## Sandbox starten & Dynamic Refresh testen

```bash
# 1. Aus dem keg-Root bauen
make build

# 2. pi-agent starten und live beobachten, wie der Token alle 5s aktualisiert wird:
./bin/keg run --repo examples/pi-agent --user-config examples/pi-agent/user_config.yaml -- go run main.go

# 3. Interaktive Shell in der Sandbox starten:
./bin/keg run --repo examples/pi-agent --user-config examples/pi-agent/user_config.yaml

# 4. Oder als werfbaren / isolierten Lauf:
./bin/keg run --repo examples/pi-agent --user-config examples/pi-agent/user_config.yaml --ephemeral -- just test-playwright
```
