# Google Antigravity (`agy`) in keg

Dieses Beispiel demonstriert die Ausführung des Google Antigravity Agenten (`agy`) innerhalb einer hermetischen **keg**-Sandbox.

---

## 1. Zero-Trust Netzwerk-Konfiguration (`mode: transparent`)

Google Antigravity (`agy`) kommuniziert über gRPC / HTTPS direkt mit Google Cloud Code Endpunkten. Die Sandbox verwendet daher den **Transparent-Modus** (ohne HTTP-Proxy-Umgebungsvariablen):

```yaml
network:
  mode: transparent
  dns:
    enabled: true
  sni_domains:
    - daily-cloudcode-pa.googleapis.com
    - oauth2.googleapis.com
    - "*.googleapis.com"
    - "*.googleusercontent.com"
    - "*.gstatic.com"
    - accounts.google.com
  tcp_endpoints:
    - host: daily-cloudcode-pa.googleapis.com
      ports: [443]
    - host: oauth2.googleapis.com
      ports: [443]
    - host: www.googleapis.com
      ports: [443]
    - host: lh3.googleusercontent.com
      ports: [443]
    - host: accounts.google.com
      ports: [443]
```

### DNS-Auflösung (CoreDNS-Äquivalent)

Die DNS-Anfragen für `*.googleapis.com` werden über den keg-DNS-Resolver auf Loopback `:53` abgefangen, gegen die Whitelist validiert und an den Upstream-DNS weitergeleitet (entspricht dem CoreDNS-Forwarding):

```text
googleapis.com:53 {
    forward . 8.8.8.8 1.1.1.1
    log
    errors
}
```

---

## 2. Lokale Konfiguration ([`local-config.yaml`](file:///home/coder/dev/keg/examples/agy/local-config.yaml))

Statt maschinenspezifische Pfade direkt im Repository zu verankern, nutzt `.keg.yaml` Template-Variablen (`gemini_config_dir`, `agy_bin_dir`). Die tatsächlichen Host-Pfade und Runner-Freigaben können in der lokalen Konfiguration (`~/.config/keg/config.yaml` bzw. `--user-config local-config.yaml`) definiert werden:

```yaml
# local-config.yaml
paths:
  storage_base: "/var/lib/containers/storage/sandbox"
  tmp_base: "/tmp"

# 1. Lokale Pfade für agy
vars:
  gemini_config_dir: "~/.gemini"
  agy_bin_dir: "~/.local/bin"

# 2. Lokale Freigaben pro Repository
repos:
  "*/examples/agy":
    vars:
      gemini_config_dir: "~/.gemini"
      agy_bin_dir: "~/.local/bin"
    runner:
      extra_exact:
        - "agy"
      extra_prefixes:
        - "agy -p"
      extra_raw:
        - cmd: agy
          subcommands: ["-p"]
```

---

## 3. Demo ausführen

```bash
# 1. Aus dem Root-Verzeichnis bauen
make build

# 2. agy-Prompt mit lokaler Benutzer-Konfiguration ausführen:
./bin/keg run --repo examples/agy --user-config examples/agy/local-config.yaml -- agy -p "sag hi"

# 3. Oder als werfbarer Lauf mit just:
./bin/keg run --repo examples/agy --user-config examples/agy/local-config.yaml --ephemeral -- just run

# 4. Interaktive agy-Session:
./bin/keg run --repo examples/agy --user-config examples/agy/local-config.yaml -- agy
```
