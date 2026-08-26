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
    upstream: 8.8.8.8:53 # DNS-Forwarding zu Google DNS
  sni_domains:
    - daily-cloudcode-pa.googleapis.com
    - oauth2.googleapis.com
    - "*.googleapis.com"
  tcp_endpoints:
    - host: daily-cloudcode-pa.googleapis.com
      ports: [443]
    - host: oauth2.googleapis.com
      ports: [443]
```

### DNS-Auflösung (CoreDNS-Äquivalent)

Die DNS-Anfragen für `*.googleapis.com` werden über den keg-DNS-Resolver auf Loopback `:53` abgefangen, gegen die Whitelist validiert und an den Upstream-DNS (`8.8.8.8:53`) weitergeleitet:

```text
googleapis.com:53 {
    forward . 8.8.8.8 1.1.1.1
    log
    errors
}
```

---

## 2. Mounts & Authentifizierung

Damit `agy` die bestehende Authentifizierung und Konfiguration nutzen kann, werden folgende Verzeichnisse eingebunden:

```yaml
mounts:
  - src: ~/.gemini
    dest: /home/sandbox/.gemini
    mode: rw
  - src: ~/.local/bin
    dest: /home/sandbox/.local/bin
    mode: ro
```

---

## 3. Demo ausführen

```bash
# 1. Aus dem Root-Verzeichnis bauen
make build

# 2. agy-Prompt in der Sandbox ausführen
./bin/keg run --repo examples/agy -- agy -p "sag hi"

# 3. Oder als werfbarer Lauf mit just:
./bin/keg run --repo examples/agy --ephemeral -- just run

# 4. Interaktive agy-Session:
./bin/keg run --repo examples/agy -- agy
```
