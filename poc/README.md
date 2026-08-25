# keg — Kernel-isolated Execution with Gateways-poc — Socketpair-Durchstich durch bwrap

Minimaler Proof of Concept (ein Go-Binary, keine externen Dependencies) für
das Kernmuster der keg-Architektur:

```
HOST                                          SANDBOX (bwrap --unshare-all)
────                                          ────────────────────────────
FD 3 ──┐                              ┌── FD 3  Echo-Kanal (roher Durchstich)
       ├─ syscall.Socketpair(AF_UNIX) ─┤
FD 4 ──┘                              └── FD 4  TCP-Tunnel -> 127.0.0.1:8080
```

## Ausführen

```bash
go build -o keg-poc .
./keg-poc
```

## Was gezeigt wird

1. **Phase 1 – Durchstich:** Host schreibt in sein Socketpair-Ende, der
   Prozess *in* der Sandbox (`--unshare-all`, nur eigenes Loopback) antwortet
   über dasselbe Paar. Kommunikation durchquert die Isolation (~30–90 µs).
2. **Phase 2 – Innerer Socket von außen erreicht:** Ein HTTP-Server läuft auf
   `127.0.0.1:8080` **in** der Sandbox. Der Host verbindet sich auf seinen
   eigenen Listener `127.0.0.1:18080`; der Verkehr wird über FD 4 getunnelt
   und vom Sandbox-HTTP-Server beantwortet (`HTTP 200`). Das ist das
   Kanal-E-Muster aus CONCEPT.md §4.9.
3. **Negativnachweis:** Gleichzeitig dialt die Sandbox nach `1.1.1.1:80`
   → `network is unreachable`. Der Tunnel funktioniert, externes Netz bleibt
   blockiert.

## Bewusste Vereinfachungen gegenüber dem Produkt

| PoC | keg produktiv |
|---|---|
| Env-Var als Rollenschalter | `moby/sys/reexec` |
| Roher Bytestrom, 1 Verbindung gleichzeitig | muxado-Multiplexing, viele Streams über 1 FD |
| 2 Kanäle | 5 Kanäle (Proxy, DNS, Runner, Control, Ports) |
| Keine Policy | Whitelist-Proxy, gefiltertes DNS, Runner-Whitelist |
