# Architektur-Schaubild: Egress-Kanäle über die Netns-Stage

> Zielbild nach der Kanal-A-Verschiebung (M3-Muster auf M2 angewendet):
> Beide Egress-Kanäle werden von der **Netns-Stage** auf Loopback exponiert
> und zur hostseitigen Policy gerelayt. Der Gast-Prozess enthält keine
> Bridges mehr und exec't den Workload direkt.
>
> Trust-Grenzen: `═══` Prozesse · `◄──fd` Socketpair-Kanäle · Policy immer
> hostseitig, Deny-by-default.

```
┌─────────────────────────────────── HOST ────────────────────────────────────┐
│                                                                             │
│  keg run ── Orchestrator (Prozess #1)                                   │
│  ├── .keg.yaml + User-Config laden, mergen, templaten (.Vars/.Env)      │
│  ├── Socketpairs anlegen:        A═►fd3      B═►fd4      C═►fd5 (M5)       │
│  ├── HOST-END-POLICY (Goroutinen):                                          │
│  │     ├── Proxy.Serve(fd3):                                                │
│  │     │     Whitelist(exakt+*.suffix) ─✓→ Upstream-CONNECT ─→ Tunnel       │
│  │     │                            ─✗→ 403 + Audit (ERLAUBT/BLOCKIERT)     │
│  │     └── DNS.Serve(fd4):                                                  │
│  │           hosts-Mappings ─→ Zonen-Whitelist (*.svc.cluster.local)        │
│  │           ─✓→ Upstream (kube-dns)      ─✗→ NXDOMAIN                      │
│  └── startet:                                                               │
│        unshare -U -r -n -m -p --fork --keep-caps                            │
│                     │                                                       │
│                     ▼  exec                                                 │
│  ┌── NETNS-STAGE (Prozess #2, argv[1]=keg/netns-stage) ──────────────┐  │
│  │  besitzt PRIVATE user+netns ── nur lo, KEINE Routen                   │  │
│  │  ├── ip link set lo up                                                │  │
│  │  ├── ip_unprivileged_port_start = 0        (per-Netns!)               │  │
│  │  ├── LISTENER 127.0.0.1:18081 ══ Kanal A ══ muxado.Client ◄── fd3      │  │
│  │  ├── LISTENER 127.0.0.1:53   ══ Kanal B ══ muxado.Client ◄── fd4      │  │
│  │  ├── dropCapabilities()  (bwrap verweigert sonst unexpected caps)     │  │
│  │  └── exec bwrap ──────────────────────────────────────────────────    │  │
│  └────────────────────────────────────────────────────────────────┬─────┘  │
│                                                                   ▼        │
│  ┌── SANDBOX (bwrap: --unshare-all --share-net --disable-userns …) ──────┐ │
│  │  Mounts: /usr ro · Repo rw|overlay|ephemeral · /etc/hosts · resolv.conf│ │
│  │                                                                       │ │
│  │  GUEST (argv[1]=keg/guest)                                        │ │
│  │  ├── Env-Hygiene (2. Verteidigungslinie) + FD-Scrub                   │ │
│  │  └── exec <Workload>   ◄── kein Bridge-Code mehr: direktes Exec       │ │
│  │                                                                       │ │
│  │  WORKLOAD (bash · go · curl · dig …)                                  │ │
│  │    erbt NUR stdio (TestInvariant_WorkloadGetsOnlyStdioFDs)            │ │
│  │    • HTTP(S)_PROXY=http://127.0.0.1:18081                              │ │
│  │    • /etc/resolv.conf → nameserver 127.0.0.1                          │ │
│  │    • /etc/hosts → statische dns.hosts-Mappings                        │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Datenflüsse

**Erlaubt (Whitelist-Treffer):**

```
curl https://proxy.golang.org
  └─► 127.0.0.1:7443 (Stage-Relay)
        └─► fd3 muxado-Frames ─► Proxy.Serve ─► Match("proxy.golang.org") ✓
              └─► Upstream-CONNECT (Firmen-Proxy/direkt) ─► Tunnel ⟳ Internet

getent hosts kubernetes.default.svc.cluster.local
  └─► 127.0.0.1:53 (Stage-Relay)
        └─► fd4 Frame ─► Resolver ─► Zonen-Match *.svc.cluster.local ✓
              └─► kube-dns ─► 10.43.0.1
```

**Verweigert (Deny-by-default):**

```
evil.invalid               ─► :53  ─► kein Zonen-Match ─► NXDOMAIN
blocked.example.com:443    ─► :18081 ─► kein Whitelist-Match ─► 403 + Audit-Zeile
```

## Was gegenüber dem M2-Stand entfällt / sich ändert

| Vorher (M2)                        | Nachher (Vorschlag)                    |
|------------------------------------|----------------------------------------|
| Gast resident, startet :18081-Bridge| Stage hält :7443-Relay (wie :53)       |
| Gast spawn't Workload als Kind     | Gast exec't Workload direkt            |
| `KEG_PROXY`-Marker an Gast     | entfällt                               |
| Signal-Forwarding im Gast          | tty-Signale erreichen Shell direkt     |
| Zwei Relay-Stile (Gast + Stage)    | ein Stil: Stage-relayed, Policy hostseitig |

Konsequenz für **M5 (Runner)**: gleiche Entscheidung nochmal bewusst treffen —
Runner als Loopback-Dienst der Stage (JSON-Protokoll auf Port, privat im
Netns) statt FD-Pass-through an den Workload.
