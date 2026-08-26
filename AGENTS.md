# AGENTS.md — Arbeitsregeln für Coding-Agents (und Menschen) für keg (Kernel-isolated Execution with Gateways)

keg wird überwiegend von Coding-Agents implementiert. Dieses Dokument ist
**bindend**. Kontext in dieser Reihenfolge lesen:

1. `CONCEPT.md` — Architektur & Designentscheidungen
2. `THREAT_MODEL.md` — Sicherheitsinvarianten (§8) und Bedrohungsmodell
3. `IMPLEMENTATION_PLAN.md` — Work-Packages, Reihenfolge, DoD

---

## 1. Entwicklungsprozess: TDD ist Pflicht

Der Zyklus **Red → Green → Refactor** ist nicht optional:

1. **Red:** Schreibe zuerst einen Test, der das gewünschte Verhalten prüft
   und fehlschlägt (`go test ./internal/foo -run TestName` muss rot sein).
2. **Green:** Implementiere genau so viel Produktionscode, bis der Test grün
   ist — nicht mehr.
3. **Refactor:** Räume auf (Duplikate, Namen, Struktur), Tests bleiben grün.

### Verbindliche Regeln

* **Keine Produktionszeile ohne vorherigen fehlgeschlagenen Test.**
  Ausnahme: reine Deklarationen (Typen, Konstanten), Makefile/CI-Änderungen.
* **Bugfix = Regressionstest zuerst.** Der Test reproduziert den Bug rot,
  dann wird gefixt.
* **Tests werden nie abgeschwächt**, damit sie durchlaufen. Wenn ein Test
  falsch war: korrigieren und im Commit begründen.
* **Table-driven Tests** als Default; Fehlerfälle sind Pflichtfälle, kein
  Anhang.
* **Fehlertexte sind API:** Erwartungstexte stehen in Golden-/Testdateien;
  Änderungen an User-sichtbaren Meldungen erfordern Testanpassung.
* Jede Sicherheitsinvariante aus `THREAT_MODEL.md` §8 hat ≥ einen benannten
  Test (`TestInvariant_*`). Eine Änderung, die solche Tests schwächt, ist
  ein Security-Vorfall — keine normale Merge-Entscheidung.
* Integrationstests tragen den Build-Tag `//go:build integration`, skippen
  **sichtbar mit Begründung**, wenn `bwrap` fehlt — niemals stumm.

## 2. Abhängigkeiten: hartes Budget

Stdlib zuerst. Das Budget steht in `IMPLEMENTATION_PLAN.md` §1 und ist
**geschlossen**:

| erlaubt | |
|---|---|
| `github.com/urfave/cli/v3` | CLI-Rahmen (Projektvorgabe) |
| `github.com/moby/sys/reexec` | Self-Start |
| `golang.ngrok.com/muxado` | Multiplexing |
| `gopkg.in/yaml.v3` | Config |
| `github.com/miekg/dns` | DNS |
| `golang.org/x/sys` | Landlock |

* Neue Dependency ⇒ PR enthält Absatz „Warum reicht die Stdlib nicht?“,
  Lizenz-Check (BSD/MIT/Apache2), Update der Budget-Tabelle. Ohne das:
  ablehnen.
* `go mod tidy` muss diff-frei bleiben; keine indirekten Deps „mitziehen“.
* **Verboten:** gRPC/protobuf (v1), Logging-Frameworks (`log/slog` genügt),
  HTTP-Frameworks (`net/http` genügt), Utility-Sammlungen (lodash-artig),
  Test-Frameworks außerhalb der Stdlib (`testing` + `t.Run` genügt; keine
  testify/gomega).
* Dev-Tooling (keine Runtime-Dep): `golangci-lint`.

## 3. Linting & Format

* `make lint` (golangci-lint, Config `.golangci.yml`) muss **warnungsfrei**
  durchlaufen — „warning-tolerant mergen" gibt es nicht.
* `gofumpt`-Formatierung; keine separaten Format-Diskussionen.
* `go vet` und `-race` laufen immer mit.

## 4. Code-Richtlinien

* **Kontext überall:** Funktionen mit I/O nehmen `ctx context.Context` als
  ersten Parameter; Server-Loops respektieren Abbruch.
* **Fehler:** wrappen mit `%w`, keine verlorenen Fehler, keine `panic` in
  Library-/Server-Pfaden (panic nur bei echten Programmierfehlern im
  Prozess-Start).
* **Reine Kerne:** Policy-Logik (Arg-Builder, Matcher, Templating, Framing)
  ohne globale Zustände und ohne I/O entwerfen — das ist die Voraussetzung
  für die Unit-Testbarkeit, die der Plan fordert.
* **FD-Hygiene:** Jede geöffnete Ressource hat einen dokumentierten Owner
  und Close-Pfad; Server-Tests nutzen den goroutine-leak-check.
* **Secrets:** Werte niemals loggen, niemals in Fehlernachrichten, niemals
  in Testausgaben. Audit sagt nur `(changed|unchanged|error)`.
* **Kommentare:** Paket-Kommentar für jedes Paket; exported Symbole
  dokumentiert (revive prüft das). Kommentare erklären *warum*, nicht *was*.

## 5. CLI (urfave/cli v3)

* Subcommands spiegeln IMPLEMENTATION_PLAN §Phase-0: `run` (Default),
  `list`, `clean`, `clean-cache`, `serve`.
* Flags zentral definiert; Hilfe-Texte sind Nutzfläche (Beispiele enthalten)
  und werden im Smoke-Test geprüft.
* Exit-Codes: 0 ok, 1 allgemeiner Fehler, 126 delegierter Job abgelehnt,
  127 Runner fehlt, 125 Protokollfehler (Bestandskompatibilität).

## 6. Commit- & PR-Disciplin

* Conventional Commits (`feat(proxy): …`, `fix(config): …`,
  `test(runner): …`, `docs: …`); ein logischer Schritt pro Commit —
  Red- und Green-Commit dürfen getrennt sein.
* PR-Beschreibung: welcher WP-Task aus dem Plan, welche Tests neu, DoD
  abgehakt.
* Keine Misch-Commits (Feature + Refactor + Doku).

## 7. Sprache

* **Code-Artefakte sind englisch:** Kommentare, Identifier, CLI-Usage-Strings,
  Fehlermeldungen und Commit-Messages auf Englisch (`misspell` prüft das).
* Projekt-Dokumentation (`CONCEPT.md`, `THREAT_MODEL.md`,
  `docs/plans/*.md`) bleibt deutsch; neue technische Docs dürfen auch
  englisch sein — Konsistenz innerhalb eines Dokuments ist Pflicht.

## 8. Definition of Done (je Task)

1. Test zuerst geschrieben, rot gesehen, dann grün (`-race`).
2. `make lint test` warnungs- und fehlerfrei; `tidy` diff-frei.
3. Integrationstests ergänzt, wenn Prozess-/bwrap-Verhalten betroffen ist.
4. Doku aktualisiert, wo Verhalten sichtbar wird (CONCEPT/Plan/Fehlerkatalog).
5. THREAT_MODEL geprüft: Berührt die Änderung eine Invariante oder eine
   Zeile des Modells? Dann Modell im selben PR nachziehen.
