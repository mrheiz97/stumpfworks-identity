# Sparsame GitHub-CI

Stand: 3. November 2026. Änderungen nur am Workflow auf development; keine
Produktivänderung, CAS-Sperre und MOBILE01-Ausschluss unverändert.

## Was automatisch läuft

| Anlass | Runnerjobs |
| --- | --- |
| Push auf development oder main | Keine |
| Pull Request nach main, einschließlich Aktualisierung | Ein Job `test` |
| Pull Request nach development | Keine; lokale Prüfung beziehungsweise gezielter manueller Lauf |
| Manueller Lauf, Standard | Ein Job `test` |
| Manueller Lauf mit `full_lab=true` | `test` und Samba-/CAS-Labor einschließlich beider Crashcontainer |

Der automatische Job behält Go-Race, PostgreSQL, Python-/Shellsyntax,
Prometheus und Rechte-/Unitverträge bei. Der bestehende verpflichtende Check
`test` für geschütztes main bleibt erhalten. Es werden keine Pfadfilter für
diesen Pflichtcheck verwendet, damit Pull Requests nicht mit dauerhaft
ausstehender Prüfung blockieren. Keine automatische Wiederholung nach dem Merge,
keine zeitgesteuerten Läufe und keine zusätzlichen Runner-Matrizen.

Veraltete Läufe derselben Pull-Request-/Branchgruppe werden abgebrochen. Jeder
Job hat maximal zehn Minuten Laufzeit. Damit verbraucht ein Lauf höchstens zehn
beziehungsweise beim vollständigen Labor höchstens zwanzig Runner-Minuten;
zusätzliche manuelle Wiederholungen sind eigene Läufe. Dies ist eine Laufzeit-
begrenzung, keine kontoweite Ausgabensperre.

## Sicherheitsprüfungen bleiben verfügbar

Die 27 Brokerverträge, 17 nativen Verträge und beide nativen Crash-/Neustartfälle
bleiben vollständig im Repository und werden weiterhin lokal ausgeführt. Bei
Änderungen an AD/CAS, Parser, Autorisierung, Journal oder Laborfixture ist vor
einer Freigabe zusätzlich der vollständige Laborlauf auf dem exakten geprüften
Stand erforderlich. Ein einfacher grüner `test`-Check ersetzt diesen Nachweis
nicht. Die CAS-Sperre wird durch diese CI-Optimierung nicht verändert.

Nach Übernahme der Workflowdatei auf den Defaultbranch main kann ein vollständiger
Lauf gezielt gestartet werden:

```sh
gh workflow run ci.yml --ref development -f full_lab=true
```

Für die normale Prüfung das Feld weglassen beziehungsweise `false` wählen.
Vor einem Release wird der dafür bestimmte exakte main-Commit gezielt geprüft
(`--ref main`); bei AD-/CAS-Änderungen mit vollständigem Labor. Ein grüner Lauf
eines anderen Commits ist kein Release-Abnahmenachweis.
Wichtig: GitHub verlangt für `workflow_dispatch` die Workflowdefinition auf dem
Defaultbranch. Solange die Änderung nur auf development liegt, bleibt der
vollständige lokale Laborweg verfügbar; der manuelle GitHub-Einstieg kann noch
fehlen. main wird deshalb nicht ungeprüft verändert oder mit dem gesamten
unveröffentlichten Developmentstand zusammengeführt.
[GitHub: manueller Workflowstart](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

## Kostenrahmen und Rückweg

Das Repository `mrheiz97/stumpfworks-identity` wurde als **öffentlich** geprüft.
Es verwendet ausschließlich Standard-Linux-Runner `ubuntu-latest`, keine großen
oder selbst betriebenen Runner, keine Artefaktuploads und keinen Deploymentjob.
Standard-GitHub-Runner sind für öffentliche Repositories laut aktueller
[GitHub-Abrechnung](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
kostenlos. Das ist keine Aussage über andere Repositories, Copilot, Packages
oder andere kostenpflichtige Produkte des Kontos.

Der vorhandene Go-Cache bleibt zur Vermeidung wiederholter Downloads bestehen.
Gelesener Ausgangsstand: fünf Caches, insgesamt 1.017.973.171 Bytes. Keine
Cachekapazität, Abrechnungseinstellung oder kostenpflichtige Option wurde erhöht.
Kontoweite Budgets wurden nicht verändert; deren tatsächlicher Zustand wurde
nicht als geprüft behauptet. Für kostenpflichtige Nutzung verwaltet GitHub
gesonderte [Budgets und Stop-Regeln](https://docs.github.com/en/billing/concepts/budgets-and-alerts).

Rückweg: Den vorherigen Workflow aus Developmentcommit `7f66a25` wiederherstellen.
Dann laufen wieder beide Jobs bei Pushes auf main/development und Pull Requests
nach beiden Branches. Branchschutz, Runtime, Datenbanken und Produktivdateien
benötigen keinen Rückweg. Die reduzierte Workflowdatei wird lokal mit actionlint
geprüft; für diese reine Workflowänderung wird bewusst kein zusätzlicher
vollständiger GitHub-Laborlauf ausgelöst.
