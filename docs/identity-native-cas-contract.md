# Vorbereitung der Identity-Anbindung an natives Samba-CAS

Stand: 3. November 2026, development. Nur lokale Entwicklung und synthetische
netzlose Labore; keine Produktivverbindung, MOBILE01 ausgeschlossen.
**Keine Runtime-Anbindung oder CAS-Entsperrung.** Der produktive LDAP-Adapter,
Executor, Webzugang, Konfiguration, Schema und Framework bleiben unverändert.

## Ergebnis und bewusst begrenzter Umfang

Der neue Adapter existiert ausschließlich in
`internal/adprofile/native_identity_contract_test.go`. Im Labor verwendet er den
echten Identity-`Service`, das AES-GCM-verschlüsselte SQLite-Journal, frische
LDAP-Anmeldungen und die [native Operation im tatsächlichen Samba-Server](samba-native-cas-lab.md).
Die Mutation geht über LDAPS mit CA-/DNS-Prüfung. Dies ist ein integrierter
**Vertragsnachweis**, kein auswählbares Backend einer installierten Identity.

Zwei konkrete Schnittstellenlücken wurden nachgewiesen:

1. `Directory.Modify(ctx, actor, before, changes)` transportiert keine dauerhafte
   Auftrags-ID, keinen Plandigest, keine Policyrevision und keinen Parent.
   Ein echter Adapter braucht dafür einen expliziten typisierten Auftrag. Der
   Contextschlüssel der Testprobe dient nur der Anbindung des unveränderten
   Service im Harness und ist **kein freigegebenes Produktionsdesign**.
2. Eine nachträgliche LDAP-Lesung liefert nicht zuverlässig die eigene Commit-
   Version. Die native Laboroperation erfasst deshalb die resultierende USN
   noch innerhalb ihrer DSDB-Transaktion und speichert sie nach bestätigtem
   Commit als zusätzlichen privaten TDB-Eintrag `V + Operations-ID` (acht Bytes
   Big Endian). Der bisherige ID-/Digest-/Statusdatensatz bleibt unverändert.
   Bei unklarem Commit wird keine bestätigte Version veröffentlicht.

`native_receipt.py` liest diese Daten ausschließlich als privilegierte lokale
Fixtureprobe. Das ist **kein authentifizierter Statusendpunkt**. Kein produktiver
Identity-Prozess erhält hierfür DC-Dateirechte oder eine SSH-/Root-Schnittstelle.

## Plan- und Freigabevertrag

| Bestandteil | Erforderliche Bindung |
| --- | --- |
| Planidentität | Kryptographisch zufällige Identity-ID entspricht exakt den 16 nativen ID-Bytes; keine neu erzeugte ID beim Dispatch |
| Actor | Frische AD-Authentifizierung, unveränderte SID, getrennte Operatorrolle; weder Webcookie noch Writer-Anmeldung ersetzen den Actor |
| Ziel | Domain/DC-Invocation, GUID, SID, feste OU und Schutzmerkmale; keine frei wählbaren DNs/Filter/Controls |
| Vorbedingung | Vollständiger bestätigter Snapshot einschließlich Objekt-USN; natives CAS prüft diese Version atomar |
| Inhalt | Vorher- und Nachherwerte aller vier Profilattribute im verschlüsselten Plan; ausschließlich echte Unterschiede im nativen Modify |
| Policy und Ablauf | Exakte aktuelle Identity-Policyrevision; Plan höchstens fünf Minuten; native Aussage höchstens 60 Sekunden und niemals länger als der Plan |
| Integrität | `Journal.Get` prüft AES-GCM, ID-/Actor-/Ziel-/Ablauf-/Parent-Bindung und vollständigen Plandigest vor der Projektion |
| Gegenauftrag | Neue ID, expliziter Parent und neue Bestätigung; niemals Wiederverwendung der erfolgreichen Original-ID |

Der Testaussteller signiert ausschließlich einen geladenen unveränderten Plan
im bereits dauerhaft beanspruchten Identity-Zustand `applying`. Er akzeptiert
keinen vom Browser gelieferten Sicherheitskontext oder frei zusammengestellten
Signierauftrag. Vor dem Versand speichert er eine eindeutige ID-/Plan-/Wire-
Digest-Zuordnung zusammen mit einem datensparsamen Dispatchvorbereitungsereignis
in einer eigenen Transaktion desselben Identity-Laborjournals.

Der konkrete native Inhalt wird anschließend erneut mit dem beanspruchten Plan,
Actor, Snapshot und den tatsächlichen Änderungen abgeglichen. Ohne gebundene
Auftragsidentität wird die alte Modify-Schnittstelle in der Probe abgewiesen.
Eine erneute Anwendung derselben ID erreicht den nativen Schreibaufruf nicht.

`SWCAS001` unterstützt nur ASCII und eng begrenzte Einzelwerte. Die Projektion
prüft **auch die Vorherwerte**, damit ein Gegenauftrag darstellbar bleibt. Es
gibt keine Transliteration, Normalisierung, Kürzung oder stilles Weglassen von
Feldern. Ein durch den allgemeinen Service erzeugter, aber nativ nicht
darstellbarer Testplan wird vor dem Angebot zur Bestätigung regulär abgebrochen;
die Signier-/Dispatchprüfung weist ihn zusätzlich unabhängig ab.

## Ergebnis-, Audit- und Wiederanlaufvertrag

| Situation | Identity | Natives Journal / Konsequenz |
| --- | --- | --- |
| Nur vorbereitet oder regulär abgebrochen | prepared / cancelled | Kein nativer Auftrag versandt |
| Nativ bestätigt und Nachlesung entspricht dem Plan | succeeded | ID/Digest stimmen überein, Status 2 und bestätigte Commit-USN vorhanden |
| Native Versions-/ACL-Ablehnung mit bestätigtem Abbruch | failed_no_effect | Status 3 mit passendem Wire-Digest; keine Teileffekte |
| Native Antwort geht nach erfolgreichem Commit verloren | reconciliation_required | Auch ein tatsächlich vorhandener nativer Erfolg ist kein Anlass zum erneuten Versand |
| Nativer Commit-/Bestätigungsfehler | reconciliation_required | applying / Status 1; alte und frische IDs am nativen Ziel bleiben gesperrt |
| Identity-Ergebniscommit scheitert nach nativer Wirkung | applying, nach exklusivem Recover reconciliation_required | Native Wirkung bleibt bestehen; Recover führt keine AD-Operation aus |

Es gibt keine gemeinsame ACID-Transaktion zwischen Identity und AD/TDB. Eine
Unterbrechung vor Versand, während des Transports oder zwischen den Commits wird
niemals durch einen automatischen neuen Schreibversuch geheilt. Die eindeutigen
offenen Zielclaims des Identity-Journals blockieren zusätzliche Aufträge; der
native unklare Zielclaim bleibt ebenfalls erhalten.

Der bisherige Service kennt `reconciled_effect_observed` durch Wertebeobachtung.
Diese Beobachtung ist **keine native Commitbestätigung**. Die Testanbindung
verweigert deshalb den bisherigen Reconcile-Aufruf für native Unklarheit.
Insbesondere darf sie damit keinen nativen Claim freigeben oder anschließend
einen Gegenauftrag anbieten. Ein späterer echter Statusvertrag muss unabhängig
authentifiziert und an ID, Digest, Actor, Ziel, DC und Zustand gebunden sein.

Das zusätzliche Identity-Audit enthält Plan-/Wire-Digest, Policy und Parent,
aber keine Profilwerte, Anmeldedaten, Signaturen oder Schlüssel. Die vorhandenen
Vorbereitungs-, Applying-, Erfolgs-, Abbruch- und Unklarheitsereignisse bleiben
erhalten. Vorher-/Nachherwerte liegen ausschließlich im verschlüsselten Plan;
Passwörter werden dort nicht gespeichert. Native C-/F-/V-Metadaten enthalten
ebenfalls keine Profilwerte. Digests sind keine Anonymisierung.

## Sicherer Rückweg und die ABA-Lücke

Die bisherigen allgemeinen Service-Rückwegprüfungen vergleichen unter anderem
Profilwerte. Ein fremdes A–B–A kann dieselben Werte wiederherstellen, obwohl die
Objektversion geändert wurde. Eine frische Version erst bei der Rückwegplanung
zu lesen würde die fremde Änderung versehentlich als eigenen Stand übernehmen.

Der vorbereitete Vertrag verlangt daher für den Parent:

- bestätigten Identity-Erfolg und passende native ID-/Wire-Digest-Zuordnung;
- bestätigte native Commit-USN und exakt diese aktuelle Objektversion;
- dieselbe GUID/SID/DC-Identität sowie vollständige aktuelle Werte gleich den
  eigenen Parent-Nachherwerten;
- einen neuen Gegenplan, dessen Nachherwerte exakt den Parent-Vorherwerten
  entsprechen und dessen Actor frisch angemeldet und weiterhin berechtigt ist.

Es gibt zwei zusätzliche Rennen: Nach der ersten Receiptprüfung könnte sich
das Objekt bis zur eigentlichen Planerstellung ändern. Der Harness vergleicht
deshalb den gespeicherten Gegenplan nochmals mit dem geprüften Snapshot und
bricht einen abweichenden Plan regulär ab. Unabhängig davon prüft der Aussteller
beim Dispatch eines Gegenplans erneut Parent-Digest, Wertebeziehung und dessen
bestätigte native Commit-USN gegen die Gegenplan-Vorversion. Jede weitere
Änderung zwischen Planung und Ausführung wird durch natives Versions-CAS
abgewiesen. Kein Gegenauftrag wird allein aufgrund gleicher Profilwerte erlaubt.

Diese strengeren Regeln befinden sich nur im vorbereiteten Testpfad. Der
allgemeine Runtime-Service wird hier weder umgestellt noch als bereits gegen
diesen zusätzlichen nativen Rückwegfall abgesichert ausgegeben.

## Noch fehlender produktiver Protokollvertrag

`SWCAS001` signiert ID, feste native Identitäten, USN, Zeitfenster und Änderungen.
Es enthält **keinen expliziten Identity-Plandigest, Parent oder frei versionierte
Identity-Policy**. Die Probe verknüpft diese Daten im vertrauenswürdigen
Testaussteller und seinem Journal. Daraus folgt keine neue serverseitige
Durchsetzung dieser zusätzlichen Identity-Felder.

Vor einer Runtime-Anbindung braucht es einen separat geprüften versionierten
Auftrag mit expliziter ID, Plandigest, Policyrevision, Parent, Actor-Proof,
Domain/DC-, Writer- und Zielbindung, erwarteter Version, Änderungen und Ablauf.
Der native Prüfer muss diese Bindungen selbst validieren; ein zusätzlicher
unsignierter JSON-Umschlag genügt nicht. Die endgültige Protokollversion wird
hier weder vergeben noch als bereits implementiert behauptet.

Ebenso fehlt ein eng begrenzter authentifizierter Receipt-/Statusweg: mindestens
ID, Plandigest/Native-Digest, Policy/Parent, Ziel-GUID/SID, DC-Invocation, Zustand,
bestätigte Commit-USN und nachvollziehbare Auditzuordnung. Ein unklarer Zustand
liefert keine erfundene Commit-USN. Statusabfragen führen niemals erneut einen
Modify aus. Kein Zugriff auf rohe TDB-Dateien durch Identity ist ein akzeptabler
Ersatz. Schlüsseltrennung, Rotation/Widerruf, TLS-/Kanalbindung und vertrauenswürdige
Actor-Aussagen sind weiter eigenständige Freigabegates.

## Labornachweise und Umfangsgrenzen

Die neue Projektion wird ohne Samba in normalen Go-Tests gegen falschen Digest,
Actor, Policy, Ziel-SID/DC, Ablauf, Parent und nicht darstellbare Vorherwerte
geprüft. Der native Vertrag läuft anschließend in **drei unabhängigen frischen
DC-Containern** mit dem echten Identity-Service:

1. Erfolg, ID-Replay ohne erneuten Versand, echter neuer Gegenauftrag, fehlerhafte
   Receiptzuordnung, fremdes ABA, Rennen bei Gegenplanerstellung, nicht darstellbare
   Werte, Fremdänderung nach dem Identity-Vorlesen, Abbruch ohne Dispatch,
   verlorener Identity-Ergebniscommit und datensparsames Audit.
2. Verlorene Adapterantwort nach tatsächlich erfolgreichem nativen Commit:
   Identity bleibt gesperrt, obwohl nativ Status 2 und Commit-USN vorliegen.
3. Echter nativer Commit-Bestätigungsfehler: Zielwerte sind geändert, nativ bleibt
   Status 1 ohne bestätigte USN; Identity hält Unklarheit über Recover hinweg und
   blockiert neue IDs. Wertebeobachtung entsperrt nichts.

Jeder Fall prüft ausdrücklich, dass der unveränderte Runtime-`LDAP.Ready` das
fehlende RFC4528 weiterhin abweist. Die neue Schnittstelle existiert nur in
`_test.go`; es gibt keine Backendauswahl, kein neues Produktivflag und keinen
HTTP-/Unixsocket-Endpunkt. Neue Metadatentabelle und Fehlertrigger existieren
nur in der privaten synthetischen Testdatenbank.

Die normale Sequenz teilt sich ein dauerhaftes Laborjournal; unabhängige
Prüfszenarien verwenden frische Serviceobjekte für getrennte Authentifizierungs-
budgets. Das ist Testisolation und kein empfohlener betrieblicher Reset.
Die drei DC-Container teilen weder Datenbank noch Journale. Kein unklarer Claim
wird für den nächsten Test gelöscht oder in einen anderen Namespace verschoben.

Die vier ursprünglichen Profilwerte werden zum Testende über den ausdrücklich
synthetischen Fixture-Administrator exakt wiederhergestellt; USN und AD-Historie
bleiben erhalten. Diese Fixturepflege ist kein Runtime-Rückweg. Der positive
Gegenauftrag in Fall 1 erfolgt dagegen tatsächlich über Service, Journal und
native CAS-Operation mit frischer ID und Autorisierung.

Reproduktion: Linux-`adprofile.test` aus aktuellem Commit bauen, dann mit
`IDENTITY_NATIVE_IDENTITY_LAB=1` und `IDENTITY_NATIVE_IDENTITY_CASE=success`,
`lost_reply` oder `uncertain` jeweils frisch provisionieren und `native_run.sh`
starten. Nur die beiden bestehenden read-only Laborskript-/Testbinary-Mounts,
`--rm --network none`, keine Hostports. Compiler-/UBSan-/Neustartgrenzen wie im
[nativen Labor](samba-native-cas-lab.md). Die manuelle `full_lab=true`-CI enthält
diese Fälle; kein automatischer Developmentlauf oder zusätzlicher GitHub-Lauf
wird für diese Arbeit gestartet. [CI-Kostenkontrolle](ci-cost-control.md).

Lokaler Abschluss: alle drei Identity-/Samba-Vertragsfälle, die bisherigen
27 Broker- und 17 nativen Verträge sowie beide nativen Prozessabbruch-/Neustart-
fälle bestanden. Vollständige lokale Go-/OpenSSL-Suite, gezielte AD-Profil-
Wiederholung, Vet, Modulprüfung, Python-/Shellsyntax und actionlint bestanden.
PostgreSQL und GitHub-Runner wurden für diesen SQLite-/Laborumfang nicht neu
ausgeführt; dafür wird kein neuer Nachweis behauptet. Native C-Compiler-/UBSan-
Prüfungen bleiben aktiv. Alle eigenen Wegwerfcontainer sind beendet.

Rückweg der Vorbereitung: die neuen Testdateien, Laborskript-/Receiptmetadaten-
Erweiterung, CI-Laborschritt und Dokumentation auf `3d18f59` zurücknehmen.
Keine Runtime-Migration, kein Produktionsjournal und kein Hostdienst müssen
zurückgesetzt werden. Unabhängiger nativer Review, vollständige effektive Rechte,
Last-/Timeout-/Commitgrenzen sowie Mehr-DC-/Replikations-/Restore-Nachweise bleiben
offen. Die CAS-Sperre darf daraus nicht automatisch aufgehoben werden.
