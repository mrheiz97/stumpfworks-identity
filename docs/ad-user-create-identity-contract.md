# Vorbereitete Identity-Anbindung der Benutzeranlage

Fortschreibung: [Session-/Permissionintegration](ad-user-create-sessions.md)
registriert inzwischen den standardmäßig gesperrten Web-Endpunkt und eine
Backend-Anschlussstelle. Kein produktives Backend oder Executortransport aktiviert.

Stand: 4. November 2026, development. Ausschließlich lokale Entwicklung und
isoliertes Samba-Labor. CAS-Sperre/Default-off bleiben bestehen; keine
Produktivkontakte, GitHub-Läufe oder MOBILE01. Kein Runtime-Endpunkt registriert.

## Dauerhafte Auftragsgrenze

`internal/adcreate.Directory` trennt jetzt `Encode(Plan)`, `Create(BoundRequest)`
und `Receipt(BoundRequest)`. `Authorize(actorSID, scope)` ist verpflichtend;
eine alte Implementierung ohne diesen Vertrag ist kein zulässiger Adapter.
Keine Contextschlüssel und kein Wiederaufbau eines Auftrags beim Senden.

Nach frischer AD-Anmeldung und Rollenprüfung erzeugt der Aussteller die exakten
signierten Bytes. Identity prüft Plan-/Scopebindung, Größe, Digest und Frist
(höchstens60s, innerhalb der Planfrist). In **einer** SQLite-Transaktion werden
`prepared → applying`, die neue `create_dispatch`-Zeile und die Auditereignisse
`dispatch_bound`/`applying` gespeichert. Die Zeile enthält Plan-/WireDigest und
AES-GCM-verschlüsselt den vollständigen typisierten Auftrag inklusive Original-
Signatur und Ablauf. AEAD-Associated-Data bindet ihn an `ID:dispatch`.
Der gespeicherte WireDigest ist SHA-256 der vollständigen signierten Bytes;
das native Statusprotokoll verwendet weiterhin SHA-256 des unsignierten Bodys.

Erst nach erfolgreichem Commit wird der Datensatz erneut entschlüsselt und
geprüft und genau dieser Auftrag einmal versandt. Bindungs-/Audit-/Claimfehler
verhindern den Versand. Fehler nach Claim bleiben konservativ unklar, auch wenn
die Rolle noch vor dem tatsächlichen Add entzogen wurde. Kein neuer Signatur-
oder Dispatchversuch beim Wiederöffnen und kein Freigeben reservierter Namen.

Die neue Tabelle wird nur über das explizite private Laborschema angelegt.
Keine automatische Migration einer vorhandenen oder produktiven Datenbank.
Fehlt die Tabelle, kann der Claim nicht committen und es erfolgt kein Add.

## Rollen und Projektion

Eine aktuelle Anlagerolle wird bei jeder authentifizierten Aktion, nach Encode
vor Claim und erneut direkt vor Dispatch verlangt. Die native Operation prüft
die Rolle und Kontozustände zusätzlich innerhalb ihrer DSDB-Transaktion.
Der Laboradapter pinnt Actor-GUID/SID und die `User Creators`-Gruppen-GUID und
liest die aktuelle Mitgliedschaft. Ein gültiges Passwort oder vorhandener Plan
verlängert keine entzogene Berechtigung. Die Profilrolle erbt weiterhin kein Create.

Der ausschließlich in `_test.go` existierende native Adapter prüft außerdem
die vollständige Payloadprojektion gegen den typisierten Plan, Signatur,
Domain/DC/OU/Actor/Writer/Gruppe/Policy, Eingaben, WireDigest und Wirefrist.
Die wirksame serverseitige Grenze bleibt die [native Laboroperation](ad-user-create-lab.md).
Kein produktiver Actor-Proof oder unabhängiger Schlüsselbetrieb wird behauptet.

## Beleg nach Neustart ohne erneutes Add

`evidence` lädt den dauerhaften Auftrag nach frischer Rollenprüfung und fragt
mit neuer Nonce den signierten DC-Beleg ab. Dafür wird auch ein inzwischen
abgelaufener Originalauftrag nur gelesen, niemals neu signiert oder ausgeführt.
Die Query hat ihre eigene kurze Frist. Manipulierte Ciphertexte, Plan-/WireDigest-
Verwechslung und falsche Scopebindung werden vor der Statusabfrage abgewiesen.

`Operation.Evidence` ist eine flüchtige Beobachtung. Der persistierte Status,
Ergebnisdatensatz und Namenssperren bleiben unverändert, auch bei positivem Beleg.
Die UI zeigt diesen Unterschied ausdrücklich. Unbekannt/fehlender Beleg ist
kein No-effect-Nachweis. Keine automatische Reconciliation oder Wiederholung.

## Nachweise und Rückweg

Lokale Schutztests prüfen die transaktionale Versandgrenze, Auditfehler, Rollen-
entzug vor/nach Claim, beschädigte Bindung, neues Serviceobjekt ohne alte Adapter-
Felder, reinen Receiptzugriff und weiterhin gesperrte Wiederholung. Im echten
netzlosen Samba-Labor werden SQLite-Datei und Adapter geschlossen/neu geöffnet:
der nach verlorener Antwort vorhandene DC-Beleg lässt sich ohne Add abfragen.
Rollenentzug sperrt auch diesen Zugriff; die Fixturemitgliedschaft wird restauriert.
Die bisherigen sieben nativen Create-Verträge laufen unverändert mit.

Abnahme lokal bestanden: vollständige Go/OpenSSL-Suite `./...`, Vet, Modul- und
Whitespaceprüfung sowie die sieben nativen Create-Verträge und der erweiterte
Identity-/HTML-/SQLite-Neuöffnungsfall. Native C/Protokoll, Framework, Abhängigkeiten,
CAS-Gate, Produktionskonfiguration und CI sind unverändert. Keine erneute
PostgreSQL-/Mehr-DC-/Crash-Abnahme oder Remote-CI für diesen Vorbereitungsumfang
behauptet. Die echten DC-Crashnachweise bleiben die dokumentierte Create-Baseline.

Reproduktion wie [Create-Labor](ad-user-create-lab.md): aktuelles Linux-Testbinary,
frische Fixture, Protokoll2/Create-Flag, zwei RO-Mounts, `--rm --network none`,
keine Ports. Keine Produktionsdaten oder Schlüssel auf den Arbeitsplatz kopieren.

Rückweg der Vorbereitung: auf Ausgangscommit `c1d6d0e` zurücknehmen, Testbinary
neu bauen und eine frische Fixture verwenden. Alte/neue Journale nicht löschen,
zurücksetzen oder für einen erneuten Dispatch umdeuten. Kein produktiver Dienst
oder Datenbestand ist beteiligt. Host-/Dateischutz, Prozessfencing/Retention,
unabhängiger Review, Actor-/Schlüsselbetrieb, echte Session-/Permissionintegration,
Mehr-DC/Forest-UPN/Restore und spätere Aktivierung bleiben eigene Freigaben.
