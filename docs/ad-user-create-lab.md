# Deaktivierte Benutzeranlage: umgesetzter Laborablauf

Aktuelle [Session-/Permissionintegration](ad-user-create-sessions.md): Der Router
registriert den inzwischen standardmäßig gesperrten Endpunkt. Die untenstehende
ursprüngliche Aussage „nicht registriert“ ist historisch; kein Backend aktiviert.

Fortschreibung: Die [vorbereitete Identity-Anbindung](ad-user-create-identity-contract.md)
persistiert inzwischen den exakten signierten Auftrag vor Versand und ermöglicht
rollenabhängigen Receiptzugriff nach Journalwiederöffnung. Die unten genannte
rein flüchtige Wirebindung beschreibt den ursprünglichen Laborstand.

Stand: 4. November 2026, development. **Keine Produktivfreigabe.** CAS-Sperre,
Default-off, bestehender Executor und Produktionskonfiguration bleiben unverändert.
MOBILE01 ausgeschlossen; keine GitHub-Läufe. Grundlage:
[Sicherheitskonzept](ad-user-create-security-design.md).

## Was funktioniert

`internal/adcreate` enthält den getrennten typisierten Service und HTML-Handler:
Name/Anzeigename → verschlüsselter Plan → frische AD-Bestätigung → deaktivierte
Anlage → bestätigtes Ergebnis und Audit. UPN wird aus Name und festem Suffix
abgeleitet und im Plan angezeigt. Keine beliebigen Attribute, OU-Auswahl,
Passwörter für das neue Konto, Gruppen oder Aktivierung.

Der Handler ist **nicht in der laufenden Identity registriert**. Ohne explizit
aktivierten Service, verifizierten normalen AD-Sessioncallback und HTTPS lehnt
er ab. Jede Aktion verlangt zusätzlich eine frische AD-Anmeldung mit aktueller
Anlagerolle. POST prüft Origin, sessiongebundenes CSRF, maximal 8KiB und eindeutige
erlaubte Formularfelder. Es gibt keinen Produktionsadapter, kein neues
Konfigurationsflag, keinen installierten Dienst und keine Runtime-CAS-Umgehung.
Der vollständige HTML-Ablauf wird mit dem echten Handler im Samba-Labor getestet.

Plan/Ergebnis liegen AES-256-GCM-verschlüsselt im separaten SQLite-Journal.
ID/Actor/Scope/Policy/Digest werden beim Öffnen geprüft; Pläne gelten maximal 5min.
SAM-/UPN-Reservierungen sind mit abgeleitetem Schlüssel HMAC-geschützt. Claim
und Audit committen vor Dispatch; ein DB-Index erlaubt global nur einen
anwendenden/unklaren Auftrag. Höchstens fünf vorbereitete Aufträge pro Actor und
Stunde werden dauerhaft gezählt, lokale Bindversuche auf 20/min begrenzt.
Audit protokolliert Zustände und Ablehnungen ohne Namen, Profilwerte oder Secrets.

Nach verlorener Antwort oder Ergebniscommit bleibt der Auftrag unklar;
derselbe und neue Aufträge können reservierte Namen nicht erneut anlegen.
Auch bei Wiederöffnung des Journals wird `applying` niemals erneut versandt.
Status ist eine lesende Anzeige, kein Wiederholungs- oder Entsperrmechanismus.
Ein Auditfehler vor Dispatch verhindert Add; danach bleibt konservativ Unklarheit.
Vor Claim kann abgebrochen werden; expliziter Abbruch/Ablauf gibt Reservierungen frei.

## Enge native Anlagegrenze

Nur `IDENTITY_NATIVE_CREATE_LAB=1` zusammen mit explizitem Protokoll2 baut
`native_create.c` ein. Setup erstellt in einer **frischen** synthetischen Fixture
ein eigenes Konto `creator` mit Create-Child ausschließlich für Benutzer in der
festen OU und eine eigene Rolle `User Creators`. Die alte Profilrolle erbt keine
Anlageberechtigung. Normale DSDB-ACLs bleiben wirksam; keine SYSTEM-Mutation oder
Tokenersetzung. Im Labor teilen Konten weiterhin das zufällige Fixturepasswort;
Aussteller und DC teilen Root-TCB. Das ist kein betrieblicher Credentialnachweis.

Roh-Add/Modify/Delete/Rename des Anlagekontos werden im nativen Modul blockiert.
Nur ein Add mit genau einem virtuellen `identityLabCreate`-Wert ist zulässig.
Der Server erzeugt die wirklichen Attribute selbst: user, CN/SAM, fester UPN,
Anzeigename und UAC514. Keine Passwort-/Gruppen-/SPN-/ACL- oder UAC-Eingabe.
Die virtuelle Hülle wird nicht gespeichert, kein Schema/OID angelegt.

`SWNEW001`: Header200 = Magic8, ID16, Domain16, DC16, OU16, Actor16, Writer16,
Gruppe16, issued8, expires8, PlanDigest32, PolicyHash32; anschließend zwei
u16-längenpräfixierte Felder SAM/Anzeigename und Ed25519-Signatur64. Maximal544
Bytes, Frist≤60s und≤Planfrist. SAM nur `[a-z][a-z0-9._-]{0,19}`, Anzeigename
ASCII32..126 bis256 Bytes. Fester Beispielsuffix `profile.test` gilt nur im Labor.
Keine Parser-/Aktionsverwechslung mit SWCAS002.

Unter DSDB-Transaktion: aktuelle Rolle/Konten/OU-GUID/Domain/DC prüfen,
operationsgebundenen dauerhaften Claim setzen, SAM-/UPN-Konflikte prüfen,
normalen Add ausführen. GUID/SID/USN werden noch im Addcallback innerhalb der
Transaktion erfasst. Erst nach bestätigtem Commit entstehen im nativen Journal
Status2, Commit-USN und Identität. Der gemeinsame Claim-Fence ist konservativ:
ein unklarer Create sperrt auch andere neue native Aufträge der Fixture.

## Eigener signierter Ergebnisnachweis

BaseSearch `CN=NativeCreateReceipt,<base>`, nur Equality
`identityLabCreateStatus=<624hex>` und Attribut `identityLabCreateReceipt`.
`SWCSTAT1` verwendet Querybody248 plus Issuersignatur64: ID/Plan-/WireDigest,
frische Nonce, Domain/DC/OU/Actor, Policy/Scope und höchstens30s. Frische
Writer-/Rollenprüfung und O_RDONLY-Journal unter DSDB-Lesesperre/Fence wie bei v2.

`SWCRECP1` ist **eigenständig**: Body366 plus DC-Signatur64. Magic8, Queryecho248,
Zustand1, Commit-USN8, GUID16, SID-Länge1, SID68 gepolstert, issued8, expires8.
Nur Zustand2 enthält GUID/SID/USN. Zustände0/1/3 liefern keine bestätigte Identität;
0 ist kein No-effect-Beweis. A/B/C/F/N/V-Journalbindungen werden geprüft.
Profil-Receipts und Profil-Gegenaufträge akzeptieren keine Create-Datensätze.

Der Go-Laborclient prüft gepinnten DC-Key, Signatur, Echo/Nonce, Fristen, Zustand,
SID-Domäne und Padding und vergleicht den aktuellen Readback mit **diesem**
Commitbeleg. Ein nach Löschung fremd neu angelegtes gleichnamiges Objekt wird
nicht adoptiert. Kein SSH-/Root-/TDB-Zugriff für Ergebnisabfragen. Wireframebindung
des Go-Testadapters liegt derzeit nur im Speicher; eine spätere Runtime braucht
deren dauerhaft verschlüsselte Speicherung vor Versand. Unklarheit wird deshalb
auch durch einen späteren positiven nativen Beleg nicht automatisch entsperrt.

## Tests und Reproduktion

`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o
dist/ad-profile-tests/adprofile.test ./internal/adprofile` bauen. Je Fall frische
Container: `--rm --network none --hostname dc1`, keine Ports, ausschließlich zwei
RO-Mounts für `scripts/ad-profile-lab` und `dist/ad-profile-tests` nach `/workspace`.
Env `IDENTITY_NATIVE_PROTOCOL=2` und `IDENTITY_NATIVE_CREATE_LAB=1`; zuerst
`provision.py`, dann `native_run.sh`.

- Standard: sieben unabhängige Python/OpenSSL-Verträge und echter Go-HTML-/Service-
  Ablauf. Template, Scope/Signatur/Fristen/Größen, fremde SAM-/UPN-Kollisionen,
  Rollen-/ACL-Entzug, parallele Add-Aufträge, read-only signierte Originalidentität
  trotz fremder Delete/Recreate, deaktiviertes Konto, Audit und kein Replay.
- Mit `IDENTITY_NATIVE_CRASH_CASE=before_commit|after_commit`: echter nativer
  Prozessabbruch, Neustart desselben DC/Journals, signierter Status1 und kein
  alter/neuer ID-Bypass. Kein Journalreset; Daten verschwinden erst mit Container.
- Go-Units: Default-off, Auth-/Scope-/Digest-/Ablauf-/Eingabeschutz, verschlüsselter
  Plan, Namensreservierung, Claim/Cancel-Rennen, Auditfehler vor/nach Add,
  Ergebnisverlust/Journalwiederöffnung sowie HTTPS/CSRF/Origin/Formulargrenzen.

## Rückweg und offene Freigaben

Lokale Abnahme: sieben Python/OpenSSL-Verträge, echter HTML-/Service-/LDAPS-
Anlageablauf und beide echten Prozessabbruch-/DC-Neustartfälle bestanden.
Profilregressionen mit 17 nativen v1- und neun v2-Verträgen ebenfalls grün.
Go/OpenSSL `./...`, Vet, Modulprüfung, Python-/Shellsyntax, actionlint und
Whitespaceprüfung bestanden. Native Kompilierung mit Werror/Stackschutz/RELRO/NOW
und UBSan, ohne Sanitizerbefund. Keine neue PostgreSQL-, Mehr-DC- oder Remote-CI-
Abnahme behauptet; bestehende CI-Definition unverändert.

Keine automatische Kontolöschung. Erfolgreich angelegte Konten bleiben deaktiviert.
Nur ausdrücklich synthetische Fixturetests löschen/ersetzen Testobjekte.
Entwicklungsrückweg: Änderungen dieses Umfangs auf Ausgangscommit `56e6e4d`
zurücknehmen, Linuxbinary neu bauen und frische Fixture ohne Create-Flag starten.
Es gibt keine Produktionsmigration; bestehende Journale nicht zurücksetzen.

Vor einer Runtime-/Betriebsfreigabe offen: unabhängiger C-Review, Host-/Credential-
Isolation und Actor-Proof, Journal-Dateischutz/Retention/Prozessfencing, dauerhafte
Wirebindung, Session-/Permissionintegration, Last-/Restore-Nachweise sowie
forestweite UPN-/Mehr-DC-/Replikationskonkurrenz. Geprüft ist ein einzelner
netzloser synthetischer DC; keine globale Eindeutigkeitsgarantie daraus ableiten.
Passwort, Gruppen und Aktivierung bleiben separate, nicht implementierte Aktionen.
