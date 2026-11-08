# Signierter Auftrag und authentifiziertes Receipt: Laborprotokoll v2

Stand: 4. November 2026, development. Ausschließlich synthetischer, netzloser
Samba-DC. Keine Runtime-Anbindung, Installation, Produktivverbindung oder
CAS-Entsperrung; Default-off bleibt bestehen. MOBILE01 bleibt ausgeschlossen.

## Vertrauens- und Ausführungsgrenze

`native_protocol_v2.c` wird ausschließlich mit `IDENTITY_NATIVE_V2` in das
Labor-LDB-Modul eingebunden. `native_setup.py` wählt dies nur bei explizitem
`IDENTITY_NATIVE_PROTOCOL=2`. Eine solche Instanz akzeptiert ausschließlich
`SWCAS002`, niemals einen Rückfall auf v1. V1 bleibt ein separat provisionierter
Regressionsweg. Go-Adapter und Receiptclient existieren ausschließlich in
`_test.go`; Directory-, Service-, Executor-, Web- und Konfigurationsschnittstellen
der Anwendung werden dadurch nicht erweitert.

Der Aussteller authentifiziert den Actor tatsächlich über LDAPS, prüft den
verschlüsselten Identity-Plan und signiert dessen Projektion. Der native Server
prüft den angemeldeten Writer ohne Tokenbildung oder Rechteerhöhung sowie frisch
Actorrolle, Kontostatus, Zielschutz und OU. Normale DSDB-ACLs bleiben wirksam.
Die Signatur bestätigt die Aussage des vertrauenswürdigen Ausstellers; sie ist
kein eigenständiger AD-Actor-Authentifizierungsbeweis für einen Produktionsdienst.

Aussteller- und DC-Receipt-Schlüssel sind verschiedene frische Ed25519-Schlüssel.
Der Client pinnt den öffentlichen DC-Schlüssel, der Server den Ausstellerschlüssel.
Beide privaten Schlüssel liegen im Labor unter derselben Root-TCB. Das belegt
Zwecktrennung, keine unabhängige Hostisolation. Bootstrap, Rotation, Widerruf,
Schlüsselaufbewahrung und Wiederherstellung für den Betrieb bleiben offen.

## Binärvertrag

Alle Ganzzahlen sind unsigned Big Endian; GUIDs/IDs sind die gepinnten 16 Bytes,
keine textuellen GUID-Konvertierungen. Hashes sind SHA-256. Ed25519 signiert den
vollständigen Body ohne algorithmische oder pfadbezogene Auswahl im Request.

| Auftrag SWCAS002 | Bytes / Bedeutung |
| --- | --- |
| Header | 144: Magic8, ID16, Domain16, DC-Invocation16, Ziel16, Actor16, Writer16, Gruppe16, erwartete USN8, issued8, expires8 |
| Erweiterte Bindung | 144: PlanDigest32, PolicyHash32, Parent16, VorherHash32, NachherHash32 |
| Änderungen | Vier Felder in fester Reihenfolge displayName/givenName/sn/mail; jeweils Länge u16 und Bytes; 65535=unverändert, 0=entfernen |
| Abschluss | Signatur64; insgesamt 360 bis maximal 1024 Bytes |

ASCII-Profilgrenzen sind 256/64/64/254 Bytes, nur Bytes 32 bis 126. Der Profilhash
umfasst **alle vier** Werte in obiger Reihenfolge, jeweils u16-Länge plus Bytes;
Abwesenheit hat Länge 0. Mehrfachwerte und nicht darstellbare Werte werden nicht
gekürzt oder normalisiert. PolicyHash ist SHA-256 der ASCII-FixtureRevision und
im Modul gepinnt; PlanDigest darf nicht null sein. Auftrag gilt höchstens 60s
und der testseitige Aussteller begrenzt ihn zusätzlich auf die Planfrist.

`B+ID` speichert die vollständige 144-Byte-Bindung atomar mit dem nativen Claim.
Vorherhash und USN werden unter der DSDB-Transaktion geprüft, Nachherhash im
Modifycallback vor Commit. Ein Gegenauftrag benötigt einen bestätigten Parent
mit Status2, dessen eigene Commit-USN als erwartete Version und exakt inverse
Hashbeziehung bei gleicher Policy. Fremdes ABA wird damit abgewiesen.

## Reiner Statusweg

Virtueller BaseSearch auf `CN=NativeCASReceipt,<base>`; ausschließlich Equality
`identityLabStatus=<624 lowercase hex>` und Attribut `identityLabReceipt`.
Kein Objekt, Schema oder öffentliches OID wird angelegt. Andere Scopes,
Wildcardattribute, zusätzliche Controls und unberechtigte Writer werden abgewiesen.
Auch Status verlangt frische DSDB-Policyprüfung und Ausstellersignatur.

| SWSTAT02 Body | Länge / Reihenfolge |
| --- | --- |
| Anfrage | 248: Magic8, ID16, PlanDigest32, WireDigest32, Nonce16, Domain16, DC16, Ziel16, Actor16, PolicyHash32, ScopeHash32, issued8, expires8 |
| Signatur | 64, insgesamt 312 Bytes |

WireDigest ist SHA-256 des vollständigen unsignierten Auftrags. Nonce wird pro
Abfrage kryptographisch frisch erzeugt und darf nicht null sein. Frist maximal
30s. ScopeHash bindet längenpräfixierte Domain-/Ziel-/Actor-/Writer-SIDs sowie
Domain-/DC-/Ziel-/Actor-/Writer-/Gruppen-GUIDs der Fixture in genau dieser Reihenfolge.

| SWRECP02 Body | Länge / Reihenfolge |
| --- | --- |
| Antwort | 393: Magic8, Echo des unsignierten Queries248, Zustand1, Commit-USN8, Parent16, VorherHash32, NachherHash32, Auditreferenz32, issued8, expires8 |
| DC-Signatur | 64, insgesamt 457 Bytes |

Auditreferenz ist SHA-256 über Query-ID/PlanDigest/WireDigest, Parent und
Zustand/Commit-USN. Sie korreliert ohne Rohwerte und ersetzt kein dauerhaftes
Betriebsaudit. Die Antwortfrist liegt innerhalb der Queryfrist und maximal 30s.
Der Go-Client prüft exakte Form, DC-Signatur, Queryecho einschließlich Nonce,
Fristen, Zustandssemantik, Parent, Profilhashes und Auditreferenz.

| Zustand | Bedeutung und Grenze |
| --- | --- |
| 0 | Unbekannt; USN0, Parent/Hashes0. **Kein No-effect-Nachweis und keine Wiederholungsfreigabe.** |
| 1 | Applying/unklar; keine bestätigte USN. Alte und frische IDs bleiben gesperrt. |
| 2 | Bestätigter Commit mit eigener USN >0. Keine Behauptung, dass spätere Fremdänderungen ausbleiben. |
| 3 | Bestätigter Abbruch ohne Effekt; USN0. Kein automatischer Schreib-Retry. |

Terminalzustand und `F+ID` müssen übereinstimmen; nur Status2 darf `V+ID` mit
nichtnull Commit-USN besitzen. Fehlende/inkonsistente Einträge werden nicht als
Erfolg signiert. Unpassender Plan- oder WireDigest wird abgewiesen.

## Sperren, Absturz und Rückweg

DSDB und TDB sind weiterhin **zwei Commitdomänen**, kein gemeinsames ACID.
Claim wird vor AD-Mutation dauerhaft; Abschluss erst nach bestätigtem DSDB-Commit.
Ein Absturz davor oder danach kann Status1 hinterlassen. Lesestand und Receipt
entsperren weder den nativen Claim noch die Identity-Unklarheit automatisch.
Es gibt keinen Replay-, Reset-, Namespacewechsel- oder Recovery-Schreibpfad.

Search verwendet eine DSDB-Lesesperre und versucht keine verbotene Hochstufung
auf eine Schreibtransaktion. Status öffnet TDB tatsächlich O_RDONLY. Da TDBs
`lockall_read` in dieser Version read-only Handles ablehnt, halten alle nativen
Claim-/Finish-Schreiber einen exklusiven, Status einen geteilten nichtblockierenden
`flock` auf demselben geprüften Journal-Inode. Eigentümer, Modus, Hardlinks und
Inodegleichheit werden geprüft. Der Fence wird vor Receipt-Signierung freigegeben.
Sperrkonflikte führen zum Fehler; ein blockierter Abschluss kann konservativ
Unklarheit erhalten. Last-/Fairnessgrenzen sind damit noch nicht betrieblich bewiesen.
Kein TDB-/SSH-/Root-Zugriff durch den v2-Go-Client, keine Statusmutation oder
Status-Recovery. Fixture-Inspektion und Korruptionsinjektion bleiben privilegierte Tests.

Rückweg dieser Entwicklung: Laborcode/Testadapter/CI-Laborschritte und Dokumentation
auf Ausgangscommit `c92e87d5d4e2a88eb771561aed10bd44eb9576c6` zurücknehmen;
Linux-Testbinary daraus neu bauen und frische v1-Fixture starten. Keine Datenmigration
oder Produktionskonfiguration ist beteiligt. Vorhandene Journale nie zurücksetzen
oder mit anderem Protokoll öffnen. Ein fachlicher Rückweg ist ein **neuer**,
autorisierter Gegenauftrag mit eigener ID, bestätigtem Parent und eigener Commit-USN.

## Reproduktion und Nachweise

Linuxbinary aus aktuellem Stand: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c
-o dist/ad-profile-tests/adprofile.test ./internal/adprofile`.
Je Fall frischen Container mit `--rm --network none --hostname dc1`, keinen Ports
und nur den zwei read-only Mounts `scripts/ad-profile-lab` und
`dist/ad-profile-tests` unter `/workspace` starten. Nach `provision.py` folgt
`native_run.sh`. `IDENTITY_NATIVE_PROTOCOL=2` wählt v2; ohne diese Auswahl läuft v1.

- Standard: unabhängige Python/OpenSSL-Matrix; v2 mit neun Verträgen einschließlich
  Signatur-/Policy-/Downgrade-/Parent-/Hash-/Nonce-/Frist-/Rollen-Gegenproben,
  unveränderten Ziel-/Journalbytes bei Status, Schlüsselfehlern, Fence und
  beschädigten Terminaldaten sowie gesperrter Unklarheit.
- `IDENTITY_NATIVE_IDENTITY_LAB=1`, zusätzlich
  `IDENTITY_NATIVE_IDENTITY_CASE=success|lost_reply|uncertain`: echter Go-Service,
  verschlüsseltes Journal, Gegenauftrag und verlorene Ergebnisse.
- `IDENTITY_NATIVE_CRASH_CASE=before_commit|after_commit`: echte Prozessabbrüche,
  Neustart desselben DC/Journals, signierte Unklarheit, kein Replay.

Lokaler Abschluss am 4. November 2026: neun v2-Verträge, alle drei Identity-Fälle
jeweils mit v1 und v2 sowie beide echten Crash-/DC-Neustartfälle je Version
bestanden. Zusätzlich bisherige Samba-Forschung, Stufe1/echter Executor,
27 Broker-/Boundaryverträge und 17 native v1-Verträge bestanden. Alle Fixture-
Profilwerte wurden exakt wiederhergestellt; USN/Historie blieben erhalten.
C wurde mit Werror, Stackschutz, RELRO/NOW und UBSan gebaut; kein UBSan-Befund.
Vollständige lokale Go-/OpenSSL-Suite, Vet, Modulprüfung, Python-/Shellsyntax,
actionlint und Whitespaceprüfung bestanden. PostgreSQL wurde nicht erneut
abgenommen. GitHub-Läufe wurden nicht gestartet; die CI-Erweiterung bleibt
ausschließlich im bestehenden manuellen `full_lab`-Pfad.

## Offene Betriebsfreigaben

Unabhängiger nativer Review, typisierter produktiver Identity-Auftrag statt
Testcontext, Actor-Proof/Step-up, Schlüsselbetrieb und getrennte Vertrauensgrenzen,
vollständige effektive Rechte, Rate-/Ressourcenlimits, Mehr-DC/Replikation,
Backup-/Restore-/Journal-Lebenszyklus und gesonderte Runtime-Abnahme bleiben offen.
Der lokale Sicherheitsreview ist keine unabhängige Zertifizierung. Kein Release
oder Produktivaktivierungspfad wird durch diese Laborarbeit freigegeben.

Primärquellen: [Samba 4.17.12 LDB-Modul-API](https://raw.githubusercontent.com/samba-team/samba/samba-4.17.12/lib/ldb/include/ldb_module.h),
[versionierte TDB-Sperrimplementierung](https://raw.githubusercontent.com/samba-team/samba/samba-4.17.12/lib/tdb/common/lock.c),
[Ed25519 / RFC 8032](https://www.rfc-editor.org/info/rfc8032/).
