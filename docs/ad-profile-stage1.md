# AD-Profilbearbeitung Stufe 1: Entwicklungsstand und Betriebsgrenzen

Die [serverseitige Broker-Laboruntersuchung](samba-cas-broker-research.md) beschreibt
einen positiven lokalen DSDB-Mechanismusnachweis und dessen offene Host-/Betriebs-
grenzen. Identity nutzt diesen Kandidaten nicht; die CAS-Sperre bleibt bestehen.

Fortschreibung: Nach der [Samba-CAS-Untersuchung](samba-cas-research.md) wurde die
[Criticality-Kodierung in Identity auf FF korrigiert](ldap-criticality-fix.md).
Die Runtime bleibt gesperrt: Ein korrekter Clientencoder ersetzt den weiterhin
fehlenden positiven Nachweis der serverseitigen CAS-Semantik nicht.

Stand: 2. November 2026. Implementierung auf development, standardmäßig aus.
Keine Veröffentlichung, Installation, Produktionsverbindung oder Delegation;
MOBILE01 vollständig ausgeschlossen. Framework und bestehende Identity-
Datenbankschemata bleiben unverändert.

**Die positive Samba-Schreibabnahme bleibt gesperrt.** Das isolierte Labor mit
Samba 4.17.12-Debian bietet das benötigte RFC-4528-Assertion-Control nicht an.
Der Executor lehnt deshalb die Planung und den Schreibaufruf ab. Es gibt keinen
Schalter für einen unbedingten Fallback. Erfolgreiche Schutztests sind keine
Freigabe einer nutzbaren AD-Schreibfunktion auf dieser Samba-Version.

## Implementierte Grenzen

Der Webdienst kennt nur einen lokalen Unix-Socket, kein Schreibcredential und
keinen Journal-Schlüssel. Ein neuer Linux-Executor (`cmd/ad-profile-executor`)
besitzt ein separates lokales SQLite-Journal und ein dediziertes AD-Credential.
Ein fehlender Konfigurationspfad oder `Directory.Enabled=false` beendet ihn
ohne Öffnen der Datenbank oder Kontakt zum AD. Der Web-Socket ist im Default leer.
Es wird keine Unit installiert oder aktiviert und kein bestehender Installer
verändert. Das Modul führt selbst keine Hintergrund-AD-Schreibaufträge aus.

Nur `displayName`, `givenName`, `sn`, `mail` sind zugelassen: höchstens ein Wert,
begrenzte Länge, gültiges UTF-8, keine Steuerzeichen und kein freier LDAP-Editor.
Ein leeres Feld entfernt den Wert. Mail-Änderungen benötigen vor jeder späteren
Aktivierung eine Prüfung der angebundenen Anwendungen: Mail darf dort keinen
ungeprüften Kontoübernahme-/Recoverypfad eröffnen.

Ziele müssen explizit über ihre rohen 16-Byte-objectGUIDs (32 Hexzeichen, LDAP-
Bytefolge, keine ungeprüfte Übernahme einer formatierten GUID) aufgenommen sein
und unmittelbar unter der festen Managed-OU liegen. Domain-GUID/-SID und
DC-Invocation-ID sind fest gebunden. Parsebare RDN-Grenzen ersetzen Stringsuffixe.
Abgelehnt werden Eigenkonto, Writerkonto, RID unter 1000, andere Domänen,
Computer, andere primäre Gruppe als Domain Users, weitere UAC-Flags als 512/514,
adminCount ungleich 0, SID-History, SPN-/Delegations-/Key-Credential-Eigenschaften und jede
explizite oder rückwärts transitiv gefundene Gruppenmitgliedschaft.
Damit ist die erste Zielmenge bewusst enger als alle gewöhnlichen AD-Benutzer.
Nicht vollständige Suchen, Referrals oder Fehler sperren den Zugriff.

Der Executor prüft eine zusätzliche, über DN **und GUID** gebundene Operatorgruppe
und authentifiziert den handelnden Benutzer für jede Aktion neu über LDAPS.
Unmittelbar vor dem Claim geschieht das erneut. Bestehende Identity-Rollen
erhalten keine neue AD-Permission. Der Webzugang benötigt zusätzlich eine normale,
aktuelle Identity-AD-Administratorsitzung; Local/Demo und ein alleiniger
Notfallzugang reichen nicht. Jede Mutation verlangt CSRF und denselben HTTPS-
Origin. Die UI zeigt Vorher/Nachher, eine separate Bestätigung und Auftragsstatus.
Passwörter verlassen nur im Speicher den Browser/Webprozess zum lokalen Socket
und werden weder in Journal, Audit, Antworten noch Logs gespeichert.

Es gelten 8 KiB Requestlimit, ein globaler Inflight-Aufruf, maximal 30 Aktionen
pro Minute global und 10 pro normalisiertem Benutzernamen, eine fünfminütige
Planfrist und begrenzte LDAP-/HTTP-Zeiten. Der Executor kommuniziert mit genau
einem verifiziertem LDAPS-Endpunkt, ohne Referral-Following oder DC-Failover.
Die kritische Domain-Scope-Suchkontrolle verhindert das Ausweichen auf andere
Naming Contexts. Vor jedem Schreiben werden Zielschutz und Snapshot erneut
geprüft; die Modifikation bereitet eine als kritisch markierte Assertion auf GUID
und uSNChanged vor. Die LDAP-FF-Drahtkodierung ist jetzt geprüft; die positive
Backendsemantik bleibt nach dem genannten Laborbefund ausdrücklich gesperrt.

Eine Zielassertion serialisiert keine externe Privilegierungsänderung im
gesamten Gruppengraphen. Enge effektive ACLs, ein isoliertes Verwaltungssegment
und ein abgestimmter Prozess für Privilegierungsänderungen bleiben deshalb
Aktivierungsvoraussetzungen. Die Software behauptet keine vollständige Analyse
beliebiger effektiver AD-Rechte. [Grundkonzept](ad-write-security-design.md).

## Journal, Audit und Unklarheit

Plan und Audit werden gemeinsam gespeichert, danach Claim und Audit ebenfalls
atomar. Erst der erfolgreich gecommittete Claim erlaubt genau einen AD-Aufruf.
Erfolg wird erst nach Readback und dauerhaftem Abschlussaudit gemeldet.
Definitive LDAP-Ablehnungen erhalten `failed_no_effect`; Transportunsicherheit
oder fehlender Abschlussnachweis bleiben `applying` beziehungsweise
`reconciliation_required`. Wiederholtes Apply liefert nur den gespeicherten
Zustand. Ein zweiter lokaler Executor wird durch einen gemeinsamen Dateilock
abgewiesen; es gibt keinen verteilten Executorbetrieb.

Beim exklusiven Neustart werden hinterlassene Claims atomar mit Audit als
klärungsbedürftig markiert. Ein unveränderter Lesestand beweist **keine**
ausgebliebene Wirkung eines früheren LDAP-Aufrufs. Solche Aufträge bleiben
gesperrt. Nur ein beobachteter Nachherzustand kann als
`reconciled_effect_observed` dokumentiert werden; das ist keine nachträglich
erfundene sichere Ausführungsbestätigung. Keine automatische Wiederholung,
kein automatischer No-effect-Abschluss und kein SQL-Entsperren als Betriebsweg.
Abbruch konkurriert mit dem Claim; abgelaufene vorbereitete Pläne werden mit
Audit als `expired` geschlossen.

Das separate `ad_profile_audit` enthält Operations-ID, Actor-SID, Ziel-GUID,
Zustand, Zeit und Metadaten mit Aktion, Attributnamen, Policyrevision und
Elternauftrag. Es enthält keine Profilwerte, Passwörter, Rohfehler oder DNs.
Die Eigentümersicht im Auftragsstatus zeigt begrenzte Auditdatensätze; es ist
kein stilles Spiegeln in das bisherige Identity-`audit_log`. Bei einer späteren
Betriebsabnahme sind beide Auditquellen gemeinsam zu sichern und auszuwerten.
SQLite-Dateirechte bilden hier die administrative Grenze; keine Behauptung
eines gegen den Betriebssystemadministrator unveränderbaren Logs.

Vorher-/Nachherwerte liegen ausschließlich in AES-256-GCM-verschlüsselten
Payloads mit separatem 32-Byte-Schlüssel und an die Auftrags-ID gebundener
Authentifizierung. Schlüsselfehler und Manipulation sperren die Nutzung.
Terminale Payloads werden sieben Tage nach Planablauf logisch entfernt; Prüfung
beim Start, bei Aktionen und alle sechs Stunden. Audit und Zustände bleiben
erhalten. Offene/unklare Aufträge behalten ihre Evidenz bis zur manuellen Klärung
und benötigen eine organisatorische Retentionsprüfung. Secure-delete für das
aktive SQLite-Journal ersetzt keine Löschung alter Backups oder Speicherkopien;
keine forensische Löschgarantie. Backup-Retention muss gesondert dazu passen.

## Geschützte Konfiguration (Vorlage, nicht aktivieren)

Webkonfiguration: `ad_profiles.executor_socket`, alternativ
`SWBADGE_AD_PROFILE_SOCKET`; Default leer. Startup verweigert eine Aktivierung
ohne geschützten AD-Modus, HTTPS oder bei Demo/Legacy-Zertifikatspin.
Seite nach einer späteren Laborfreigabe: `/ad-profiles`.

Executor-Konfiguration ist eine private JSON-Datei; Beispiel bleibt deaktiviert:

```json
{
  "Directory": {
    "Enabled": false,
    "URL": "ldaps://dc.lab.example:636",
    "BaseDN": "DC=lab,DC=example",
    "ManagedOU": "OU=Managed,DC=lab,DC=example",
    "DomainGUID": "<32 Hexzeichen der LDAP-Bytefolge>",
    "DomainSID": "<erfasste Domain-SID>",
    "DCIdentity": "<32 Hexzeichen der Invocation-ID>",
    "WriterDN": "CN=profile-writer,OU=Services,DC=lab,DC=example",
    "PasswordFile": "/private/ad-profile/writer-password",
    "CAFile": "/private/ad-profile/ca.pem",
    "OperatorGroupDN": "CN=Profile Operators,OU=Roles,DC=lab,DC=example",
    "OperatorGroupGUID": "<32 Hexzeichen der LDAP-Bytefolge>",
    "Revision": "stage1-policy-1",
    "Targets": [],
    "ProtectedGUIDs": []
  },
  "Driver": "sqlite",
  "DatabaseFile": "/private/ad-profile/database-path",
  "KeyFile": "/private/ad-profile/journal-key",
  "Socket": "/run/ad-profile/executor.sock"
}
```

DatabaseFile enthält ausschließlich den absoluten kanonischen SQLite-Dateipfad,
keinen URI, keine Queryparameter. Der Datenordner ist 0700; Konfiguration,
DSN-Datei, Passwort und Schlüssel sind reguläre private Dateien ohne Gruppen-/
Weltrechte oder Links. Der Linuxleser verwendet No-follow und prüft den offenen
Dateideskriptor. Lock und Datenpfad müssen für alle lokalen Starts identisch sein.
Der Socket liegt in einem nicht beschreibbaren 0700/0750-Elternverzeichnis;
seine Gruppe darf nur den vorgesehenen Webdienst enthalten (Socket 0660).
Ein existierender Socket wird nicht automatisch entfernt. Nie zwei Hosts oder
Netzdateisysteme als gemeinsames SQLite-Journal verwenden.

Schemaanlage ist ausschließlich explizit mit `--initialize-journal` möglich,
ohne AD-Kontakt und ohne stilles Übernehmen eines vorhandenen Schemas.
Normale Starts führen keine DDL aus. Die Journal-Verträge werden zusätzlich
gegen PostgreSQL getestet; der Executor nimmt `Driver=pgx` aktuell nicht an.
So wird eine verlorene separate Advisory-Lock-Verbindung nicht fälschlich als
weiterhin gültige verteilte Ausführungssperre behandelt.

Vor einer späteren Betriebsfreigabe fehlen weiterhin: echte positive CAS-
Semantikprüfung am vorgesehenen Backend, minimale effektive Delegation,
Lesesicht auf sämtliche Schutzattribute, externe Konkurrenzfälle, Privilegierungs-
Prozess, geschützte Betriebssystemidentität/Unit, Backup-/Retention-Abnahme und
ein gesondertes Wartungsfenster. Es wurden dafür keine Produktionskonten erzeugt.

## Rückweg und nachgewiesene Grenzen

1. Neue Webaufträge sperren, Executor kontrolliert beenden und Inflight-Aufträge
   anhand des dauerhaften Journals klären. Journal, Schlüssel, Konfiguration und
   Binärversion gemeinsam geschützt sichern. Keine offene Operation löschen.
2. Fachlicher Rückweg ist ein neuer `rollback-plan` mit Bezug zum ursprünglichen
   Erfolg. Die aktuellen vier Profilwerte müssen noch exakt dessen Nachherwerten
   entsprechen; der Gegenplan stellt die früheren Werte beziehungsweise deren
   Abwesenheit her. Er benötigt dieselbe frische Authentifizierung, neue
   Bestätigung, Schutzprüfung und CAS. Fremdänderungen sperren den Rückweg.
3. Nach Payload-Retention oder bei unklarer Wirkung gibt es keinen automatischen
   Gegenplan. Manuelle autorisierte Klärung mit DC-Evidenz ist erforderlich.
4. Ein Binär-/Konfigurationsrückweg schaltet die Funktion aus, macht AD-Wirkungen
   aber nicht rückgängig. DB-Restore darf niemals bereits ausgeführte Operationen
   vergessen und erneut zulassen. Vor einem älteren Restore alle möglichen
   Wirkungen seit dem Sicherungsstand reconciliieren und Nachweise erhalten.
5. Keine Domain-Wiederherstellung für einzelne Profilwerte, kein Passwortreset,
   kein Kontostatus-/Gruppen-/ACL-Schreiben und keine anderen Stufen.

Nachweise sind getrennt:

| Ebene | Ergebnis und Aussage |
| --- | --- |
| Runtime-Protokoll mit synthetischem Directory | Erfolg, Byte-/Werttreue des neuen Gegenplans, Fremdänderungsablehnung, Entzug, Ablauf, konkurrierender Claim/Abbruch und kein Replay geprüft |
| SQLite-Journal | Reale Transaktionen mit Auditfehlern, Manipulations-/Schlüsselschutz, Payload-Retention und konsistenter VACUUM-INTO-Snapshot; Wiederöffnung erhält Audit und erledigte Zustände ohne AD-Wiederholung |
| PostgreSQL-Journal | Reale isolierte Transaktion: AD-Erfolg im Modell, Abschlussaudit verworfen, Claim bleibt gesperrt, Neustart-Recovery und beobachtete Wirkung separat dokumentiert |
| Samba 4.17.12 | Verifiziertes LDAPS, falsche CA/DNS-Namen abgewiesen, Operator-/Eigen-/privilegierte/nested/OU-Grenzen und fehlendes CAS geprüft; echter Executor/Socket, Default-off und Zweitprozesssperre geprüft |
| Samba-ACL-/Rückwegfixture | Nur im Test direkt erlaubtes Attribut geändert und ursprünglicher Zustand exakt wiederhergestellt; fremde Attribute und OU-Ziel vom Servicekonto abgewiesen |
| Positive Runtime-CAS-Abnahme auf Samba | **Offen und gesperrt**. Der direkte Fixture-Schreibtest ist ausdrücklich kein Runtime-Fallback und kein positiver Runtime-Rollbacknachweis |

Das Laborimage baut aus gepinntem Debian-Bookworm-Basisdigest; Paketstände werden
im Testlauf ausgegeben. Neue synthetische Domäne je Lauf, nur Loopback, Docker
`--network none`, keine Hostports oder Produktionsmounts. Eingebunden sind nur
Laborskripte und Testbinaries read-only. Container und seine erzeugten Secrets
werden nach dem Lauf entfernt. Die CI führt diese Schutz-/Fixture-Probe als
separaten Job und die restliche Go-Suite mit Race Detector/PostgreSQL 16 aus.

Reproduktion ohne Produktionskonfiguration:

```sh
mkdir -p /tmp/ad-profile-tests
CGO_ENABLED=0 go test -c -o /tmp/ad-profile-tests/adprofile.test ./internal/adprofile
CGO_ENABLED=0 go build -o /tmp/ad-profile-tests/executor ./cmd/ad-profile-executor
docker build -t identity-ad-profile-lab:local scripts/ad-profile-lab
docker run --rm --network none --hostname dc1 \
  --mount type=bind,source="$PWD/scripts/ad-profile-lab",target=/workspace/scripts/ad-profile-lab,readonly \
  --mount type=bind,source=/tmp/ad-profile-tests,target=/workspace/dist/ad-profile-tests,readonly \
  --entrypoint sh identity-ad-profile-lab:local /workspace/scripts/ad-profile-lab/run.sh
```

Der konkrete nächste technische Freigabepunkt ist ein backendseitig nachgewiesenes
atomar bedingtes Schreibverfahren unter unveränderten Least-Privilege-Grenzen.
Bis dahin bleiben Runtime-Schreibplanung und Produktivaktivierung gesperrt.

Lokaler Abschlussnachweis: vollständige Go-Suite ohne Cache einschließlich
OpenSSL, Vet und Modulverifikation bestanden. Neue Journalverträge zusätzlich
mit PostgreSQL 17 im netzlosen Wegwerfcontainer bestanden; Cluster kontrolliert
gestoppt. Linux-Dateirechte-/Link-/Prozesssperrtests sowie der aktuelle Samba-
Schutz-/Executor-/Fixture-Rückweglauf bestanden. Der frühere gestoppte reine
Labor-Diagnosecontainer wurde nach Prüfung von Name, Image und Netzmodus gezielt
entfernt. Es wurden keine echten AD-Zugangsdaten oder Produktivdaten verwendet.
