# WYSE01: Worker, Stable-Katalog und Timer vorbereiten

Stand: 2. November 2026. **Lokale Vorbereitung, keine Produktivaktivierung.**
In dieser Phase wurden weder LOGIN01 noch WYSE01 oder MOBILE01 kontaktiert.
MOBILE01 bleibt ausgeschlossen. Grundlage ist die
[abgeschlossene Status-/Updater-Abnahme](v1.13.0-wyse01-acceptance.md).
Diese historische Abnahme ersetzt keine frische Vorprüfung im nächsten Fenster.

## Geprüfter Kandidat

Der Worker ist bereits Bestandteil des unveränderten, veröffentlichten
Releasecommits `37f928aa5774b18f661abcd580bf33d03322fd1d` (v1.13.0), Go 1.26.10.
Es gibt keine neue Version, keinen neuen Signierschlüssel und keine Änderung am
Framework. `scripts/prepare-wyse01-update-worker.py` erzeugt ausschließlich lokal
das create-only Verzeichnis `dist/wyse01-scheduled-updates-v1.13.0/`:

| Kandidat | Ziel bei späterer freigegebener Aktivierung |
| --- | --- |
| `client/sw-badge-client-update-worker` | WYSE01 `/usr/local/sbin/sw-badge-client-update-worker`, root:root 0755 |
| `client/client-update.pub` | WYSE01 `/etc/stumpfworks-badge/client-update.pub`, root:root 0644 |
| `client/swbadge-client-updates.service` und `.timer` | WYSE01 `/etc/systemd/system/`, root:root 0644 |
| `server/update-stable.pub` | LOGIN01 `/etc/stumpfworks-badge/update-stable.pub`, root:root 0644 |
| `server/releases/approved.json` | LOGIN01 `/var/lib/stumpfworks-badge/releases/approved.json`, root:root 0600; Verzeichnis 0700 |
| `server/updates.yaml.fragment` | Nur die zwei `updates`-Werte kontrolliert in bestehende LOGIN01-Konfiguration integrieren; keine komplette Konfiguration ersetzen |

Worker-SHA256:
`e0ca7b649f8c702c051eac0a25c1b8479d64e75f729f997c7305c429a5698492`.
Stable-Key-Fingerprint (SHA256 der dekodierten 32 Bytes):
`d94bd2573b017898d771913f358bff5386af5b300392bcc75ec02d8e42fec069`.
Der private Schlüssel wird nicht gelesen oder kopiert. Der installierte
Development-Key und die bestehende Clientkonfiguration bleiben erhalten.
`SHA256SUMS` und `PREPARATION.json` binden alle erzeugten Dateien; das Hashmanifest
ist ein lokaler Integritätsnachweis, keine zusätzliche digitale Signatur.

Der **Aktivierungskatalog ist absichtlich `[]`**. Der getrennte
`verification-catalog` enthält die unverändert signierte Status-/Updater-ZIP
v1.13.0 mit ID `wyse01-v1130-status-updater`, SHA256
`b77d62b4e307010aa8e802851e53888d4a76e661af64a69b14bc2aa7d05045a0`.
Dieser Prüfstand darf nicht als produktiver Katalog übertragen werden:
WYSE01 hat diese Version bereits. Beide Bootstrappakete sind keine neuen
Worker-Testaufträge. Kein Legacy-Engine, kein Equal-Version-Bypass, kein
Umetikettieren eines Releases. Ein echter Updateauftrag benötigt ein späteres,
eigenständig veröffentlichtes und freigegebenes Stable-Release >1.13.0.

## Prüfungen und reproduzierbare Vorbereitung

```powershell
python scripts/prepare-wyse01-update-worker.py
$env:IDENTITY_TEST_WYSE01_PREPARATION = Join-Path (Get-Location) 'dist/wyse01-scheduled-updates-v1.13.0'
./scripts/test-local-postgres.ps1
```

Bei bereits vorhandenem Kit bricht der Generator ab; überprüfte Kandidaten
werden nicht überschrieben. Er prüft Worker-/ZIP-Hash und Public-Key-Fingerprint
vor dem Schreiben. Alle Eingaben sind öffentliche Releaseartefakte.
`TestWYSE01PreparedStableCatalog` lädt mit dem produktiven Verifier sowohl den
leeren Aktivierungskatalog als auch die tatsächliche signierte ZIP und prüft
Komponentenumfang, Signatur, Key, Gleichstand, Downgrade und Architektur.
`TestWorkerAlreadyInstalledReleaseNeverRequestsStart` beweist mit einer korrekt
signierten synthetischen ZIP: Bei bereits erfolgreicher gleicher Version kein
Startgrant und keine Änderung des Installationstargets.
`TestWorkerEmptyPollDoesNotInstallOrCreateJobEvidence` prüft drei aufeinanderfolgende
204-Polls ohne Serviceaufruf, Jobjournal, Transaktionsmarker oder Ergebnisänderung.

Die vollständige lokale Go-Suite einschließlich PostgreSQL 17, Import/
Reconciliation/Restore, TLS/OpenSSL und `go vet` bestand am 2. November 2026.
Bestehende Verträge prüfen Rollen/CSRF, mTLS-Isolation, konkurrierenden Start/
Abbruch, manipulierte Pakete, Lock, Absturzjournal, verlorene Antworten und
Rollback. Der Browser-zu-Worker-Test verwendet isolierte Dateiziele und einen
Service-Stub: Er behauptet keine echte systemd- oder Hardwareabnahme.
Linux-CI ergänzt Race Detector und PostgreSQL 16. Offline-systemd-Verifikation
der beiden Units erfolgt in Linux-CI; der echte Timerlauf bleibt Wartungsabnahme.

## Späteres Wartungsfenster: Vorprüfung und Sicherung

Die Aktivierung betrifft **WYSE01 und die Katalogkonfiguration auf LOGIN01**;
die aktuelle Vorbereitung erteilt dafür keine Produktionsfreigabe.

1. Frisch lesend prüfen: beide Versionen/Hashes, Zeit/TLS, Zertifikat und
   `certificate_required`, aktiven Credentialstatus, freien Speicher, Warnjournal,
   Servicezustände und Update-/Workerjournal. Keine offenen oder dispatched Jobs,
   keine Pending-Transaction. WYSE01 Status/Updater müssen die abgenommenen
   1.13.0-Hashes besitzen; VNC/LightDM stabil. Kein Zugang zu MOBILE01.
2. Clientkonfiguration auf die benötigten vier vorhandenen Werte prüfen:
   `SWBADGE_DEVICE_SERVER` (DNS-HTTPS-Origin auf 8444), `SWBADGE_CLIENT_ID`
   (`wyse01-greeter`), `SWBADGE_CA_FILE`, `SWBADGE_DEVICE_BUNDLE_FILE`.
   Nur Vorhandensein/Verwendbarkeit bestätigen, keine Inhalte ausgeben.
   Fehlende Werte bedeuten vor Installation eine neu zu prüfende Konfigänderung.
3. Frischen root-only Clientrollback erstellen: Binaries, neue Zielpfade samt
   Abwesenheitsbelegen, Units/Drop-ins/Enablement, komplette Konfiguration,
   Schlüsselmaterial nur auf dem Client, Verzeichnis-UID/GID/Modi, Update-State,
   Journale/Lock und bisherige Rollbackreferenzen. SHA256 und Metadaten verifizieren.
   Shared-Konfigverzeichnis root:lightdm 0750 erhalten; keinesfalls pauschal 0700
   setzen. VNC-Reparatur, PAM, Greeter, Devicewerkzeug und Status-Timer erhalten.
4. Auf LOGIN01 frischen konsistenten Anwendungs-/Konfig-/Unit-/DB-Rollback im
   kontrollierten Dienststopp erstellen und Restore prüfen. Jobs und Audit müssen
   denselben Stand besitzen. Aktuelle Schema7-Binaries bleiben; keine Migration.
   Bestehende Sicherungen vom 1. November sind Referenz, kein frischer Rollback.
   Off-Host-Sicherung separat feststellen; Host-Snapshots nicht als unabhängig
   bezeichnen. Produktivdaten/Secrets nicht auf den Arbeitsplatz übertragen.

## Stufenweise Aktivierung und Abnahme (noch nicht ausgeführt)

1. Genehmigten, leeren Stable-Katalog und Public-Key auf LOGIN01 installieren,
   nur die beiden `updates`-Konfigwerte ergänzen. Geschützte AD-Administration
   und vorhandene mTLS-API müssen aktiviert bleiben. Kontrollierter Serverstart,
   HTTP-/LDAP-/OIDC-/Metrics- und Job-/Auditprüfung; Katalog und Jobs bleiben leer.
   Keine Managed-Client-Zielversion oder Token-/Zertifikatspolicy ändern.
2. Auf WYSE01 Worker, Public-Key und beide Units atomar installieren. Kandidaten
   und Zielhashes prüfen; `systemd-analyze verify` mit vorhandenen Abhängigkeiten
   ausführen, `daemon-reload`. Timer zunächst **disabled/inactive**. Kein Installer-
   Gesamtlauf; keine Schlüsselrotation, kein Enrollment, kein LightDM-/VNC-Neustart.
3. Einmal `swbadge-client-updates.service` starten. Dies ist ein echter
   produktiver mTLS-Poll mit lokaler Zustandserstellung, kein Dry-run. Bei leerem
   Katalog/Jobs ist HTTP204 zu erwarten: kein Download, kein Startgrant, keine
   Installation, kein Updateergebnis. Arbeitsverzeichnis `update-jobs` root0700,
   Dateien0600; keine offenen Marker. mTLS-/DNS-/CA-Fehler nicht abschalten.
4. Erst danach Timer aktivieren. Bestehender Takt: OnBoot90s, OnUnitActive60s,
   Zufallsversatz bis10s, kein Persistent-Nachholen. Mindestens fünf Minuten
   natürliche Läufe abnehmen: letzte/nächste Ausführung, Result=success,
   kontinuierliche Statusberichte, gleiche VNC-/LightDM-/Netzwerk-PIDs und
   Neustartzähler, keine Jobs/Installationen/Fehler. AD-/VNC-Benutzerabnahme
   getrennt festhalten. Kein Badge/PIN-Neutest als zusätzliche Voraussetzung.
5. Erster tatsächlicher geplanter Updateauftrag ist ein eigenes Gate:
   neuer signierter Stable-Kandidat >1.13.0, Hashfreigabe, lokale Health-Fehler-
   und Recoveryprobe, neues Fenster/frischer Rollback. Nur `wyse01-greeter`
   über das geschützte Formular auswählen, vor Start Abbruch und anschließend
   genehmigten Lauf samt Ergebnis/Audit/Rollback abnehmen. Greeterkomponenten
   erfordern zusätzliche ausdrückliche LightDM-Wartung. Kein Probeauftrag für
   MOBILE01, keine direkten SQL-Änderungen.

Der Stable-Katalog ist serverweit, keine Geräte-Allowlist. Die Clientbindung
entsteht erst im auditierten Auftrag. MOBILE01 darf weder aktiviert noch auf
Zertifikatsbetrieb umgestellt oder mit einem Job versehen werden.

## Rückweg und Abbruchkriterien

Vor Aktivierung: jeder Hash-/Signatur-/Backupfehler, instabiles Display, offener
Job oder unklare Recovery beendet den Ablauf vor der nächsten Änderung.
Keine automatischen Wiederholungen eines möglicherweise ausgeführten Updates.

Nach Aktivierung zuerst `swbadge-client-updates.timer` stoppen/deaktivieren;
die laufende oneshot-Ausführung kontrolliert beenden lassen. Bei dispatched Job,
Pending-Marker oder Journal zuerst Zustand/Lock/Signaturbindung prüfen und über
bestehende Recovery/Ergebniswege reconciliieren. Nicht blind killen, Marker
löschen oder DB-Zeilen ändern. Abschalten des Timers zieht keinen bereits
erteilten Startgrant zurück. Server-Katalogentzug benötigt Neustart, weil Bytes
im Speicher eingefroren sind; leere Konfiguration verhindert neue Grants,
erhält aber Geschichte und Ergebnisannahme.

Ohne jemals gestartete Jobs: frische gesicherte Konfiguration und ursprüngliche
Unit-/Enablementzustände wiederherstellen; nur nach Abwesenheitsbeleg neu
angelegte Worker-/Public-Key-/Unitdateien gezielt entfernen, `daemon-reload`,
ursprüngliche Dienste prüfen. Worker-/Updatebeweise bis Abnahme behalten.
Keine Rücknahme des bereits abgenommenen Status/Updater1.13.0 und keine
Rücknahme der VNC-Reparatur für diesen Aktivierungsrückweg.

Nach echten Jobs keine ältere DB blind wiederherstellen: neuere Writes sowie
Jobs/Audit/Clientjournal müssen zuerst abgeglichen werden. DB-Restore benötigt
eine ausdrückliche Datenverlust-/Reconciliationentscheidung. Keine Schema-
Downmigration. Alle alten und neuen Rollbacks geschützt erhalten.

## Ergebnisgrenze

Kandidat, lokaler Katalogprüfstand, Tests und Wartungs-/Rollbackplan sind
vorbereitet. Produktiver Worker/Timer, Stable-Katalogaktivierung, natürlicher
204-Poll und erster neuer Updateauftrag sind **noch nicht abgenommen**.
Sie werden durch diese Dokumentation weder ausgeführt noch freigegeben.
