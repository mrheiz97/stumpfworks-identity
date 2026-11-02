# WYSE01 / LOGIN01: geplanter Updatebetrieb aktiviert

Wartung am 2. November 2026 nach ausdrücklicher Freigabe für Worker, leeren
Stable-Katalog, Timer und erforderliche LOGIN01-Konfiguration. Keine Freigabe
für einen Updateauftrag oder einen neuen Komponentenrollout abgeleitet.
MOBILE01 wurde weder kontaktiert noch verändert.

## Frische Vorprüfung und Rückwege

LOGIN01 lief gesund mit den drei abgenommenen v1.13.0-Binärhashes, Schema7,
Jobs0, keinen ausstehenden Credentials/Enrollmenttokens, sieben LDAP-Benutzern,
synchroner Uhr und etwa6,5GiB freiem Speicher. Alle sechs HTTPS-Routen bestanden
mit voller OpenSSL-Ketten-/DNS-Prüfung. WYSE01 meldete1.13.0,
`certificate_required` und vier gesunde Bereitschaftswerte. Die bestehende
Zertifikatsidentität bleibt gültig bis29.Januar2027. Keine Zertifikatserneuerung.

WYSE01: Status-/Updaterhashes wie abgenommen, etwa4,1GiB frei, Zeit synchron,
Status-Timer aktiv, kein Worker, kein Jobjournal, kein Pending-Update. VNC hatte
seit dem Abschluss vom Vortag einen einmaligen XIO-bedingten automatischen
Neustart um18:34:15UTC; danach bis Wartung unverändert aktiv. Historischer
Auslöser nicht als neue Portkollision behauptet. Eintrittsbaseline:
LightDM PID1023312/NRestarts802, VNC PID1057650/NRestarts1,
NetworkManager PID719/NRestarts0. Kein LightDM-/VNC-/Netzwerkneustart ausgelöst.

Frischer voller Clientrollback:
`/root/wyse01-updates-rollback-20261102T091000Z`, root0700,
**40 Manifestdateien**, Original-UID/GID/Modi und Abwesenheitsbelege geprüft.
Konfiguration, Token/CA/aktuelle und vorherige Devicebundles, Keytab, Domänen-,
PAM-/LightDM-/VNC-Konfiguration, Binaries/Wrapper, Units, Update-State und Lock
bleiben geschützt auf dem Client. Status-Timer für die konsistente Kopie kurz
pausiert, aktive Ausführung abgewartet und danach wieder gestartet.

Ursprünglicher LOGIN01-Aktivierungsrollback (Rückweg zum deaktivierten Katalog):
`/root/identity-updates-rollback-20261102T092000Z`, root0700,
**60 Manifestdateien** samt Originalmetadaten, Binaries, vollständiger
Konfiguration/Secrets/Units, PostgreSQL-Konfiguration/Rollen und frischem
Schema7-Custom-Dump. Identity gestoppt, Anwendungs-DB-Verbindungen vollständig
beendet. Vollständige isolierte Restoreprobe auf LOGIN01: **alle16 Tabellen**
mit kanonischen Zeilendigesten sowie Indizes und Eigentümern identisch. Probe-DB
entfernt und Abwesenheit geprüft. Dump/Globals und private Evidenz0600.

Ein erster ebenfalls geprüfter Serverrollback unter
`/root/identity-updates-rollback-20261102T091000Z` bleibt erhalten. Der
vorgezogene Leserechtest brach die erste Aktivierung noch vor Konfigänderung ab:
umask077 hatte das angeforderte Katalogverzeichnis0750 auf0700 begrenzt.
Neue Dateien wurden gezielt zurückgenommen und der alte Dienst/Timer gestartet.
Vor Wiederholung wurde der oben genannte **neue konsistente** Serverrollback
inklusive vollständiger Restoreprobe erstellt. Finalrechte wurden anschließend
explizit gesetzt und mit der tatsächlichen Dienstidentität geprüft.

Beide Rückwege sind hostlokal. Keine unabhängige Off-Host-Sicherung bestätigt
oder behauptet, keine Produktivdaten/privaten Schlüssel auf den Arbeitsplatz
übertragen. Die Zeitzeichen in den Pfaden sind feste Wartungskennungen;
tatsächliche Erstellungs-/Ausführungszeiten stehen in den geschützten Belegen.

Vor der abschließenden Absicherung des Elternverzeichnisses weiterer frischer
gestoppter Serverrollback:
`/root/identity-updates-rollback-20261102T093000Z`, root0700,
**62 Manifestdateien**, einschließlich zwischenzeitlichem leerem Katalog.
Erneut vollständiger Restorevergleich aller16 Tabellen samt Indizes/Eigentümern
bestanden; Probe-DB entfernt. Dieser zusätzliche Rückweg bewahrt den bereits
aktivierten Zwischenstand, während der092000Z-Rollback den Ausgangszustand
vor Katalogaktivierung enthält. Beide werden behalten.

## LOGIN01: leerer Stable-Katalog

Nur zwei Werte in `/etc/stumpfworks-badge/config.yaml` ergänzt:

```yaml
updates:
  catalog_directory: /var/lib/stumpfworks-badge-releases
  public_key_file: /etc/stumpfworks-badge/update-stable.pub
```

Der vorhandene Dienst läuft als `swbadge`, nicht als root. Daher ist das neue
Katalogverzeichnis **root:swbadge0750**, `approved.json` und Public-Key sind
**root:swbadge0640**. Der Dienst kann lesen, aber nicht die rootkontrollierten
Dateien oder das Katalogverzeichnis überschreiben. Ausschließlich `[]` im
Katalog; keine ZIP, keine Freigabe für die bereits installierte1.13.0, keine
Veröffentlichung eines neuen Releases. Der Stable-Key ist derselbe vorbereitete
öffentliche Schlüssel, SHA256 der dekodierten32Bytes:
`d94bd2573b017898d771913f358bff5386af5b300392bcc75ec02d8e42fec069`.

Der ursprünglich vorbereitete Pfad unter `/var/lib/stumpfworks-badge/releases`
lag unter einem dienstbeschreibbaren Elternverzeichnis. Deshalb wurde der leere
Katalog nach der zusätzlichen Vollsicherung atomar in das separate Verzeichnis
unter root:root0755 `/var/lib` verlegt. Dort sind Katalog **und alle Eltern**
rootkontrolliert; Dienstlesezugriff sowie fehlender Schreibzugriff auf Verzeichnis
und Eltern geprüft. Alter Pfad danach abwesend. Generator und Vorbereitung sind
für künftige Kits korrigiert, das ursprüngliche Kit bleibt als Beleg unverändert.

Neuer isolierter Linux-Rechtevertrag
`scripts/test-update-catalog-permissions.py`: echte unprivilegierte Lese-/
Schreib-/Umbenennungsversuche in temporären Root-Fixtures. Drei Fälle prüfen
Gruppenlesezugriff trotz umask077, unveränderliche Freigabedatei, blockierten
Katalogersatz unter rootkontrolliertem Elternverzeichnis und demonstrieren den
Umbenennungsfehler bei dienstbeschreibbarem Elternverzeichnis. Keine echten
Dienste, Produktivdateien oder Credentials im Test; in Linux-CI verdrahtet.

Server/Admin/Migrator bleiben unverändert1.13.0, Schema7 unverändert. Keine
Service-Unit-, Umgebungs-, Managed-Zielversions-, Rollen-, Clientmodus- oder
Tokenpolicyänderung. Genau die bestehende Serverinstanz kontrolliert gestartet;
kein Restartloop. Sechs HTTPS-Routen, LDAP, OIDC und Metrics bestanden erneut.
Natürlicher WYSE01-mTLS-Status nach Aktivierung gesund; Jobs weiterhin0,
MOBILE01 bleibt deaktiviert/token_only/version1.2.1.

## WYSE01: Worker und Timer

Worker aus unverändertem veröffentlichtem Releasecommit
`37f928aa5774b18f661abcd580bf33d03322fd1d`, Go1.26.10,
`vcs.modified=false`, Framework1.2.0. Installiert root:root0755:
`/usr/local/sbin/sw-badge-client-update-worker`, SHA256
`e0ca7b649f8c702c051eac0a25c1b8479d64e75f729f997c7305c429a5698492`.

Stable-Public-Key `/etc/stumpfworks-badge/client-update.pub` root:root0644.
Installierter Development-Key unverändert. Privater Stable-Key nie gelesen
oder übertragen. Beide bestehenden Release-Units root:root0644 installiert,
`systemd-analyze verify` auf dem echten Client bestanden, `daemon-reload`.

Die vier benötigten Workerwerte stehen auf diesem gewachsenen Client nicht
gemeinsam in client.conf: ID und CA dort, mTLS-Origin und Gerätebundle beim
Statusdienst in dessen bestehendem Zusatz. Statt die gemeinsame Greeterkonfig
zu ändern, neuer Workerzusatz
`/etc/systemd/system/swbadge-client-updates.service.d/20-device-certificate.conf`
(root:root0644):

```ini
[Service]
Environment=SWBADGE_DEVICE_SERVER=https://login01.ad.stumpfworks.de:8444
Environment=SWBADGE_DEVICE_BUNDLE_FILE=/etc/stumpfworks-badge/device-credential.pem
```

ID/CA weiter über das bestehende `EnvironmentFile`. Bestehendes privates Bundle
root0600 nur auf WYSE01 benutzt; kein Token gelesen und keine Credentials
kopiert/ersetzt. Shared-Verzeichnis root:lightdm0750 unverändert.

Timer zunächst disabled/inactive. Manueller oneshot-Lauf erfolgreich,
`Result=success`, `ExecMainStatus=0`, `update-jobs` root0700 und leer, kein
Transaktionsmarker. Vor diesem Lauf wurde die Prüfskriptbehandlung des erwarteten
Exitcodes1 von `systemctl is-enabled` bei `disabled` korrigiert; der Worker war
zu diesem Zeitpunkt noch nicht gestartet. Danach zusätzlicher direkter
OpenSSL-mTLS-POST auf8444 mit voller Ketten-/DNS-Prüfung: **HTTP204**. Lock
root0600 regulär und frei. Erst danach Timer **enabled/active**.

Takt unverändert gemäß Release: OnBoot90s, OnUnitActive60s, Zufallsversatz
bis10s, kein Persistent-Nachholen. Kein Legacy-Engine und kein signiertes
Updatepaket installiert oder als Probeauftrag geplant. Status/Updater bleiben
1.13.0; Devicewerkzeug1.12.0, Greeter/PAM/VNC-Reparatur unverändert.

## Abnahme und Evidenz

Benutzer bestätigte Desktop beziehungsweise normale AD-Anmeldung und VNC auf
WYSE01 sowie normalen LOGIN01-Adminlogin, Dashboard und leere Clientupdates.
Kein erzwungener Logout/Neustart, Badge/PIN nicht neu getestet und nicht erneut
als Gate geöffnet.

Die erste Messung überlappte die zusätzliche Serverwartung und enthielt einen
erwarteten fehlgeschlagenen Poll während des Dienststopps. Als
`initial-stability-during-server-maintenance.json` erhalten, nicht als bestandene
Stabilität ausgegeben. Der nächste natürliche Timerlauf erholte sich selbst am
2.November um09:21:40UTC; Statusbericht ebenfalls wieder erfolgreich.
Die abschließende Messung **09:22:45–09:27:50UTC** nach allen Serveränderungen
bestand mit **elf gesunden Proben** und **fünf unterschiedlichen erfolgreichen
Workerläufen**. Display-/VNC-/Netzwerk-PIDs und Restartzähler identisch zur
Eintrittsbaseline, RFB-Banner in jeder Probe, erfolgreiche natürliche
Statusberichte, keine Jobjournale/Pending-Transaction, Workerfehler0,
VNC-Bind-/XIO-Fehler0. Sämtliche ursprünglichen Clientdateien und UID/GID/Modi
erneut bytegenau unverändert geprüft. Abschließende Serverprüfung: sechs
HTTPS-Routen200, LDAP7, Jobs0, natürliche Statusmeldung09:27:50UTC gesund,
Wartungsmodus0, Wartungstimer aktiv und Warnjournal seit letztem Start leer.
Abschluss09:28:35UTC: Clientrollback40Dateien, ursprüngliche Livebytes und
Metadaten, neue Zielhashes und beide Timer erneut geprüft. Beweise und sämtliche
Rollbacks behalten; kein offener Job und kein Pending-Marker. Wartung technisch
und interaktiv abgeschlossen.
Geschützte Belege:

- WYSE01 `/root/wyse01-updates-stage-20261102T091000Z/`: öffentliche Kandidaten,
  `activation.json`, `timer-enabled.json`, `final-stability.json`, `closure.json`.
- LOGIN01 `/root/identity-updates-stage-20261102T093000Z/`: endgültige
  `activation.json`, `closure.json`; die091000Z-/092000Z-Stages bleiben als
  Zwischenbelege mit öffentlichen Katalogkandidaten erhalten.
- Reguläres abschließendes LOGIN01-Backup `identity-20261102T092138Z.dump`,0600,
  `pg_restore --list` bestanden, Backupmarker frisch. Wartungstimer wieder
  enabled/active, eigener Wartungsmarker entfernt.

## Geprüfter Rückweg und nächste Grenze

Timer zuerst stoppen/deaktivieren, laufenden oneshot kontrolliert abwarten.
Lock/Jobs/Pending/Journale prüfen. Nur solange weiterhin **kein Updateauftrag**
existiert, diese Aktivierung anhand der Abwesenheitsbelege zurücknehmen:
neue Workerdatei, Public-Key, zwei Units und Worker-Drop-in nach Hashprüfung
gezielt entfernen, `daemon-reload`, ursprüngliche Dienstzustände verifizieren.
Die bisherigen Status-/Updaterbinaries und VNC-Reparatur nicht zurückbauen.
Leeres Worker-Verzeichnis nur nach gesicherter Evidenz und nachgewiesener Leere
entfernen; keine rekursive Löschung produktiver Beweise.

LOGIN01 kontrolliert stoppen, gesicherte vorherige Konfiguration mit Original-
UID/GID/Modi aus dem092000Z-Ausgangsrollback herstellen, nur neuen Key und
nachgewiesen leeren endgültigen Katalog gezielt
entfernen; Service starten und TLS/LDAP/OIDC/Status prüfen. Keine Binär- oder
Schemaänderung nötig. Der frische Dump ist eine vollständig geprüfte Notfall-
Reserve, **kein Anlass zum Zurückspielen neuerer Writes**. DB-Restore erst nach
ausdrücklicher Datenverlust-/Reconciliationentscheidung. Nach echten Jobs
zuerst Aufträge/Audit/Clientjournal über bestehende Recoverywege abgleichen;
keine SQL-Bypässe und kein Löschen offener Journale. Server hält Katalogbytes im
Speicher; Entzug erfordert kontrollierten Neustart.

Erster echter geplanter Auftrag bleibt getrennt: neu veröffentlichtes und
freigegebenes Stable-Release **>1.13.0**, signierte lokale Installations-/Health-
Fehler-/Rollbackprobe, frische Vorprüfung/Rückwege und aktuelles Wartungsfenster.
MOBILE01 bleibt ausgeschlossen. AD-Schreibfunktionen und UX-Folgearbeit wurden
in dieser Wartung nicht begonnen.
