# Create-Journal aufbewahren, sichern und wiederherstellen

Stand 5. November 2026 auf `development`. Die Befehle gehören zum standardmäßig deaktivierten [Linux-Executor für die Samba-Fixture](ad-user-create-native-executor.md).

## Aufbewahrung

Der aktive Executor prüft beim Start und danach jede Minute das Journal. Bei einer laufenden Aktion versucht er die Prüfung beim nächsten Takt erneut. Ein anderer Wartungsfehler beendet den Dienst. Die Änderungen einschließlich Audit erfolgen gemeinsam in einer SQLite-Transaktion.

| Vorgang | Behandlung |
| --- | --- |
| Abgelaufener Plan in `prepared` | Wechsel auf `expired` und Freigabe seiner Namensreservierungen. |
| `succeeded`, `cancelled`, `expired` | Sieben Tage nach dem passenden terminalen Audit-Ereignis werden Plan, Ergebnis und Dispatchdaten entfernt. Auftrags-ID, Actor und Status bleiben abfragbar. Erfolgreiche Namensreservierungen bleiben als HMAC erhalten. |
| `applying`, `uncertain` | Journal, Dispatch, Audit und Namensreservierungen bleiben vollständig erhalten. |
| Audit | Ereignisse zu bereits gekürzten terminalen Vorgängen und Einträge ohne Auftrags-ID werden nach 90 Tagen entfernt. |

SQLite verwendet `secure_delete=ON`. Die Fristen betreffen das aktive Journal. Externe Archive, Datenträgerkopien und ältere Snapshots haben ihren eigenen Löschzyklus. Die Aufbewahrung garantiert keine physische Löschung auf dem Datenträger.

## Offline sichern

Den Executor geordnet stoppen. Das Archivziel liegt in einem separaten vorhandenen privaten Verzeichnis mit Modus `0700`, das der Executor-UID gehört. Dateiname und Zustandsverzeichnis werden absolut angegeben.

```sh
create-executor -state /path/to/private-state -backup-journal /path/to/private-archives/create.backup
```

Der Befehl nimmt dieselbe exklusive Journalsperre wie der Executor. Er prüft Schema, Schlüssel-/Konfigurationsbindung und SQLite-Integrität und erstellt mit `VACUUM INTO` eine konsistente Momentaufnahme. Das Format `SWCRBAK1` verschlüsselt und authentifiziert die gesamte Kopie mit AES-GCM und einem vom Journalschlüssel und der Adapterbindung abgeleiteten Schlüssel. Die SQLite-Kopie ist auf 64 MiB begrenzt. Das Archiv erhält Modus `0600`, wird synchronisiert und ohne Überschreiben veröffentlicht. Für die Erstellung entsteht vorübergehend eine SQLite-Datei im privaten Zustandsverzeichnis. Nach einem abrupten Prozessabbruch können private `.snapshot-*`- oder `.archive-*`-Dateien zurückbleiben.

Das Archiv getrennt vom Journalschlüssel ablegen. Zur Wiederherstellung werden der ursprüngliche `journal.key` und dieselbe statische `Directory`-, `Pins`- und `OU`-Konfiguration benötigt. Für spätere Status- und Belegabfragen sind auch die zum Backend passenden CA-, Writer- und Issuer-Dateien erforderlich. Ein Archiv enthält weder diese Dateien noch die Samba-Datenbank oder das native Claimjournal.

## In ein frisches Zustandsverzeichnis wiederherstellen

Das Zielverzeichnis mit Modus `0700`, der passenden `config.json` und dem ursprünglichen `journal.key` vorbereiten. `journal.db` und seine Begleitdateien dürfen dort noch nicht existieren. Den neuen Socket im `Transport`-Abschnitt separat pinnen.

```sh
create-executor -state /path/to/recovery-state -restore-journal /path/to/private-archives/create.backup
create-executor -state /path/to/recovery-state -enable
```

Restore authentifiziert das Archiv vor der Veröffentlichung und prüft Schema, Journalbindung und SQLite-Integrität. Die temporäre `.restore-*`-Datei bleibt im privaten Zielverzeichnis. Vor der atomaren Veröffentlichung schreibt der Restore eine eigene HMAC-Bindung für den Wiederherstellungsmodus zusammen mit dem SQLite-Versionsmarker. Der Executor öffnet das restaurierte Journal lesend. Status, Audit und Belegabfrage stehen nach der üblichen Authentifizierung zur Verfügung. Planung, Bestätigung, Abbruch und Wartung sind gesperrt. Auch ein im Archiv noch vorhandener Plan darf dadurch keinen Schreibvorgang auslösen.

Ein Snapshot enthält möglicherweise keine späteren Claims oder Verzeichnisänderungen. Für die wiederhergestellte Kopie gibt es daher keinen automatischen Rückweg in den Schreibbetrieb. Das ursprüngliche Journal und das native Claimjournal bleiben für die weitere Klärung maßgeblich.

## Labornachweis und Rückweg

Der [bestehende netzlose Prozess-Labortest](ad-user-create-native-executor.md#labortest-und-rückweg) prüft den Backup-Fence bei laufendem Executor, unveränderte vorhandene Ziele, manipulierte Archive, falsche Schlüssel, Status und Beleg nach Restore, abgewiesene Schreibaktionen sowie den zurückgesetzten Versionsmarker. Die restaurierte SQLite-Datei bleibt während der Abfragen bytegleich. Go-Tests prüfen die transaktionale Ablaufbereinigung, die Löschfristen und die Erhaltung offener Claims.

Für den Rückweg den Recovery-Executor stoppen und die ursprüngliche, unveränderte Journalinstanz behalten. Die Codebasis vor dieser Änderung ist `df3e764`. Bereits entfernte Detaildaten werden durch einen Code-Rückweg nicht wiederhergestellt. Produktive Restore- und Mehr-DC-Freigaben gehören in einen separaten Betriebsnachweis.
