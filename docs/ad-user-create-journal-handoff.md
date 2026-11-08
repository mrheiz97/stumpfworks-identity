# Offline-Übergabe eines bestehenden Create-Journals

Der Befehl `create-executor -state /pfad/zum/privaten-zustand -handoff-journal`
gilt für das isolierte SWNEW002-Zwei-DC-Labor. Er startet keinen Listener.
Das bisherige Journal und sein Schlüssel bleiben am selben Ort. Der Executor
bleibt standardmäßig deaktiviert und der Profil-CAS-Pfad bleibt gesperrt.

## Übergabe

1. Web-Create sperren, Executor stoppen und ein verschlüsseltes Offline-Backup
   mit der bisherigen Konfiguration prüfen. Die alte Konfiguration und den
   zugehörigen Issuer für die Wiederherstellung aufbewahren.
2. Native Route einfrieren und die [Receipt- und DRS-Prüfung](ad-user-create-native-handoff.md)
   abschließen. Ein Journal in `applying` oder `uncertain` blockiert die
   Übergabe. Der alte Journalstand bleibt in diesem Fall vollständig erhalten.
   Ein replizierter Treffer ersetzt keinen bestätigten Auftragsabschluss.
3. Im selben privaten Zustandsverzeichnis `next-config.json` und
   `next-issuer.pem` mit Modus 0600 bereitstellen. Die Policy und der
   Namensraum bleiben gleich. Die neue Konfiguration enthält den anderen
   Labor-DC, dessen Receipt-Pins und eine höhere Epoche. Nach der nativen
   Freigabe den Offline-Befehl ausführen. Er prüft beide Konfigurationsbindungen,
   hält die Executor- und native Fence-Sperre und verifiziert ein signiertes
   Status-Receipt des Ziel-DCs.
4. Die Transaktion storniert ungesendete Pläne und protokolliert
   `handoff_cancelled` sowie `handoff_rebound`. Alle Namensclaims, IDs und
   verschlüsselten Aufträge bleiben erhalten. Ältere Terminalaufträge bleiben
   für ihren Actor einsehbar. Für sie ist kein neuer Versand und kein
   Receipt-Abruf über die neue Route möglich.
5. Erst nach erfolgreicher Umbindung die geprüften Staging-Dateien als
   `config.json` und `issuer.pem` installieren. Beide Dateien bleiben
   privat. Ein Start mit der alten Konfiguration scheitert an der
   Journalbindung. Ein Abbruch zwischen Commit und Dateiinstallation lässt
   den Executor aus. In diesem Fall die geprüften Dateien zu Ende installieren.

## Rückweg

Vor der Umbindung bleibt das Journal an den alten DC gebunden. Eine bereits
umgeschaltete native Route muss auch dann kontrolliert behandelt werden.
Nach der Umbindung erfolgt die Rückkehr als weitere geplante Übergabe mit
höherer Epoche, erneuter Fence- und DRS-Prüfung und demselben Journal.
Das Backup ist eine Quelle für die lesende Wiederherstellung. Es darf
keinen alten aktiven Namens- oder Dispatch-Stand wieder einführen.

## Labornachweis

Der netzlose Zwei-DC-Runner verwendet den echten Executor-Befehl. Ein auf
DC1 vorbereiteter Plan wird auf DC2 als storniert gelesen. Bestätigung und
Wiedervergabe des reservierten Namens scheitern. Ein neuer Name kann über
dasselbe Journal als deaktiviertes Konto angelegt werden. Ein synthetisch
gesetzter unklarer Dispatch dient als Gegenprobe für die Übergabesperre.

Am 6. November 2026 wurde der vollständige Rückwechsel mit zwei Samba-DCs
auf einem Laborhost geprüft. DC2 legte in Epoche 2 über das übergebene
Identity-Journal ein deaktiviertes Konto an. Der Runner fror die Route ein,
replizierte die Domänenpartition per DRS von DC2 zurück nach DC1 und verglich
die replizierten Objekt-GUIDs mit den bestätigten Receipts. Die Freigabe
erfolgte erst nach Abgleich aller nativen UPN-Reservierungen der Fixture.

DC1 nahm in Epoche 3 das ursprüngliche Identity-Journal weiter in Betrieb.
Alle sechs Zuordnungen aus Namensclaim und Auftrags-ID blieben exakt erhalten.
Der bestätigte Auftrag blieb erfolgreich. Die beiden ungesendeten Pläne
blieben als storniert einsehbar. Beide DCs wiesen verspätete Aufträge aus
alten Epochen ab, und ein neuer Auftrag auf DC1 erzeugte ein deaktiviertes Konto.

Zur Wiederholung die [Zwei-DC-Identity-Laboranleitung](ad-user-create-native-handoff.md)
verwenden und dem Docker-Aufruf zusätzlich `-e IDENTITY_CREATE_RETURN_LAB=1`
übergeben. Der Rückwechsel prüft die gemeinsame lokale Fence-Autorität.
Ein Rückwechsel über getrennte Hosts und eine Wiederherstellung nach
Hostverlust sind gesonderte Betriebsnachweise.

## Ausfall- und Restore-Proben

- Der Linux-Testprozess wird vor und nach dem Commit der Umbindung mit
  SIGKILL beendet. Das erneute Öffnen prüft die alte beziehungsweise neue
  Bindung samt Planstatus, Audit und unverändertem Claim. Eine zusätzliche
  SQL-Gegenprobe erzwingt einen späten Schreibfehler.
- Der Samba-Runner prüft fehlgeschlagene Zielauthentifizierung sowie den
  Zeitraum nach Commit und vor Installation der neuen Konfiguration.
  Alte Konfiguration und alter Issuer öffnen das umgebundene Journal nicht.
  Der separate Identity-Lauf auf DC2 verwirft absichtlich die Antwort nach
  einem echten nativen Add. Der Auftrag bleibt nach dem Neustart unklar.
  Das lesbare Receipt erlaubt weder erneuten Versand noch Freigabe des Namens.
- Nach dem Rückwechsel erzeugt der Runner ein verschlüsseltes Archiv aus
  Epoche 3. Restore mit falscher Epoche und Restore über das aktive Journal
  scheitern. Ein frisches Recovery-Journal behält die exakten Claims. Ein
  separater Unix-Peer liest Status und signiertes Receipt, während neue
  Pläne und die erneute Umbindung gesperrt sind. Der lesende Zugriff ändert
  keine Journalbytes.

Die Prozessproben modellieren einen abrupten Prozessverlust. Stromausfall
und Wiederherstellung über getrennte Hosts bleiben gesonderte Nachweise.
Unter Linux lassen sich die Transaktionsproben mit
`go test ./cmd/ad-create-executor -run 'TestRebind'` wiederholen.
