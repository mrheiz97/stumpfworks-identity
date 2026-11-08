# Benutzeranlage: abgesicherter lokaler Executortransport

Der [native Linux-Executor für die Samba-Fixture](ad-user-create-native-executor.md) ergänzt den Transport um den standardmäßig deaktivierten Prozessstart und ein privat gebundenes Journal.

Stand: 4. November 2026, development. Standardmäßig deaktiviert, CAS-Sperre
unverändert. Keine Produktivkontakte/-änderungen, GitHub-Läufe oder MOBILE01.

## Umgesetzter Weg

`internal/adcreateipc` verbindet die vorhandene `adcreate.Operations`-Schnittstelle
mit einem separaten Linux-Executor über einen Unix-Socket. Der Client hält keine
AD-Writer-Credentials, Signierkeys oder Journaldaten. Er überträgt ausschließlich
typisierte Benutzeraktionen und die aktuelle Actor-Anmeldung. Keine TCP-Option,
Proxy-/Redirect-Verfolgung oder automatische Wiederholung.

Der Receiver benötigt explizit ein aktiviertes Backend mit `PrepareWithID`,
prüft vor jedem Request den kernelbestätigten Peer und delegiert dann an den
vorhandenen Service. Websession, separate Permission, frische AD-Anmeldung,
dauerhafter Claim und native DSDB-Policy bleiben zusätzliche Grenzen.
Der Transport ersetzt keine davon und verändert kein natives Protokoll.

Der Serverstart kann den Client nur bei **ausdrücklicher** Aktivierung anschließen.
Default ist aus: keine Socketverbindung, kein Menü, kein Executorstart. Der
Receiver ist eine getestete `Listen/Serve/Close`-Komponente; kein produktiver
AD-Createadapter, installierter Daemon oder Systemd-Dienst wird mitgeliefert.
Die native Anbindung existiert weiterhin ausschließlich im isolierten Labor.

## Peer- und Dateigrenze

- Beide Seiten pinnen UID **und primäre GID** über Linux `SO_PEERCRED`, bevor
  der Client Actor-Credentials sendet oder der Receiver HTTP akzeptiert.
  Eigene Executor-/Web-UIDs müssen verschieden sein; keine Root-/Headerfallbacks.
  Alle Prozesse unter einer gepinnten UID gehören zur jeweiligen Vertrauensgrenze.
- Absoluter kanonischer Socketpfad, maximal100 Bytes. Alle Eltern werden mit
  `openat/O_NOFOLLOW` geprüft: Root/Executor als Eigentümer, keine fremden
  Schreibrechte. Ausnahme nur für root-owned sticky `/tmp` als Vorfahr, niemals
  als direktes Socketverzeichnis. Direktes Verzeichnis gehört Executor/Socketgruppe,
  ohne Gruppen-Schreibrecht oder Rechte für Andere (typisch0750).
- Socket muss Executor-UID/Socket-GID und Modus0660 besitzen. Client prüft Typ,
  Eigentümer, Rechte und Inode vor/nach Connect zusätzlich zum tatsächlichen Peer.
  Der Webprozess benötigt nur Traverse/Read auf dem Verzeichnis und Socketzugang.
- Privater `.lock`-FD: 0600, Executor-Eigentümer, genau ein Hardlink, kein Symlink,
  exklusiver nichtblockierender `flock`. Zweite Listener und vorhandene Endpunkte
  werden abgewiesen. Kein implizites Löschen alter oder ersetzter Sockets, auch
  nicht beim Schließen. Dieser Fence schützt den Endpunkt, nicht das Journal.
- Maximal acht zugelassene Verbindungen, kein Keepalive; Header-/Read-/Write-
  Grenzen und kurze Kontextfristen. Nicht-Linux verweigert aktivierten Transport.

## Geschlossenes Protokoll und Fehler

Nur `POST http://executor/v1/create` über den gepinnten Unix-Socket, JSON-Version1.
Erlaubt sind `prepare`, `confirm`, `status`, `evidence`, `cancel`, `history`.
Keine freien DNs/Attribute, Wirepayloads, Initialisierung, Reconciliation,
Passwörter des neuen Kontos, Gruppen, Aktivierung oder Löschung.

Requests maximal8KiB, Responses64KiB; feste Header-/Form, keine Request-Kompression
oder Chunked-Requests. Decoder verweigert unbekannte Felder, doppelte Schlüssel
einschließlich Case-Aliasen, überschüssiges JSON und zu tiefe Verschachtelung.
Antworten werden auf Version, Zustand, Größe und Auftragskorrelation geprüft.
Backendfehler werden ausschließlich als `denied`/`uncertain` ausgegeben, nie als
freie LDAP-/DB-/Go-Fehlertexte. Actor-Passwort nur transient im lokalen Request,
niemals in URL, Argumenten, Umgebung, Journal oder Logs.

Der Client erzeugt eine zufällige ID **vor** dem Planversand. `PrepareWithID`
speichert genau diese ID; widersprechende/erneute IDs werden nicht adoptiert.
Bei verlorener Planantwort zeigt der Client die bekannte ID als unklar an:
erst Status abfragen, kein automatisches Neuplanen. Bestätigung benötigt weiterhin
den gespeicherten Plandigest und erneute Anmeldung. Ein verlorener Apply-Reply
hebt keine persistente Sperre auf; Receiptbeobachtung entsperrt weiterhin nichts.

## Explizite Clientkonfiguration

```yaml
ad_user_creation:
  enabled: false
  socket: ""
  executor_uid: ""
  executor_gid: ""
  socket_gid: ""
```

Environment: `SWBADGE_AD_USER_CREATION_ENABLED`, `_SOCKET`, `_EXECUTOR_UID`,
`_EXECUTOR_GID`, `_SOCKET_GID` (jeweils derselbe Präfix). Alle Pins müssen bei
Aktivierung explizite kanonische uint32-Werte sein, auch eine beabsichtigte0.
Executor-GID ist die primäre Prozess-GID; Socket-GID ist die gemeinsame
Dateizugriffsgruppe. Peer-UID und Socket-Eigentümer-UID sind identisch.

Aktivierung verlangt zusätzlich geschützten AD-Betrieb ohne Demo, HTTPS und die
getrennte gepinnte Creator-Rolle aus der [Sessionintegration](ad-user-create-sessions.md).
Ein Read-Overlay reicht diese strikte AD-Sessionfähigkeit nur dann weiter, wenn
sein tatsächlicher Basisadapter sie explizit bestätigt; Local gewinnt nichts.
Der Client erzeugt weder Verzeichnisse noch Sockets und installiert keinen Receiver.
Die Konfiguration wurde auf keinem Produktivsystem gesetzt.

## Lokale Nachweise und Reproduktion

- Protokolltests: Defaults, Peercontext-/Headerspoofing, unbekannte Aktion/Version,
  Duplikate/Case-Aliase, Payload-/Antwortgrenzen, Fehlerredaktion.
- Linux-Prozessproben: Root-Fixture-Receiver und tatsächlicher UID/GID65534-Client,
  falsche Peers in beiden Richtungen, Antwortverlust nach Dispatch (genau ein
  Aufruf), Redirect/beschädigte/zu große Antwort, Socketrechte/Links/Fences.
- Echtes Samba-Labor: UID65534-Prozess → IPC → Service/AES-GCM-Journal → signierter
  nativer Add → deaktiviertes Konto/Receipt/Audit; wiederholte Bestätigung abgewiesen.
  Der Web-UID kann Schlüssel, Journale und DC-Konfiguration nicht lesen.
  Nur Actor-Credentials werden im anonymen Stdin-Pipe der Testfixture übergeben.
  Das gemeinsame zufällige Fixturepasswort ist weiterhin **kein** produktiver
  Credentialtrennungsnachweis.

Linux-Testbinaries mit `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c` aus
`./internal/adcreateipc` beziehungsweise `./internal/adprofile` nach
`dist/ad-profile-tests/adcreateipc.test`/`adprofile.test` bauen. Transporttests im
netzlosen Root-Wegwerfcontainer ausführen; Nicht-Root-Läufe überspringen die
expliziten UID-Wechselproben. Den vollständigen Createfall wie im
[Create-Labor](ad-user-create-lab.md) mit zwei RO-Mounts, ohne Ports und mit
Protokoll2/Create-Flag ausführen. Der Createfall enthält die neue Transportprobe.

## Rückweg und Betriebsgrenze

Lokale Abnahme bestanden: vollständige Go/OpenSSL-Suite `./...`, Vet, Modul- und
Whitespaceprüfung; Linux-Kernel-/Datei-/Prozessproben inklusive zehn Peer-/
Antwortverlustfällen; echter separater Web-UID bis zum nativen Samba-Create,
Audit/Receipt/Neustartbindung und sieben native Create-Verträge. Native C,
CAS-Gate, Framework, Abhängigkeiten und CI unverändert. Keine neue PG-/Mehr-DC-/
DC-Crash- oder Remote-CI-Abnahme für diesen Transportumfang behauptet.

`enabled: false` und Neustart des Webprozesses entfernt den Clientanschluss.
Receiver geordnet stoppen; Claims/Journale und unbekannte Ergebnisse erhalten.
Einen verbliebenen Socket erst nach unabhängiger Prozess-/UID-/Inodeprüfung im
separat freigegebenen Betriebsverfahren entfernen, niemals per blindem Unlink
oder Journalreset. Entwicklungsrückweg: Ausgangscommit `6281d91` und frische Fixture.

Offen vor Betrieb: produktiver nativer Adapter/Executor-Start, private Journal-
Dateien/Prozessfencing/Retention/Backup, unabhängiger Review, Schlüssel-/Actorbetrieb,
Last/Mehr-DC/Forest-UPN/Restore. Root beziehungsweise kompromittierte gepinnte UIDs
sind Teil der Host-TCB. Kein produktionsfähiger Gesamtdienst oder CAS-Entsperrung
wird allein aus diesem Transportnachweis abgeleitet.
