# Nativer Create-Adapter und Executor-Start

Aufbewahrung, Offline-Backup und lesender Restore sind im [Journal-Handbuch](ad-user-create-journal.md) beschrieben.

Stand 5. November 2026 auf `development`. Der Startpfad ist standardmäßig deaktiviert und für die synthetische Samba-Fixture ausgelegt. Der ausführbare Linux-Executor liegt unter `cmd/ad-create-executor`.

## Start und Journal

Ein Aufruf ohne `-enable` oder `-initialize-journal` beendet sich erfolgreich im deaktivierten Zustand. `-state` benennt ein vorhandenes privates Verzeichnis mit Modus `0700`, das der Executor-UID gehört. Die beiden Betriebsmodi sind gegenseitig ausgeschlossen.

Das Zustandsverzeichnis enthält `config.json`, `journal.key`, `issuer.pem`, `writer.password` und `ca.pem`. Alle Dateien gehören der Executor-UID und haben Modus `0600`. Der Journalschlüssel besteht aus 32 Rohbytes. Der Signierschlüssel ist ein Ed25519-Privatschlüssel im PKCS#8-PEM-Format. Verzeichnis- und Dateiprüfungen weisen Symlinks, unsichere Eigentümer oder Rechte und mehrfach verlinkte private Dateien ab.

`config.json` enthält `Directory` mit den LDAP-, Domain-, Invocation-, OU-, Writer- und Gruppenwerten der Fixture, `Pins` mit `ActorGUID`, `ActorSID`, `WriterGUID`, `ReceiptPublic` und `Scope`, `OU` mit der rohen OU-GUID als Hexstring und `Transport` mit den expliziten Unix-Peer- und Socketpins. `Directory.Enabled` und `Transport.Enabled` müssen gesetzt sein. Die Dateien `writer.password` und `ca.pem` werden relativ zum geprüften Zustandsverzeichnis verwendet. Die Socketgruppe erhält nur Zugriff auf das separate Socketverzeichnis.

```sh
create-executor -state /path/to/private-state -initialize-journal
create-executor -state /path/to/private-state -enable
```

Die Initialisierung legt `journal.db` exklusiv an und schreibt das Schema und die Schlüssel-/Konfigurationsbindung in einer Transaktion. Sie liest dazu `config.json` und `journal.key` lokal. Der aktive Start öffnet ausschließlich ein vorhandenes Journal. Ein exklusiver `journal.lock` gilt unabhängig vom Socketpfad. Der Start prüft das erwartete Schema einschließlich Dispatch-Index und einen HMAC über die statische Adapterkonfiguration. Ein anderer Journalschlüssel oder eine andere Adapterkonfiguration wird abgewiesen. Socketpins können für den Neustart geändert werden, ohne die Journalbindung zu verändern.

## Freigabe des Sockets

Der aktive Prozess verlangt einen Netzwerk-Namespace mit genau einer Loopback-Schnittstelle. Der Adapter bindet LDAPS mit CA- und Namensprüfung an `dc1.profile.test` und `DC=profile,DC=test`. Er prüft Domain-GUID und SID, DC-Invocation-ID sowie OU- und Writer-GUID. Eine authentifizierte Statusabfrage mit zufälliger Auftrags-ID und Nonce muss einen frischen `SWCRECP1`-Beleg vom separat gepinnten Receipt-Schlüssel liefern. Der leere Zustand dieses Belegs dient ausschließlich dem Protokollnachweis. Erst danach öffnet der Receiver den Unix-Socket.

Der Adapter verwendet im bisherigen Einzel-DC-Labor `SWNEW001`. Ein expliziter positiver `Pins.Epoch`-Wert wählt `SWNEW002` für das [Zwei-DC-Labor](ad-user-create-native-handoff.md). Die Epoche ist Teil des verschlüsselten Plans und des signierten Auftrags. Vorschau, Namensreservierung und LDAP-Readback verwenden dann den festen Suffix `managed.profile.test`. Der Adapter prüft die signierte `SWCRECP2`-Antwort auf seine `SWCSTAT2`-Anfrage. Der Digest umfasst den Auftragskörper einschließlich Epoche. Die alte Version bleibt auf das bisherige Labor beschränkt und es gibt keinen automatischen Downgrade.

Das Executor-Journal bleibt an seine aktive Konfiguration einschließlich DC, Schlüsselpins und Epoche gebunden. Die [Offline-Übergabe](ad-user-create-journal-handoff.md) bindet das bestehende Journal im Zwei-DC-Labor nach dem nativen Wechsel an die höhere Epoche. Der Befehl bewahrt Claims und sperrt die Übergabe bei unklaren Dispatches.

Frische Actor-Anmeldung, Rollenprüfung, persistente Dispatch-Bindung und Behandlung unklarer Ergebnisse gelten weiter. Das Readiness-Receipt prüft Protokoll und Schlüssel. Die Schreibfreigabe der konkreten Epoche entscheidet der native Fence bei jedem Add. Der Profilpfad behält die RFC4528-Prüfung seiner CAS-Sperre.

## Labortest und Rückweg

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/ad-profile-tests/create-executor ./cmd/ad-create-executor
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o dist/ad-profile-tests/adprofile.test ./internal/adprofile
```

Im bestehenden `identity-ad-profile-lab:native`-Container mit `--rm --network none --hostname dc1`, den beiden schreibgeschützten Skript- und Testbinary-Mounts sowie `IDENTITY_NATIVE_PROTOCOL=2` und `IDENTITY_NATIVE_CREATE_LAB=1` provisionieren und `native_run.sh` ausführen. Die Suite startet den separaten Executor und ruft ihn aus einem Prozess unter UID/GID 65534 auf. Sie prüft Default-off, fehlendes Journal, exklusive Offline-Initialisierung, falsche Journal- und Signierschlüssel, die Sperre gegen einen zweiten Executor mit anderem Socket sowie die Anlage und den Beleg nach Neustart.

SIGTERM und SIGINT stoppen die Annahme neuer Requests und lassen aktive Handler bis zu 25 Sekunden auslaufen. Für den Rückweg den Webtransport deaktivieren, den Executor stoppen und das Journal mit seinen Claims erhalten. Einen verbliebenen Socket erst nach Prozess-, Eigentümer- und Inodeprüfung entfernen. Der Code-Rückweg ist `37b17f1`. Der Betriebsnachweis für andere Domains und Hostkonfigurationen bleibt ein separater Schritt.
