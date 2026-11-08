# Installation des festen Create-Executors

Der Linux-Installer legt das Executor-Binary und eine statische systemd-Unit
ab. Die Installation erstellt weder einen Aktivierungsmarker noch ein Journal
und startet keinen Dienst. Das Web-Feature bleibt standardmäßig deaktiviert.

```sh
CGO_ENABLED=0 go build -o ./create-executor ./cmd/ad-create-executor
sudo sh scripts/install-ad-create-executor.sh ./create-executor
```

`DESTDIR` erlaubt die Installation in ein vorhandenes Staging-Verzeichnis.
Die Unit heißt `sw-badge-ad-create-executor.service`. Nach einer manuellen
Installation kann systemd die Unit mit `daemon-reload` einlesen.

## Isolierte Bereitstellung

- Eine dedizierte UID und Primärgruppe `swbadge-create` bereitstellen. Das
  private Zustandsverzeichnis `/var/lib/stumpfworks-badge-create` gehört dieser
  UID und hat Modus 0700. Konfiguration und Schlüssel werden entsprechend
  dem [Executor-Handbuch](ad-user-create-native-executor.md) provisioniert.
  Das Journal wird einmalig offline unter derselben UID initialisiert.
- Den separaten Socket-Parent `/run/stumpfworks-badge-create` mit Modus 0750
  und Executor-UID/Socket-GID bereitstellen. Der Webprozess benötigt
  Gruppenzugriff auf den Socket. Die Primär-GID und UID der beiden Prozesse
  bleiben explizit gepinnt. Der Webprozess erhält keinen Zugriff auf den
  privaten Zustand. Der konfigurierte Socket liegt in diesem Socket-Parent.
- Die Unit verlangt den bereits eingerichteten isolierten Namespace
  `/run/netns/swbadge-create` und einen expliziten Aktivierungsmarker unter
  `/etc/stumpfworks-badge/ad-create.enabled`. Der feste DC muss innerhalb
  dieses Namespace über den geprüften LDAPS-Namen erreichbar sein. Die
  vorhandene Loopback- und Fixture-Prüfung begrenzt diese Unit auf den
  synthetischen Samba-Schreibpfad. Der reguläre feste DC hat einen
  [eigenen Build und eine eigene Unit](ad-user-create-fixed-installation.md).

## Natives Modul in der Fixture

Der Fixture-Build erstellt ein LDB-Modul mit den statischen Pins des festen
DCs. `install_native_create.py` kopiert die ABI-gebundene Datei exklusiv
als reguläre Datei in das Samba-Modulverzeichnis. Die Dateikopie ändert
`@MODULES` nicht. Erst der explizite Fixture-Setup-Schritt aktiviert den
Eintrag im synthetischen DSDB-Stack. Bestehende Module werden nicht ersetzt.

Der gezielte Starttest verwendet `IDENTITY_TEST_CREATE_SERVICE_UID=1`
zusätzlich zu den bestehenden Create-Laborflags. Er verwendet das installierte
Executor-Binary unter einer eigenen UID/GID, prüft Default-off, die signierte
Readiness des installierten Moduls, den Socket-Eigentümer und das erhaltene
Journal nach SIGTERM. Das Laborimage enthält keinen systemd-Manager. Der
systemd-Start mit Namespace und Dienst-Härtung bleibt separat nachzuweisen.

Für diese Abnahme in einer entkoppelten VM mit systemd als PID 1 den
synthetischen DC und den Executor-Namespace bereitstellen. Im Executor
den Socket `/run/stumpfworks-badge-create/executor.sock` konfigurieren.
Zuerst ohne Marker prüfen, dass die Unit inaktiv bleibt. Danach nur in der
Fixture den Marker setzen und den Dienst explizit starten. Die lesende
Gegenprobe prüft systemd-MainPID, reale UID/GID und den Socket.

```sh
sudo env IDENTITY_CREATE_SYSTEMD_VM=1 python3 -B scripts/ad-profile-lab/verify_create_systemd.py
```

Der [reguläre Build](ad-user-create-fixed-installation.md) verwendet dafür
explizite Installationspins für ABI, Datenbank, Invocation ID und
LDAPS-Vertrauen.

## Abschalten und Nachweis

Web-Create deaktivieren, Aktivierungsmarker entfernen und die Unit stoppen.
Die Unit lässt dem Executor Zeit für laufende Requests. Journal, Schlüssel
und Claims verbleiben im privaten Zustand. Bei einem verbliebenen Unix-Socket
den dokumentierten [Socket-Rückweg](ad-user-create-native-executor.md)
verwenden.

Die gezielte Integration installiert das Binary im netzlosen Samba-Container.
Sie verwendet das installierte Binary für den Default-off-Start, die
Benutzeranlage mit Audit und das Abschalten mit erhaltenem Journal. Der
Container startet das Binary direkt. Der systemd-Dienststart unter eigener
Dienst-UID ist eine separate Abnahme. Die CAS-Sperre gilt weiter.
