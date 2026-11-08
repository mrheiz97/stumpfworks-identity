# Installation für einen festen Samba-DC

Der Fixed-DC-Build erzeugt ein eigenes Samba-LDB-Modul für die ABI des
Zielsystems. Es akzeptiert ausschließlich Create-Aufträge über SWNEW002.
Der bisherige Laborpfad bleibt separat.

## Build und Installation

Auf einem Buildsystem mit denselben Samba-, LDB- und TDB-Paketen wie der DC
das geprüfte Pin-Manifest als JSON vorbereiten. Die Felder sind verpflichtend.

| Gruppe | Felder |
| --- | --- |
| Pfade | `NATIVE_DB` für die exakte sam.ldb, `NATIVE_DIR` für DC-Schlüssel und Journal, `CREATE_AUTHORITY` für den lokalen Fence |
| DNs | `BASE`, `MANAGED_OU`, `WRITER_DN`, `ACTOR_DN`, `GROUP_DN` |
| Roh-GUIDs | `DOMAIN_GUID`, `DC_GUID` (Invocation ID), `GROUP_GUID`, `WRITER_GUID`, `ACTOR_GUID`, `CREATE_OU_GUID`, `TARGET_GUID` |
| Binäre SIDs als Hex | `DOMAIN_SID`, `WRITER_SID`, `ACTOR_SID`, `TARGET_SID` |
| Schlüssel und Policy | `PUBLIC_KEY` und `RECEIPT_PUBLIC_KEY` als rohe Ed25519-Public-Keys, `SCOPE_HASH` als 32 rohe Bytes in Hex, `REVISION`, `UPN_SUFFIX` |

GUIDs sind die rohen 16 LDAP-Bytes als kleingeschriebenes Hex. Das Zielpaar
`TARGET_GUID` und `TARGET_SID` bezeichnet das gepinnte Schutzobjekt in der
Ziel-OU. Der Receipt-Scope ist ein gemeinsamer statischer Pin von Modul und
Executor. Der Policy-Hash bindet Revision und UPN-Suffix.

```sh
python3 scripts/ad-profile-lab/build_fixed_create_module.py pins.json ./identity_fixed_create.so
```

Mit `--install-dir /absoluter/samba/ldb/modulpfad` kann der Build die Datei
exklusiv in das explizite, root-eigene Modulverzeichnis kopieren. Der Pfad
muss zur Samba-Paketinstallation passen. Der Installer überschreibt keine
Moduldatei und verändert weder die DSDB noch den Samba-Dienst.

## Getrennte Aktivierung

Nach Offline-Backup den Samba-Dienst stoppen. Das Modul muss im lokalen
`@MODULES`-Stack vor `samba_dsdb` eingebunden werden. Den vorhandenen Stack
und seine Reihenfolge vorher sichern. Die Moduldatei allein aktiviert
den Stack-Eintrag nicht. Die [Freigabecheckliste](ad-user-create-fixed-dc-readiness.md)
gilt insbesondere für die OU-ACL und die exklusive UPN-Vergabe über alle
anderen Schreibwege und DCs.

`NATIVE_DIR` und `CREATE_AUTHORITY` brauchen Modus 0700 und Root-Eigentum
auf einem lokalen Dateisystem. Im ersten Verzeichnis liegen `receipt.pem`
und das explizit initialisierte TDB-Journal `journal.tdb` mit Modus 0600.
Im zweiten liegen die dauerhafte Datei `lock` und `route`, ebenfalls mit
Modus 0600. `route` enthält acht Bytes Epoche in Big Endian und die 16
rohen Bytes der Invocation ID. Die Schreibfreigabe verlangt außerdem
eine leere, root-eigene Datei `enabled` mit Modus 0600. Den Marker erst
nach Abnahme unter demselben Fence setzen. Journal und Claims bleiben
bei einer Deaktivierung erhalten.

Auf der Executor-Seite `Pins.FixedUPNSuffix` und eine positive
`Pins.Epoch` explizit setzen. Die URL ist ein fester kanonischer
`ldaps://fqdn:636`-Endpunkt. CA, Domain, Invocation ID, OU, Writer und
Receipt-Schlüssel werden vor dem Socketstart geprüft. Die statische Unit
`sw-badge-ad-create-fixed.service` läuft als `swbadge-create` und verlangt
einen eigenen root-verwalteten Aktivierungsmarker. Der Installer setzt
keinen der Marker. Bei DC-Ausfall pausiert die Vergabe.

## Ein gezielter systemd-Test

Eine Debian-VM oder ein unprivilegierter Proxmox-LXC ohne Netzschnittstelle,
Autostart, Host-Bindmounts und Produktionsdaten genügt. systemd muss PID 1
sein. Für den Test einen synthetischen Samba-DC lokal auf Loopback
bereitstellen und die benötigten Pakete offline einspielen. Ein administrativer
Konsolenzugang über `pct exec <ID> -- …` genügt. Ein SSH-Dienst im Gast ist
entbehrlich.

Der Runner erwartet einen frischen Gast und ein für dessen Architektur
gebautes Linux-Binary. Er provisioniert synthetische Konten, baut und
installiert das Modul gegen die Gast-ABI und startet die statische Unit.

```sh
sudo env IDENTITY_CREATE_SYSTEMD_VM=1 python3 -B scripts/ad-profile-lab/run_fixed_systemd_fixture.py /pfad/create-executor
```

Den Zustand ohne Marker prüfen. Danach den synthetischen DC mit den
geprüften Pins starten, den Executor explizit freigeben und die
[systemd-Gegenprobe](../scripts/ad-profile-lab/verify_create_systemd.py)
ausführen. Sie prüft den tatsächlichen systemd-Hauptprozess unter eigener
UID/GID und den Socket nach dem signierten Readiness-Check. Für den
Rückweg beide Aktivierungen entziehen, Executor stoppen und Journal sowie
Claims erhalten. Die Profil-CAS-Sperre bleibt aktiv.

Der Test lief am 6. November 2026 im unprivilegierten, netzlosen Proxmox-LXC
100 `identity-create-lab` mit Debian 13, Samba 4.22.11 und systemd 257
als PID 1. Die Unit blieb ohne Marker inaktiv. Nach der Freigabe prüfte
der Runner den aktiven Hauptprozess unter `swbadge-create` und den
Socket nach authentifiziertem LDAPS-Readiness. Nach dem Stop blieb das
Journal erhalten. Dieser Nachweis umfasst den Dienststart in einer
synthetischen Domäne. Die Abnahme von ACLs und UPN-Vergabe in der
vorgesehenen Umgebung bleibt gesondert.
