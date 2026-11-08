# Benutzeranlage: Session- und Permissionintegration

Fortschreibung: [Abgesicherter Executortransport](ad-user-create-executor-transport.md)
ergänzt inzwischen den explizit deaktivierten Startup-Clientanschluss. Die frühere
Aussage „kein Transportanschluss im Serverstart“ ist dadurch überholt; kein
produktiver Receiver oder nativer Adapter ist installiert.

Stand: 4. November 2026, development. Standardmäßig deaktiviert; CAS-Sperre
unverändert. Keine Produktivkontakte/-änderungen, GitHub-Läufe oder MOBILE01.

## Integrierte Grenze

`GET/POST /ad-users/create` ist im Identity-Router registriert. Ohne Backend
liefert der Endpunkt 403 und erscheint nicht im Menü. Der ausgelieferte
Serverstart schließt **kein** Anlagebackend an und erzeugt weder Executor noch
Writer-Credentials. `ConfigureADUserCreation(Operations)` ist ausschließlich
eine explizite Startup-Anschlussstelle; sie aktiviert den Backend-Service nicht.
`nil` schaltet den Anschluss ab. Ein späterer Executortransport benötigt einen
gesonderten Auftrag; In-process-Schreibcredentials sind nicht erforderlich.

Der Endpunkt verwendet eine eigene Sessiongrenze, ohne den bisherigen
Notfall-/Legacy-Kompatibilitätsfallback. Er verlangt:

- geschützten Serverbetrieb und HTTPS;
- genau ein gültiges `swbadge_admin`-Cookie mit normaler Admin-Audience;
- keinen `swbadge_emergency_admin`-Cookie, auch nicht leer oder zusätzlich;
- einen expliziten AD-Sessionadapter mit strikten TLS-/Gruppen-Pins;
- frisch aufgelöste Permission `directory.users.create` pro Request.

Benutzername und CSRF stammen ausschließlich aus der verifizierten Sitzung.
Cookie-Rollen, OIDC-Claims, Formular-Benutzernamen und Request-Kontextrollen
vergeben keine Berechtigung. Lookupfehler und Rollenentzug lehnen geschlossen ab.
POST erhält zusätzlich die vorhandenen Origin-/Form-CSRF-/Größen-/Duplikat-
Prüfungen. Jeder Serviceaufruf verlangt weiterhin das aktuelle AD-Passwort;
Executor und nativer DC prüfen Actor und Rolle separat vor beziehungsweise in
der Transaktion. Eine langlebige Websitzung ersetzt diesen Step-up nicht.

## Getrennte Rolle und Konfiguration

Neue Rolle: `directory-user-creator`. Sie erhält ausschließlich
`directory.users.create` und Dashboardzugang. Die bisherigen Admin-, Operator-,
OIDC-, Client- und Auditorrollen erben Create nicht, auch nicht zusammen.
Explizite Kombination von Admin- und Creatorrolle ist möglich.

Optionale, standardmäßig leere Konfiguration:

```yaml
directory:
  user_creator_group_dn: ""
  user_creator_group_guid: ""
```

Environment: `SWBADGE_DIRECTORY_USER_CREATOR_GROUP_DN` und
`SWBADGE_DIRECTORY_USER_CREATOR_GROUP_GUID`. GUID ist genau die Hexkodierung der
16 rohen LDAP-`objectGUID`-Bytes, nicht eine umformatierte GUID-Zeichenkette.
Diese Optionen konfigurieren ausschließlich Rollenauflösung, keinen Schreibdienst.

Bei ausdrücklicher Konfiguration verlangt die Validierung LDAPS, eine CA-Datei,
DNS-/Kettenprüfung ohne Legacy-Zertifikat-Pin-Bypass, eine nichtnull Gruppen-GUID
und eine eigene Gruppe innerhalb der Base-DN. Identität mit vorhandenen
Rollengruppen wird anhand geparster DNs abgewiesen. Teilkonfiguration ist ungültig.

Die Rollenauflösung liest direkt die feste Gruppe (BaseSearch), prüft DN,
objectGUID und Sicherheitsgruppenbit sowie **direkte** `member`-Zugehörigkeit.
Keine rekursive Creator-Vererbung, Referral-Verfolgung oder Übernahme einer
gleichnamig neu angelegten Gruppe. Andere bestehende Rollen behalten ihr bisheriges
Verhalten; ohne neue Konfiguration entsteht keine zusätzliche LDAP-Abfrage.

## Tests, Nachweise und Rückweg

Server-Schutztests: Default-off, deaktiviertes Backend, erlaubte Sitzung,
fehlende/abgelaufene/manipulierte/falsche Audience, Notfall-/Misch-/Doppelcookies,
Lokalsitzung/Legacy-Adapter, HTTP, Origin, CSRF, Header-only-CSRF, doppelte/fremde/
übergroße Formularfelder und fehlgeschlagener Passwort-Step-up. Derselbe Cookie
verliert nach Rollenentzug sofort den Zugriff. Menü nur mit Backend und Permission.

Directory-/Config-/Permissiontests prüfen direkte gepinnte Sicherheitsgruppe,
Referrals, falsche GUID/DN/Gruppe, fehlende Mitgliedschaft und ungültige Transport-
oder Gruppenkonfiguration. Im netzlosen Samba-Labor werden der tatsächliche
`directory.LDAP.AuthenticateAdministrative`-Anmeldeweg, die neue Permission und
der Rollenentzug nach erfolgreicher AD-Anmeldung nachgewiesen; Rollenmitgliedschaft
wird restauriert. Bisheriger echter Create-/Receipt-/Journal-Neuöffnungsablauf
und sieben native Create-Verträge laufen unverändert mit.

Lokale Abnahme bestanden: vollständige Go/OpenSSL-Suite `./...`, Vet, Modul- und
Whitespaceprüfung, neue Session-/Permission-/Directory-/Config-Schutztests sowie
der erweiterte echte Samba-Anmelde-/Createfall einschließlich sieben nativer
Verträge. Native C/Protokoll, CAS-Gate, Framework, Abhängigkeiten und CI unverändert.
Keine neue PG-/Mehr-DC-/Crash- oder Remote-CI-Abnahme daraus ableiten.

Rückweg Entwicklung: Änderungen auf Ausgangscommit `431a7b3` zurücknehmen und
Testbinaries neu bauen. Anschluss per `ConfigureADUserCreation(nil)` deaktiviert
den Webweg beim nächsten Serverstart; Änderungen am Anschluss nur vor dem
Serving. Offene Claims und Journale bleiben erhalten. Neue Rollenkonfiguration
nur in getrennt freigegebenen Umgebungen entfernen, keine Journal-/AD-Resets.
Es gibt keine produktive Migration oder Delegation aus diesem Umfang.

Offen bleiben der installierbare abgesicherte Executortransport, Host-/Datei-/
Prozessgrenze, Schlüssel-/Actorbetrieb, unabhängiger Review, Mehr-DC/Forest-UPN,
Last-/Restore-Nachweise und gesonderte Betriebsfreigabe. Passwortsetzung, Gruppen
und Aktivierung neuer Benutzer bleiben ausgeschlossen.
