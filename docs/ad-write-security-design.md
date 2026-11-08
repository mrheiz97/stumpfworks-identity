# AD-Schreibfunktionen: Least Privilege und Schutzkonzept

Ergänzung vom 4. November 2026: [Sicherheitskonzept Benutzeranlage](ad-user-create-security-design.md)
konkretisiert Stufe 2: zunächst deaktivierte Konten, separate Folgeaktionen,
wirksame Add-Rechtegrenze, Namenskonkurrenz und operationsgebundener Rückweg.
Nur Konzept; keine Implementierung oder Aktivierung.

Fortschreibung: Die standardmäßig deaktivierte Stufe-1-Implementierung ist auf
development vorhanden. [Implementierung, Sicherheitsreview und Nachweise](ad-profile-stage1.md)
trennen bestandene Schutz-/Journaltests von der weiterhin gesperrten positiven
Samba-CAS-Abnahme. Der folgende Text bleibt die ursprüngliche Designgrundlage.

Stand: 2. November 2026. Entwicklungsentscheidung und testbarer Protokollentwurf,
**keine implementierte AD-Schreibfunktion oder Betriebsfreigabe**. Nur development;
keine Verbindung zu Produktivsystemen, keine Delegation, Konten, Migrationen oder
Dienste geändert. MOBILE01 bleibt vollständig ausgeschlossen.

## Ausgangspunkt und Systemgrenze

`internal/directory` bietet bislang Lesen und Authentifizierung. `identity.write`
verwaltet Identity-Daten, nicht das AD. Die aktuellen Rollen erhalten deshalb
keine der unten vorgeschlagenen Berechtigungen. Auch der Notfalladministrator
und der Local-/Demomodus dürfen keine AD-Schreibaktionen auslösen.
Framework v1.2.0 bleibt unverändert: seine LDAP-Lesebausteine sind keine
Schreibfreigabe. Fachliche Ziel-, Rollen-, Audit- und Rückwegregeln gehören zu
Identity; generische Schreibbausteine würden einen gesonderten Frameworkauftrag
mit eigenständigen Verträgen benötigen.

Die spätere Funktion startet standardmäßig deaktiviert. Vorgesehen sind ein
Planungsdienst ohne AD-Schreibcredential und ein separater, eng begrenzter
Executor mit eigener Betriebssystemidentität. Dieser akzeptiert ausschließlich
typisierte, gespeicherte Aufträge, keine freien LDAP-Filter, DNs, Attribute,
URLs oder Shellbefehle. Beide prüfen die Policy; nur der Executor besitzt das
dedizierte Schreibcredential. Der bisherige AD-Leseaccount bleibt unverändert.
Credentials kommen aus einem geschützten Credentialmechanismus, niemals aus
Browserdaten, Kommandozeilen, Audit oder Repository. Keine Produktionscredentials
werden für Entwicklung oder Tests verwendet.

## Stufen, Rechte und Delegationsgrenzen

| Stufe / vorgeschlagene Permission | Engster zukünftiger AD-Umfang | Zusätzliches Gate |
| --- | --- | --- |
| 1: `directory.users.modify` | Nur displayName, givenName, sn, mail gewöhnlicher Benutzer direkt in einer dedizierten ManagedUsers-OU | Labor-ACL- und Konkurrenztests; keine Login-/UPN-/Namensänderung |
| 2: `directory.users.create` | Nur Benutzer aus versionierter Vorlage, zunächst deaktiviert, direkt in derselben OU | Pflichtattribute und minimal nötige Create-Child-/Attributrechte separat nachweisen; kein freier Attributeditor |
| 3: `directory.users.disable` | Ausschließlich erlaubte Kontostatusänderung | Eigenes Credential/Delegationsprofil, Bit-erhaltende Änderung und Sperrschutz nachweisen |
| 4: `directory.passwords.reset` | Separates Reset-Recht auf freigegebenen gewöhnlichen Zielkonten | Frische Bestätigung, geschützte Übergabe, kein automatischer Wiederholungsversuch |
| 5: `directory.groups.membership` | Einzelne Benutzer-Mitgliedschaftskante in explizit freigegebenen unprivilegierten Gruppen | Gruppen-GUID/SID-Allowlist, keine Verschachtelung, kein vollständiger member-Ersatz |

Stufe 1 ist der erste Implementierungs- und Laborumfang. Die weiteren Stufen
sind geplant und bleiben gesperrt, bis ihre eigenen Nachweise vorliegen.
Löschen, Umbenennen, Verschieben und beliebige Massenaktionen sind ausgeschlossen.
Auch Kontoaktivierung erhält erst nach Prüfung eine eigene explizite Aktion.
Ein deaktiviertes neu angelegtes Konto ist nicht automatisch sicher: Passwort,
Zielgruppen, Vorlage und jede spätere Aktivierung benötigen eigene Regeln.

Delegation ausschließlich auf einer dafür eingerichteten OU, möglichst auf die
direkten Benutzerobjekte beschränkt: nur die konkret benötigten Attributrechte,
kein Domain Admin, Enterprise Admin, Account Operators, GenericAll, GenericWrite,
WriteDACL, WriteOwner, DeleteTree, Replikationsrecht oder pauschales Extended Right.
Vererbte Rechte, Gruppenmitgliedschaften und zusätzliche ACEs des Servicekontos
müssen mitgeprüft werden; eine enge neue ACE neutralisiert keine breiten Alt-Rechte.
Das Konto darf weder seine eigene Delegation noch Gruppen verändern, aus denen
Identity-Rollen oder administrative Rechte entstehen. AD-ACLs bilden die äußere
Sicherheitsgrenze auch bei kompromittiertem Executor.

Reset Password ist ein eigenes Extended Right; dessen GUID ist
`00299570-246d-11d0-a768-00aa006e0529`. Es wird für Stufe 1 nicht delegiert.
`userAccountControl` bündelt mehrere sicherheitsrelevante Bits: ein Attribut-
Schreibrecht begrenzt den Account nicht auf das Disable-Bit. Diese zusätzliche
Befugnis muss vor Stufe 3 ausdrücklich bewertet werden; kein pauschaler
UAC-Schreibzugriff als Abkürzung. [Reset-Recht](https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password),
[UAC-Bedeutung](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties).

## Autorisierung, Zielschutz und Transport

Neue AD-Rollengruppen werden explizit und getrennt von heutigen Identity-Rollen
konfiguriert. Aktuelle AD-Mitgliedschaft wird beim Planen, Bestätigen und direkt
vor Ausführung geprüft. Kein Rollen-Cache darf eine entzogene Berechtigung
verlängern. Schreibaktionen benötigen eine höchstens fünf Minuten alte normale
AD-Administratorauthentifizierung, CSRF-/Origin-Prüfung und eine einmalige,
kurzlebige Bestätigung, gebunden an Actor-SID, Ziel-GUID, Aktion, Änderungsdigest,
Policyrevision und Ablauf. Sensible spätere Stufen benötigen zusätzlich eine
unabhängige zweite berechtigte Person; der Antragsteller bestätigt nicht selbst.
Keine Passwortdaten im Planungsformular oder in einer persistierten Warteschlange.

Ziele werden über Forest-/Domain-Identität, objectGUID und SID gebunden, niemals
allein über Anzeigenamen oder einen vom Browser gelieferten DN. DN-Vergleiche
verwenden den LDAP-Parser und RDN-Grenzen; Stufe 1 erlaubt nur direkte Kinder der
festen OU. GUID, DN, Objektklasse und Risikoattribute werden unmittelbar vor
dem Schreiben erneut gelesen. Unbekannte, abgeschnittene oder fehlgeschlagene
Prüfergebnisse bedeuten Ablehnung, nicht unprivilegiert.

Abzulehnen sind mindestens Eigenkonto, Executor-/Dienstkonten, Computer/DC/gMSA,
bekannte privilegierte SIDs, Identity-Rollenkonten und -gruppen, geschützte
Konten sowie Konten mit riskanten SPN-/Delegations-/Key-Credential-Eigenschaften.
Verschachtelte Mitgliedschaften, primaryGroupID und domänenübergreifende
Mitgliedschaften müssen berücksichtigt werden. Zyklen werden erkannt; bei
Suchlimit, unbekanntem Trust oder unvollständiger Auflösung wird abgelehnt.
`adminCount=1` ist ein zusätzliches Sperrsignal, `0` oder Abwesenheit sind kein
Unbedenklichkeitsbeweis. AdminSDHolder oder Vererbungsverhalten werden niemals
geändert, um eine abgewiesene Aktion durchzusetzen. Die Microsoft-Dokumentation
beschreibt geschützte Konten und SDProp; die konkrete Samba-Version muss im
Labor eigenständig geprüft werden. [Geschützte Konten](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory).

Schreibverkehr ausschließlich zu einem explizit zugelassenen schreibbaren DC
mit vollständig verifiziertem TLS (Kette, DNS-Name, mindestens TLS 1.2).
Kein Legacy-Pin-Bypass, kein unverschlüsselter Bind, keine Referral-Verfolgung,
kein automatischer DC-Wechsel oder Schreibretry. DC-Identität und Versionsbeleg
(einschließlich Invocation-ID bei USN-Nutzung) werden an den Plan gebunden.
Ein USN allein ist nicht DC-übergreifend vergleichbar.

Die geplante Änderung benötigt eine **kritische** bedingte LDAP-Operation,
z. B. Assertion Control OID `1.3.6.1.1.12`, mit überprüfter Zielidentität und
Versionsbedingung. RFC 4528 beschreibt die bedingte Ausführung; Unterstützung
und tatsächliche Semantik des konkreten DC werden vor Aktivierung nachgewiesen.
Fehlende Unterstützung sperrt die Funktion, ohne unbedingten Fallback.
[RFC 4528](https://www.rfc-editor.org/rfc/rfc4528.html).

Eine Assertion auf dem Zielobjekt schützt nicht atomar die gesamte Gruppen-
und Privilegienstruktur. Ein lokaler Lock schützt ebenfalls nicht vor externen
AD-Administratoren. Daher sind OU-Segregation, ACL-Begrenzung und ein abgestimmter
Prozess für Privilegierungsänderungen zwingend. Ein in das Verwaltungssegment
verschobenes privilegiertes Konto darf nicht einfach durch Software als sicher
gelten. Dieser verbleibende Konkurrenzfall ist ein eigenes Aktivierungsgate.

## Dauerhafter Auftrag und Audit über zwei Systeme

AD und Identity-Datenbank bilden keine gemeinsame ACID-Transaktion. Das
bestehende atomare DB-Mutationsaudit wird nicht als AD-Atomarität ausgegeben.
Vorgesehenes Protokoll:

1. Nach vollständiger Vorprüfung einen unveränderlichen Plan speichern:
   zufällige Operations-ID, gebundener Idempotenzschlüssel, Actor-/Ziel-ID,
   Aktion, erlaubte Attributnamen, nicht geheimer Digest, Policy-/DC-/Zielversion,
   Ablauf und Audit `directory_write_prepared` in derselben DB-Transaktion.
2. Nach Bestätigung und erneuter Prüfung bedingt `prepared → applying` ändern
   und `directory_write_claimed` atomar schreiben. Erst **nach erfolgreichem
   Commit** darf genau der Gewinner den einmaligen LDAP-Aufruf beginnen.
3. Ergebnis am gleichen DC prüfen. Bestätigten Erfolg und Erfolgsaudit atomar
   speichern; erst dann Erfolg anzeigen. Ein definitiver Fehler ohne Wirkung
   wird als `failed_no_effect` samt begrenztem Fehlercode dokumentiert.
4. Timeout, Prozessabbruch, verlorene Antwort oder DB-Ausfall nach Aufruf führen
   zu `reconciliation_required`. Ein verbliebenes `applying` gilt nach Neustart
   ebenfalls als unklar, selbst wenn der Prozess möglicherweise vor dem Aufruf
   starb. Es wird niemals erneut geclaimt oder automatisch zurückgesetzt.
5. Reconciliation liest Zielzustand und verfügbare DC-Evidenz. Beobachtete Wirkung
   heißt `reconciled_effect_observed`, nicht nachträglich erfundene sichere
   Ausführung. Unaufklärbare Fälle bleiben gesperrt. Jede Kompensation ist eine
   neue autorisierte Operation mit Referenz auf die ursprüngliche ID.

Abbruch ist ausschließlich vor `applying` möglich; Claim und Abbruch konkurrieren
über dieselbe bedingte DB-Änderung. Wiederholte HTTP-Anfragen liefern die vorhandene
Operation; derselbe Schlüssel mit anderem nicht geheimem Plan wird abgelehnt.
Nach unklarem Ergebnis liefert die UI eine feste Operations-ID und gesperrten
Status statt einer Aufforderung zur erneuten Ausführung. Keine Exactly-once-
Behauptung über AD und DB; die konservative Sperre opfert Verfügbarkeit.

Audit enthält Zeit, Operations-/Korrelations-ID, Actor- und Zielreferenz,
Aktion, Attributnamen, Policyrevision, Zustand, Bestätigungspartner und begrenzte
Ergebnis-/Reconciliationcodes. Keine Passwörter, Hashes von Passwörtern, Tokens,
freien LDAP-Fehlertexte, vollständigen Requests, DNs oder Attributwerte.
Leserechte und Retention werden getrennt von Schreibrechten verwaltet.
Benötigte Vorherwerte für Kompensation sind ein gesonderter verschlüsselter,
kurzlebiger und zugriffsauditierter Datensatz für ausschließlich erlaubte
Profilattribute; Schlüssel- und Löschkonzept sind Implementierungsgates.
Keine generische Kopie des AD-Objekts und keine Secrets in diesem Datensatz.

Aufträge sind auf ein Objekt und eine Aktion begrenzt. Eingabewerte erhalten
attributspezifische Längen-/Syntaxgrenzen; Filter werden escaped und Änderungen
über typisierte LDAP-Requests übertragen. Executor-Aufruf, LDAP-Suche, Graph-
Auflösung und Readback haben feste Zeit-/Größen-/Knotengrenzen. Rate Limits pro
Actor und Ziel sowie ein globales Inflight-Limit schützen vor Fehlbedienung und
Missbrauch; Limits erzeugen keine automatischen Wiederholungen. Alerts betreffen
unklare Aufträge, Auditverlust, Policyablehnungen und ungewöhnliche Häufungen,
ohne Personen- oder Secretwerte in Metriklabels zu übernehmen.

Ein Passwortreset ist administratives Ersetzen von unicodePwd; das Passwort
kann nicht zurückgelesen werden. Ein verlorenes Ergebnis lässt sich deshalb
nicht durch Wertvergleich eindeutig klären. Kein erneuter automatischer Reset,
keine Persistierung des Passworts, kein Wiederherstellen eines alten Passworts.
Ein späterer neuer Reset benötigt eine neue ausdrückliche Autorisierung und
sichere Übergabe. [Microsoft LDAP-Passwortverfahren](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password).

## Rückweg und Betriebsplan

Vor einer späteren Labor- oder Produktivaktivierung: aktuelle Versionen und
effektive Delegation erfassen, geprüfte Konfig-/Binär-/DB-Rückwege und ACL-Export
erstellen, geschützte unabhängige AD-Sicherung sowie isolierte Restoreprobe
nachweisen. Ein Snapshot oder eine Datei auf demselben Host wird nicht als
unabhängige Sicherung bezeichnet. Heute wurde keine solche Sicherung erstellt.

Bei Fehlern neue Aufträge sperren, Executor anhalten, Inflight-Aufträge einzeln
klären und gegebenenfalls das dedizierte Schreibcredential durch zuständige
AD-Administratoren sperren. Nicht blind Rollen, Journale oder Aufträge löschen.
Ein Binary-/DB-Downgrade macht AD-Änderungen nicht rückgängig. Vor DB-Restore
müssen alle seit dem Sicherungsstand möglichen AD-Wirkungen reconciliiert und
Idempotenz-/Auditnachweise erhalten werden, damit keine Aufträge erneut laufen.

| Aktion | Zulässige Kompensation | Grenze |
| --- | --- | --- |
| Profilattribute | Dieselbe GUID, aktuelle Werte exakt unsere Nachherwerte, neue kritische Versionsbedingung; frühere Werte oder Abwesenheit gezielt zurücksetzen | Fremdänderung oder fehlender Vorherbeleg: manuelle Klärung statt Überschreiben |
| Benutzeranlage | Nur nachgewiesene eigene GUID deaktiviert in kontrollierter Quarantäne halten | Kein automatisches Löschen; bei verlorener Add-Antwort niemals fremdes Objekt anhand DN übernehmen |
| Gruppenkante | Nur die nachgewiesene eigene Einzeländerung unter erneuter Policy-/Versionsprüfung invertieren | Kein vollständiges Zurückschreiben einer alten Mitgliederliste |
| Kontostatus | Neue geprüfte Einzelaktion, sonstige aktuelle UAC-Bits erhalten | Kein blindes Zurückschreiben des gesamten früheren UAC-Wertes |
| Passwortreset | Neuer separat freigegebener Reset | Altes Passwort ist nicht wiederherstellbar |

Ein Domain-Restore ist ein eigener Notfallprozess mit isolierter Restoreprobe
und Konsistenzprüfung; kein Rückweg für eine einzelne Profiländerung.
Samba dokumentiert dafür eigene Domain-Backup-/Restore-Verfahren; daraus wird
keine heute ausgeführte Sicherung abgeleitet.
[Samba-Werkzeuge](https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html).

## Tests, Nachweisgrenzen und nächste Freigaben

Die neuen Dateien sind ausschließlich `_test.go`; keine Runtime-API, Migration,
Delegation oder standardmäßig aktivierte Funktion wird eingeführt.

| Nachweis | Hier ausführbar | Vor Aktivierung zusätzlich zwingend |
| --- | --- | --- |
| Zielbereich | Echter LDAP-DN-Parser: direkte OU-Kinder, escaped comma, Groß-/Kleinschreibung, fremde/nested/ungültige DNs | GUID-/SID-Bindung, Move-/Rename-Rennen und echtes ACL-Verhalten |
| Rollen | Alle heutigen Rollen gemeinsam erhalten keine vorgeschlagene AD-Permission | Aktuelle Rollenauflösung, Entzug, Step-up, CSRF, Bestätigung, Vieraugenprinzip |
| Persistenz | Echte SQLite-/PostgreSQL-Transaktionen: Auditfehler rollt Claim zurück, acht konkurrierende Claims haben einen Gewinner, fehlendes Abschlussaudit erhält unklaren Zustand, Neustartclaim abgewiesen, getrennte Reconciliation | Runtime-Schema, Intent-Erstellung, Idempotenzkonflikt, Cancel-Rennen, Crash-Injektion an jeder Prozessgrenze |
| AD-Wirkung | Nur modellierter externer Aufruf; kein LDAP-Schreiben | Isoliertes Samba-Labor: minimale ACL positiv/negativ, geschützte/nested/primaryGroup-/Trust-Ziele, TLS/Referral/Assertion, externe Konkurrenz und Fehler nach erfolgreichem Modify |
| Rückweg | Protokoll und aktionsbezogene Bedingungen festgelegt | Echte isolierte Kompensation, Fremdänderungsablehnung, Secret-/Log-Leakprüfung, Backuprestore und Wiederanlauf ohne Replay |

Reproduzierbar: `go test -count=1 ./internal/directory ./internal/database`;
PostgreSQL opt-in über den bestehenden strikt lokalen Test-DSN-Guard
`IDENTITY_TEST_POSTGRES_URL` (127.0.0.1:55441/postgres). Die Design-Tabellen liegen
in einer temporären SQLite-Datei beziehungsweise einem eigenen Wegwerfschema.
Sie sind kein Ersatz für echte AD-/Samba-Integrationstests.

Nächster Auftrag: standardmäßig deaktivierte Stufe-1-Implementierung und
isoliertes Samba-Labor mit obiger Negativmatrix. Erst nach deren Abnahme dürfen
konkrete Produktionsdelegation und Wartungsplan separat vorgelegt werden.
Dieses Konzept erteilt weder eine Produktions- noch eine Frameworkfreigabe.

### Lokale Verifikation

Vollständige Go-Suite ohne Testcache, OpenSSL-Verträge, `go vet ./...` und
`go mod verify` bestanden. Unter eingeschränktem Windows-Prozesszugriff waren
zunächst Loopback-/OpenSSL-Aufrufe blockiert; die unveränderte Suite bestand
mit erlaubtem lokalem Prozess-/Socketzugriff. Kein Guard wurde dafür gelockert.
Der neue PostgreSQL-Vertrag und die bestehende Datenbank-Vertragsgruppe samt
synthetischem Import/Restore bestanden zusätzlich in `postgres:17-alpine`
mit `--network none`, ohne Hostports; der Cluster wurde gestoppt und der
Wegwerfcontainer automatisch entfernt. Echte AD-Schreib-/ACL-Tests sind damit
ausdrücklich nicht nachgewiesen.
