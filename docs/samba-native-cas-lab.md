# DC-native CAS-Operation im isolierten Samba-Labor

Stand: 3. November 2026, development. Nur synthetische Daten im netzlosen
Wegwerfcontainer. Keine Produktivverbindung oder -änderung; MOBILE01 ausgeschlossen.
Identity-Runtime, CAS-Sperre, Default-off, Framework und Go-Abhängigkeiten bleiben
unverändert. Kein Release, keine Installation auf einem echten DC.

## Ergebnis und genaue Einordnung

`native_cas.c` ist ein kompiliertes natives **LDB-Modul im tatsächlichen Samba-
Serverprozess**. Der Testclient sendet normale LDAP-Modify-Nachrichten über
verifiziertes LDAPS; die Versionsprüfung und Mutation erfolgen serverseitig.
Python konstruiert und signiert Testaufträge, führt aber weder die CAS-Entscheidung
noch den eigentlichen Profil-Modify aus. Damit geht dieser Nachweis über den
[früheren lokalen Python-Kandidaten](samba-cas-broker-research.md) und den
[Ausführungsentwurf](samba-cas-broker-boundary.md) hinaus.

Das ist eine **Laboroperation, kein betreibbarer Broker**. Das Modul wird nur in
der frischen synthetischen `sam.ldb` vor `samba_dsdb` geladen. Eine spezielle
Modify-Hülle ersetzt ein neues öffentliches Extended-Operation-OID: genau ein
Attribut `identityLabCAS`, genau ein binärer Wert, ausschließlich Replace. Dieses
Attribut wird abgefangen und niemals gespeichert. Kein Schemaobjekt, kein
Assertion-Control und keine RootDSE-CAS-Fähigkeit werden hinzugefügt. Insbesondere
bleibt Identity beim fehlenden RFC4528-Control gesperrt.

## Vertrauensgrenze und Least Privilege

Der tatsächliche LDAP-Anmeldekontext wird über `sessionInfo` gelesen. Der
native Code erzeugt **kein** Token, benutzt weder `system_session` noch
`user_session` und ersetzt den Sicherheitskontext nicht. Zulässig ist nur die
frisch im Labor angelegte, an SID und GUID gepinnte normale Writer-Identität.
Administrative Token-SIDs und weitergehende Privilegien sind ausgeschlossen;
höchstens Change-Notify ist erlaubt. SYSTEM und der Operator selbst dürfen den
nativen Auftrag nicht als Writer ausführen.

Der downstream Modify läuft durch den unveränderten Samba-DSDB-/ACL-Stack.
Ein Entzug der vorhandenen objektbezogenen Write-Property-ACEs führt auch bei
frischer Zielversion tatsächlich zu LDAP 50. Es gibt keine zusätzliche Delegation
und keinen privilegierten Fallback. Das Modul blockiert normale Add-/Modify-/
Delete-/Rename-Aufrufe des festen Writers, sodass dessen bestehende Profilrechte
nicht zum Rohschreiben am CAS-Einstieg vorbei verwendet werden können. Andere
Identitäten behalten ihren regulären Samba-Verarbeitungsweg und ihre ACLs.
Das ist kein Beweis sämtlicher sonstiger AD-/RPC-/Authentifizierungsbefugnisse
des Writerkontos.

Das Modul gehört zum vertrauenswürdigen DC-Code. Ein Fehler darin kann den DC
kompromittieren; es ist keine Isolation gegenüber einem bereits kompromittierten
Samba-Prozess. Die bislang fehlende DC-native Operation ist jetzt als konkreter
Laborbaustein vorhanden, unabhängiger Sicherheitsreview und Betriebsfreigabe
fehlen weiterhin.

## Enger binärer Auftragsvertrag

Der native Parser akzeptiert maximal 1024 Bytes einschließlich 64-Byte-Ed25519-
Signatur. Signaturprüfung erfolgt über OpenSSL EVP im Prozess, ohne Unterprozess,
Shell, JSON, frei wählbaren Algorithmus, Pfad oder Schlüssel. Der öffentliche
Schlüssel und alle Identitätspins werden frisch aus der vertrauenswürdigen
synthetischen Fixture in einen nur im Container erzeugten Header kompiliert.

| Bereich | Fester Vertrag |
| --- | --- |
| Format / Policy | Acht Bytes `SWCAS001`; unbekanntes Format abgewiesen |
| Identität | Je 16 Bytes ID, Domain-GUID, DC-Invocation-ID, Ziel-GUID, Actor-GUID, Writer-GUID und Operatorgruppen-GUID |
| Version / Frist | Drei vorzeichenlose 64-Bit-Zahlen in Big Endian: erwartete USN, Ausgabezeit, Ablaufzeit; maximal 60 Sekunden |
| Änderungen | Genau vier feste Positionen: displayName, givenName, sn, mail; je 16-Bit-Länge und Bytes |
| Semantik | 65535 bedeutet unverändert, 0 bedeutet entfernen; mindestens eine Änderung erforderlich |
| Werte | Bewusst nur druckbares ASCII; maximal 256/64/64/254 Bytes. Kein generischer Unicode-/Attributeditor |
| Signatur | Letzte 64 Bytes; deckt sämtliche vorangehenden Bytes ab; keine Zusatzbytes |

Domain und Invocation-ID binden die Operation an diesen einzelnen DC; das feste
Format und der frisch gepinnte Schlüssel begrenzen ihre Audience. Das ist kein
stilles Failover und kein für andere DCs gültiges Stable-Protokoll. SID-Bindungen
der beteiligten Objekte sind zusätzliche kompilierte Pins und werden aktuell
gelesen. Der äußere LDAP-DN muss dem aktuell gefundenen festen Ziel entsprechen.

Der vertrauenswürdige Testaussteller authentifiziert den festen Actor vor der
Signierung durch echten LDAPS-Bind und prüft dessen SID. Die Operation vertraut
dieser kurzlebigen signierten Aussage und prüft Kontostatus und Rolle erneut.
Eine kompromittierte Ausstellerinstanz könnte Aussagen für diesen Actor erzeugen;
die Signatur beweist keine separate unmittelbare Passwortprüfung im C-Modul.
Produktiver Identity-Step-up, Benutzerbestätigung und Kanalbindung sind noch
nicht angebunden. Der private Testschlüssel bleibt in `/tmp/native-cas` im
Container; die gemeinsame Root-Vertrauensdomäne von Testaussteller und DC ist
ausdrücklich **keine** produktive Schlüsseltrennung.

## Atomare Ausführung und dauerhafte Ergebnissperre

Samba eröffnet für die LDAP-Änderung eine Transaktion. Das Modul verlangt diese
Transaktion und verwendet ihre nativen Start-/Prepare-/Commit-/Cancel-Hooks;
es nimmt keinen vom Client behaupteten Transaktionsstatus an. Innerhalb dieses
Schreibstands werden erneut geprüft:

- Domain-GUID/SID, aktuelle DC-Invocation-ID sowie feste Writer-/Actor-GUID/SID;
- Writerstatus und fehlende zusätzliche Gruppen; aktueller Actorstatus und
  genau die feste Operatorrolle, deren Gruppe selbst keiner übergeordneten
  Gruppe angehören darf;
- Sperrstatus, Ablauf, gesetztes Passwort und berechnete Kontorestriktionen von
  Actor und Writer, auch nach vorheriger Signierung oder bestehendem LDAP-Bind;
- genau ein festes Benutzerziel unmittelbar in der festen OU, Ziel-SID,
  primäre Gruppe, UAC, Adminschutz und Risikoattribute einschließlich SPN,
  Gruppenmitgliedschaft, SID-History, Key-Credentials und Delegation;
- die gesamte Objektversion `uSNChanged` und die Frist unmittelbar vor Modify.

ABA und Änderungen anderer Attribute werden dadurch abgewiesen. Zwei bereits
angemeldete unabhängige LDAP-Verbindungen mit demselben Versionsstand erhalten
genau einen Erfolg. Ein nach Signierung erfolgter ACL- oder Rollenentzug wirkt.

Vor der Mutation wird ein gesonderter synchroner TDB-Claim mit ID, SHA256 des
signierten Inhalts und dem festen Ziel gespeichert. Ein nichtblockierender
TDB-Transaktionsversuch begrenzt die zusätzliche Journal-Warteschlange. Private
Root-Datei/-Verzeichnisrechte, reguläre Datei, einzelner Hardlink, No-follow und
gleiches Device/Inode vor/nach Öffnen werden geprüft. Lesefehler gelten niemals
als fehlender Eintrag. Clientfelder bestimmen weder Journal noch Namespace.

Erst **nach** erfolgreichem downstream DSDB-Commit wird der TDB-Zustand auf Erfolg
gesetzt; nur bestätigter Cancel ergibt `failed_no_effect`. Die Commit-Hooks
verhindern eine vorzeitige Erfolgsmeldung aus dem bloßen Modify-Callback. Nach
Commitfehler, Prozessverlust oder verlorener Bestätigung bleibt `applying`
unklar und sperrt sowohl alte als auch frische IDs auf diesem Ziel. Kein Replay,
kein Reset, keine SQL-/TDB-Entsperrung und keine automatische Reconciliation.
Ein identischer erfolgreicher Auftrag liefert den gespeicherten Zustand ohne
neue USN; dieselbe ID mit neu signiertem geändertem Inhalt wird abgewiesen.

DSDB und TDB sind weiterhin **zwei getrennte Commits**, keine gemeinsame ACID-
Transaktion. Claim- und Terminalereignisse enthalten nur ID, Actor-SID,
Ziel-GUID, Attributmaske beziehungsweise Zustand. Profilwerte und Passwörter
stehen nicht im Journal. Der Inhaltsdigest ist keine Anonymisierung. Vollständige
Zeit-/Freigabe-/Ablehnungsaudits, Verschlüsselung, Retention und gesicherter
Journal-/DC-Restore gehören weiterhin zum späteren Identity-Betriebsvertrag.

## Controls, Transport und tatsächliche Nachweise

Nur Sambas internes `DSDB_CONTROL_NO_GLOBAL_CATALOG` mit OID
`1.3.6.1.4.1.7165.4.3.17` ohne Daten wird durchgereicht. Dieses Metadatum des
normalen 636-Listeners verleiht keine Schreibbefugnis. Andere beim Modul
ankommende Controls werden abgewiesen. Die versionsgebundene Definition steht
in [Sambas samdb.h](https://github.com/samba-team/samba/blob/samba-4.17.12/source4/dsdb/samdb/samdb.h).

Eine wichtige Testkorrektur: Der entfernte Python-SamDB-Aufruf transportierte
die übergebenen Permissive-Modify-Controls in dieser Probe nicht wie erwartet.
Die endgültige Gegenprobe sendet deshalb selbst eine begrenzte TLS/BER-Nachricht
mit echtem kritischem Control und LDAP-TRUE `FF`; der Server weist sie ohne
Zieländerung ab. Aus der Wrapper-Parameterübergabe wird kein Drahtnachweis abgeleitet.

Alle positiven Aufträge gehen über LDAPS mit CA-/DNS-Prüfung an den echten
Samba-Server. Der Client öffnet keine lokale AD-Datenbank zur Durchführung des
Auftrags. Lokaler SYSTEM-Zugriff wird ausschließlich für synthetische Fixture-
Änderungen und deren Rücknahme verwendet. Ein nativer Modulpfad über andere
Samba-Endpunkte oder eine verbindliche serverseitige TLS-Kanalbindung werden
hier noch nicht als abgenommen behauptet.

## Tests, Reproduktion und Rückweg

Gemessen: Samba 4.17.12-Debian, LDB 2.6.2, OpenSSL 3.0.22. Das Image behält die
gepinnt gleiche Debian-Basis; zusätzlich nur Laborcompiler und Entwicklungsheader.
Debian-Paketquellen sind kein vollständig eingefrorener Binärsnapshot. Der
frische Modulbuild verwendet die installierten passenden Header und Bibliotheken,
`-Wall -Wextra -Werror`, Stackschutz, RELRO/NOW und UndefinedBehaviorSanitizer
mit sofortigem Abbruch. Daraus folgt kein vollständiger Speicher- oder Fuzzbeweis.

Lokaler Abschlussnachweis: vollständige Go-Samba-/Executor-Matrix, alle 27
bisherigen Brokerverträge und die 17 nativen Verträge bestanden. Beide echten
Crash-/Neustartfälle in unabhängigen frischen DC-Containern bestanden; keine
UBSan-Meldung. Python-/Shellsyntax und Whitespace geprüft, Identity-Runtime und
Moduldateien unverändert. Zusätzliche native Prüfungen laufen in derselben CI
wie Linux-Race, PostgreSQL und die vorhandenen Rechte-/Unitverträge.

Das abschließende Eigenreview des Laborumfangs prüfte Parsergrenzen,
Signatur-/Identitätsbindung, unveränderten Writer-Kontext, nachgelagerte ACLs
und Claim-/Commit-/Cancel-Übergänge. Ergänzend bleiben die privaten Serverlogs
über einen Crash-Neustart erhalten; jede UBSan-Diagnose lässt den Testlauf
scheitern, auch wenn ein negativer LDAP-Test ansonsten eine Fehlermeldung erwartet.
Ein unabhängiger Review oder eine sichere Betriebsfreigabe wird damit nicht behauptet.

Die native Matrix enthält 17 Verträge: Erfolg/Gegenauftrag/Replay, signierte
Identitäten und Manipulation, Parser und Controls, Rollen-/Writer-/Zielschutz,
ABA/Fremdänderung, Backend-ACL, Zwei-Verbindungs-Rennen, Fristen/Audit,
Fristablauf in der Transaktion, Rohschreibsperre für Add/Modify/Delete/Rename,
OU-Wechsel, Anonymous/falsches Passwort, unsicheres Journal, begrenzter
Parserkorpus, Kontosperre/-ablauf nach Signierung, bereits angemeldeter externer
LDAP-Schreiber während der nativen Transaktion und Commit-Bestätigungsfehler.
Zusätzlich bleiben alle 27 früheren Brokerverträge und Go-Samba-/Executorproben
im Ablauf erhalten.

Zwei weitere **frische Container** prüfen echte `_exit`-Abbrüche des nativen
Samba-Prozesses vor und nach Commit, dann einen echten Neustart desselben DCs
mit **unverändertem** Journal. Vor Commit bleiben Werte und USN gleich; nach
Commit bleibt die Wirkung gespeichert. Beide Fälle verhindern alte und neue
IDs auf dem unklaren Ziel. Es werden keine Journalnamespaces zum Entsperren
gewechselt. Die nächste unabhängige Crashprobe beginnt mit einem vollständig
neuen synthetischen DC. Crash-/Warteinjektionen sind nur mit dem expliziten
Labor-Buildflag und fester privater Root-Datei möglich, niemals Requestfelder.

Reproduktion wie in der [Stufe-1-Anleitung](ad-profile-stage1.md), jedoch das
Image aus dem aktuellen Dockerfile **neu bauen**. `run.sh` beendet nach den
bisherigen Proben den ersten Labor-DC, kompiliert das Modul in `/tmp`, ergänzt
ausschließlich die synthetische `@MODULES`-Fixture und startet den DC erneut.
`native_run.sh` übernimmt die native Matrix. Für die zwei unabhängigen
Crashcontainer setzt die CI `IDENTITY_NATIVE_CRASH_CASE=before_commit` oder
`after_commit`, provisioniert frisch und startet `native_run.sh`. Jeder Lauf:
`--rm --network none`, keine Hostports, nur die bisherigen zwei read-only Mounts
für Laborskripte und Testbinaries. Kein Host-Samba-Verzeichnis wird eingebunden.

Die vier ursprünglichen Profilwerte sowie ACL, OU, Rollen, UAC, Sperr- und
Ablaufwerte werden im Harness wiederhergestellt; der ACL-Descriptor wird
bytegenau verglichen. USN und AD-Historie werden nicht zurückgedreht. Auch nach
der Fixture-Rücknahme bleiben unklare Claims gesperrt bis zum Containerende.
Das ist kein produktives Reconciliation- oder Rollbackverfahren.

Die frische native Fixture setzt für Actor und Writer vor ihrer Baseline explizit
`lockoutTime=0`: Samba erlaubt das Entsperren mit 0, aber kein Löschen dieses
Attributes. Die Sperrprobe stellt daher diesen expliziten Ausgangswert wieder
her und behauptet keine Wiederherstellung eines zuvor fehlenden Attributes.

Rückweg des Entwicklungsumfangs: Änderungen ausschließlich an Laborskripten,
Laborimage, CI und Dokumentation zurücknehmen. Wegwerfcontainer enden samt
Modulsymlink, synthetischem Modulstapel, Schlüsseln und Journaldaten. Keine
Identity-Migration, Produktivdatei oder Unit ist zurückzusetzen. Ein alter
gesunder Produktivzustand wurde weder gesichert noch verändert.

**Offene Freigabegates:** unabhängiger nativer Code-/ABI-/Speicherreview,
vollständige effektive Rechte und lesbare Schutzattribute, Schlüsseltrennung/
Rotation/Widerruf, Identity-Plan/Step-up/Actor-Proof/Audit/Rückweg, harte globale
Last-/Lock-/Commitgrenzen, Mehr-DC/Replikation/Failover und gemeinsamer gesicherter
Wiederanlauf nach Datenverlust. Der native positive Ein-DC-Nachweis öffnet die
CAS-Sperre nicht und legitimiert keine Installation außerhalb des Labors.
