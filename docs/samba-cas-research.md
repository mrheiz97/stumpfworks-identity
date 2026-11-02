# Samba-CAS: Laboruntersuchung und Entscheidung

Stand: 2. November 2026. Ausschließlich development, synthetisches isoliertes
Labor. Keine Produktivverbindung, keine Produktivmutation, MOBILE01 ausgeschlossen.
**Die Runtime und ihre CAS-Sperre bleiben unverändert.** Änderungen beschränken
sich auf Testcode, Laborfixture und Dokumentation; kein Framework-/Bibliotheks-
Update, keine Paketfreigabe, keine Änderung an AD-Schema oder Produktiv-ACLs.

## Ergebnis

Für die bestehende Stufe-1-Sicherheitsgrenze ist **kein freigabefähiger Ersatz
für atomare GUID-/Objektversionsbedingungen nachgewiesen**. Ein einzelner
LDAP-Modify kann einen brauchbaren begrenzten Attributwertvergleich ausführen.
Er erkennt jedoch weder A→B→A noch Änderungen anderer Objektattribute. Ein
Wertvergleich darf deshalb nicht als vorhandener uSNChanged-CAS ausgegeben werden.
Das ist ein Ergebnis der untersuchten Verfahren und Samba-Version, kein Beweis,
dass es grundsätzlich nie ein geeignetes serverseitiges Verfahren geben kann.

Zusätzlich wurde ein Drahtformatproblem der gepinnten Clientbibliothek gefunden:
`ldap.NewControlString(..., true, ...)` kodiert TRUE über die generische BER-
Funktion als `01`. LDAP fordert `FF`. Im Labor wurde eine garantiert falsche
Assertion mit der generischen Kodierung akzeptiert und der Testwert geändert.
Mit einer **ausschließlich in `_test.go` vorhandenen** FF-Kodierung verweigerte
Samba dieselbe Art Anfrage mit Ergebniscode 12. Ein boolesches Go-Feld oder
ein erfolgreicher positiver Request allein sind daher kein CAS-Nachweis.

Die bisherige RootDSE-Fähigkeitsprüfung blockiert den Runtime-Schreibweg bereits
vor dem Aufruf; der Befund öffnet keinen Fallback. Vor jeder späteren Freigabe
müssen sowohl die Clientkodierung als auch die echte serverseitige Semantik
nachgewiesen werden. Die Untersuchung repariert oder aktiviert die Runtime nicht.

## Normative Grundlage und Quellenabgleich

Ein LDAP-Modify führt seine Änderungsliste atomar aus. Bei einer Fehlerantwort
darf keine Teiländerung verbleiben; bei verlorener Antwort ist die Wirkung
unbekannt. Diese Atomarität macht einen vorausgehenden separaten Leseaufruf
noch nicht zu einem atomaren Versionsvergleich.
[RFC 4511 §4.6](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6).

Ein als kritisch gesetztes unbekanntes Control darf nicht still ignoriert
werden. Für BOOLEAN TRUE verlangt LDAP das Wertbyte `FF`; generisches BER TRUE
mit `01` reicht für diesen LDAP-Vertrag nicht.
[RFC 4511 §4.1.11](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.11),
[§5.1](https://www.rfc-editor.org/rfc/rfc4511.html#section-5.1).

RFC 4528 beschreibt die integrierte atomare Prüfung einer Zielbedingung.
Eine Assertion auf GUID und uSNChanged könnte den geforderten Zielobjektvertrag
tragen, sofern der konkrete Server sie tatsächlich korrekt unterstützt.
[RFC 4528 §3](https://www.rfc-editor.org/rfc/rfc4528.html#section-3).

`uSNChanged` ist ein systemgesetzter lokaler Änderungszähler. Er ist kein
gewöhnliches delegierbares Profilattribut. Die Untersuchung versucht deshalb
keine Rechteausweitung oder manuelle Zählerpflege als Ausweg.
[Microsoft Attributbeschreibung](https://learn.microsoft.com/en-us/windows/win32/adschema/a-usnchanged).

Permissive Modify hebt gerade Fehler beim Löschen nicht vorhandener Werte auf.
Damit ist es für ein auf gezieltem Löschen basierendes Vorbedingungsverfahren
ausgeschlossen. [Microsoft MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/49cdb1e3-3baa-4c7c-8cde-7c26b13d3ba7).

Die lokale, durch go.mod/go.sum gepinnte Quelle
`github.com/go-ldap/ldap/v3@v3.4.14/control.go` verwendet in
`ControlString.Encode` die generische `ber.NewBoolean`-Funktion. Im ebenfalls
gepinnten BER-Modul unterscheidet sich diese von `NewLDAPBoolean`. Der neue
Byteformat-Test hält den tatsächlich verwendeten Stand fest und fordert bei
einer künftigen Änderung eine erneute Bewertung.
[BER-Primärquelle v1.5.8](https://raw.githubusercontent.com/go-asn1-ber/asn1-ber/v1.5.8/ber.go).

## Aufbau und gemessene Ergebnisse

Samba **4.17.12-Debian**, OpenSSL **3.0.22**, gepinntes Debian-Bookworm-Basisimage.
Je Lauf entsteht eine neue Domäne `PROFILE.TEST`; nur Loopback im Container,
`--network none`, keine Hostports. Zwei read-only Mounts enthalten ausschließlich
Laborskripte und Testbinaries. Testpasswörter werden im Container erzeugt, nicht
aus Produktivkonfiguration gelesen und nicht ausgegeben.

Ein zusätzlicher Benutzer `casprobe` erhält dieselben vier attributspezifischen
Write-Property-ACEs wie die bisherige gewöhnliche Testidentität. Weder generische
Schreibrechte noch Rechte für uSNChanged, Gruppen, UAC oder ACL-Änderungen werden
dem Writer hinzugefügt. Die bestehende Stufe-1-Schutzmatrix läuft weiterhin.

| Probe | Gemessener Befund | Bedeutung |
| --- | --- | --- |
| RootDSE | RFC-4528-Control nicht angeboten | Runtime-Ready bleibt abgewiesen |
| Generischer Client, TRUE=`01` | Positive und garantiert falsche Assertion akzeptiert, gewünschter Testwert tatsächlich geschrieben | Client-Drahtformat nicht als Schutzbeweis verwendbar |
| LDAP-konformes TRUE=`FF` | Falsche Assertion abgelehnt, vier Profilwerte und Versionssnapshot unverändert | Kein erfolgreicher CAS; Ablehnung des unbekannten Controls |
| Rohe begrenzte FF-TLS/BER-Probe | Antworttag 24 (ExtendedResponse), LDAP-Code 12 (`unavailableCriticalExtension`) | Erklärt `ldap: unexpected response: 24` der normalen Modify-Methode; nicht mit Erfolg oder einem Versionskonflikt verwechseln |
| Modify: Markierung ändern, dann falschen Altwert löschen | Fehler, gesamter Snapshot einschließlich Version unverändert | Keine Teiländerung trotz vorangehender Änderung in derselben Liste |
| Zwei echte LDAP-Verbindungen mit gleichem Altwert | Genau ein Gewinner; zweiter spezifischer Delete abgewiesen | Begrenztes atomisches Wert-CAS ohne Permissive Modify funktioniert |
| A→B→A vor dem alten Wert-CAS | uSNChanged fortgeschritten, altes Wert-CAS trotzdem erfolgreich | ABA-Lücke; keine Objektversionsprüfung |
| Fremde Änderung an `sn` vor Wert-CAS auf displayName | Zähler fortgeschritten, Wert-CAS trotzdem erfolgreich; fremder Nachname bleibt erhalten | Änderungsumfang des Vergleichs ist kleiner als der Objektvertrag |
| Gespeichertes `Alpha`, erwartetes `ALPHA` | Spezifischer Delete akzeptiert | Verzeichnisgleichheit ist kein bytegenauer Vergleich |
| Add/Delete-Sentinel bei vorhandenem displayName | Abgewiesen, kein Teileffekt | Auf dieser Version enger Abwesenheitstest möglich; allein kein Objekt-CAS |
| Derselbe Sentinel mit wirklich fehlendem displayName | Übergang zum neuen Wert erfolgreich | Positiver Gegenfall zur Abwesenheitsprobe |
| Falschen Altwert löschen und Replace mit FF-Permissive-Control | Veraltete Bedingung ignoriert, Replace ausgeführt | Bewusst unsichere Testgegenprobe; niemals Runtime-Verfahren |
| uSNChanged löschen/hinzufügen plus Profiländerung | Abgewiesen; gesamter Snapshot unverändert | Kein stilles Ausweiten der Delegation auf Systemattribute |

Die FF-Probe prüft das tatsächlich serialisierte Byte `01 01 FF`, nicht nur
`Criticality=true`. Der rohe Test liest begrenzte Pakete über verifiziertes TLS,
hat eine feste Frist und schreibt ausschließlich feste synthetische Profilwerte.
Bindpakete und Credentials werden nicht geloggt. Die bestätigte Fehlerantwort
ist eine Messung dieser Version; keine Behauptung über alle Samba-/AD-Versionen.

Die vier ursprünglichen Profilwerte werden am Ende über den normalen, eng
delegierten LDAP-Zugang exakt wiederhergestellt und erneut gelesen. Änderungs-
zähler und AD-Historie werden dabei **nicht** zurückgesetzt. Danach wird der
Container samt synthetischen Geheimnissen entfernt. Das ist ein Labor-Rückweg,
kein Produktionsbackup und kein positiver Runtime-CAS-Rollbacknachweis.

## Bewertung der Alternativen

| Verfahren | Bewertung innerhalb der bisherigen Sicherheitsgrenze |
| --- | --- |
| Spezifischer Delete+Add innerhalb eines Modify | Als eingeschränkter Wertvergleich demonstriert; wegen ABA, Matchingregeln und fehlendem Gesamtobjekt-/Identitätsnachweis nicht freigeben |
| Alle vier Profilwerte vergleichen | Erweitert den Wertvergleich, erkennt aber weiterhin weder ABA noch Änderungen an Schutz-/Identitätsmerkmalen; keine ausreichende Ersatzlösung |
| Separater LDAP Compare/Search vor Modify | Zwischen den Requests bleibt ein Konkurrenzfenster; lokaler Executorlock bindet externe AD-Schreiber nicht |
| Eigenes Versionsattribut | Neue Delegation beziehungsweise Schema-/Konventionsarbeit; externe Schreiber müssten ausnahmslos teilnehmen. Kein Schutz gegen nicht kooperierende Admin-/Systemänderungen |
| uSNChanged als schreibbare Vergleichsmarke | Systemattribut; kein zulässiger Profil- oder Delegationsumfang |
| RFC-5805-Transaktionen | Start-/End-OIDs im gemessenen RootDSE nicht angeboten. Keine Implementierung nachgewiesen; auch keine Annahme eines isolierten Search+Modify allein aus dem Namen „Transaktion“ |
| Lokale LDB-Transaktion oder privilegierter DC-Broker | Könnte nur als gesonderte serverseitige Architektur untersucht werden. Direkter Live-Datenbankzugriff ist kein Ersatz für delegierte LDAP-ACLs, normale DC-Auswertung und Replikations-/Auditverträge |
| Geprüfte serverseitige Assertion-Unterstützung | Fachlich passender nächster Nachweispfad; konkrete Version/Implementierung und exakte Semantik erst separat verifizieren, keine pauschale Upgrade-Empfehlung |

RFC 5805 definiert eine experimentelle Erweiterung für zusammengefasste
Updateoperationen. Aus deren Existenz folgt hier keine verfügbare oder
ausreichende Samba-Implementierung.
[RFC 5805](https://www.rfc-editor.org/rfc/rfc5805.html).

Ein eventueller serverseitiger Baustein müsste zuerst einen neuen, begrenzten
Vertrag erfüllen: authentifizierter Actor; genau ein GUID-gebundenes Ziel und
feste DC-Identität; atomare Prüfung der erwarteten Objektversion und relevanten
Schutzwerte gemeinsam mit der Änderung; normale effektive ACL-Prüfung; keine
freien Filter, DNs, Attribute oder System-Rechte; begrenzte Ressourcen; positive,
negative, ABA-, Rename-/Identitätswechsel-, Rollenentzug-, Absturz- und
Antwortverlusttests. Gruppengraph-Rennen benötigen weiterhin eine gesonderte
Grenze. Diese Architektur ist hier weder implementiert noch freigegeben.

## Tests und Fortsetzung

Neue Nachweise: `internal/adprofile/samba_cas_research_test.go`.
Die vorhandene Samba-CI führt alle `TestSamba…`-Fälle automatisch aus. Ein
zusätzlicher Offline-Byteformatvertrag läuft auch ohne Samba in der normalen
Go-Suite. Änderungen an Kodierung oder Backendverhalten müssen eine erneute
fachliche Bewertung auslösen; die Tests öffnen keine Fähigkeit automatisch.

Reproduktion über die unveränderte Laboranleitung in
[Stufe 1](ad-profile-stage1.md). Vor dem Lauf Testbinary aus dem aktuellen
development-Stand neu bauen. Die Proben verwenden einen eigenen Testbenutzer;
sie verändern nicht die bestehende gewöhnliche Schutzfixture.

Der Untersuchungsumfang ist abgeschlossen, sobald diese Gegenproben und CI
bestanden sind. **Nicht abgeschlossen ist die Freigabe eines nutzbaren
Samba-Runtime-CAS.** Nächster eigenständiger Entwicklungsumfang: Clientkodierung
gezielt härten und eine tatsächlich unterstützte serverseitige atomare Bedingung
unter unverändertem Least Privilege nachweisen. CAS-Sperre und Default-off bis
dahin beibehalten; keine Produktiv- oder Frameworkfreigabe ableiten.

Lokaler Nachweis: vollständige Go-Suite ohne Cache einschließlich OpenSSL,
Vet und Modulverifikation bestanden. Finale netzlose Samba-Probe mit neun
CAS-Unterfällen und unveränderter Stufe-1-/Executor-Schutzmatrix bestanden;
Systemversionsschreiben lieferte LDAP 50, die rohe FF-Control-Probe LDAP 12.
Die ursprünglichen vier Profilwerte wurden erneut verglichen. Runtime-Quellen,
Executor, go.mod und go.sum sind gegenüber dem Ausgangsstand unverändert.
