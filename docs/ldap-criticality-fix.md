# LDAP-Criticality: FF-Korrektur in Identity

Stand: 2. November 2026, development. Keine Veröffentlichung oder Installation,
keine Produktivverbindung/-änderung; MOBILE01 vollständig ausgeschlossen.
CAS-Sperre und Default-off bleiben bestehen. Framework, Abhängigkeiten,
AD-Delegation, Datenbankschemata und andere Funktionsstufen bleiben unverändert.

## Änderung

Die beiden kritischen Identity-Controls im AD-Profilmodul verwenden jetzt einen
lokalen, unveränderlichen `criticalControl`-Adapter:

- Domain-Scope-Suche: `1.2.840.113556.1.4.1339`, ohne Controlwert.
- Assertion: `1.3.6.1.1.12`, mit unverändertem BER-kodiertem Filterwert.

Der Adapter kodiert Criticality zwingend mit `ber.NewLDAPBoolean(..., true, ...)`
als `01 01 FF`. Er bietet keinen nichtkritischen Fallback. OID und binärer
Controlwert bleiben erhalten; leere Controlwerte werden wie bisher ausgelassen.
Die diagnostische Stringdarstellung enthält nur die OID, keinen Filterwert.
Es gibt keine globale Änderung an BER oder einen Fork/Update der Bibliothek.

Der gepinnte generische `ldap.ControlString` verwendet weiterhin BER TRUE=`01`.
Identity umgeht diesen Encoder ausschließlich an den beiden betroffenen eigenen
Runtime-Aufrufstellen. Die alte Kodierung bleibt nur als ausdrücklich unsichere
Gegenprobe im Labortest. LDAP verlangt für TRUE das Wertbyte `FF`.
[RFC 4511 §5.1](https://www.rfc-editor.org/rfc/rfc4511.html#section-5.1).

## Tests und gemessene Wirkung

| Nachweis | Aussage |
| --- | --- |
| Exakte Bytevektoren | Vollständige Control-TLVs mit und ohne Wert stimmen; Criticality ist `01 01 FF` |
| Binär- und Langwert | NUL/FF-Bytes und ein Wert über der BER-Kurzlängengrenze werden unverändert übertragen |
| SDK-Drahtprobe über lokale Speicherverbindung | Tatsächlich serialisierte Search-/Modify-Envelopes enthalten FF; OID, ausgelassener Domain-Scope-Wert und Assertion-Filter stimmen |
| Diagnose | Controlwert erscheint nicht in `String()` |
| Samba 4.17.12-Debian | Domain-Scope mit dem korrigierten Runtime-Encoder funktioniert in Rollen-/Schutz-/Executorprüfungen |
| Falsche Assertion mit Runtime-Encoder | Abgewiesen; Snapshot einschließlich Version unverändert. Begrenzte rohe TLS/BER-Probe bestätigt Antworttag 24 / LDAP-Code 12 |
| Alte generische 01-Gegenprobe | Falsche Assertion wird im Labor weiter akzeptiert; grenzt den beseitigten Clientpfad vom korrigierten Pfad ab |
| Sperre | RootDSE bietet Assertion weiterhin nicht an; `Ready`, Schreibplanung und der echte Executor bleiben gesperrt |

Die SDK-Drahtprobe verwendet `net.Pipe` ohne echte Verzeichnisdaten oder
Zugangsdaten. Das Samba-Labor verwendet verifiziertes LDAPS, eine frisch erzeugte
synthetische Domäne, `--network none`, keine Hostports und ausschließlich zwei
read-only Testmounts. Die ursprünglichen vier Profilwerte werden geprüft
wiederhergestellt; der Container samt Testgeheimnissen wird entfernt.

Die Samba-Forschungstests verwenden für ihre FF-Proben jetzt den **tatsächlichen
Runtime-Adapter** statt eines parallelen Testencoders. Die rohe BER/TLS-Probe
zeigt den Fehlercode, den die normale Modify-Methode wegen Sambas Antworttag
als `unexpected response: 24` meldet. Diese Korrektur übersetzt den Fehler nicht
in einen Erfolg oder einen sicheren Versionskonflikt. Unklare Ergebnisse bleiben
nach dem bestehenden Journalvertrag gesperrt und werden nicht wiederholt.

## Freigabegrenze und Rückweg

Korrekte Criticality-Kodierung ist eine Voraussetzung für sichere LDAP-Controls,
**kein Nachweis eines funktionierenden Samba-CAS**. Der getestete Server lehnt
das nicht unterstützte Control ab; die bestehende Fähigkeitsprüfung bleibt
unverändert vor dem Schreibaufruf. Es wird weder auf Wert-CAS noch auf eine
unkritische oder unbedingte Modifikation ausgewichen.

Ein Code-Rückweg ist im Entwicklungsverlauf über den Vorgängercommit
`02875cf070dce5cdb968190ac24387f7c315cf16` nachvollziehbar. Er würde aber den
bekannten fehlerhaften Encoder wiederherstellen und ist keine Empfehlung für
eine spätere Betriebswartung. Der sichere betriebliche Rückweg bleibt:
AD-Profilfunktion deaktivieren und die CAS-Sperre erhalten; niemals die Korrektur
durch Absenken der Criticality umgehen. Da nichts installiert wurde, ist kein
Produktivrollback erforderlich oder behauptet.

Reproduktion: `go test -count=1 ./internal/adprofile`, vollständige Go-/OpenSSL-
Suite und Vet, anschließend die bestehende
[netzlose Samba-Laboranleitung](ad-profile-stage1.md). Die vorhandene CI führt
Offline-Drahtformatverträge mit Race Detector sowie die Samba-/Executorprobe aus.
Die [CAS-Untersuchung](samba-cas-research.md) bleibt als historische Messung und
Begründung der weiterhin offenen serverseitigen Abnahme erhalten.

Lokale Verifikation bestanden: vollständige Go-/OpenSSL-Suite ohne Cache, Vet,
Modulprüfung und netzloser Samba-/Executorlauf mit dem korrigierten Runtime-
Encoder. Ein unabhängiger Windows-Dateisperrfehler im bestehenden Updater-Test
wurde ohne Codeänderung gezielt nachgeprüft; Einzel- und vollständiger
Wiederholungslauf bestanden. An Produktionssystemen wurde nichts geprüft oder
geändert.
