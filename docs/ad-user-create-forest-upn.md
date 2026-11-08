# Mehr-DC-Prüfung der Benutzeranlage

Am 5. November 2026 mit Samba 4.17.12-Debian im netzlosen Labor geprüft.
Zwei beschreibbare DCs derselben synthetischen Domäne PROFILE.TEST hatten
dieselbe Domänen-SID und unterschiedliche Invocation IDs. DC2 wurde per
echtem DC-Join mit Replikation von Domäne, Konfiguration und Schema aufgebaut.

| Probe | Beobachtung |
| --- | --- |
| Zweiter Add mit demselben UPN auf DC1, andere Schreibweise und anderer SAM-Name | LDAP 19 (Constraint Violation) |
| Add auf DC2, bevor der Eintrag von DC1 dort sichtbar war | Beide DCs akzeptierten je ein deaktiviertes Konto |
| Inkrementeller DRS-Abgleich in beide Richtungen | Beide DCs lieferten anschließend zwei Objekt-GUIDs für denselben UPN. Beide Konten blieben deaktiviert (UAC 514). |
| Global Catalog auf DC1, Port 3268 | Die Suche im Domänen-Naming-Context lieferte ebenfalls beide Objekte. |
| Signierte native Create-Regression | Ein bereits lokal sichtbarer, großgeschriebener UPN mit fremdem SAM-Namen sperrte den nativen Add. Signierte Aufträge mit abweichender DC-Bindung wurden abgewiesen. |

Die Kollision wurde mit gewöhnlichen authentifizierten LDAP-Adds eines
Laboradministrators erzeugt. Damit ist die Forest-weite Eindeutigkeit schon
für einen Forest mit einer einzigen Domäne widerlegt. Ein zweiter Domain-Naming-
Context sowie das Verhalten regulärer standortübergreifender Replikation bleiben
ungeprüft. Der DRS-Test importierte jeweils in den gestoppten Ziel-DC per
`samba-tool drs replicate --local`. Die native Create- und Executor-Regression
lief separat auf dem gepinnten Einzel-DC.

## Auswirkung auf den Create-Vertrag

Der native Add sucht nach SAM-Name und UPN im lokalen Domänen-Naming-Context
innerhalb der DSDB-Transaktion. Die Identity-Reservierung gilt für das eigene
Journal. Ein externer Schreiber auf einem anderen DC kann beide Grenzen umgehen.
Eine GC-Vorabfrage kann sichtbare Kollisionen melden. Zwischen dieser Abfrage
und dem Add kann ein anderer DC denselben Namen vergeben.

Der Adapter bindet Aufträge und Receipts an die Invocation ID. Bei Ausfall oder
abweichender Invocation ID bleibt der Auftrag am ursprünglichen DC gebunden.
Auf DC2 sichtbare Benutzerobjekte ersetzen kein signiertes Receipt. Offene
Claims bleiben erhalten. Vor einer Freigabe wäre eine durchgesetzte exklusive
Vergabe des vorgesehenen UPN-Namensraums nötig, einschließlich aller anderen
Schreibwege und des Vorgehens bei DC-Wechsel und Wiederherstellung.

## Wiederholung im Labor

Vom Repository aus mit dem vorhandenen Laborimage starten.

```powershell
$lab = (Resolve-Path scripts/ad-profile-lab).Path
docker --context desktop-linux run --rm --network none --hostname dc1 `
  -e IDENTITY_CREATE_FOREST_LAB=1 `
  --mount "type=bind,source=$lab,target=/lab,readonly" `
  --entrypoint python3 identity-ad-profile-lab:native -B /lab/create_forest_research.py
```

Der Container hat nur Loopback und keine veröffentlichten Ports. Der Join nutzt
ein frisch erzeugtes Fixture-Kennwort im Prozessspeicher. Alle Änderungen an
Konten, Konfiguration und Replikationsdaten enden mit dem Wegwerfcontainer.
Für den Entwicklungsrückweg genügt das Zurücknehmen des Test- und Dokucommits.
Die Benutzeranlage bleibt standardmäßig deaktiviert und die CAS-Sperre gilt weiter.
