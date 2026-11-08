# Nativer Create-Fence im Zwei-DC-Labor

Der [Übergabeentwurf](ad-user-create-upn-handoff.md) ist für zwei beschreibbare
Samba-DCs derselben synthetischen Domäne als native Laboroperation umgesetzt.
Der Modus wird ausschließlich durch den isolierten Testaufbau einkompiliert.
Der [Identity-Executor](ad-user-create-native-executor.md) kann mit expliziter
Epoche das neue Protokoll nutzen und bleibt standardmäßig deaktiviert.

## Ausführungsgrenze

- `SWNEW002` ergänzt hinter dem bestehenden 200-Byte-Header eine signierte
  64-Bit-Epoche in Big Endian. Der Fence-Modus verweigert `SWNEW001`.
  Invocation ID, Signatur, Writer und Policy werden weiterhin nativ geprüft.
  Der Name muss bereits kanonisches ASCII sein. Samba erzeugt selbst den UPN
  mit dem festen Suffix `@managed.profile.test`.
- Beide DCs lesen dieselbe private Routen- und Reservierungsablage. Auf dem
  stabilen Lock-Inode hält der native Add einen exklusiven, nichtblockierenden
  Fence von der Routenprüfung bis zum Ende der DSDB-Transaktion einschließlich
  Journalabschluss. Der Übergabecontroller benutzt dieselbe Sperre und ersetzt
  den Routendatensatz atomar. Eine eingefrorene Route hat keine aktive
  Invocation ID. Fehler, fehlende Dateien und Sperrkonflikte verweigern den Add.
- Die dauerhafte UPN-Reservierung bindet den kanonischen Namen an den Digest
  des signierten Auftragskörpers. Sie wird vor der Mutation exklusiv angelegt
  und synchronisiert. Ein identischer Auftrag unter derselben Route gelangt
  zur bestehenden Journalprüfung. Andere Aufträge können den Namen auch nach
  dem Wechsel nicht übernehmen. Unvollständige oder verwaiste Reservierungen
  bleiben gesperrt. Die lokalen Journale und Receipt-Schlüssel bleiben je DC
  getrennt.
- In dieser synthetischen Domäne sperrt das Modul direkte UPN-Adds und
  UPN-Modifikationen auch für den getesteten LDAP-Administrator. Geprüft
  wurden der LDAP-Attributname und seine numerische OID. Der signierte
  Create schreibt über den normalen nachgelagerten DSDB- und ACL-Pfad.
  Replikation und lokale Root-/Restore-Pfade gehören zur Labor-Vertrauensgrenze.

## Nachgewiesener Wechsel

1. DC2 tritt per Samba-DC-Join bei und erhält sein eigenes natives Modul mit
   eigenen Pins und Schlüsseln. Solange DC1 in Epoche 1 aktiv ist, scheitert
   der signierte Add auf DC2. Ein gehaltener Fence sperrt auch den aktiven DC.
2. DC1 legt ein deaktiviertes Konto an. Der Test liest auf DC2 vor der
   Replikation keinen Treffer. Danach friert der Controller die Route ein.
   Ein gültig signierter, verzögerter Auftrag auf DC1 wird abgewiesen.
   Das authentifizierte Receipt bleibt lesbar.
3. Der Test repliziert die Domänenpartition per DRS in den gestoppten DC2.
   Nach dessen Neustart vergleicht er den UPN-Treffer, UAC 514 und die
   Objekt-GUID mit dem authentifizierten Receipt. Der Controller vergleicht
   auch den Digest mit der vollständigen Reservierungsliste der Testfixture.
   Ein abweichender Digest lässt die Route eingefroren.
4. Der Controller aktiviert DC2 in Epoche 2. DC1 bleibt erreichbar und
   verweigert den alten Auftrag weiterhin. DC2 verweigert Epoche 1 und
   die Wiedervergabe des reservierten UPN. Ein frischer Auftrag in Epoche 2
   legt ein weiteres deaktiviertes Konto an.

Zusätzlich bestanden sieben native Create-Vertragstests, die Identity- und
Executor-Labortests sowie die 17 und neun nativen Profiltests für v1 und v2.

## Ausführung und Rückweg

```powershell
$lab = (Resolve-Path scripts/ad-profile-lab).Path
docker --context desktop-linux run --rm --network none --hostname dc1 `
  -e IDENTITY_CREATE_FENCE_LAB=1 `
  --mount "type=bind,source=$lab,target=/lab,readonly" `
  --entrypoint python3 identity-ad-profile-lab:native -B /lab/create_native_handoff.py
```

Die Fixture hat nur Loopback und keine veröffentlichten Ports. Beim Abbruch
bleibt eine eingefrorene Route gesperrt. Ein Rückwechsel erfordert eine
erneute geprüfte Übergabe mit höherer Epoche und erhaltenen Claims.
Der Entwicklungsrückweg ist das Zurücknehmen des Laborcommits. Die Fixture
wird mit dem Container verworfen.

Für den vollständigen Identity-Test zusätzlich `IDENTITY_CREATE_V2_LAB=1`
übergeben und die lokal für Linux/amd64 gebauten Programme `adprofile.test`
und `create-executor` schreibgeschützt unter `/tests` einhängen. Der Runner
startet die Identity- und Executor-Tests nach dem Wechsel auf DC2. Sie prüfen
den UPN im Webplan, signierten Versand, Receipt und Readback, alte Epochen und
Protokolldowngrade, erneute Rollenprüfung, Audit und Auftragsbindung nach
verlorener Antwort. Die [Journal-Übergabeprobe](ad-user-create-journal-handoff.md)
führt außerdem ein auf DC1 erzeugtes Journal auf DC2 weiter.

Die gemeinsame Sperre gilt auf einem Host und einem lokalen Dateisystem.
Der Controller ist ein Testszenario für einen bekannten Auftrag. Eine
verteilte Fence-Autorität, Forest-weite Rechte über mehrere Domänen,
allgemeine Replikations-Watermarks und Crash-/Restore-Abnahme über getrennte
Hosts bleiben offen. Die CAS-Sperre gilt weiter.
