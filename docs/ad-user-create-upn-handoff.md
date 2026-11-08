# Exklusive UPN-Vergabe und geplanter DC-Wechsel

Entwurf für die deaktivierte Benutzeranlage. Der [Mehr-DC-Nachweis](ad-user-create-forest-upn.md)
zeigt, dass der lokale UPN-Check und der Global Catalog eine konkurrierende
Vergabe durch mehrere DCs nicht verhindern.

## Exklusive Vergabe

- Ein eigener, forestweit reservierter UPN-Suffix begrenzt den Vertrag auf
  verwaltete Konten. Das Labor verwendet `managed.profile.test` als Beispiel.
  Der produktive Suffix wäre eine separate Policy-Entscheidung. Der Aussteller
  erzeugt den UPN aus dem kanonischen ASCII-Namen und dem festen Suffix.
- Vor Einführung alle Domänen und Schreibwege erfassen. Der Suffix muss frei
  sein oder alle bestehenden Zuweisungen müssen ins Register übernommen werden.
  Der GC dient der Bestandskontrolle. Exklusivität setzt voraus, dass alle
  relevanten Add-, Modify-, Import-, Restore- und Provisionierungspfade die
  Reservierung durchsetzen oder für diesen Suffix wirksam gesperrt sind.
  Ein alternativer Suffix und OU-ACLs allein reichen dafür nicht aus. Privilegierte
  Administratoren, Restore-Werkzeuge und Replikationsquellen gehören zur
  Vertrauensgrenze. Wenn die Grenze nicht durchsetzbar ist, bleibt Create aus.
- Ein dauerhaftes, gemeinsames Register besitzt einen eindeutigen Index auf
  dem kanonischen UPN. Reservierung, Auftragsbindung, Routenprüfung und
  Dispatch-Audit erfolgen atomar vor Versand. Auftrag, Originalbytes und
  Receipt binden dieselbe Policy, Epoche, Domain- und DC-Identität. Reservierungen
  bleiben über Wechsel, Neustart und unklare Ergebnisse erhalten. Kein
  Journalreset, keine automatische Wiedervergabe und kein LDAP-Retry.
- Die aktive Route enthält genau eine Invocation ID und eine monoton steigende
  Epoche. Nur der aktive DC darf Create-Aufträge ausführen. Die native
  Ausführungsgrenze muss alte Epochen auch bei verspäteten, gültig signierten
  Paketen und bestehenden LDAP-Verbindungen zurückweisen. Für eine spätere
  Umsetzung sind eine neue Wire-Version und ein dauerhafter, am Commit
  durchgesetzter Fence erforderlich. Der bestehende DC-Pin bleibt maßgeblich.

## Ablauf und Rückweg

1. Die Route im selben Register einfrieren, das Dispatch-Claims vergibt.
   Prepared-Aufträge des alten DC verfallen oder werden auditiert storniert.
   Bereits versandte Aufträge über den bisherigen DC und seinen gepinnten
   Receipt-Key klären. Ein beobachtetes Objekt oder ein fehlender GC-Treffer
   ersetzt kein Receipt. Bei `applying` oder `uncertain` bleibt die Route zu.
2. Alten Schreibpfad dauerhaft sperren. Eine unabhängige Prüfung muss
   Stillstand beziehungsweise Entzug der nativen Ausführungsberechtigung,
   einschließlich bestehender Verbindungen und verzögerter Aufträge,
   bestätigen. Zeitablauf, Nichterreichbarkeit und eine geänderte DNS-Adresse
   liefern keinen Fence. Beim ungeplanten DC-Verlust gilt dieselbe Sperre.
3. Am neuen DC TLS, Domain-GUID/SID, Invocation ID, OU, Writer, Rolle und
   Receipt-Key neu prüfen. Die Replikation des alten Schreibstands anhand
   des relevanten Originating-USN-/Invocation-ID-Fortschritts und der
   bestätigten Objektidentitäten nachweisen. Ein lokaler USN-Vergleich zwischen
   DCs reicht dafür nicht. Das Register und seine Claims vollständig erhalten.
4. Erst nach erfolgreicher Prüfung und dokumentierter Freigabe die neue
   Epoche atomar veröffentlichen und neue Pläne zulassen. Audit speichert
   alte und neue Route, Freigabe, Fence- und Replikationsnachweise sowie
   Ergebnisreferenzen ohne Kennwörter oder Rohpakete. Bei Abbruch bleibt die
   Route eingefroren. Die Rückkehr zum alten DC erfordert denselben
   Übergabeprozess mit einer weiteren Epoche.

## Labornachweis und Grenzen

Das ausführbare SQLite-Modell prüft konkurrierende Schreibweisen,
Neustart und dauerhafte Reservierung, die Ablehnung alter Routen sowie
Sperren bei fehlendem Fence, fehlender Replikation, fehlender Exklusivität
oder unklarem Dispatch. Externe Nachweise sind im Modell boolesche Eingaben.
Die vorhandene Samba-Zwei-DC-Probe ist der Gegenversuch ohne Exklusivgrenze.

```powershell
$lab = (Resolve-Path scripts/ad-profile-lab).Path
docker --context desktop-linux run --rm --network none `
  --mount "type=bind,source=$lab,target=/lab,readonly" `
  --entrypoint python3 identity-ad-profile-lab:native -B /lab/create_handoff_research.py
```

Vor einer Implementierungsfreigabe bleiben die native Fence-Durchsetzung,
die Forest-weite Rechteprüfung, ein echter positiver DC-Wechsel und
Crash-/Restore-Tests für das gemeinsame Register offen. Die CAS-Sperre und
die standardmäßige Deaktivierung bleiben bestehen.
