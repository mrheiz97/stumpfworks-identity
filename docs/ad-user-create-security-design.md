# Sichere Benutzeranlage über Identity

Fortschreibung: [Umgesetzter Laborablauf](ad-user-create-lab.md) mit Plan,
HTML-Bestätigung, nativer deaktivierter Anlage und signierter Ergebnisbindung.
Die folgenden Betriebsfreigaben bleiben offen; keine Runtime-Aktivierung.

Stand: 4. November 2026. **Konzept, keine Implementierung oder Freigabe.**
Nur development; keine Produktivkontakte, keine GitHub-Läufe, MOBILE01 ausgeschlossen.
CAS-Sperre und Default-off bleiben bestehen. Ergänzt das
[AD-Schreibschutzkonzept](ad-write-security-design.md), ersetzt dessen Regeln nicht.

## Umfang und Rechte

Erster Lieferumfang: genau einen gewöhnlichen Benutzer aus einer versionierten
Vorlage **deaktiviert** in einer fest gepinnten ManagedUsers-OU erstellen.
Passwortsetzung, Gruppenaufnahme und Aktivierung sind eigene, zunächst gesperrte
Aktionen. Kein Kopieren bestehender Konten, keine freien DNs/Attribute, keine
Dienst-/Admin-/Computerobjekte, kein Import oder automatisches Löschen.

| Grenze | Entscheidung |
| --- | --- |
| Bedienung | Neue Permission `directory.users.create`, keine Übernahme heutiger Adminrechte; normale frische AD-Anmeldung ≤5min, aktionsgebundene Einmalbestätigung, CSRF/Origin-Prüfung |
| Delegation | Separates Anlagecredential; nur nötiges Create-Child für Benutzer in der festen OU und nachgewiesene Attributrechte; kein GenericAll/GenericWrite, WriteDACL/Owner, Delete, Gruppen- oder Passwortrecht |
| Vorlage | Nur CN, sAMAccountName, UPN, displayName/givenName/sn/mail und serverseitig festgelegter gewöhnlicher deaktivierter Kontotyp; keine SPN, Delegation, KeyCredentials, SIDHistory, frei wählbaren UAC-/primaryGroupID-Werte oder ACLs |
| Identität | Domain-/DC-Invocation und OU-GUID gepinnt; OU-DN frisch auflösen und Lage/ACL/Schutz prüfen; neue objectGUID/SID erst aus bestätigtem DC-Ergebnis übernehmen |
| Grenzen | Ein globaler Anlageauftrag gleichzeitig, höchstens 5 pro Actor/Stunde als konservativer Startwert; kurze feste Such-/Ausführungslimits, keine automatischen Schreibwiederholungen |

Create-Child ist eine echte Zusatzbefugnis: Eine UI-Allowlist begrenzt ein
gestohlenes LDAP-Credential nicht. Effektive Add-Rechte einschließlich expliziter
Attribute, Owner/DACL und nachträglicher Änderungsrechte müssen mit **direktem LDAP**
angegriffen werden. Falls die ACL-Grenze die Vorlage nicht erzwingt, ist vor
Freigabe eine eng begrenzte DC-native Create-Operation samt gesperrtem Roh-Add
nötig. Keine Delegation als vermeintlich ausreichend voraussetzen.

## Auftrag, Konkurrenz und Ergebnis

1. Vorlage, erlaubtes UPN-Suffix, Namenssyntax/-längen und vollständige
   Namenskonflikte prüfen. Eingaben eindeutig kanonisieren und Ergebnis anzeigen;
   keine stillen Ersatznamen oder dynamischen Suffixe bei Konflikten.
2. Verschlüsselten unveränderlichen Plan speichern: zufällige ID, Actor-SID,
   Domain/DC/OU-GUID, Vorlage-/Policyrevision, gewünschte Namen und Profildaten,
   Digest, Ablauf ≤5min. Vor Anlage existiert **keine** Ziel-GUID; keine fremde
   GUID allein durch Namensfund an den Auftrag binden.
3. Bestätigung frisch autorisieren; dauerhaften Identity-Claim und Audit vor
   Versand committen. Signierter typisierter Create-Auftrag mit eigener
   Protokollversion/Aktionskennung; SWCAS002 unverändert nur für Profil-Modify.
   Kein Wiederverwenden seiner Parser oder Receipts ohne neuen Vertrag/Review.
4. DC-seitig Autorisierung, OU/Vorlage und Konflikte prüfen; Add mit dauerhaftem
   operationsgebundenem Claim und bestätigtem Receipt durchführen. Receipt bindet
   Aktion/ID/Digest/Actor/Policy/OU/DC und die **neu erzeugte** GUID/SID/Commit-USN
   sowie den deaktivierten Sollzustand. Terminalnachweis erst nach Commit.
5. Identity meldet nur bestätigten Erfolg. Fehlende oder ungültige Antwort,
   Crash oder Ergebniscommitverlust sperrt Auftrag **und dieselben reservierten
   Namen** als unklar; auch frische IDs dürfen keine Doppelanlage auslösen.
   Statusabfrage ist read-only, signiert und noncegebunden. Unbekannt bedeutet
   keinen bewiesenen Abbruch. Kein automatisches Adoptieren eines Namensfunds.

Eine Vorab-Suche reserviert keine Namen. sAMAccountName muss domänenweit und UPN
forestweit konfliktfrei sein; identischer CN allein genügt nicht. Externe Writer
und mehrere DCs umgehen einen Identity-Lock. Vor Freigabe sind die konkreten
Samba-Add-/Eindeutigkeits- und Replikationsregeln experimentell nachzuweisen.
Ohne belastbare domänen-/forestweite Konkurrenzgrenze bleibt Create gesperrt;
ein gepinnter DC allein löst dieses Problem nicht.

## Spätere Fertigstellung und Rückweg

Passwortsetzung: eigenes Recht/Credential, geprüfter TLS-Weg, Secret nur kurz im
Speicher und über geschützten Übergabekanal; niemals Plan, Journal, Audit, URL
oder Logs. Bei verlorenem Ergebnis kein Retry und keine Aktivierung. Ein neuer
Reset verlangt neue Autorisierung; alte Passwörter sind nicht wiederherstellbar.

Gruppen nur per eigener erlaubter Mitgliedschaftskante auf GUID/SID-Allowlist,
keine Rollen-/Admin-/verschachtelte Privilegierung. Aktivierung verlangt eigene
Permission `directory.users.activate`, zweite unabhängige berechtigte Person,
bestätigte Vorstufen und frische Prüfung von GUID/SID/OU/USN, Passwortstatus,
Gruppen und Schutzattributen. Kein blindes UAC-Replace: UAC-Rechte ermöglichen
mehr als das Aktivieren und brauchen eine eigene wirksame Servergrenze.

Rückweg: vor Claim abbrechen. Nach bestätigter Anlage bleibt das Konto deaktiviert;
kein automatisches Löschen oder Entfernen fremder Änderungen. Bei Drift oder
Unklarheit isolierte manuelle Klärung durch gesondert Berechtigte. Nach späterer
Aktivierung ist Deaktivieren eine neue autorisierte Operation und widerruft
nicht automatisch bestehende Sitzungen/Tickets. Kein Gesamtrollbackversprechen.

Audit: Operations-/Parent-ID, Actor/Bestätiger, Domain/DC/OU-/Zielreferenzen,
Aktion, Vorlage-/Policyrevision, Zustand und begrenzter Fehlercode. Keine Namen,
Profilwerte, Passwörter oder Passwort-Hashes im Audit; notwendige Planwerte nur
verschlüsselt mit begrenzter Retention. Auditfehler vor Versand sperrt Schreiben.
Featureabschaltung verhindert neue Aufträge, erhält Journale und offene Claims.

## Pflichtnachweise vor Implementierungsfreigabe

| Laborprobe | Erwartung |
| --- | --- |
| Roh-Add mit fremder OU, Klasse, UAC, SPN, ACL, Gruppen oder Passwort | Keine Ausweitung der Vorlage; andernfalls Architektur sperren |
| Zwei Identity-Aufträge und externer LDAP-Writer mit gleichen SAM-/UPN-Namen, auch an anderem DC | Kein unentdecktes Duplikat; echte Eindeutigkeitsgrenze belegen |
| OU-Verschiebung/-Ersetzung, Rollen-/ACL-Entzug nach Planung | Ablehnung vor Add; keine Namens-/DN-Verwechslung |
| Crash vor/nach Add-Commit, verlorene LDAP-/DB-Antwort | Signiert zuordenbarer Zustand, keine Wiederholung/Adoption, Namenssperre bleibt |
| Falsche Aktion, Signatur, Nonce, Policy, Frist oder fremde neue GUID im Receipt | Fail-closed; kein Erfolg oder Aktivierung |
| Passwort-/Gruppenfehler, fremde Änderung, Restore/Replikation | Konto bleibt gesperrt; keine automatische Löschung/Aktivierung |

Reihenfolge: isolierter Create-Laborvertrag → unabhängiger Review und effektive
Delegationsnachweise → typisierte Identity-Anbindung → separate Freigabe.
Die bestandenen Profil-CAS-v2-Tests ersetzen **keinen** dieser Create-Nachweise.

Primärgrundlagen: Microsoft beschreibt die Anlage deaktivierter Konten und
erforderliche Attribute unter [Creating a User](https://learn.microsoft.com/en-us/windows/win32/ad/creating-a-user)
sowie Namensidentitäten unter [User Naming Attributes](https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties).
Dies sind AD-DS-Verträge, kein Nachweis der konkreten Samba-Version.
