# Roadmap-Stand

Stand: 2. November 2026. Aktuelle Reihenfolge aus dem Projektauftrag;
historische Versionsüberschriften in AGENTS.md sind keine neuen offenen Aufgaben.

| Bereich | Stand |
| --- | --- |
| Linux-Anmeldung, Self-Service, OIDC/Access, Rollen, Passkeys, Notfallzugang | Implementiert, veröffentlicht und im vereinbarten Umfang abgenommen |
| PostgreSQL, Audit, Observability | Produktiv abgeschlossen |
| Geräteauthentifizierung WYSE01 | Enrollment/Renewal/mTLS und Pflichtmodus abgenommen; MOBILE01 ausgeschlossen |
| Geplante Clientupdates über Adminoberfläche | Für WYSE01 abgeschlossen: Erstauftrag Status1.13.1, Abbruchprobe, Audit, gebundener Rückweg, fünfminütige Stabilität und interaktive Benutzerabnahme bestanden |
| Zertifikatsstatus/Ablauf/Authentifizierungsmodus in Clientverwaltung | In v1.13.0 veröffentlicht und auf LOGIN01 abgenommen |
| Wiederverwendbare Zertifikatsprüfer im Framework | Framework v1.2.0 veröffentlicht, Identity umgestellt und als v1.13.0 ausgerollt |
| AD-Schreibfunktionen | Stufe 1 standardmäßig deaktiviert implementiert; Schutz-, Journal- und isolierte Samba-Tests vorhanden. Positive Runtime-CAS-Abnahme bleibt wegen fehlendem Assertion-Control im Samba-Labor gesperrt; keine Produktivfreigabe |
| Greeter-Redesign | Noch offen: zuerst lokaler klickbarer HTML-Entwurf, nach visueller Freigabe Python/GTK |
| Abschließender Webinterface-/UX-Feinschliff | Noch offen, nach den fachlichen Funktionen |

Wir stehen am **Abschluss der geplanten Clientupdates**. Die beiden danach
genannten Zertifikatsschritte sind bereits erledigt. v1.13.1 ist geschützt
veröffentlicht, aus dem exakten Releasecommit gebaut/signiert und im separat
freigegebenen Fenster über den echten Worker auf WYSE01 ausgeführt.
[Erstauftrag, Abbruchprobe und technische Abnahme](releases/v1.13.1-wyse01-job-acceptance.md)
sind einschließlich interaktiver Desktop/VNC-Bestätigung bestanden.
Die [Aktivierungsabnahme](releases/wyse01-scheduled-updates-acceptance.md) trennt
den leeren Timerbetrieb ausdrücklich vom ersten echten Update. Danach folgt als
nächster fachlicher Entwicklungsblock die AD-Administration. Ihr
[Schutzkonzept](ad-write-security-design.md) ist erarbeitet. Auch die
[Stufe-1-Implementierung mit isoliertem Labor](ad-profile-stage1.md) ist
vorhanden. Der offene technische Freigabepunkt ist ein nachgewiesenes atomares
CAS-Schreibverfahren am Backend; Schutztests und Fixture-Rückweg ersetzen diese
positive Runtime-Abnahme nicht. Keine Produktionsdelegation oder Schreibfreigabe
ist erfolgt.

Die [Samba-CAS-Untersuchung](samba-cas-research.md) hat begrenztes atomares
Wert-CAS demonstriert, aber ABA-/Objektversionslücken und ein Criticality-
Kodierungsproblem nachgewiesen. Damit ist noch kein sicherer Ersatz für den
geforderten Runtime-Vertrag freigegeben; die CAS-Sperre bleibt unverändert.

Eine Gesamtprozentzahl wäre ohne gewichtete Restumfänge irreführend. Der
stabile Identity-Kern, die Zertifikatsarbeit und der WYSE01-Updatebetrieb sind
fertig; offen sind drei größere Funktions-/Gestaltungsblöcke.

Nachgelagerte ältere Ideen (Captive Portal, Windows Credential Provider,
Biometrieforschung) sind keine stillschweigend gestarteten Aufgaben dieser Phase.
ntfy bleibt aus der Roadmap entfernt. Der bewusst ausgelassene erneute Badge/PIN-
Test bleibt nicht blockierend und wird nicht als ausgeführt dargestellt.
