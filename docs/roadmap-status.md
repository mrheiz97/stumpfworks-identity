# Roadmap-Stand

Stand: 2. November 2026. Aktuelle Reihenfolge aus dem Projektauftrag;
historische Versionsüberschriften in AGENTS.md sind keine neuen offenen Aufgaben.

| Bereich | Stand |
| --- | --- |
| Linux-Anmeldung, Self-Service, OIDC/Access, Rollen, Passkeys, Notfallzugang | Implementiert, veröffentlicht und im vereinbarten Umfang abgenommen |
| PostgreSQL, Audit, Observability | Produktiv abgeschlossen |
| Geräteauthentifizierung WYSE01 | Enrollment/Renewal/mTLS und Pflichtmodus abgenommen; MOBILE01 ausgeschlossen |
| Geplante Clientupdates über Adminoberfläche | Software/Migration7 in v1.13.0 veröffentlicht; Server und WYSE01-Status/Updater produktiv. Worker, leerer Stable-Katalog und Timer im freigegebenen Fenster aktiviert; erster geplanter neuer Releaseauftrag noch offen |
| Zertifikatsstatus/Ablauf/Authentifizierungsmodus in Clientverwaltung | In v1.13.0 veröffentlicht und auf LOGIN01 abgenommen |
| Wiederverwendbare Zertifikatsprüfer im Framework | Framework v1.2.0 veröffentlicht, Identity umgestellt und als v1.13.0 ausgerollt |
| AD-Schreibfunktionen | Noch offen: zuerst Least-Privilege-Konzept, Schutz privilegierter Konten, Audit und Rückweg; keine AD-Schreibfreigabe aus diesem Auftrag |
| Greeter-Redesign | Noch offen: zuerst lokaler klickbarer HTML-Entwurf, nach visueller Freigabe Python/GTK |
| Abschließender Webinterface-/UX-Feinschliff | Noch offen, nach den fachlichen Funktionen |

Wir stehen am **Betriebsabschluss der geplanten Clientupdates**. Die beiden danach
genannten Zertifikatsschritte sind bereits erledigt. Nächster Betriebsschritt ist
ein erster echter Auftrag mit einem neueren freigegebenen
Stable-Release. Die installierte v1.13.0 wird nicht als Test erneut installiert.
Ein [signierter v1.13.1-Statuskandidat](releases/v1.13.1-wyse01-planned-job.md)
mit tatsächlicher1.13.0-Worker-/Rollbackprobe ist lokal vorbereitet; geschützt
veröffentlichtes Release und produktives Wartungsfenster bleiben offen.
Die [Aktivierungsabnahme](releases/wyse01-scheduled-updates-acceptance.md) trennt
den leeren Timerbetrieb ausdrücklich vom ersten echten Update. Danach folgt als
nächster fachlicher Entwicklungsblock die AD-Administration; diese wird hier
nicht begonnen.

Eine Gesamtprozentzahl wäre ohne gewichtete Restumfänge irreführend. Der
stabile Identity-Kern und die Zertifikatsarbeit sind fertig; offen sind der
genannte Update-Betriebsschritt und drei größere Funktions-/Gestaltungsblöcke.

Nachgelagerte ältere Ideen (Captive Portal, Windows Credential Provider,
Biometrieforschung) sind keine stillschweigend gestarteten Aufgaben dieser Phase.
ntfy bleibt aus der Roadmap entfernt. Der bewusst ausgelassene erneute Badge/PIN-
Test bleibt nicht blockierend und wird nicht als ausgeführt dargestellt.
