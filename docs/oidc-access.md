# StumpfWorks Access über OpenID Connect anbinden

StumpfWorks Identity kann optional als OpenID-Connect-Provider für StumpfWorks
Access betrieben werden. OIDC ist standardmäßig deaktiviert. Badge/PIN, PKINIT,
Clientverwaltung, Adminanmeldung und Self-Service funktionieren ohne aktiviertes
OIDC unverändert weiter.

Identity bestätigt ausschließlich die Identität. Access verwaltet weiterhin alle
Rollen, Policies und physischen Zutrittsrechte. Weder Benutzername noch E-Mail
werden zum automatischen Linking verwendet. Die Verknüpfung erfolgt einmalig und
explizit über das Paar `(issuer, subject)`.

## Fester Homelab-Vertrag

Für den aktuellen Development-Betrieb gelten:

- Identity-Issuer: `https://login01.ad.stumpfworks.de:8080`
- Access-Origin: `https://192.168.178.85:8443`
- Client-ID: `stumpfworks-access`
- Redirect-URI: `https://192.168.178.85:8443/api/v1/auth/oidc/callback`
- Scopes: `openid profile email`
- Flow: Authorization Code mit PKCE S256
- ID-Token-Signatur: RS256

Issuer und Redirect-URI müssen bytegenau mit diesen Werten übereinstimmen. Wird
Access später über einen DNS-Namen veröffentlicht, wird ein neuer exakter
Redirect registriert und `ACCESS_ORIGIN` gemeinsam geändert; eine Wildcard ist
nicht zulässig.

## Signaturschlüssel vorbereiten

Auf LOGIN01 einen ausschließlich für OIDC verwendeten Schlüssel erzeugen. Der
PKINIT-CA-Schlüssel darf nicht wiederverwendet werden:

```sh
install -d -m 0700 /etc/stumpfworks-badge/oidc
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /etc/stumpfworks-badge/oidc/signing-current.pem
chown root:swbadge /etc/stumpfworks-badge/oidc/signing-current.pem
chmod 0640 /etc/stumpfworks-badge/oidc/signing-current.pem
```

Die Datei ist ein Secret und darf weder in Git noch in Logs oder Diagnosepakete
gelangen.

## Identity konfigurieren

Die produktive LOGIN01-Konfiguration erhält:

```yaml
oidc:
  enabled: true
  issuer: "https://login01.ad.stumpfworks.de:8080"
  signing_key_files: "/etc/stumpfworks-badge/oidc/signing-current.pem"
```

Alternativ stehen folgende Umgebungsvariablen zur Verfügung:

```text
SWBADGE_OIDC_ENABLED=true
SWBADGE_OIDC_ISSUER=https://login01.ad.stumpfworks.de:8080
SWBADGE_OIDC_SIGNING_KEY_FILES=/etc/stumpfworks-badge/oidc/signing-current.pem
```

OIDC verlangt den bereits vorhandenen geschützten Directory-Modus und damit die
aktive LDAPS-Anbindung. Discovery ist anschließend unter
`/.well-known/openid-configuration` erreichbar. Authorization, Token und JWKS
liegen unter `/oauth2/authorize`, `/oauth2/token` und `/oauth2/jwks`.

## Access als vertraulichen Client registrieren

Vorher eine konsistente SQLite-Sicherung erstellen. Danach erzeugt das CLI ein
zufälliges Client-Secret, speichert ausschließlich dessen bcrypt-Hash und zeigt
das Secret genau einmal an:

```sh
identity-admin --config /etc/stumpfworks-badge/config.yaml \
  oidc-client create \
  --client-id stumpfworks-access \
  --redirect-uri https://192.168.178.85:8443/api/v1/auth/oidc/callback \
  --scopes "openid profile email"
```

Das ausgegebene Secret unmittelbar in eine root-only Access-Environment-Datei
übernehmen. Es darf nicht in Shell-History, Tickets, Chat, Git oder Logs kopiert
werden. Ein erneuter `create`-Aufruf überschreibt einen bestehenden Client nicht.
Für einen Wechsel dient ausschließlich `oidc-client rotate-secret`.

ACCESS01 benötigt:

```text
ACCESS_ORIGIN=https://192.168.178.85:8443
ACCESS_OIDC_ISSUER=https://login01.ad.stumpfworks.de:8080
ACCESS_OIDC_CLIENT_ID=stumpfworks-access
ACCESS_OIDC_CLIENT_SECRET=<einmalig ausgegebenes Secret>
```

Die Homelab-CA muss auf ACCESS01 im System-Truststore installiert sein, damit
Discovery, JWKS und Tokenaustausch ohne Abschalten der TLS-Prüfung funktionieren.

## Benutzer explizit verknüpfen

Zuerst auf LOGIN01 das stabile Subject des bereits importierten Identity-Benutzers
ermitteln:

```sh
identity-admin --config /etc/stumpfworks-badge/config.yaml \
  oidc-subject --login BENUTZER
```

Danach auf ACCESS01 genau dieses Subject mit einem bereits vorhandenen
Access-Benutzer verbinden:

```sh
ACCESS_ADMIN_DATABASE_URL='postgres://…' \
  /opt/stumpfworks-access/bin/access-admin link-oidc \
  --login ACCESS_BENUTZER \
  --issuer https://login01.ad.stumpfworks.de:8080 \
  --subject IDENTITY_SUBJECT
```

Die Access-Rollen und Zutrittspolicies des vorhandenen Benutzers bleiben
unverändert. Ein nicht verknüpftes Subject wird von Access abgelehnt.

## Schlüsselrotation

1. Aktuelle SQLite-Datenbank, Konfiguration und beide Schlüssel sicher sichern.
2. Einen neuen RSA-Schlüssel als `signing-next.pem` mit Besitzer
   `root:swbadge` und Modus `0640` erzeugen.
3. `signing_key_files` auf `signing-next.pem,signing-current.pem` setzen. Der
   erste Schlüssel signiert neu ausgestellte Tokens; beide öffentlichen Schlüssel
   erscheinen über JWKS.
4. Identity kontrolliert neu starten und Discovery, JWKS und einen Login prüfen.
5. Nach Ablauf aller ID-Tokens zuzüglich Zeitpuffer den alten Schlüssel aus der
   Liste entfernen, den neuen in `signing-current.pem` umbenennen und erneut
   kontrolliert starten.

Bei der aktuellen Tokenlaufzeit sind mindestens zehn Minuten Überlappung
vorgesehen. Ein fehlgeschlagener Wechsel wird durch Wiederherstellen der gesicherten
Konfiguration und Schlüsseldateien zurückgerollt.

## Backup und Wiederherstellung

Zum OIDC-Backup gehören:

- konsistente Identity-SQLite-Sicherung;
- OIDC-Konfiguration;
- aktuelle und während Rotation überlappende private Signaturschlüssel;
- Access-Konfiguration mit dem Client-Secret in einem getrennten Secret-Backup;
- PostgreSQL-Backup von Access einschließlich `external_identities`.

Private Schlüssel und Client-Secrets benötigen verschlüsselte, zugriffsbeschränkte
Backups. Das normale Identity-Diagnosepaket darf sie nicht enthalten.

## Abnahme

1. Discovery und JWKS über verifiziertes HTTPS abrufen.
2. Access-OIDC-Start öffnen und als aktiver Identity-Benutzer anmelden.
3. Callback, Nonce, PKCE und ID-Token-Verifikation müssen erfolgreich sein.
4. Ohne vorheriges Linking muss Access ablehnen.
5. Nach explizitem Linking muss Access eine Sitzung für den vorhandenen Benutzer
   ausstellen.
6. Access-Rollen und physische Grants vor und nach OIDC vergleichen; Identity-
   Claims dürfen sie nicht verändern.
7. Deaktivierten AD-Benutzer, falsches Secret, falsche Redirect-URI, Code-Replay
   und Signaturfehler negativ prüfen.
8. Lokale Access-Anmeldung sowie Badge/PIN, PKINIT und Self-Service von Identity
   als Regression prüfen.

## Reverse Proxy

Bei späterer TLS-Terminierung am Proxy müssen der externe Issuer und alle in
Discovery veröffentlichten Endpunkte weiterhin exakt stimmen. Der Proxy darf
keine beliebigen Hostnamen akzeptieren, keine OIDC-Antworten cachen und keine
Authorization-Header, Codes oder Tokens protokollieren. Direkter HTTP-Betrieb oder
das Abschalten der TLS-Zertifikatsprüfung ist nicht freigegeben.
