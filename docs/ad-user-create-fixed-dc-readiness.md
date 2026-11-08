# Freigabevorbereitung für einen festen Schreib-DC

Für den ersten Betrieb ist genau ein beschreibbarer DC vorgesehen. Der
Executor verwendet einen festen LDAPS-Endpunkt mit geprüfter CA, Domain-GUID
und -SID sowie Invocation ID. Fällt der DC aus oder ändert sich seine
Invocation ID, pausiert die Benutzeranlage. Andere Identity-Anmeldewege
haben ihre eigenen Berechtigungen. Die Profil-CAS-Sperre gilt weiter.

## AD-Rechte

- Eigener Writer mit ausschließlich objektklassenspezifischem CreateChild
  für Benutzer in der fest gepinnten Ziel-OU. Alle direkten und geerbten
  ACEs und Gruppen des Writers prüfen. Breite Schreibrechte, OU-übergreifende
  Delegation und Rechte zur Rechtevergabe schließen die Freigabe aus.
- Im isolierten Samba-Labor war der signierte Add mit der Delegation
  erfolgreich. Nach Entzug des CreateChild-ACE wurde er abgewiesen. Die
  zusätzliche native Grenze verweigerte dem Writer direkte Adds innerhalb
  und außerhalb der Ziel-OU sowie Aktivierung, Passwortänderung, Änderung
  von UPN oder SPN, Gruppenänderung, Verschieben und Löschen. Der bestätigte
  Benutzer blieb deaktiviert. Der Rollenentzug für den Actor wurde separat
  geprüft.
- Vor Freigabe die effektiven Rechte in der vorgesehenen Umgebung anhand
  der tatsächlichen Writer-SID, Ziel-OU und Gruppenmitgliedschaften abnehmen.
  Den UPN-Suffix inventarisieren und alle übrigen Vergabewege einschließlich
  anderer beschreibbarer DCs, Importe und privilegierter Wartung erfassen.
  Der feste Identity-Schreib-DC allein garantiert die Exklusivität des Suffixes
  gegenüber externen Schreibern nicht.

## Schlüsselbetrieb

- Issuer-Schlüssel und Writer-Passwort bleiben beim separaten Executor.
  Der Receipt-Signierschlüssel gehört zur DC-Vertrauensgrenze. Journal- und
  Archivschlüsselmaterial getrennt von den Daten verwahren. Private
  Zustandsdateien sind für die Executor-UID vorgesehen und haben Modus 0600.
  Der Webdienst erhält den gepinnten Unix-Socket und keine privaten
  Writer-, Signier- oder Journaldateien.
- Falsches Writer-Passwort, falscher Issuer, gruppenlesbarer Issuer und falscher
  Journalschlüssel verhindern den Start. Der Laborprozess mit Web-UID kann
  die privaten Dateien nicht lesen. Diese Proben prüfen die Softwaregrenze.
  Die synthetische Fixture nutzt eine gemeinsame Root-Vertrauensgrenze.
- Writer-Passwortwechsel mit gestopptem Executor und anschließendem
  signiertem Readiness-Check planen. Änderungen der Issuer- und Receipt-Pins
  erfordern einen gesonderten Rotationsablauf. Die statischen nativen Pins
  und die Journalbindung brauchen dafür eine geprüfte Übergabe. Vor Freigabe
  Verantwortliche, Verwahrung, Rotation und Verhalten bei Schlüsselverlust
  dokumentieren und abnehmen.

## Rückweg und Freigabekriterien

1. Create im Web deaktivieren und Executor stoppen. Falls der native
   Schreibpfad noch erreichbar ist, die Schreibfreigabe am festen DC
   entziehen. Ausstehende Vorgänge am ursprünglichen DC anhand des
   signierten Receipts prüfen. Unklare Claims bleiben gesperrt.
2. Das bestehende Journal samt Claims erhalten und ein verschlüsseltes
   Offline-Archiv mit zugehöriger Bindung und Schlüsselverwahrung prüfen.
   Restore in einem separaten Zustand dient der lesenden Wiederherstellung.
   Der Executor-Test hat Status und Receipt aus einem solchen Restore
   gelesen sowie neue Pläne und alte Schreibaktionen abgewiesen.
3. Den festen Schreibpfad erst freigeben, wenn Ziel-ACLs, UPN-Namensraum,
   Schlüsselbetrieb und Rückweg abgenommen sind. Das aktuelle native
   Modul und der Adapter sind auf die synthetische Loopback-Fixture
   begrenzt. Ein unabhängig geprüfter installierbarer Schreibpfad sowie
   die Abnahme in der vorgesehenen Umgebung stehen aus.

Der Stand ist eine Freigabevorbereitung. Benutzeranlage bleibt
standardmäßig deaktiviert.
