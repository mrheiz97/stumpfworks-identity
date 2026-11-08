# Vorbereitung eines Create-Fence über getrennte Hosts

Der aktuelle Samba-Nachweis verwendet einen gemeinsamen lokalen Lock-Inode.
Für getrennte Hosts braucht die Übergabe eine linearisierbare Schreibautorität
und einen überprüfbaren Entzug der alten Ausführungsberechtigung.

## Vorgesehene Sicherheitsgrenze

- Eine unabhängige Quorum-Autorität hält pro Namensraum die aktive Invocation
  ID, Host-/Boot-Identität, Epoche, Freeze-Phase und dauerhafte UPN-/Dispatch-
  Claims. Eine Transaktion prüft die aktuelle Route und reserviert den Namen
  vor einem Add. Ohne Quorum gibt es keine neue Schreibfreigabe.
- Ein DC startet standardmäßig gesperrt. Er darf eine Freigabe nur für seine
  konkrete Boot- und Invocation-ID sowie für exakt einen Auftragsdigest
  ausführen. Die Freigabe darf kein Retry oder keine Übernahme eines fremden
  Auftrags zulassen. Ein ausstehender Claim bleibt über Ausfall und Neustart
  gesperrt. Ein ausbleibendes Receipt blockiert die Freigabe des Ziel-DCs.
- Eine geplante Übergabe friert zunächst die Vergabe ein, klärt offene
  Dispatches am Ursprungs-DC und prüft die replizierte Objektidentität samt
  Ursprungs-Watermark. Anschließend muss eine unabhängige Instanz das
  Ausführen auf dem alten Host nachweislich unterbinden. Für einen ersten
  Mehrhostversuch ist ein bestätigter Hypervisor-Power-Fence mit gesperrtem
  Autostart der einfachste zu prüfende Kandidat. DNS, eine Zeitüberschreitung,
  abgelaufene Leases oder ein erreichbarer Global Catalog liefern dafür
  keinen ausreichenden Nachweis.
- Die Freigabe des Ziel-DCs ist ein eigener Quorum-Commit in höherer Epoche.
  Fence- und Replikationsnachweise müssen an Quellroute und Zielroute
  gebunden sein. Die neue Route darf auch nach Restore oder Neustart
  keine frühere Epoche oder bereits vergebene UPNs wieder freigeben.
  Eine Rückkehr ist eine weitere Übergabe unter denselben Bedingungen.

## Testgrenze

`scripts/ad-profile-lab/create_distributed_fence_model.py` prüft die
Zustandsregeln bei Quorumverlust, ausstehendem Dispatch, falschem Receipt,
fehlenden Nachweisen und neu gestarteter Boot-Identität. Die Eingaben stehen
für bereits verifizierte externe Nachweise. Der Modelltest misst weder
Quorum-Konsens noch die Wirksamkeit eines Hypervisor-Fence.

Die nächste Abnahme braucht zwei getrennte, synthetische DC-Hosts und eine
separate Autorität. Zu prüfen sind asymmetrische Partitionen, ein verzögertes
bereits freigegebenes Paket, der Wiederanlauf eines alten Hosts, Quorum-
Restore mit veraltetem Snapshot und der Replikationsnachweis über mehrere
Hosts. Bis dahin gilt der Nachweis für den gemeinsamen Laborhost.
