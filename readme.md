# Network Security Exam Project
Dieses Projekt teilt sich in zwei `C` Programme. Eines der Programme wird auf einem Zielrechner installiert, das andere Programm empfängt die Daten der Malware.

## Anforderungen

### Programm `A` (Malware-Simulation)
- **Textdatei einlesen**: Liest eine vorgegebene Textdatei aus.
- **Daten codieren**: Codiert den Inhalt (z. B. mit Base64).
- **Datenübertragung**: Sendet die codierten Daten über das Netzwerkprotokoll ICMP oder DNS.
- **Fehlererkennung und -korrektur**: Stellt die Integrität der Daten sicher und korrigiert Übertragungsfehler.
- **Packet Capture**: Erzeugt während der Übertragung eine pcap-Datei zur Aufzeichnung der Netzwerkkommunikation.

### Programm `B` (Angreifer-Simulation)
- **Daten empfangen**: Empfängt die codierten Daten von Programm A.
- **Daten decodieren**: Decodiert die empfangenen Daten zurück in Klartext.
- **Bildschirmausgabe**: Gibt den Klartext vollständig und korrekt aus.
- **Fehlererkennung und -korrektur**: Überprüft die Integrität der empfangenen Daten und korrigiert eventuelle Fehler.
- **Packet Capture**: Erzeugt während des Empfangs eine pcap-Datei zur Aufzeichnung der Netzwerkkommunikation.

## Projektaufbau
Jede der beiden Applikationen folgt folgender Projektstruktur:
```txt
├── bin                     the executable (created by make)
├── build                   intermediate build files e.g. *.o (created by make)
├── docs                    documentation
├── include                 header files
├── lib                     third-party libraries
├── scripts                 scripts for setup and other tasks
├── src                     C source files
│   ├── main.c             (main) Entry point for the CLI
│   └── *.c
├── .gitignore
├── LICENSE
├── Makefile
└── README.md
```