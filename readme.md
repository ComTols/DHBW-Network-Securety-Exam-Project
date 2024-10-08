# Network Security Exam Project
Dieses Projekt teilt sich in zwei `C` Programme. Eines der Programme wird auf einem Zielrechner installiert, das andere Programm empfängt die Daten der Malware.

## Anforderungen

### Programm `A` (Malware-Simulation)
- **Textdatei einlesen**: Liest eine vorgegebene Textdatei aus.
- **Daten codieren**: Codiert den Inhalt (z. B. mit Base64).
- **Datenübertragung**: Sendet die codierten Daten über das Netzwerkprotokoll `DNS`.
- **Fehlererkennung und -korrektur**: Stellt die Integrität der Daten sicher und korrigiert Übertragungsfehler.
- **Packet Capture**: Erzeugt während der Übertragung eine pcap-Datei zur Aufzeichnung der Netzwerkkommunikation.

### Programm `B` (Angreifer-Simulation)
- **Daten empfangen**: Empfängt die codierten Daten von Programm `A`.
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

## Programmablauf
1. `A` liest Datei ein und interpretiert als UTF8-Bytes
2. `A` nimmt 100 Byte Block, berechnet Hemming-Korrektur-Summen und fügt diese hinzu
3. `A` kodiert Block mit Base64
4. Der Base64 String wird als Subdomain in der DNS-Anfrage gesetzt und an `B` gesendet
5. `A` fügt Netzwerkaktivität zur pcap-File hinzu
6. `B` extrahiert Subdomain
7. `B` decodiert den Base64 String
8. `B` überprüft die Checksum und korrigiert evtl. Fehler 
   1. `B` gibt `85.143.80.47` zurück, wenn die Daten erfolgreich empfangen wurden
   2. `B` gibt `47.81.64.105` zurück, wenn die Daten nicht erfolgreich empfangen wurden
9. `B` fügt Netzwerkaktivität zur pcap-File hinzu
10. `B` zeigt den String als UTF8 Interpretation auf der Konsole an.