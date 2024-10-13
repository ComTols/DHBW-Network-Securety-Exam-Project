# Network Security Exam Project
Dieses Projekt teilt sich in zwei `C` Programme. Eines der Programme wird auf einem Zielrechner installiert, das andere Programm empfängt die Daten der Malware.

## Setup
Verwende `MinGW` zum Kompilieren des Programms:
1. Lade `mingw-get-setup.exe` [hier](https://sourceforge.net/projects/mingw/) herunter.
2. Führe `mingw-get-setup.exe` als Administrator aus.
3. Installiere `MinGW` z.B. unter diesem Pfad: `C:\MinGW`
4. Wähle die Pakete aus, die du installieren möchtest
   1. `mingw32-gcc` (`bin, dev, doc, lang`)
   2. `mingw32-gcc-g++` (`bin, dev, doc`)
   3. `mingw32-gdb` (`bin, doc`)
   4. `mingw32-make` (`bin, doc`)
   5. `msys-make` (`bin, doc`)

![Pakete zur installation auswählen](https://github.com/ComTols/DHBW-Network-Securety-Exam-Project/blob/main/docs/src/MinGW-install.png?raw=true)

5. Füge den Installationspfad den Umgebungsvariablen hinzu, z.B. `C:\MinGW\bin`. Achte darauf, dass du vorherige Installationen von C-Compiler (z.B. Cygwin) aus den Umgebungsvariablen entfernst.
6. Starte den PC neu.
7. Öffne das Projekt in C-Lion. Tipp: Um besser arbeiten zu können, öffne nur den Ordner `malware` oder `receiver` in C-Lion und nicht den übergeordneten Projektordner.
8. Gehe zu File | Settings | Build, Execution, Deployment | Toolchains und stelle sicher, dass auf die korrekte Installation verwiesen wird.

![Toolchain settings](https://github.com/ComTols/DHBW-Network-Securety-Exam-Project/blob/main/docs/src/MinGW-toolchains-settings.png?raw=true)

9. Gehe zu File | Settings | Build, Execution, Deployment | Build Tools | Make und stelle sicher, dass auf die correlate Installation verwiesen wird. (Z.B. `C:\MinGW\bin\mingw32-make.exe`)
10. Füge als Run-Konfiguration ein `Makefile Target` hinzu und verweise auf die jeweilige Datei, um das Programm auszuführen.

![Run-Konfiguration](https://github.com/ComTols/DHBW-Network-Securety-Exam-Project/blob/main/docs/src/Run-configuration.png?raw=true)


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