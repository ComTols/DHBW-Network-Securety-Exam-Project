# Regeln
all: bin/Receiver
	$(MAKE) run  # Nach dem Build automatisch das run-Target aufrufen

# Regel zum Erstellen der ausführbaren Datei
bin/Receiver: build/main.o
	@mkdir -p bin  # Binärverzeichnis erstellen, falls es nicht existiert
	gcc -Wall -g -o bin/Receiver build/main.o

# Regel zum Kompilieren der main.c in eine .o Datei
build/main.o: src/main.c
	@mkdir -p build  # Build-Verzeichnis erstellen, falls es nicht existiert
	gcc -Wall -g -c src/main.c -o build/main.o

# Regel zum Ausführen der ausführbaren Datei
run:
	@echo ""
	@echo ""
	./bin/Receiver
	@echo ""
	@echo ""

# Bereinigen der erstellten Dateien
clean:
	rm -rf build bin
