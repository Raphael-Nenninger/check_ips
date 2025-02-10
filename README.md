# PCAP VirusTotal Scanner

## Beschreibung
Dieses CLI-Tool extrahiert IP-Adressen aus einer PCAP-Datei und überprüft sie mithilfe der VirusTotal-API auf potenzielle Bedrohungen. Die Ergebnisse werden sowohl im Terminal ausgegeben als auch in eine Datei geschrieben.

## Voraussetzungen
- Python 3.x
- Abhängigkeiten:
  - `pyshark`
  - `requests`
  - `argparse`
  - `logging`
- Ein gültiger VirusTotal API-Schlüssel
- Wireshark/TShark zur PCAP-Analyse

## Installation
1. Klone das Repository oder lade die Datei herunter.
2. Installiere die benötigten Python-Abhängigkeiten:
   ```sh
   pip install pyshark requests
   ```

## Nutzung
Das Tool wird über die Kommandozeile ausgeführt:
```sh
python pcap_virus_total.py <pcap_datei>
```

### Argumente
- `<pcap_datei>`: Pfad zur PCAP-Datei, die analysiert werden soll.

### Beispiel
Um IP-Adressen aus einer Datei `traffic.pcap` zu analysieren:
```sh
python pcap_virus_total.py traffic.pcap ip
```

## Ausgabe
- Ergebnisse werden in einer Datei gespeichert, z. B. `results_YYYY-MM-DD_HH-MM-SS.txt`.
- Ein Logfile wird generiert, z. B. `pcap_analysis_YYYY-MM-DD_HH-MM-SS.log`.
- Ergebnisse werden auch in der Konsole ausgegeben.

## Hinweise
- Das Tool benötigt Zugriff auf das Internet für Anfragen an VirusTotal.
- Die VirusTotal-API hat eine Anfragebeschränkung für kostenlose Benutzer.
- Falls TShark nicht installiert ist, muss es erst installiert werden (z. B. über `sudo apt install tshark`).

## Lizenz
Dieses Projekt steht unter der MIT-Lizenz.


