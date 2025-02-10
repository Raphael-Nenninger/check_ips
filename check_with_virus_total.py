import argparse
import pyshark
import requests
from datetime import datetime
from time import sleep

VIRUSTOTAL_API_KEY = ""
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/"


def extract_ips_from_pcap(pcap_file):
    ips = set()
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    for packet in cap:
        try:
            if hasattr(packet.ip, "src"):
                ips.add(packet.ip.src)
            if hasattr(packet.ip, "dst"):
                ips.add(packet.ip.dst)
        except AttributeError:
            continue

    cap.close()
    return ips


def check_virustotal(resource):
    sleep(15)  # Wartezeit, um API-Rate-Limits zu vermeiden
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"{VIRUSTOTAL_URL}ip_addresses/{resource}", headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        malicious_count = (
            json_response.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0)
        )
        return malicious_count
    return 0


def save_results(filename, results):
    with open(filename, "w") as f:
        for result in results:
            f.write(result + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extrahiert Hosts oder IPs aus einer PCAP-Datei und überprüft sie bei VirusTotal."
    )
    parser.add_argument("pcap", help="Pfad zur PCAP-Datei")
    args = parser.parse_args()

    results = []

    ips = extract_ips_from_pcap(args.pcap)
    for ip in ips:
        malicious_count = check_virustotal(ip)
        result = f"IP: {ip} - Malicious Detections: {malicious_count}"
        results.append(result)

    result_filename = "result.txt"
    save_results(result_filename, results)
