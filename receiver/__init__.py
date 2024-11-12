import threading

from scapy.all import sniff

import sniffer
from handler import CONSOLE_LOCK
from receiver import process_packet

if __name__ == "__main__":
    with CONSOLE_LOCK:
        print("Start sniffing...")
    sniffer.start()
    with CONSOLE_LOCK:
        print("Listening for DNS packets...")
    udp_thread = threading.Thread(target=lambda: sniff(filter="udp port 53", prn=process_packet, store=False))
    udp_thread.start()
    udp_thread.join()