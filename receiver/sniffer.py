import scapy.all as scapy
import threading
import os
import time

from scapy.utils import PcapWriter

from handler import CONSOLE_LOCK


def sniff_adapter(adapter, file_name):
    #with CONSOLE_LOCK:
    #    print(f"Starting sniffing on {adapter}... Writing to {file_name}")
    pcap_writer = PcapWriter(file_name, append=True, sync=True)
    scapy.sniff(iface=adapter, prn=lambda pkt: pcap_writer.write(pkt), store=False)
    #with CONSOLE_LOCK:
    #    print(f"Finished sniffing on {adapter}.")


def start():
    adapters = scapy.get_if_list()
    threads = []

    output_dir = "cap"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for adapter in adapters:
        file_name = os.path.join(output_dir, f"{adapter.replace("\\", "_")}.pcap")
        thread = threading.Thread(target=sniff_adapter, args=(adapter, file_name))
        thread.daemon = True
        threads.append(thread)
        thread.start()

