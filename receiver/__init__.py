from scapy.all import sniff

from receiver import process_packet

if __name__ == "__main__":
    print("Listening for DNS packets...")
    sniff(filter="udp port 53", prn=process_packet, store=0)
