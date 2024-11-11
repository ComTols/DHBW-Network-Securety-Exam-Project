import math
import threading
import zlib
from asyncio import timeout
from threading import Lock
from time import sleep
from typing import Dict

import scapy.packet
from scapy.layers.dns import DNS, IP, UDP, DNSRR, DNSQR
from scapy.sendrecv import send

SUCCESS_IP_PREFIX = "85.143.80."
ERROR_IP_PREFIX = "47.81.64."


def calculate_crc32(data: bytes) -> bytes:
    # Berechne den CRC32-Wert
    crc_value = zlib.crc32(data) & 0xFFFFFFFF  # CRC32 berechnen und sicherstellen, dass es ein 32-Bit-Wert ist
    # Wandle den CRC-Wert in 4 Bytes im Big-Endian-Format um
    crc_bytes = crc_value.to_bytes(4, byteorder='big')
    return crc_bytes


class Request:
    content: bytes
    crc_correct: bool = False
    num: int
    answer_correct: IP
    answer_incorrect: IP
    answer_total_error: IP

    def send_correct(self):
        send(self.answer_correct, verbose=0)

    def send_incorrect(self):
        send(self.answer_incorrect, verbose=0)

    def send_total_error(self):
        send(self.answer_total_error, verbose=0)


class Handler:
    identity: int
    received_data: Dict[int, Request]
    dataBlockCount: int = -1
    parityBlockCount: int = -1
    _lock: Lock
    finished: bool = False

    def __init__(self, identity: int):
        self.identity = identity
        self._lock = Lock()

    def timeout(self):
        print("Start timer...")
        sleep(3 * 60)
        with self._lock:
            print("Timeout, maby we are ready...")
            self.finished = True
            ready, errors = self.check_rady()
            if ready:
                print("Yeah, we are ready!")
                # integrität prüfen und printen
                # antworten
                self.integrity_check(errors)
            else:
                print("Ups, We weren't ready after all :(")
                self.total_error()

    def run(self, packet: scapy.packet.Packet, data: bytes, full_query: str):
        print("Start handling for connection", self.identity)
        handler = DataHandler(self.identity, packet, data, full_query)
        received = handler.proceed_data()

        with self._lock:
            if len(self.received_data) == 0:
                timer = threading.Thread(target=timeout)
                timer.start()

            if self.finished:
                return

            # Check if metadata
            if received.num == 0:
                if received.crc_correct:
                    raise "metadata block incorrect, unable to repair"
                print("Metadata received :)")
                self.dataBlockCount = int.from_bytes(data[5:9])
                self.parityBlockCount = int.from_bytes(data[9:13])
                received.send_correct()

            # Save data
            if self.received_data.get(received.num, None) is not None:
                raise "duplicate data"
            self.received_data[received.num] = received

            ready, errors = self.check_rady()
            if ready:
                print("We are ready.")
                # integrität prüfen und printen
                # antworten
                self.integrity_check(errors)

    def check_rady(self) -> (bool, int):
        if self.dataBlockCount == -1 or self.parityBlockCount == -1 or self.received_data.get(0, None) is None:
            return False

        max_error = self.parityBlockCount
        errors = 0
        for i in range(self.dataBlockCount):
            block = self.received_data.get(i, None) is None
            if block is None:
                errors += 1
            elif not block.crc_correct:
                errors += 1
            if errors > max_error:
                return False, errors

        for i in range(self.dataBlockCount, self.dataBlockCount + self.parityBlockCount):
            if self.received_data.get(i, None) is None:
                return False, errors

        return True, errors

    def integrity_check(self, errors: int):
        if errors == 0:
            for key in self.received_data:
                self.received_data[key].send_correct()
                print(self.received_data[key].content.decode("utf-8"), end="")
            self.finished = True
            return

        # TODO: Solomon rekonstruktion
        # Es sind genügend pakete da um die nachricht zu erhalten.
        # setzte nachricht zusammen und sende antworten
        pass

    def total_error(self):
        for key in self.received_data:
            self.received_data[key].send_total_error()


class DataHandler(Handler):
    packet: scapy.packet.Packet
    data: bytes
    full_query: str

    def __init__(self, identity: int, packet: scapy.packet.Packet, data: bytes, full_query: str):
        super().__init__(identity)
        self.packet = packet
        self.data = data
        self.full_query = full_query

    def proceed_data(self) -> Request:
        req = Request()
        req.content = self.data[5:-4]
        req.num = self.data[0]
        req.answer_correct = self.get_response(SUCCESS_IP_PREFIX + str(req.num))
        req.answer_incorrect = self.get_response(ERROR_IP_PREFIX + str(req.num))

        req.crc_correct = calculate_crc32(self.data[:-4]) == self.data[-4:]

        print("Get request data", req)

        return req

    def get_response(self, ip: str):
        return IP(dst=self.packet[IP].src, src=self.packet[IP].dst) / \
            UDP(dport=self.packet[UDP].sport, sport=53) / \
            DNS(id=self.packet[DNS].id, qr=1, aa=1, qd=self.packet[DNS].qd,
                an=DNSRR(rrname=self.full_query, ttl=300, rdata=ip))
