import threading
import zlib
from threading import Lock
from time import sleep
from typing import Dict
from reedsolo import RSCodec
from typing import List, Optional
import scapy.packet
from scapy.layers.dns import DNS, IP, UDP, DNSRR, DNSQR
from scapy.sendrecv import send


SUCCESS_IP_PREFIX = "85.143.80."
ERROR_IP_PREFIX = "47.81.64."
CONSOLE_LOCK = threading.Lock()


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
    is_data: bool = False

    def send_correct(self):
        send(self.answer_correct, verbose=0)

    def send_incorrect(self):
        send(self.answer_incorrect, verbose=0)

    def send_total_error(self):
        send(self.answer_total_error, verbose=0)


class Handler:
    #identity: int
    #received_data: Dict[int, Request] = {}
    #dataBlockCount: int = -1
    #parityBlockCount: int = -1
    #_lock: Lock
    #finished: bool = False
    #timer = None

    def __init__(self, identity: int):
        self.received_data: Dict[int, Request] = {}
        self.dataBlockCount: int = -1
        self.parityBlockCount: int = -1
        self.finished: bool = False
        self.timer = None
        self.identity: int = identity
        self._lock = Lock()

    def timeout(self):
        with CONSOLE_LOCK:
            print("Start timer...")
        sleep(3)
        if self.finished:
            return
        with self._lock:
            with CONSOLE_LOCK:
                print("Timeout, maby we are ready...")
            self.finished = True
            ready, errors = self.check_rady()
            if ready:
                with CONSOLE_LOCK:
                    print("Yeah, we are ready!")
                # integrität prüfen und printen
                # antworten
                self.integrity_check(errors)
            else:
                with CONSOLE_LOCK:
                    print("Ups, We weren't ready after all :(")
                self.total_error()
            self.finished = True

    def run(self, packet: scapy.packet.Packet, data: bytes, full_query: str):
        with CONSOLE_LOCK:
            print("Start handling for connection", self.identity)
        handler = DataHandler(self.identity, packet, data, full_query)
        received = handler.proceed_data(self.dataBlockCount)

        with self._lock:
            if self.timer is None:
                self.timer = threading.Thread(target=self.timeout)
                self.timer.start()

            if self.finished:
                return

            # Check if metadata
            if received.num == 0:
                if not received.crc_correct:
                    raise "metadata block incorrect, unable to repair"
                with CONSOLE_LOCK:
                    print("Metadata received :)")
                self.dataBlockCount = int.from_bytes(data[5:9], byteorder="big")
                self.parityBlockCount = int.from_bytes(data[9:13], byteorder="big")
                received.send_correct()

            # Save data
            if self.received_data.get(received.num, None) is not None:
                print(self.received_data)
                raise ValueError(str(self.identity) + " duplicate data for block "+str(received.num))
            self.received_data[received.num] = received

            ready, errors = self.check_rady()
            if ready:
                with CONSOLE_LOCK:
                    print("We are ready.")
                # integrität prüfen und printen
                # antworten
                self.integrity_check(errors)
        self.timer.join()

    def check_rady(self) -> (bool, int):
        if self.dataBlockCount == -1 or self.parityBlockCount == -1 or self.received_data.get(0, None) is None:
            return False, 0

        with CONSOLE_LOCK:
            print("Es sind schon da:", self.received_data.keys())

        max_error = self.parityBlockCount
        errors = 0
        for i in range(self.dataBlockCount+self.parityBlockCount+1):
            block: Request = self.received_data.get(i, None)
            if block is None:
                errors += 1
            elif block.is_data and not block.crc_correct:
                errors += 1
                block.send_incorrect()
                del self.received_data[i]
            if errors > max_error:
                return False, errors

        return True, errors

    def integrity_check(self, errors: int):
        if errors == 0:
            self.finish_print()
            return

        with CONSOLE_LOCK:
            print("recover with errors:", errors)
        blocks = []
        for i in range(1, self.dataBlockCount+self.parityBlockCount+1):
            n = (self.received_data.get(i, None))
            if n is not None:
                n = n.content
            blocks.append(n)

        recovered_data = self.reed_solomon_erasure_recover(blocks)
        with CONSOLE_LOCK:
            print("data repaired:", recovered_data)
        if None in recovered_data:
            print("data not repaired, aborting")
            return
        self.finish_print(recovered_data)

    def reed_solomon_erasure_recover(self, data_blocks: List[Optional[bytes]]) -> List[bytes]:
        with CONSOLE_LOCK:
            print("repairing this data:", data_blocks)
        parity_blocks = self.parityBlockCount

        # Determine block size
        block_size = max(len(block) for block in data_blocks if block is not None)
        if block_size == 0:
            with CONSOLE_LOCK:
                print("Error: block_size is zero, cannot proceed with recovery.")
            return data_blocks

        # Ensure all data blocks have the same size by padding with zeros if necessary
        padded_blocks = [block.ljust(block_size, b'\x00') if block is not None else b'\x00' * block_size for block in
                         data_blocks]

        # Create RSCodec instance with the number of parity blocks
        rsc = RSCodec(parity_blocks)

        # Collect the known data blocks and their positions
        erasures = [i for i, block in enumerate(data_blocks) if block is None]

        # Concatenate the encoded data for decoding
        encoded_data_bytes = b''.join(padded_blocks)

        # Recover the message
        try:
            rmes, _, _ = rsc.decode(encoded_data_bytes, nsym=parity_blocks, erase_pos=erasures)
            # Convert bytearray to bytes
            rmes = bytes(rmes)
        except Exception as e:
            with CONSOLE_LOCK:
                print("Reed-Solomon decoding failed:", str(e))
            return data_blocks  # Return original blocks if recovery fails

        # Split recovered data into original block size
        return [rmes[i:i + block_size] for i in range(0, len(rmes), block_size)]

    def finish_print(self, rdata: List[bytes]=None):
        if self.finished:
            return
        with CONSOLE_LOCK:
            if rdata is not None:
                txt = b''.join(rdata)
                try:
                    print(txt.decode("utf-8"), end="")
                except UnicodeDecodeError:
                    print("unable to print data")
                    return
            else:
                for k in range(self.dataBlockCount+1):
                    d = self.received_data.get(k, None)
                    if d is None:
                        continue
                    if d.num == self.dataBlockCount:
                        d.content = d.content.rstrip(b'\x00')
                    if d.is_data:
                        d.send_correct()
                        print(d.content.decode("utf-8"), end="")
            print()
            self.finished = True

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

    def proceed_data(self, data_count: int) -> Request:
        req = Request()
        req.num = self.data[0]

        if req.num == 0:
            req.content = self.data[5:-4]
            req.is_data = False
            req.crc_correct = calculate_crc32(self.data[:-4]) == self.data[-4:]
        elif req.num <= data_count:
            req.content = self.data[5:-4]
            req.is_data = True
            req.crc_correct = calculate_crc32(self.data[:-4]) == self.data[-4:]
        else:
            req.content = self.data[5:]
            req.is_data = False

        req.answer_correct = self.get_response(SUCCESS_IP_PREFIX + str(req.num))
        req.answer_incorrect = self.get_response(ERROR_IP_PREFIX + str(req.num))
        req.answer_total_error = self.get_response(ERROR_IP_PREFIX + "255")

        with CONSOLE_LOCK:
            print("Get request data", req.__dict__)

        return req

    def get_response(self, ip: str):
        return IP(dst=self.packet[IP].src, src=self.packet[IP].dst) / \
            UDP(dport=self.packet[UDP].sport, sport=53) / \
            DNS(id=self.packet[DNS].id, qr=1, aa=1, qd=self.packet[DNS].qd,
                an=DNSRR(rrname=self.full_query, ttl=300, rdata=ip))
