import struct
from typing import Generator, Optional
from models import PcapGlobalHeader, PcapPacketHeader

PCAP_GLOBAL_HEADER_FORMAT = '!IHHiIII'
PCAP_PACKET_HEADER_FORMAT = '!IIII'

GLOBAL_HEADER_SIZE = struct.calcsize(PCAP_GLOBAL_HEADER_FORMAT)  # 24
PACKET_HEADER_SIZE = struct.calcsize(PCAP_PACKET_HEADER_FORMAT)  # 16


class PcapReader:
    """Reads PCAP files and yields raw packets one at a time.

    The PCAP format is simple:
    1. Global header (24 bytes) — file metadata, link type
    2. For each packet:
       a. Packet header (16 bytes) — timestamp, length
       b. Packet data (incl_len bytes) — raw network bytes

    The magic number in the global header tells us if byte-order
    swapping is needed. If the file was written on a big-endian
    machine but we're on little-endian (x86), we need to swap.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None
        self._swapped = False
        self.global_header: Optional[PcapGlobalHeader] = None

    def open(self) -> 'PcapReader':
        self._file = open(self.filepath, 'rb')
        raw_global_header = self._file.read(GLOBAL_HEADER_SIZE)
        if len(raw_global_header) < GLOBAL_HEADER_SIZE:
            raise ValueError("File too small to contain a PCAP global header")

        magic = struct.unpack('!I', raw_global_header[:4])[0]
        self._swapped = (magic == PcapGlobalHeader.SWAPPED_MAGIC)

        fmt = PCAP_GLOBAL_HEADER_FORMAT
        if self._swapped:
            fmt = '<' + fmt[1:]

        fields = struct.unpack(fmt, raw_global_header)
        self.global_header = PcapGlobalHeader(*fields)

        if not self.global_header.is_valid:
            raise ValueError(
                f"Invalid PCAP magic number: {self.global_header.magic_number:#010x}"
            )

        return self

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()

    def _get_fmt(self, base_fmt: str) -> str:
        if self._swapped:
            return '<' + base_fmt[1:]
        return base_fmt

    @property
    def packet_header_fmt(self) -> str:
        return self._get_fmt(PCAP_PACKET_HEADER_FORMAT)

    def read_next_packet(self) -> Optional[tuple[PcapPacketHeader, bytes]]:
        if not self._file:
            return None

        raw_header = self._file.read(PACKET_HEADER_SIZE)
        if len(raw_header) < PACKET_HEADER_SIZE:
            return None

        fields = struct.unpack(self.packet_header_fmt, raw_header)
        pkt_header = PcapPacketHeader(*fields)

        raw_data = self._file.read(pkt_header.incl_len)
        if len(raw_data) < pkt_header.incl_len:
            return None

        return pkt_header, raw_data

    def packets(self) -> Generator[tuple[PcapPacketHeader, bytes], None, None]:
        while True:
            result = self.read_next_packet()
            if result is None:
                break
            yield result

    @property
    def link_type(self) -> int:
        return self.global_header.network if self.global_header else 0

    @property
    def is_ethernet(self) -> bool:
        return self.link_type == 1
