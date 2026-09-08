import struct
from typing import Optional
from pcap_reader import GLOBAL_HEADER_SIZE
from models import PcapGlobalHeader, DPIStats


PCAP_GLOBAL_HEADER_FORMAT = '!IHHiIII'
PCAP_PACKET_HEADER_FORMAT_WRITE = '!IIII'


def write_pcap_global_header(file) -> int:
    """Write PCAP global header (24 bytes) for a new output file.

    Uses:
    - Magic: 0xa1b2c3d4 (native byte order)
    - Version: 2.4
    - Snaplen: 65535 (max typical capture size)
    - Network: 1 (Ethernet)
    """
    header = struct.pack(
        PCAP_GLOBAL_HEADER_FORMAT,
        PcapGlobalHeader.NATIVE_MAGIC,
        2,  # version_major
        4,  # version_minor
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        1,  # network (1 = Ethernet)
    )
    file.write(header)
    return GLOBAL_HEADER_SIZE


def write_pcap_packet(file, ts_sec: int, ts_usec: int, data: bytes) -> int:
    """Write a single packet to the output PCAP file.

    Writes 16-byte packet header + raw packet data.
    Returns total bytes written.
    """
    header = struct.pack(
        PCAP_PACKET_HEADER_FORMAT_WRITE,
        ts_sec,
        ts_usec,
        len(data),
        len(data),
    )
    file.write(header)
    file.write(data)
    return 16 + len(data)


def format_timestamp(ts: float) -> str:
    """Format a Unix timestamp as a human-readable string."""
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
