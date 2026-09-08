import struct
from typing import Optional
from models import ParsedPacket, PcapPacketHeader

ETHERNET_HEADER_FORMAT = '!6s6sH'
ETHERNET_HEADER_SIZE = struct.calcsize(ETHERNET_HEADER_FORMAT)  # 14

IPV4_HEADER_FORMAT = '!BBHHHBBH4s4s'
IPV4_HEADER_MIN_SIZE = 20  # minimum IP header length (IHL=5)

TCP_HEADER_FORMAT = '!HHIIBBHHH'
TCP_HEADER_MIN_SIZE = 20  # minimum TCP header length

UDP_HEADER_FORMAT = '!HHHH'
UDP_HEADER_SIZE = struct.calcsize(UDP_HEADER_FORMAT)  # 8

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ICMP = 1


def mac_to_str(mac_bytes: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def ip_to_str(ip_bytes: bytes) -> str:
    return '.'.join(str(b) for b in ip_bytes)


class PacketParser:
    @staticmethod
    def parse(
        pkt_header: PcapPacketHeader,
        raw_data: bytes
    ) -> Optional[ParsedPacket]:
        """Parse a raw packet into a structured ParsedPacket.

        The parsing follows encapsulation:
        Ethernet → IPv4 → TCP/UDP → payload
        """
        packet = ParsedPacket(
            ts_sec=pkt_header.ts_sec,
            ts_usec=pkt_header.ts_usec,
            incl_len=pkt_header.incl_len,
            orig_len=pkt_header.orig_len,
            raw_data=raw_data,
        )

        offset = PacketParser._parse_ethernet(raw_data, packet)
        if offset is None:
            return None

        if packet.ethertype == ETHERTYPE_IPV4:
            offset = PacketParser._parse_ipv4(raw_data, offset, packet)
            if offset is None:
                return None
        else:
            return packet

        if packet.protocol == PROTOCOL_TCP:
            PacketParser._parse_tcp(raw_data, offset, packet)
        elif packet.protocol == PROTOCOL_UDP:
            PacketParser._parse_udp(raw_data, offset, packet)

        return packet

    @staticmethod
    def _parse_ethernet(
        data: bytes, packet: ParsedPacket
    ) -> Optional[int]:
        """Parse Ethernet header (14 bytes).

        Structure:
        - Destination MAC: 6 bytes
        - Source MAC: 6 bytes
        - EtherType: 2 bytes (0x0800 = IPv4)
        """
        if len(data) < ETHERNET_HEADER_SIZE:
            return None

        dst_mac, src_mac, ethertype = struct.unpack(
            ETHERNET_HEADER_FORMAT, data[:ETHERNET_HEADER_SIZE]
        )

        packet.dst_mac = mac_to_str(dst_mac)
        packet.src_mac = mac_to_str(src_mac)
        packet.ethertype = ethertype

        return ETHERNET_HEADER_SIZE

    @staticmethod
    def _parse_ipv4(
        data: bytes, offset: int, packet: ParsedPacket
    ) -> Optional[int]:
        """Parse IPv4 header (20-60 bytes).

        Key fields:
        - Version (4 bits) + IHL (4 bits) in first byte
          IHL = Internet Header Length in 32-bit words
          Actual header length = IHL * 4 bytes
        - Total Length: entire IP packet length (header + payload)
        - Protocol: 6=TCP, 17=UDP
        - Source IP: 4 bytes
        - Destination IP: 4 bytes
        """
        if offset + IPV4_HEADER_MIN_SIZE > len(data):
            return None

        fields = struct.unpack(IPV4_HEADER_FORMAT, data[offset:offset + IPV4_HEADER_MIN_SIZE])
        version_ihl, _, total_length, _, _, ttl, protocol, _, src_ip, dst_ip = fields

        # IHL is lower 4 bits of first byte, multiply by 4 to get byte count
        ihl = (version_ihl & 0x0F) * 4

        packet.src_ip = ip_to_str(src_ip)
        packet.dst_ip = ip_to_str(dst_ip)
        packet.ip_header_len = ihl
        packet.total_length = total_length
        packet.ttl = ttl
        packet.protocol = protocol

        # Payload starts after IP header
        payload_offset = offset + ihl
        # Payload length = total IP packet length minus IP header
        payload_length = total_length - ihl

        packet.payload_offset = payload_offset
        packet.payload_length = max(0, payload_length)

        return offset + ihl

    @staticmethod
    def _parse_tcp(
        data: bytes, offset: int, packet: ParsedPacket
    ):
        """Parse TCP header (20-60 bytes).

        Key fields:
        - Source Port (2 bytes), Dest Port (2 bytes)
        - Sequence Number (4 bytes), Ack Number (4 bytes)
        - Data Offset (upper 4 bits of byte 12): header length in 32-bit words
        - Flags (1 byte): SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08
        - Window Size (2 bytes)
        """
        if offset + TCP_HEADER_MIN_SIZE > len(data):
            return

        fields = struct.unpack(TCP_HEADER_FORMAT, data[offset:offset + TCP_HEADER_MIN_SIZE])
        (
            src_port, dst_port, seq_number, ack_number,
            data_offset_reserved, flags, window_size, _, _
        ) = fields

        packet.src_port = src_port
        packet.dst_port = dst_port
        packet.seq_number = seq_number
        packet.ack_number = ack_number
        packet.tcp_flags = flags
        packet.window_size = window_size
        packet.is_tcp = True

        # Data Offset is upper 4 bits, multiply by 4 to get byte count
        tcp_header_len = ((data_offset_reserved >> 4) & 0x0F) * 4
        packet.tcp_header_len = tcp_header_len

        # Adjust payload offset to skip TCP header
        tcp_payload_offset = offset + tcp_header_len
        tcp_payload_length = packet.payload_length - (tcp_header_len - TCP_HEADER_MIN_SIZE)

        packet.payload_offset = tcp_payload_offset
        packet.payload_length = max(0, tcp_payload_length)

    @staticmethod
    def _parse_udp(
        data: bytes, offset: int, packet: ParsedPacket
    ):
        """Parse UDP header (8 bytes).

        UDP is simpler than TCP — no handshake, no sequence numbers.
        Just ports, length, and checksum.
        """
        if offset + UDP_HEADER_SIZE > len(data):
            return

        src_port, dst_port, length, _ = struct.unpack(
            UDP_HEADER_FORMAT, data[offset:offset + UDP_HEADER_SIZE]
        )

        packet.src_port = src_port
        packet.dst_port = dst_port
        packet.is_udp = True

        # UDP length includes the 8-byte header
        udp_payload_offset = offset + UDP_HEADER_SIZE
        udp_payload_length = length - UDP_HEADER_SIZE

        packet.payload_offset = udp_payload_offset
        packet.payload_length = max(0, udp_payload_length)
