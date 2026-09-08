from dataclasses import dataclass, field
from typing import Optional, List
from enum import IntEnum, auto
from struct import pack, unpack


class AppType(IntEnum):
    UNKNOWN = 0
    GOOGLE = 1
    YOUTUBE = 2
    FACEBOOK = 3
    TIKTOK = 4
    TWITTER = 5
    INSTAGRAM = 6
    LINKEDIN = 7
    NETFLIX = 8
    SPOTIFY = 9
    AMAZON = 10
    APPLE = 11
    MICROSOFT = 12
    CLOUDFLARE = 13
    DISCORD = 14
    TELEGRAM = 15
    WHATSAPP = 16
    SNAPCHAT = 17
    REDDIT = 18
    GITHUB = 19
    STACKOVERFLOW = 20
    HTTP = 21
    HTTPS = 22
    DNS = 23
    MAIL = 24
    SSH = 25
    FTP = 26
    P2P = 27
    STREAMING = 28
    SOCIAL_MEDIA = 29
    GAMING = 30
    CLOUD = 31
    CDN = 32
    AD_TRACKER = 33
    MALWARE = 34


class ConnectionState(IntEnum):
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4


class PacketAction(IntEnum):
    FORWARD = 0
    DROP = 1


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int

    SWAPPED_MAGIC = 0xD4C3B2A1
    NATIVE_MAGIC = 0xA1B2C3D4

    @property
    def is_swapped(self) -> bool:
        return self.magic_number == self.SWAPPED_MAGIC

    @property
    def is_valid(self) -> bool:
        return self.magic_number in (self.NATIVE_MAGIC, self.SWAPPED_MAGIC)


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000


@dataclass
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __hash__(self):
        return hash((
            self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.protocol
        ))

    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (
            self.src_ip == other.src_ip and
            self.dst_ip == other.dst_ip and
            self.src_port == other.src_port and
            self.dst_port == other.dst_port and
            self.protocol == other.protocol
        )

    def reversed(self) -> 'FiveTuple':
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )

    def __str__(self):
        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        proto_str = proto_map.get(self.protocol, str(self.protocol))
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} ({proto_str})"


@dataclass
class ParsedPacket:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int

    src_mac: str = ''
    dst_mac: str = ''
    ethertype: int = 0

    src_ip: str = ''
    dst_ip: str = ''
    ip_header_len: int = 0
    total_length: int = 0
    ttl: int = 0
    protocol: int = 0

    src_port: int = 0
    dst_port: int = 0
    seq_number: int = 0
    ack_number: int = 0
    tcp_flags: int = 0
    tcp_header_len: int = 0
    window_size: int = 0

    is_tcp: bool = False
    is_udp: bool = False

    payload_offset: int = 0
    payload_length: int = 0
    raw_data: bytes = b''

    @property
    def five_tuple(self) -> Optional[FiveTuple]:
        if not self.src_ip or not self.dst_ip:
            return None
        return FiveTuple(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol
        )

    @property
    def reverse_tuple(self) -> Optional[FiveTuple]:
        if not self.src_ip or not self.dst_ip:
            return None
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )

    @property
    def payload(self) -> bytes:
        if self.payload_offset and self.payload_length:
            end = self.payload_offset + self.payload_length
            return self.raw_data[self.payload_offset:end]
        return b''

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000


@dataclass
class FlowState:
    five_tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: Optional[str] = None
    domain: Optional[str] = None
    tls_version: Optional[str] = None

    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    init_win_bytes_forward: int = 0
    init_win_bytes_backward: int = 0

    fwd_pkt_lengths: List[int] = field(default_factory=list)
    bwd_pkt_lengths: List[int] = field(default_factory=list)
    fwd_iat: List[float] = field(default_factory=list)
    bwd_iat: List[float] = field(default_factory=list)
    last_pkt_time: float = 0.0

    def update(self, packet: ParsedPacket, direction_forward: bool):
        if direction_forward:
            self.packets_forward += 1
            self.bytes_forward += packet.payload_length or packet.incl_len
            self.fwd_pkt_lengths.append(packet.payload_length or packet.incl_len)
            if self.last_pkt_time > 0:
                self.fwd_iat.append(packet.timestamp - self.last_pkt_time)
            if self.init_win_bytes_forward == 0 and packet.window_size:
                self.init_win_bytes_forward = packet.window_size
        else:
            self.packets_reverse += 1
            self.bytes_reverse += packet.payload_length or packet.incl_len
            self.bwd_pkt_lengths.append(packet.payload_length or packet.incl_len)
            if self.last_pkt_time > 0:
                self.bwd_iat.append(packet.timestamp - self.last_pkt_time)
            if self.init_win_bytes_backward == 0 and packet.window_size:
                self.init_win_bytes_backward = packet.window_size

        if self.first_seen == 0:
            self.first_seen = packet.timestamp
        self.last_seen = packet.timestamp
        self.last_pkt_time = packet.timestamp

        if packet.is_tcp:
            if packet.tcp_flags & 0x02:
                self.syn_count += 1
            if packet.tcp_flags & 0x01:
                self.fin_count += 1
            if packet.tcp_flags & 0x04:
                self.rst_count += 1
            if packet.tcp_flags & 0x08:
                self.psh_count += 1
            if packet.tcp_flags & 0x10:
                self.ack_count += 1
            if packet.tcp_flags & 0x20:
                self.urg_count += 1
            if packet.tcp_flags & 0x80:
                self.cwe_count += 1
            if packet.tcp_flags & 0x40:
                self.ece_count += 1

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_reverse

    def __str__(self):
        return (
            f"[{self.state.name}] {self.five_tuple} | "
            f"App: {self.app_type.name} | "
            f"SNI: {self.sni or 'N/A'} | "
            f"Pkts: {self.total_packets} | "
            f"Bytes: {self.total_bytes}"
        )


@dataclass
class DPIStats:
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    total_flows: int = 0
    classified_flows: int = 0
    blocked_flows: int = 0
    sni_found: int = 0
    http_hosts_found: int = 0
    dns_queries_found: int = 0

    app_classification: dict = field(default_factory=dict)
    top_domains: dict = field(default_factory=dict)
    processing_time: float = 0.0

    def __str__(self):
        lines = [
            "=" * 60,
            "DPI ENGINE REPORT",
            "=" * 60,
            f"Total packets:      {self.total_packets:>10}",
            f"TCP packets:        {self.tcp_packets:>10}",
            f"UDP packets:        {self.udp_packets:>10}",
            f"Other packets:      {self.other_packets:>10}",
            "",
            f"Forwarded:          {self.forwarded_packets:>10}",
            f"Dropped:            {self.dropped_packets:>10}",
            "",
            f"Total flows:        {self.total_flows:>10}",
            f"Classified flows:   {self.classified_flows:>10}",
            f"Blocked flows:      {self.blocked_flows:>10}",
            "",
            f"SNI extracted:      {self.sni_found:>10}",
            f"HTTP Hosts found:   {self.http_hosts_found:>10}",
            f"DNS queries found:  {self.dns_queries_found:>10}",
            "",
            f"Processing time:    {self.processing_time:>10.2f}s",
            "",
            "--- Application Classification ---",
        ]
        sorted_apps = sorted(
            self.app_classification.items(),
            key=lambda x: x[1],
            reverse=True
        )
        for app, count in sorted_apps[:15]:
            bar = "#" * min(count, 50)
            lines.append(f"  {app:<20} {count:>6}  {bar}")

        if self.top_domains:
            lines.append("")
            lines.append("--- Top Domains ---")
            sorted_domains = sorted(
                self.top_domains.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for domain, count in sorted_domains[:10]:
                lines.append(f"  {domain:<40} {count:>6}")

        lines.append("=" * 60)
        return "\n".join(lines)
