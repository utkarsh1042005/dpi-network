from typing import Dict, Optional, Set
from models import (
    FiveTuple, FlowState, ParsedPacket, ConnectionState,
    AppType, DPIStats
)
from sni_extractor import (
    SNIExtractor, HTTPHostExtractor, DNSExtractor,
    TLS_VERSION_NAMES
)
from rules import RuleEngine, _sni_to_app_type, _port_to_app_type


FLOW_IDLE_TIMEOUT = 300.0  # seconds — connections idle longer are evicted
MAX_FLOWS = 100_000


class FlowTracker:
    """Tracks network flows (bidirectional connections).

    Each flow is identified by a FiveTuple (src_ip, dst_ip, src_port,
    dst_port, protocol). The tracker maintains a state machine:

    NEW → ESTABLISHED → CLASSIFIED (or BLOCKED) → CLOSED

    Flows idle for > FLOW_IDLE_TIMEOUT seconds are removed during
    periodic cleanup.
    """

    def __init__(self):
        self._flows: Dict[FiveTuple, FlowState] = {}
        self._reverse_index: Dict[FiveTuple, FiveTuple] = {}

    def get_or_create_flow(
        self, packet: ParsedPacket
    ) -> Optional[FlowState]:
        """Get existing flow or create a new one for this packet.

        Handles bidirectional matching — looks up both the forward
        and reverse five-tuple so we track both directions of a
        conversation as one flow.
        """
        ft = packet.five_tuple
        if ft is None:
            return None

        if ft in self._flows:
            flow = self._flows[ft]
            flow.state = ConnectionState.ESTABLISHED
            flow.update(packet, direction_forward=True)
            return flow

        rev = packet.reverse_tuple
        if rev in self._flows:
            flow = self._flows[rev]
            flow.state = ConnectionState.ESTABLISHED
            flow.update(packet, direction_forward=False)
            return flow

        flow = FlowState(five_tuple=ft, first_seen=packet.timestamp)
        flow.last_seen = packet.timestamp
        flow.state = ConnectionState.NEW
        flow.update(packet, direction_forward=True)
        self._flows[ft] = flow
        self._reverse_index[rev] = ft

        if len(self._flows) > MAX_FLOWS:
            self._evict_old_flows()

        return flow

    def update_flow_state(
        self,
        flow: FlowState,
        packet: ParsedPacket
    ):
        """Update flow state based on TCP flags."""
        if not packet.is_tcp:
            return

        if packet.tcp_flags & 0x04:  # RST
            flow.state = ConnectionState.CLOSED
        elif packet.tcp_flags & 0x01:  # FIN
            flow.state = ConnectionState.CLOSED
        elif packet.tcp_flags & 0x02:  # SYN
            if packet.tcp_flags & 0x10:  # SYN-ACK
                flow.state = ConnectionState.ESTABLISHED
            else:
                if flow.state == ConnectionState.NEW:
                    flow.state = ConnectionState.ESTABLISHED

    def classify_flow(
        self,
        flow: FlowState,
        packet: ParsedPacket,
        stats: DPIStats
    ):
        """Attempt to classify a flow using DPI techniques.

        Tries, in order:
        1. TLS SNI extraction (port 443)
        2. HTTP Host header extraction (port 80)
        3. DNS query extraction (port 53)
        4. Port-based fallback

        Once classified, sets app_type and domain on the flow.
        """
        if flow.state in (ConnectionState.CLASSIFIED, ConnectionState.BLOCKED):
            return

        payload = packet.payload

        # Try TLS SNI extraction
        if packet.dst_port == 443 or packet.src_port == 443:
            if SNIExtractor.is_tls_client_hello(payload):
                sni = SNIExtractor.extract_sni(payload)
                if sni:
                    flow.sni = sni
                    flow.domain = sni
                    flow.app_type = _sni_to_app_type(sni)
                    tls_ver = SNIExtractor.extract_tls_version(payload)
                    if tls_ver:
                        flow.tls_version = tls_ver
                    stats.sni_found += 1
                    flow.state = ConnectionState.CLASSIFIED
                    return

        # Try HTTP Host header
        if packet.dst_port == 80 or packet.src_port == 80:
            if HTTPHostExtractor.is_http_request(payload):
                host = HTTPHostExtractor.extract_host(payload)
                if host:
                    flow.domain = host
                    flow.app_type = _sni_to_app_type(host)
                    stats.http_hosts_found += 1
                    flow.state = ConnectionState.CLASSIFIED
                    return

        # Try DNS query extraction
        if packet.dst_port == 53 or packet.src_port == 53:
            domains = DNSExtractor.extract_queries(payload)
            if domains:
                flow.domain = domains[0]
                flow.app_type = _sni_to_app_type(domains[0])
                stats.dns_queries_found += 1
                flow.state = ConnectionState.CLASSIFIED
                return

        # Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            flow.app_type = _port_to_app_type(packet.dst_port)

    def cleanup_stale_flows(self, current_time: float):
        """Remove flows that have been idle for too long."""
        stale = []
        for ft, flow in self._flows.items():
            if current_time - flow.last_seen > FLOW_IDLE_TIMEOUT:
                stale.append(ft)

        for ft in stale:
            rev = FiveTuple(
                src_ip=ft.dst_ip, dst_ip=ft.src_ip,
                src_port=ft.dst_port, dst_port=ft.src_port,
                protocol=ft.protocol
            )
            self._reverse_index.pop(rev, None)
            self._flows.pop(ft, None)

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    @property
    def flows(self) -> Dict[FiveTuple, FlowState]:
        return self._flows

    def get_all_flows(self) -> list[FlowState]:
        return list(self._flows.values())


class DPIEngine:
    """Main DPI orchestrator.

    Ties together:
    - PCAP reader (input)
    - Packet parser (protocol parsing)
    - Flow tracker (connection state)
    - Rule engine (blocking decisions)
    - SNI/HTTP/DNS extractors (application identification)

    Processing pipeline:
    Read PCAP → Parse headers → Track flows → Classify apps →
    Check rules → Forward/Drop → Report
    """

    def __init__(self):
        self.flow_tracker = FlowTracker()
        self.rule_engine = RuleEngine()
        self.stats = DPIStats()

    def process_packet(
        self,
        packet: ParsedPacket
    ) -> bool:
        """Process a single parsed packet through the DPI pipeline.

        Returns True if the packet should be forwarded, False if dropped.
        """
        self.stats.total_packets += 1

        if packet.is_tcp:
            self.stats.tcp_packets += 1
        elif packet.is_udp:
            self.stats.udp_packets += 1
        else:
            self.stats.other_packets += 1

        flow = self.flow_tracker.get_or_create_flow(packet)
        if flow is None:
            return True  # can't determine flow, forward it

        self.flow_tracker.update_flow_state(flow, packet)

        if flow.state == ConnectionState.NEW:
            self.stats.total_flows += 1

        if flow.state not in (ConnectionState.CLASSIFIED, ConnectionState.BLOCKED):
            self.flow_tracker.classify_flow(flow, packet, self.stats)

        if flow.state == ConnectionState.CLASSIFIED:
            self.stats.classified_flows += 1

        action = self.rule_engine.should_block(
            src_ip=packet.src_ip,
            dst_port=packet.dst_port,
            app_type=flow.app_type,
            domain=flow.domain,
        )

        if action:
            flow.state = ConnectionState.BLOCKED
            self.stats.dropped_packets += 1
            self.stats.blocked_flows += 1
            return False

        self.stats.forwarded_packets += 1
        return True

    def _collect_stats(self):
        """Aggregate statistics from all tracked flows."""
        app_counts = {}
        domain_counts = {}

        for flow in self.flow_tracker.get_all_flows():
            app_name = flow.app_type.name
            app_counts[app_name] = app_counts.get(app_name, 0) + 1

            if flow.domain:
                domain_counts[flow.domain] = domain_counts.get(flow.domain, 0) + 1

        self.stats.app_classification = app_counts
        self.stats.top_domains = domain_counts
