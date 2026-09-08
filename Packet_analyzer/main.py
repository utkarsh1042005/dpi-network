#!/usr/bin/env python3
"""
DPI Engine — Deep Packet Inspection & Network Traffic Analyzer

CLI entry point for analyzing PCAP files with protocol parsing,
flow tracking, SNI extraction, application classification, and rule-based blocking.

Usage:
    python main.py input.pcap [options]

Options:
    --output FILE       Output filtered PCAP
    --block-ip IP       Block traffic from this IP
    --block-port PORT   Block traffic on this port
    --block-domain DOM  Block traffic to this domain
    --block-app APP     Block this application type
    --rules FILE        Load blocking rules from file
    --verbose           Verbose output (show per-packet info)
    --no-output         Don't write output PCAP (analysis only)
"""

import argparse
import os
import sys
import time
from typing import Optional

from pcap_reader import PcapReader
from packet_parser import PacketParser, ip_to_str
from flow_tracker import DPIEngine
from models import AppType, ConnectionState, DPIStats
from utils import write_pcap_global_header, write_pcap_packet


def parse_args():
    parser = argparse.ArgumentParser(
        description='Deep Packet Inspection Engine — Analyze PCAP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('--output', '-o', default='output.pcap',
                        help='Output PCAP file (default: output.pcap)')
    parser.add_argument('--block-ip', action='append', default=[],
                        help='Block IP address (can be used multiple times)')
    parser.add_argument('--block-port', action='append', default=[],
                        help='Block port (can be used multiple times)')
    parser.add_argument('--block-domain', action='append', default=[],
                        help='Block domain (can be used multiple times)')
    parser.add_argument('--block-app', action='append', default=[],
                        help='Block application type (can be used multiple times)')
    parser.add_argument('--rules', '-r', help='Load rules from file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--no-output', action='store_true',
                        help='Do not write output PCAP (analysis only)')
    return parser.parse_args()


def setup_rules(engine: DPIEngine, args):
    """Configure blocking rules from CLI arguments and rule file."""
    for ip in args.block_ip:
        engine.rule_engine.block_ip(ip)
        print(f"  [Rule] Blocked IP: {ip}")

    for port_str in args.block_port:
        try:
            port = int(port_str)
            engine.rule_engine.block_port(port)
            print(f"  [Rule] Blocked Port: {port}")
        except ValueError:
            print(f"  [Warning] Invalid port: {port_str}", file=sys.stderr)

    for domain in args.block_domain:
        engine.rule_engine.block_domain(domain)
        print(f"  [Rule] Blocked Domain: {domain}")

    for app_str in args.block_app:
        try:
            app = AppType[app_str.upper()]
            engine.rule_engine.block_app(app)
            print(f"  [Rule] Blocked App: {app.name}")
        except KeyError:
            valid = ', '.join(a.name for a in AppType)
            print(f"  [Warning] Invalid app: {app_str}. Valid: {valid}",
                  file=sys.stderr)

    if args.rules:
        if os.path.exists(args.rules):
            engine.rule_engine.load_from_file(args.rules)
            print(f"  [Rules] Loaded from: {args.rules}")
        else:
            print(f"  [Warning] Rules file not found: {args.rules}",
                  file=sys.stderr)


def main():
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print("  DPI Engine - Packet Analyzer")
    print("=" * 60)
    print(f"  Input: {args.input}")
    print(f"  Output: {args.output if not args.no_output else '(none)'}")
    print()

    engine = DPIEngine()
    setup_rules(engine, args)

    if engine.rule_engine.has_rules:
        print()
        print("  Active Rules:")
        for line in engine.rule_engine.summary():
            print(line)
        print()

    output_file = None
    if not args.no_output:
        try:
            output_file = open(args.output, 'wb')
            write_pcap_global_header(output_file)
            print(f"  Writing filtered output to: {args.output}")
        except IOError as e:
            print(f"  [Warning] Cannot write output: {e}", file=sys.stderr)
            output_file = None

    print()
    print("  Processing...")
    start_time = time.time()
    packet_count = 0

    try:
        with PcapReader(args.input) as reader:
            print(f"  Link type: {reader.link_type} "
                  f"({'Ethernet' if reader.is_ethernet else 'Other'})")
            print()

            for pkt_header, raw_data in reader.packets():
                packet = PacketParser.parse(pkt_header, raw_data)
                if packet is None:
                    continue

                should_forward = engine.process_packet(packet)

                if should_forward and output_file:
                    write_pcap_packet(
                        output_file,
                        pkt_header.ts_sec,
                        pkt_header.ts_usec,
                        raw_data,
                    )

                if args.verbose and packet.is_tcp:
                    flow = engine.flow_tracker._flows.get(
                        packet.five_tuple
                    )
                    sni = flow.sni if flow else 'N/A'
                    action = 'FORWARD' if should_forward else 'DROP'
                    print(
                        f"  [{action}] {packet.src_ip}:{packet.src_port} → "
                        f"{packet.dst_ip}:{packet.dst_port} "
                        f"| SNI: {sni or 'N/A'}"
                    )

                packet_count += 1
                if packet_count % 10_000 == 0:
                    print(f"  ... processed {packet_count} packets")

    except Exception as e:
        print(f"  Error during processing: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        if output_file:
            output_file.close()

    end_time = time.time()
    flow_tracker = engine.flow_tracker
    engine.stats.processing_time = end_time - start_time
    engine.stats.total_flows = flow_tracker.flow_count

    engine.stats.classified_flows = sum(
        1 for f in flow_tracker.get_all_flows()
        if f.state == ConnectionState.CLASSIFIED
    )
    engine.stats.blocked_flows = sum(
        1 for f in flow_tracker.get_all_flows()
        if f.state == ConnectionState.BLOCKED
    )

    engine._collect_stats()

    print()
    print(engine.stats)
    print()


if __name__ == '__main__':
    main()
