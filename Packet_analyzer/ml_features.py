"""Feature Extraction Module — Converts network flows into ML feature vectors.

WHY THIS EXISTS:
Rule-based DPI (what we built above) relies on SNI/HTTP/DNS string matching.
It fails when:
- Traffic is encrypted without SNI (e.g., ESNI, DoH, VPNs)
- New applications appear with unknown domain patterns
- Traffic is obfuscated or tunneled

ML-based DPI solves this by learning patterns from flow statistics
(packet sizes, timing, directions) instead of relying on string matching.
"""

import math
import statistics
from typing import List, Dict, Optional
from models import FlowState, AppType

import numpy as np


def compute_statistics(values: List[float]) -> Dict[str, float]:
    """Compute statistical features from a list of values.

    Features: min, max, mean, std, variance, median, percentiles (10, 25, 75, 90)
    """
    if not values:
        return {
            'min': 0, 'max': 0, 'mean': 0, 'std': 0,
            'variance': 0, 'median': 0,
            'p10': 0, 'p25': 0, 'p75': 0, 'p90': 0,
            'total': 0, 'count': 0,
        }

    arr = np.array(values, dtype=np.float64)
    return {
        'min': float(np.min(arr)),
        'max': float(np.max(arr)),
        'mean': float(np.mean(arr)),
        'std': float(np.std(arr)),
        'variance': float(np.var(arr)),
        'median': float(np.median(arr)),
        'p10': float(np.percentile(arr, 10)),
        'p25': float(np.percentile(arr, 25)),
        'p75': float(np.percentile(arr, 75)),
        'p90': float(np.percentile(arr, 90)),
        'total': float(np.sum(arr)),
        'count': len(values),
    }


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of payload bytes.

    High entropy → encrypted/compressed data
    Low entropy → plaintext (HTTP, DNS, etc.)

    Entropy range:
    - 0.0 (all same byte) to 8.0 (perfectly random, each of 256 bytes equally likely)
    - Encrypted TLS payload ≈ 7.5-8.0
    - HTTP text ≈ 4.0-5.5
    - DNS ≈ 3.0-4.5
    """
    if not data:
        return 0.0

    byte_counts = np.zeros(256, dtype=np.int64)
    for byte in data:
        byte_counts[byte] += 1

    probabilities = byte_counts / len(data)
    probabilities = probabilities[probabilities > 0]

    return float(-np.sum(probabilities * np.log2(probabilities)))


def extract_flow_features(
    flow: FlowState,
    payload_samples: Optional[List[bytes]] = None
) -> Dict[str, float]:
    """Extract a comprehensive feature vector from a network flow.

    This is the core feature engineering function. It converts a
    raw flow (sequence of packets with timestamps, sizes, directions)
    into a fixed-length numerical vector for ML algorithms.

    Feature categories:
    1. BASIC FLOW INFO — duration, port, protocol
    2. PACKET COUNTS — forward/reverse packet and byte counts
    3. PACKET LENGTH STATS — min/max/mean/std of packet sizes
    4. INTER-ARRIVAL TIME STATS — timing patterns
    5. TCP FLAGS — SYN/FIN/RST counts
    6. BYTE RATIOS — forward/reverse ratios
    7. PAYLOAD ENTROPY — encryption detection
    8. TLS FEATURES — if available
    """
    features = {}

    # === 1. Basic Flow Information ===
    features['flow_duration'] = flow.duration
    features['dst_port'] = flow.five_tuple.dst_port
    features['protocol'] = flow.five_tuple.protocol

    # === 2. Packet/Byte Counts ===
    features['fwd_packets'] = flow.packets_forward
    features['bwd_packets'] = flow.packets_reverse
    features['fwd_bytes'] = flow.bytes_forward
    features['bwd_bytes'] = flow.bytes_reverse
    features['total_packets'] = flow.total_packets
    features['total_bytes'] = flow.total_bytes

    # === 3. Packet Length Statistics ===
    fwd_len_stats = compute_statistics(flow.fwd_pkt_lengths)
    bwd_len_stats = compute_statistics(flow.bwd_pkt_lengths)

    for prefix, stats in [('fwd', fwd_len_stats), ('bwd', bwd_len_stats)]:
        for stat_name, value in stats.items():
            features[f'{prefix}_pkt_len_{stat_name}'] = value

    # === 4. Inter-Arrival Time Statistics ===
    fwd_iat_stats = compute_statistics(flow.fwd_iat)
    bwd_iat_stats = compute_statistics(flow.bwd_iat)

    for prefix, stats in [('fwd_iat', fwd_iat_stats), ('bwd_iat', bwd_iat_stats)]:
        for stat_name, value in stats.items():
            features[prefix + '_' + stat_name] = value

    # Flow IAT (combine both directions)
    all_iats = flow.fwd_iat + flow.bwd_iat
    iat_stats = compute_statistics(all_iats)
    for stat_name, value in iat_stats.items():
        features[f'flow_iat_{stat_name}'] = value

    # === 5. Ratios ===
    if flow.packets_reverse > 0:
        features['pkt_ratio'] = flow.packets_forward / flow.packets_reverse
    else:
        features['pkt_ratio'] = float(flow.packets_forward)

    if flow.bytes_reverse > 0:
        features['byte_ratio'] = flow.bytes_forward / flow.bytes_reverse
    else:
        features['byte_ratio'] = float(flow.bytes_forward)

    # === 6. TCP Flags ===
    features['syn_count'] = flow.syn_count
    features['fin_count'] = flow.fin_count
    features['rst_count'] = flow.rst_count
    features['psh_count'] = flow.psh_count
    features['ack_count'] = flow.ack_count
    features['urg_count'] = flow.urg_count
    features['cwe_count'] = flow.cwe_count
    features['ece_count'] = flow.ece_count

    features['init_win_bytes_forward'] = flow.init_win_bytes_forward
    features['init_win_bytes_backward'] = flow.init_win_bytes_backward

    if flow.total_packets > 0:
        features['syn_ratio'] = flow.syn_count / flow.total_packets
        features['fin_ratio'] = flow.fin_count / flow.total_packets
        features['rst_ratio'] = flow.rst_count / flow.total_packets
    else:
        features['syn_ratio'] = 0
        features['fin_ratio'] = 0
        features['rst_ratio'] = 0

    # === 7. Payload Entropy (if samples provided) ===
    if payload_samples:
        entropies = [shannon_entropy(sample) for sample in payload_samples if sample]
        if entropies:
            features['payload_entropy_mean'] = float(np.mean(entropies))
            features['payload_entropy_std'] = float(np.std(entropies))
            features['payload_entropy_max'] = float(np.max(entropies))
        else:
            features['payload_entropy_mean'] = 0.0
            features['payload_entropy_std'] = 0.0
            features['payload_entropy_max'] = 0.0
    else:
        features['payload_entropy_mean'] = 0.0
        features['payload_entropy_std'] = 0.0
        features['payload_entropy_max'] = 0.0

    # === 8. TLS Version (categorical encoded as numeric) ===
    tls_version_map = {
        'TLS 1.3': 3,
        'TLS 1.2': 2,
        'TLS 1.1': 1,
        'TLS 1.0': 0,
    }
    features['tls_version'] = tls_version_map.get(flow.tls_version, -1)

    # === 9. Overall Packet Length Stats (both directions) ===
    all_pkt_lengths = flow.fwd_pkt_lengths + flow.bwd_pkt_lengths
    all_len_stats = compute_statistics(all_pkt_lengths)
    features['min_pkt_len'] = all_len_stats['min']
    features['max_pkt_len'] = all_len_stats['max']
    features['mean_pkt_len'] = all_len_stats['mean']
    features['std_pkt_len'] = all_len_stats['std']
    features['pkt_len_variance'] = all_len_stats['variance']
    features['avg_pkt_size'] = all_len_stats['mean']
    features['pkt_len_total'] = all_len_stats['total']
    features['pkt_len_count'] = all_len_stats['count']

    # === 10. Header Lengths (approximate: TCP header * packet count) ===
    # CICFlowMeter computes actual header bytes; we approximate
    avg_tcp_header = 20  # minimum TCP header without options
    features['fwd_header_len'] = flow.packets_forward * avg_tcp_header
    features['bwd_header_len'] = flow.packets_reverse * avg_tcp_header

    # === 11. Rate Features ===
    dur = max(flow.duration, 0.000001)
    features['flow_bytes_per_sec'] = flow.total_bytes / dur
    features['flow_packets_per_sec'] = flow.total_packets / dur
    features['fwd_packets_per_sec'] = flow.packets_forward / dur
    features['bwd_packets_per_sec'] = flow.packets_reverse / dur

    # === 12. Down/Up Ratio ===
    if flow.packets_forward > 0:
        features['down_up_ratio'] = flow.packets_reverse / flow.packets_forward
    else:
        features['down_up_ratio'] = float(flow.packets_reverse)

    # === 13. Active/Idle Times ===
    # Active time: total time with packet activity
    # Idle time: gaps > 1.0s between packets
    all_times = []
    if flow.fwd_iat:
        all_times.extend(flow.fwd_iat)
    if flow.bwd_iat:
        all_times.extend(flow.bwd_iat)

    if all_times:
        idle_times = [t for t in all_times if t > 1.0]
        active_times = [t for t in all_times if t <= 1.0]
        features['idle_time_total'] = sum(idle_times)
        features['active_time_total'] = sum(active_times)
        features['idle_ratio'] = sum(idle_times) / max(sum(all_times), 0.001)
        features['active_mean'] = np.mean(active_times) if active_times else 0
        features['idle_count'] = len(idle_times)
    else:
        features['idle_time_total'] = 0
        features['active_time_total'] = 0
        features['idle_ratio'] = 0
        features['active_mean'] = 0
        features['idle_count'] = 0

    return features


def flow_to_feature_vector(
    flow: FlowState,
    payload_samples: Optional[List[bytes]] = None
) -> tuple:
    """Convert a flow to (feature_vector, label) tuple for ML training.

    Returns:
        features: numpy array of numerical features
        label: AppType enum (for classification) or None
    """
    feats = extract_flow_features(flow, payload_samples)
    # Sort keys for deterministic ordering
    keys = sorted(feats.keys())
    vector = np.array([feats[k] for k in keys], dtype=np.float64)
    return vector, flow.app_type


def get_feature_names() -> List[str]:
    """Get the ordered list of feature names (for model interpretability)."""
    # Create a dummy flow to extract feature names
    from models import FiveTuple
    dummy_flow = FlowState(
        five_tuple=FiveTuple('0.0.0.0', '0.0.0.0', 0, 0, 6)
    )
    feats = extract_flow_features(dummy_flow)
    return sorted(feats.keys())


FEATURE_NAMES = get_feature_names()
NUM_FEATURES = len(FEATURE_NAMES)
