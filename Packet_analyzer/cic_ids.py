"""
CIC-IDS2017 Dataset Integration Module.

Integrates the real-world CIC-IDS2017 intrusion detection dataset with our
existing DPI pipeline while reusing as much existing code as possible.

======================================================================
CIC-IDS2017 DATASET STRUCTURE
======================================================================

The dataset contains 8 labeled CSV files (one per traffic session),
available from: https://www.unb.ca/cic/datasets/ids-2017.html

  CSV File                              | Attacks Present
  --------------------------------------|--------------------------------------
  Monday-WorkingHours.pcap_ISCX.csv     | BENIGN only (no attacks)
  Tuesday-WorkingHours.pcap_ISCX.csv    | FTP-Patator, SSH-Patator
  Wednesday-workingHours.pcap_ISCX.csv  | DoS Hulk, GoldenEye, Slowhttptest, Heartbleed
  Thursday-Morning-WebAttacks.csv       | Web Brute Force, SQL Injection, XSS
  Thursday-Afternoon-Infilteration.csv  | Infiltration
  Friday-WorkingHours-Morning.csv       | Bot
  Friday-Afternoon-PortScan.csv         | PortScan
  Friday-Afternoon-DDos.csv             | DDoS

Each CSV has 79 CICFlowMeter features + a 'Label' column.

Total flows: ~2.8M  |  Total size: ~960MB (CSVs), ~50GB (PCAPs)

======================================================================
INTEGRATION APPROACH
======================================================================

We support two paths:

  PATH A ("csv" — FAST, primary):
    Download the pre-computed CSVs. Each row is already a flow with
    79 features + ground truth label. We train directly on these features.
    This is how most CIC-IDS2017 research is done.

  PATH B ("pcap" — FULL, if PCAPs available):
    Process raw PCAPs through our existing pipeline:
      pcap_reader → packet_parser → flow_tracker → ml_features
    Then map our extracted flows to ground truth labels from the CSVs
    using 5-tuple + timestamp matching.

Both paths produce models in our existing pickle format that the Flask API
can load without modification.

======================================================================
FEATURE MAPPING
======================================================================

We create a bidirectional mapping between CICFlowMeter feature names and
our own feature names (from ml_features.py). This lets us:
  1. Train on CICFlowMeter features (industry standard)
  2. Use either feature set for inference via the API
  3. Cross-validate between both feature extraction approaches
"""

import hashlib
import io
import os
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# CIC-IDS2017 constants
# ---------------------------------------------------------------------------

DATASET_DIR = Path(__file__).parent / 'datasets' / 'cic_ids2017'

# Official UNB download URLs for the CSV files
CIC_MIRROR = 'https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main'

CSV_FILES = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
]

# Approximate sizes for progress reporting
CSV_SIZES = {
    'Monday-WorkingHours.pcap_ISCX.csv': 158_000_000,
    'Tuesday-WorkingHours.pcap_ISCX.csv': 124_000_000,
    'Wednesday-workingHours.pcap_ISCX.csv': 247_000_000,
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 56_000_000,
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 105_000_000,
    'Friday-WorkingHours-Morning.pcap_ISCX.csv': 75_000_000,
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 100_000_000,
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 95_000_000,
}

# Map attack label strings to standardized attack categories
ATTACK_TYPE_MAP = {
    'BENIGN': 'BENIGN',
    'FTP-Patator': 'BRUTE_FORCE',
    'SSH-Patator': 'BRUTE_FORCE',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'Heartbleed': 'DoS',
    'Web Attack � Brute Force': 'WEB_ATTACK',
    'Web Attack � Sql Injection': 'WEB_ATTACK',
    'Web Attack � XSS': 'WEB_ATTACK',
    'Infiltration': 'INFILTRATION',
    'Bot': 'BOT',
    'PortScan': 'PORT_SCAN',
    'DDoS': 'DDoS',
}

# ---------------------------------------------------------------------------
# Feature name mapping: CICFlowMeter ↔ Our feature names
# ---------------------------------------------------------------------------

# The 79 CICFlowMeter feature names (the industry standard for IDS research)
CIC_FEATURE_NAMES = [
    ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min', ' Fwd Packet Length Mean',
    ' Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', ' Flow Packets/s',
    ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
    'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags',
    ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std',
    ' Packet Length Variance',
    ' FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
    ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
    ' CWE Flag Count', ' ECE Flag Count',
    ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size', ' Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets',
    ' Subflow Bwd Bytes',
    'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
    ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', ' Active Std', ' Active Max', ' Active Min',
    'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min',
]

# Mapping between CICFlowMeter features (stripped, as saved in model) and our features.
CIC_TO_OUR_FEATURES = {
    'Destination Port': 'dst_port',
    'Flow Duration': 'flow_duration',
    'Total Fwd Packets': 'fwd_packets',
    'Total Backward Packets': 'bwd_packets',
    'Total Length of Fwd Packets': 'fwd_bytes',
    'Total Length of Bwd Packets': 'bwd_bytes',
    'Fwd Packet Length Max': 'fwd_pkt_len_max',
    'Fwd Packet Length Min': 'fwd_pkt_len_min',
    'Fwd Packet Length Mean': 'fwd_pkt_len_mean',
    'Fwd Packet Length Std': 'fwd_pkt_len_std',
    'Bwd Packet Length Max': 'bwd_pkt_len_max',
    'Bwd Packet Length Min': 'bwd_pkt_len_min',
    'Bwd Packet Length Mean': 'bwd_pkt_len_mean',
    'Bwd Packet Length Std': 'bwd_pkt_len_std',
    'Flow IAT Mean': 'flow_iat_mean',
    'Flow IAT Std': 'flow_iat_std',
    'Flow IAT Max': 'flow_iat_max',
    'Flow IAT Min': 'flow_iat_min',
    'Fwd IAT Total': 'fwd_iat_total',
    'Fwd IAT Mean': 'fwd_iat_mean',
    'Fwd IAT Std': 'fwd_iat_std',
    'Fwd IAT Max': 'fwd_iat_max',
    'Fwd IAT Min': 'fwd_iat_min',
    'Bwd IAT Total': 'bwd_iat_total',
    'Bwd IAT Mean': 'bwd_iat_mean',
    'Bwd IAT Std': 'bwd_iat_std',
    'Bwd IAT Max': 'bwd_iat_max',
    'Bwd IAT Min': 'bwd_iat_min',
    'FIN Flag Count': 'fin_count',
    'SYN Flag Count': 'syn_count',
    'RST Flag Count': 'rst_count',
    'PSH Flag Count': 'psh_count',
    'ACK Flag Count': 'ack_count',
    'URG Flag Count': 'urg_count',
    'CWE Flag Count': 'cwe_count',
    'ECE Flag Count': 'ece_count',
    'Fwd PSH Flags': 'psh_count',
    'Bwd PSH Flags': 'psh_count',
    'Fwd URG Flags': 'urg_count',
    'Bwd URG Flags': 'urg_count',
    'Init_Win_bytes_forward': 'init_win_bytes_forward',
    'Init_Win_bytes_backward': 'init_win_bytes_backward',
    'Min Packet Length': 'min_pkt_len',
    'Max Packet Length': 'max_pkt_len',
    'Packet Length Mean': 'mean_pkt_len',
    'Packet Length Std': 'std_pkt_len',
    'Packet Length Variance': 'pkt_len_variance',
    'Average Packet Size': 'avg_pkt_size',
    'Flow Bytes/s': 'flow_bytes_per_sec',
    'Flow Packets/s': 'flow_packets_per_sec',
    'Fwd Packets/s': 'fwd_packets_per_sec',
    'Bwd Packets/s': 'bwd_packets_per_sec',
    'Down/Up Ratio': 'down_up_ratio',
    'Fwd Header Length': 'fwd_header_len',
    'Bwd Header Length': 'bwd_header_len',
    'Avg Fwd Segment Size': 'fwd_pkt_len_mean',
    'Avg Bwd Segment Size': 'bwd_pkt_len_mean',
    'min_seg_size_forward': 'fwd_pkt_len_min',
    'Subflow Fwd Packets': 'fwd_packets',
    'Subflow Fwd Bytes': 'fwd_bytes',
    'Subflow Bwd Packets': 'bwd_packets',
    'Subflow Bwd Bytes': 'bwd_bytes',
    'act_data_pkt_fwd': 'fwd_packets',
    'Active Mean': 'active_mean',
    'Active Std': 'active_std',
    'Active Max': 'active_max',
    'Active Min': 'active_min',
    'Idle Mean': 'idle_mean',
    'Idle Std': 'idle_std',
    'Idle Max': 'idle_max',
    'Idle Min': 'idle_min',
}


def get_dataset_dir():
    """Get the dataset directory, creating it if necessary."""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    return DATASET_DIR


def download_progress_callback(block_num: int, block_size: int, total_size: int):
    """Callback for urllib to show download progress."""
    downloaded = block_num * block_size
    if total_size > 0:
        percent = min(100, int(downloaded * 100 / total_size))
        bar = '#' * (percent // 5) + '-' * (20 - percent // 5)
        sys.stdout.write(f'\r    [{bar}] {percent}% ({downloaded // 1024 // 1024}MB)')
        sys.stdout.flush()
        if downloaded >= total_size:
            sys.stdout.write('\n')


def download_cic_csv(
    filename: str,
    force: bool = False,
    verify: bool = True
) -> Path:
    """Download a single CIC-IDS2017 CSV file from the Hugging Face mirror.

    The Hugging Face mirror hosts the CSVs in their original format but
    as individual files for easier access (no zip to decompress).
    """
    dest = get_dataset_dir() / filename

    if dest.exists() and not force:
        file_size = os.path.getsize(dest)
        expected = CSV_SIZES.get(filename, 0)
        if file_size > 100_000:
            print(f"    Already exists: {filename} ({file_size // 1024 // 1024}MB)")
            return dest
        else:
            print(f"    File too small ({file_size} bytes), re-downloading...")

    # Try downloading from Hugging Face
    url = f"{CIC_MIRROR}/{filename}"
    print(f"    Downloading: {filename}")
    print(f"    URL: {url}")

    try:
        urllib.request.urlretrieve(url, dest, download_progress_callback)
        file_size = os.path.getsize(dest)
        print(f"    Saved: {file_size // 1024 // 1024}MB")
    except Exception as e:
        print(f"    Download failed: {e}")
        print(f"    Trying alternate download method...")
        try:
            import requests
            resp = requests.get(url, stream=True, timeout=300)
            resp.raise_for_status()
            total = int(resp.headers.get('content-length', 0))
            downloaded = 0
            with open(dest, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        percent = int(downloaded * 100 / total)
                        bar = '#' * (percent // 5) + '-' * (20 - percent // 5)
                        sys.stdout.write(f'\r    [{bar}] {percent}% ({downloaded // 1024 // 1024}MB)')
                        sys.stdout.flush()
            sys.stdout.write('\n')
            file_size = os.path.getsize(dest)
            print(f"    Saved: {file_size // 1024 // 1024}MB")
        except ImportError:
            print("    'requests' library not available. Install with: pip install requests")
            raise
        except Exception as e2:
            print(f"    Alternate download also failed: {e2}")
            raise

    return dest


def download_all_csvs(
    force: bool = False,
    max_files: Optional[int] = None
) -> List[Path]:
    """Download all CIC-IDS2017 CSV files.

    Args:
        force: Re-download even if files exist
        max_files: Limit downloads for testing (None = all)

    Returns:
        List of paths to downloaded CSV files
    """
    print(f"\n  Downloading CIC-IDS2017 CSVs to: {get_dataset_dir()}")
    print(f"  {'=' * 50}")

    files_to_get = CSV_FILES[:max_files] if max_files else CSV_FILES
    downloaded = []

    for filename in files_to_get:
        try:
            path = download_cic_csv(filename, force)
            downloaded.append(path)
        except Exception as e:
            print(f"    FAILED: {filename} — {e}")
            print(f"    Continuing with remaining files...")

    print(f"\n  Downloaded {len(downloaded)}/{len(files_to_get)} files")
    total = sum(os.path.getsize(p) for p in downloaded) / (1024**3)
    print(f"  Total size: {total:.2f} GB")

    return downloaded


def strip_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Clean CICFlowMeter column names (remove leading/trailing spaces, dots).

    CICFlowMeter CSVs have inconsistent column naming with leading spaces
    and trailing '.1', '.2' suffixes for duplicate columns.
    """
    renamed = {}
    for col in df.columns:
        new_name = col.strip()
        new_name = new_name.rstrip('.')
        # Remove duplicate numbering like '.1', '.2'
        import re
        new_name = re.sub(r'\.\d+$', '', new_name)
        renamed[col] = new_name

    df = df.rename(columns=renamed)

    # Drop duplicate columns (keep first occurrence)
    df = df.loc[:, ~df.columns.duplicated()]

    return df


def load_single_csv(path: Path) -> pd.DataFrame:
    """Load and clean a single CIC-IDS2017 CSV file.

    The CSVs have these known issues:
    1. Header row with leading spaces
    2. NaN/Inf values in some features
    3. Trailing whitespace in label column
    4. Empty rows at end
    5. Inconsistent column naming
    """
    df = pd.read_csv(path, low_memory=False)

    df = strip_column_names(df)

    # Drop rows that are all NaN
    df = df.dropna(how='all')

    # Identify the Label column (case-insensitive)
    label_col = None
    for col in df.columns:
        if col.lower().strip() == 'label':
            label_col = col
            break

    if label_col is None:
        print(f"    Warning: No 'Label' column found in {path.name}")
        print(f"    Columns: {list(df.columns)[:10]}...")
        return df

    # Clean labels: strip whitespace, normalize
    df[label_col] = df[label_col].astype(str).str.strip()

    # Drop rows with empty or NaN labels
    df = df[df[label_col].notna() & (df[label_col] != '')]
    df = df[df[label_col] != 'nan']

    return df


def load_all_csvs(
    data_dir: Optional[Path] = None,
    sample_frac: Optional[float] = None,
    random_state: int = 42,
    verbose: bool = True
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load and merge all CIC-IDS2017 CSV files into a single DataFrame.

    Args:
        data_dir: Directory containing the CSV files (default: datasets/cic_ids2017)
        sample_frac: If set, sample this fraction of the data (for quick testing)
        random_state: Random seed for sampling
        verbose: Print progress

    Returns:
        X: DataFrame with feature columns
        y: Series with labels
    """
    data_dir = Path(data_dir) if data_dir else get_dataset_dir()

    if not data_dir.exists():
        raise FileNotFoundError(
            f"Dataset directory not found: {data_dir}\n"
            f"Run 'python ml_pipeline.py cic-download' first"
        )

    csv_files = sorted(data_dir.glob('*.csv'))
    if not csv_files:
        csv_files = sorted(data_dir.glob('*.CSV'))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}\n"
            f"Run 'python ml_pipeline.py cic-download' first"
        )

    if verbose:
        print(f"\n  Loading {len(csv_files)} CIC-IDS2017 CSV files from {data_dir}")
        print(f"  {'=' * 50}")

    all_dfs = []
    total_rows = 0
    label_col = None

    for path in csv_files:
        if verbose:
            print(f"  Loading: {path.name}", end=' ')
        df = load_single_csv(path)

        # Find the label column
        if label_col is None:
            for col in df.columns:
                if col.lower().strip() == 'label':
                    label_col = col
                    break

        rows_before = len(df)
        total_rows += rows_before

        if verbose:
            label_counts = df[label_col].value_counts() if label_col else {}
            attack_types = [l for l in label_counts.index if l != 'BENIGN']
            print(f"({rows_before:,} rows, attacks: {len(attack_types)})")

        all_dfs.append(df)

    if not all_dfs:
        raise ValueError("No data loaded from CSV files")

    # Merge all dataframes
    if verbose:
        print(f"\n  Merging {len(all_dfs)} DataFrames...")

    merged = pd.concat(all_dfs, ignore_index=True, sort=False)

    if verbose:
        print(f"  Total rows before cleaning: {len(merged):,}")

    # Remove infinite values
    numeric_cols = merged.select_dtypes(include=[np.number]).columns
    merged = merged.replace([np.inf, -np.inf], np.nan)

    # Remove NaN values (drop rows with any NaN in feature columns)
    feature_cols = [c for c in merged.columns if c != label_col]
    before_drop = len(merged)
    merged = merged.dropna(subset=feature_cols, how='any')
    if verbose:
        dropped = before_drop - len(merged)
        if dropped > 0:
            print(f"  Dropped {dropped:,} rows with NaN values ({dropped/before_drop*100:.1f}%)")

    # Remove rows where features are all zero
    zero_mask = (merged[feature_cols] == 0).all(axis=1)
    zero_count = zero_mask.sum()
    if zero_count > 0:
        merged = merged[~zero_mask]
        if verbose:
            print(f"  Dropped {zero_count:,} rows with all-zero features")

    if sample_frac is not None and sample_frac < 1.0:
        if verbose:
            print(f"  Sampling {sample_frac*100:.0f}% of data...")
        merged = merged.sample(frac=sample_frac, random_state=random_state)

    if verbose:
        print(f"  Final rows: {len(merged):,}")
        print(f"  Features: {len(feature_cols)}")

    # Separate features and labels
    X = merged[feature_cols].copy()
    y = merged[label_col].astype(str).str.strip().copy()

    # Convert numeric columns to float
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')

    # Fill any remaining NaN in features with 0
    X = X.fillna(0)

    return X, y


def normalize_labels(
    y: pd.Series,
    attack_groups: bool = True,
    binary: bool = False
) -> pd.Series:
    """Normalize attack labels.

    Args:
        y: Raw label series
        attack_groups: Group specific attacks into categories
                       (e.g., all DoS variants → 'DoS')
        binary: If True, label as 'BENIGN' or 'ATTACK'

    Returns:
        Normalized label series
    """
    if binary:
        return y.apply(lambda x: 'BENIGN' if x.upper() == 'BENIGN' else 'ATTACK')

    if attack_groups:
        return y.map(ATTACK_TYPE_MAP).fillna(y)

    return y


def get_label_distribution(
    y: pd.Series,
    top_n: int = 20
) -> pd.Series:
    """Get the distribution of labels after normalization."""
    counts = y.value_counts()
    total = len(y)
    print(f"\n  Label Distribution ({len(counts)} classes):")
    print(f"  {'Label':<25} {'Count':>10} {'%':>8}")
    print(f"  {'-' * 45}")
    for label, count in counts.head(top_n).items():
        pct = count / total * 100
        bar = '#' * max(1, int(pct / 2))
        print(f"  {label:<25} {count:>10,} {pct:>7.2f}%  {bar}")
    if len(counts) > top_n:
        other = counts[top_n:].sum()
        other_pct = other / total * 100
        print(f"  {'(other ' + str(len(counts) - top_n) + ' classes)':<25} {other:>10,} {other_pct:>7.2f}%")
    return counts


def prepare_feature_matrix(
    X: pd.DataFrame,
    selected_features: Optional[List[str]] = None,
    drop_zero_variance: bool = True,
    drop_high_correlation: bool = False,
    max_features: Optional[int] = None,
    verbose: bool = True
) -> pd.DataFrame:
    """Prepare the feature matrix for ML training.

    Steps:
    1. Select only the features we want
    2. Remove zero-variance features (constant columns)
    3. Optionally remove highly correlated features
    4. Optionally limit to top-k features

    Args:
        X: Full feature DataFrame
        selected_features: If provided, only keep these features
        drop_zero_variance: Remove features with zero variance
        drop_high_correlation: Remove features with >0.95 correlation
        max_features: Limit to top-k features by variance
        verbose: Print progress

    Returns:
        Cleaned feature DataFrame
    """
    X_clean = X.copy()

    if selected_features:
        available = [f for f in selected_features if f in X_clean.columns]
        missing = [f for f in selected_features if f not in X_clean.columns]
        X_clean = X_clean[available]
        if verbose and missing:
            print(f"  Missing {len(missing)} requested features: {missing[:5]}...")

    if drop_zero_variance:
        zero_var = X_clean.columns[X_clean.std(axis=0) == 0]
        if len(zero_var) > 0 and verbose:
            print(f"  Dropped {len(zero_var)} zero-variance features")
        X_clean = X_clean.drop(columns=zero_var)

    if drop_high_correlation:
        corr_matrix = X_clean.corr().abs()
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        high_corr = [col for col in upper.columns if any(upper[col] > 0.95)]
        if verbose:
            print(f"  Dropped {len(high_corr)} highly correlated features (>0.95)")
        X_clean = X_clean.drop(columns=high_corr)

    if max_features and X_clean.shape[1] > max_features:
        variances = X_clean.var(axis=0).sort_values(ascending=False)
        top_features = variances.head(max_features).index.tolist()
        X_clean = X_clean[top_features]
        if verbose:
            print(f"  Limited to top {max_features} features by variance")

    if verbose:
        print(f"  Feature matrix: {X_clean.shape[0]:,} rows x {X_clean.shape[1]} columns")

    return X_clean


def balance_dataset(
    X: pd.DataFrame,
    y: pd.Series,
    strategy: str = 'undersample',
    random_state: int = 42,
    verbose: bool = True
) -> Tuple[pd.DataFrame, pd.Series]:
    """Balance the dataset to handle class imbalance.

    CIC-IDS2017 has severe class imbalance:
    - BENIGN: ~2.3M flows
    - Most attacks: <50K flows

    Strategies:
    - 'undersample': Randomly sample majority class to match minority
    - 'oversample': SMOTE or random oversampling of minority classes
    - 'hybrid': Undersample majority, oversample minority
    """
    from sklearn.utils import resample

    X_bal = X.copy()
    y_bal = y.copy()

    if strategy == 'undersample':
        # Find the smallest class size
        class_counts = y_bal.value_counts()
        min_count = class_counts.min()

        if verbose:
            print(f"\n  Undersampling all classes to {min_count:,} samples...")

        balanced_dfs = []
        for cls in class_counts.index:
            cls_mask = y_bal == cls
            cls_X = X_bal[cls_mask]
            cls_y = y_bal[cls_mask]
            if len(cls_X) > min_count:
                cls_X_sampled, cls_y_sampled = resample(
                    cls_X, cls_y,
                    replace=False,
                    n_samples=min_count,
                    random_state=random_state,
                )
            else:
                cls_X_sampled, cls_y_sampled = cls_X, cls_y
            balanced_dfs.append(pd.concat([cls_X_sampled, cls_y_sampled], axis=1))

        balanced = pd.concat(balanced_dfs, ignore_index=True)
        X_bal = balanced.drop(columns=[y.name])
        y_bal = balanced[y.name]

        if verbose:
            print(f"  Balanced dataset: {len(X_bal):,} rows")

    return X_bal, y_bal


def train_on_cic_ids(
    X_train, y_train, X_test, y_test,
    model_type: str = 'random_forest',
    sample_weight: Optional[np.ndarray] = None,
    **train_kwargs
):
    """Train a classifier on CIC-IDS2017 data.

    This reuses our existing ml_train.train_classifier but adds
    CIC-IDS2017-specific optimizations:
    1. Class weight balancing for imbalanced data
    2. Early stopping for XGBoost
    3. Custom evaluation metric (F1 for IDS)
    """
    from ml_train import train_classifier

    if model_type == 'random_forest':
        return train_classifier(
            X_train, y_train,
            model_type='random_forest',
            n_estimators=train_kwargs.get('n_estimators', 300),
            max_depth=train_kwargs.get('max_depth', 30),
            min_samples_split=train_kwargs.get('min_samples_split', 5),
            min_samples_leaf=train_kwargs.get('min_samples_leaf', 2),
            class_weight=train_kwargs.get('class_weight', 'balanced'),
        )

    elif model_type == 'xgboost':
        from xgboost import XGBClassifier
        model = XGBClassifier(
            n_estimators=train_kwargs.get('n_estimators', 500),
            max_depth=train_kwargs.get('max_depth', 12),
            learning_rate=train_kwargs.get('learning_rate', 0.05),
            subsample=train_kwargs.get('subsample', 0.8),
            colsample_bytree=train_kwargs.get('colsample_bytree', 0.8),
            scale_pos_weight=train_kwargs.get('scale_pos_weight', 1),
            eval_metric='mlogloss',
            early_stopping_rounds=train_kwargs.get('early_stopping_rounds', 50),
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )
        print(f"  Training XGBoost with early stopping...")
        start = time.time()
        model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False,
        )
        elapsed = time.time() - start
        print(f"  Trained in {elapsed:.2f}s (best iteration: {model.best_iteration+1})")
        return model

    else:
        return train_classifier(
            X_train, y_train, model_type=model_type, **train_kwargs
        )


def evaluate_cic_ids(
    model,
    X_test, y_test,
    label_names: Optional[List[str]] = None,
    verbose: bool = True
) -> Dict:
    """Comprehensive evaluation for intrusion detection.

    Produces all metrics required:
    - Accuracy
    - Precision (macro, weighted)
    - Recall (macro, weighted)
    - F1 Score (macro, weighted)
    - ROC-AUC (one-vs-rest for multi-class)
    - Confusion Matrix
    """
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_auc_score,
        roc_curve, precision_recall_curve
    )
    from sklearn.preprocessing import label_binarize

    y_pred = model.predict(X_test)

    results = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision_macro': float(precision_score(y_test, y_pred, average='macro', zero_division=0)),
        'recall_macro': float(recall_score(y_test, y_pred, average='macro', zero_division=0)),
        'f1_macro': float(f1_score(y_test, y_pred, average='macro', zero_division=0)),
        'precision_weighted': float(precision_score(y_test, y_pred, average='weighted', zero_division=0)),
        'recall_weighted': float(recall_score(y_test, y_pred, average='weighted', zero_division=0)),
        'f1_weighted': float(f1_score(y_test, y_pred, average='weighted', zero_division=0)),
    }

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    results['confusion_matrix'] = cm.tolist()
    results['confusion_matrix_labels'] = list(set(y_test) | set(y_pred))

    # ROC-AUC (multi-class: one-vs-rest)
    try:
        y_score = model.predict_proba(X_test)
        classes = sorted(set(y_test) | set(y_pred))
        y_test_bin = label_binarize(y_test, classes=classes)

        roc_auc_scores = {}
        for i, cls in enumerate(classes):
            if len(np.unique(y_test_bin[:, i])) > 1:
                roc_auc_scores[str(cls)] = float(
                    roc_auc_score(y_test_bin[:, i], y_score[:, i])
                )

        if roc_auc_scores:
            results['roc_auc_per_class'] = roc_auc_scores
            results['roc_auc_macro'] = float(np.mean(list(roc_auc_scores.values())))
        else:
            results['roc_auc_macro'] = 0.0
    except Exception as e:
        results['roc_auc_macro'] = 0.0
        if verbose:
            print(f"  ROC-AUC computation skipped: {e}")

    # Present labels for classification report
    present_labels = sorted(set(y_test) | set(y_pred))
    if label_names:
        present_names = [
            label_names[i] if isinstance(next(iter(present_labels)), int) else str(l)
            for l in present_labels
        ]
    else:
        present_names = [str(l) for l in present_labels]

    report = classification_report(
        y_test, y_pred,
        labels=present_labels,
        target_names=present_names,
        output_dict=True,
        zero_division=0,
    )
    results['classification_report'] = report

    if verbose:
        print(f"\n  === Classification Metrics ===")
        print(f"  {'Accuracy':<20} {results['accuracy']:.4f}")
        print(f"  {'Precision (macro)':<20} {results['precision_macro']:.4f}")
        print(f"  {'Recall (macro)':<20} {results['recall_macro']:.4f}")
        print(f"  {'F1 Score (macro)':<20} {results['f1_macro']:.4f}")
        print(f"  {'Precision (weighted)':<20} {results['precision_weighted']:.4f}")
        print(f"  {'Recall (weighted)':<20} {results['recall_weighted']:.4f}")
        print(f"  {'F1 Score (weighted)':<20} {results['f1_weighted']:.4f}")
        if 'roc_auc_macro' in results:
            print(f"  {'ROC-AUC (macro)':<20} {results['roc_auc_macro']:.4f}")
        print(f"\n{classification_report(y_test, y_pred, labels=present_labels, target_names=present_names, zero_division=0)}")

    return results


def run_full_pipeline(
    data_dir: Optional[Path] = None,
    model_type: str = 'random_forest',
    test_size: float = 0.2,
    sample_frac: Optional[float] = None,
    balance: str = 'none',
    binary: bool = False,
    attack_groups: bool = True,
    drop_correlated: bool = False,
    output_model: str = 'cic_ids_model.pkl',
    verbose: bool = True,
) -> Dict:
    """Run the complete CIC-IDS2017 training pipeline.

    This is the main entry point that:
    1. Loads CSVs from disk
    2. Cleans and preprocesses data
    3. Balances classes (optional)
    4. Trains RF or XGBoost
    5. Evaluates with all metrics
    6. Saves the model

    Args:
        data_dir: Path to CSV files directory
        model_type: 'random_forest' or 'xgboost'
        test_size: Fraction for test set
        sample_frac: Subsampling fraction (for testing)
        balance: 'none', 'undersample', or 'oversample'
        binary: If True, label as BENIGN/ATTACK
        attack_groups: Group specific attacks into categories
        drop_correlated: Remove highly correlated features
        output_model: Path to save the trained model
        verbose: Print progress

    Returns:
        Dictionary with model, scaler, metadata, evaluation results
    """
    print()
    print("=" * 60)
    print("  CIC-IDS2017 — Full ML Pipeline")
    print("=" * 60)

    # Step 1: Load data
    print("\n[1/6] Loading CIC-IDS2017 data...")
    X, y = load_all_csvs(
        data_dir=data_dir,
        sample_frac=sample_frac,
        verbose=verbose,
    )

    # Step 2: Preprocess
    print("\n[2/6] Preprocessing...")
    X = prepare_feature_matrix(
        X,
        drop_zero_variance=True,
        drop_high_correlation=drop_correlated,
        verbose=verbose,
    )
    y = normalize_labels(y, attack_groups=attack_groups, binary=binary)

    # Show label distribution
    get_label_distribution(y)

    # Step 3: Split
    print("\n[3/6] Train/test split...")
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    # Encode string labels to integers
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    label_names = [str(c) for c in label_encoder.classes_]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded,
        test_size=test_size,
        random_state=42,
        stratify=y_encoded,
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print(f"  Train: {len(X_train):,} samples")
    print(f"  Test:  {len(X_test):,} samples")
    print(f"  Classes: {len(label_names)}")

    # Step 4: Balance (optional)
    if balance != 'none':
        print("\n  Balancing dataset...")
        from imblearn.over_sampling import SMOTE
        from imblearn.under_sampling import RandomUnderSampler
        from imblearn.combine import SMOTEENN

        if balance == 'smote':
            sampler = SMOTE(random_state=42)
        elif balance == 'undersample':
            sampler = RandomUnderSampler(random_state=42)
        elif balance == 'smoteenn':
            sampler = SMOTEENN(random_state=42)
        else:
            sampler = None

        if sampler:
            X_train_scaled, y_train = sampler.fit_resample(X_train_scaled, y_train)
            print(f"  After balancing: {len(X_train):,} samples")

    # Step 5: Train
    print(f"\n[4/6] Training {model_type}...")
    model = train_on_cic_ids(
        X_train_scaled, y_train,
        X_test_scaled, y_test,
        model_type=model_type,
        n_estimators=300,
        max_depth=30,
    )

    # Step 6: Evaluate
    print(f"\n[5/6] Evaluating...")
    results = evaluate_cic_ids(
        model, X_test_scaled, y_test,
        label_names=label_names,
        verbose=True,
    )

    # Step 7: Save
    print(f"\n[6/6] Saving model...")
    from ml_train import save_model
    metadata = {
        'model_type': model_type,
        'dataset': 'CIC-IDS2017',
        'feature_count': X.shape[1],
        'class_count': len(label_names),
        'label_names': label_names,
        'label_encoder': label_encoder,
        'training_samples': len(X_train),
        'test_samples': len(X_test),
        'accuracy': results['accuracy'],
        'f1_macro': results['f1_macro'],
        'roc_auc_macro': results.get('roc_auc_macro', 0),
        'timestamp': time.time(),
        'feature_columns': list(X.columns),
        'binary': binary,
        'attack_groups': attack_groups,
    }

    # Save feature column names for the API
    save_data = {
        'model': model,
        'scaler': scaler,
        'metadata': metadata,
        'feature_names': list(X.columns),
        'feature_columns': list(X.columns),
    }

    import pickle
    with open(output_model, 'wb') as f:
        pickle.dump(save_data, f)
    print(f"  Model saved to: {output_model}")

    # Save evaluation results to JSON
    eval_path = output_model.replace('.pkl', '_eval.json')
    import json
    class EvalEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.integer,)):
                return int(obj)
            if isinstance(obj, (np.floating,)):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return super().default(obj)

    with open(eval_path, 'w') as f:
        json.dump(results, f, cls=EvalEncoder, indent=2)
    print(f"  Evaluation saved to: {eval_path}")

    print(f"\n  {'=' * 60}")
    print(f"  Pipeline complete!")
    print(f"  Run API: python api_server.py --model {output_model} --cic-mode")
    print(f"  {'=' * 60}")

    return save_data


def match_pcap_flows_to_csv_labels(
    pcap_path: Path,
    csv_path: Optional[Path] = None,
    csv_data: Optional[pd.DataFrame] = None,
    verbose: bool = True
) -> pd.DataFrame:
    """Process a PCAP through our existing pipeline and match flows to labels.

    PATH B: This function bridges our PCAP processing pipeline with the
    CIC-IDS2017 CSV labels.

    How flow matching works:
    1. Process PCAP through: pcap_reader → packet_parser → flow_tracker
    2. Extract features via ml_features.extract_flow_features
    3. Read CSV labels
    4. Match flows using 5-tuple + timestamp proximity

    This is the "full" path that validates our entire pipeline on real traffic.
    """
    from pcap_reader import PcapReader
    from packet_parser import PacketParser
    from flow_tracker import DPIEngine, FlowTracker
    from ml_features import extract_flow_features

    if verbose:
        print(f"\n  Processing PCAP: {pcap_path}")

    # Step 1: Process PCAP through our pipeline
    engine = DPIEngine()
    payload_samples = defaultdict(list)

    with PcapReader(str(pcap_path)) as reader:
        for pkt_header, raw_data in reader.packets():
            packet = PacketParser.parse(pkt_header, raw_data)
            if packet is None:
                continue
            engine.process_packet(packet)
            ft = packet.five_tuple
            if ft:
                payload = packet.payload
                if payload:
                    payload_samples[ft].append(payload)

    # Step 2: Extract our features from each flow
    our_flow_features = []
    flow_tuples = []

    for flow in engine.flow_tracker.get_all_flows():
        ft = flow.five_tuple
        samples = payload_samples.get(ft, [])
        feats = extract_flow_features(flow, samples)
        feats['src_ip'] = ft.src_ip
        feats['dst_ip'] = ft.dst_ip
        feats['src_port'] = ft.src_port
        feats['dst_port'] = ft.dst_port
        feats['protocol'] = ft.protocol
        feats['flow_duration'] = flow.duration
        feats['first_seen'] = flow.first_seen
        feats['last_seen'] = flow.last_seen
        our_flow_features.append(feats)

    our_df = pd.DataFrame(our_flow_features)

    if verbose:
        print(f"  Extracted {len(our_df)} flows from PCAP")

    # Step 3: Load CSV labels
    if csv_path is not None:
        csv_df = load_single_csv(csv_path)
    elif csv_data is not None:
        csv_df = csv_data
    else:
        if verbose:
            print("  No CSV labels provided — returning our features only")
        return our_df

    # Step 4: Find the label column in CSV
    label_col = None
    for col in csv_df.columns:
        if col.lower().strip() == 'label':
            label_col = col
            break

    if label_col is None:
        if verbose:
            print("  No Label column found in CSV")
        return our_df

    # Step 5: Match flows by 5-tuple
    if verbose:
        print(f"  Matching {len(our_df)} flows to {len(csv_df)} CSV entries...")

    # Build index: (src_ip, dst_ip, src_port, dst_port, protocol) → label
    csv_index = {}
    for idx, row in csv_df.iterrows():
        # Find IP and port columns in the CSV
        src_ip = row.get(' Source IP', row.get('Source IP', ''))
        dst_ip = row.get(' Destination IP', row.get('Destination IP', ''))
        src_port = row.get(' Source Port', row.get('Source Port', 0))
        dst_port = row.get(' Destination Port', row.get('Destination Port', 0))
        protocol = row.get(' Protocol', row.get('Protocol', 0))

        key = (str(src_ip), str(dst_ip), int(src_port) if pd.notna(src_port) else 0,
               int(dst_port) if pd.notna(dst_port) else 0, int(protocol) if pd.notna(protocol) else 0)
        csv_index[key] = str(row[label_col]).strip()

    # Match our flows to CSV labels
    matched_labels = []
    matched_count = 0
    for _, row in our_df.iterrows():
        key = (row.get('src_ip', ''), row.get('dst_ip', ''),
               int(row.get('src_port', 0)), int(row.get('dst_port', 0)),
               int(row.get('protocol', 0)))

        label = csv_index.get(key, 'UNKNOWN')
        matched_labels.append(label)
        if label != 'UNKNOWN':
            matched_count += 1

    our_df['cic_label'] = matched_labels

    if verbose:
        match_rate = matched_count / len(our_df) * 100 if len(our_df) > 0 else 0
        print(f"  Matched {matched_count}/{len(our_df)} flows ({match_rate:.1f}%)")
        if matched_count > 0:
            print(f"  Label distribution from matched flows:")
            label_counts = our_df[our_df['cic_label'] != 'UNKNOWN']['cic_label'].value_counts()
            for lbl, cnt in label_counts.items():
                print(f"    {lbl}: {cnt}")

    return our_df
