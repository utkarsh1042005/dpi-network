"""
ML Training & Evaluation Module for Network Traffic Analysis.

ARCHITECTURE:
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│  PCAP Files  │───▶│ Flow Tracker │───▶│ Feature     │
│  (labeled)   │    │              │    │ Extraction  │
└─────────────┘    └──────────────┘    └──────┬──────┘
                                              │
                                              ▼
                                     ┌────────────────┐
                                     │  Train/Test     │
                                     │  Split          │
                                     └────┬───────────┘
                                          │
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                   ┌────────────┐  ┌────────────┐  ┌────────────┐
                   │ Classifier │  │  Anomaly   │  │   Save     │
                   │ (RF/LGBM)  │  │  Detector  │  │   Model    │
                   │            │  │ (Isolation │  │ (pickle)   │
                   │            │  │  Forest)   │  │            │
                   └────────────┘  └────────────┘  └────────────┘
"""

import json
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from models import AppType, FlowState, DPIStats, FiveTuple, ConnectionState
from flow_tracker import DPIEngine, FlowTracker
from pcap_reader import PcapReader
from packet_parser import PacketParser
from ml_features import extract_flow_features, get_feature_names, FEATURE_NAMES


def generate_dataset_from_pcaps(
    pcap_files: List[str],
    labels: Optional[Dict[str, AppType]] = None,
    max_flows: int = 10000,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Generate a labeled dataset from PCAP files.

    This is the bridge between raw network traffic and ML.
    It processes PCAPs through the DPI engine, classifies flows,
    extracts features, and returns a pandas DataFrame ready for training.

    Args:
        pcap_files: List of paths to PCAP files
        labels: Optional dict mapping filename -> AppType for ground truth
        max_flows: Maximum number of flows to extract

    Returns:
        X: DataFrame with feature columns
        y: Series with labels (AppType)
    """
    all_features = []
    all_labels = []

    for pcap_file in pcap_files:
        print(f"  Processing {pcap_file}...")
        engine = DPIEngine()
        flow_map: Dict[FiveTuple, FlowState] = {}
        payload_samples: Dict[FiveTuple, List[bytes]] = defaultdict(list)

        try:
            with PcapReader(pcap_file) as reader:
                for pkt_header, raw_data in reader.packets():
                    packet = PacketParser.parse(pkt_header, raw_data)
                    if packet is None:
                        continue

                    # Process through DPI engine for classification
                    engine.process_packet(packet)

                    # Collect payload samples for entropy calculation
                    ft = packet.five_tuple
                    if ft:
                        payload = packet.payload
                        if payload:
                            payload_samples[ft].append(payload)

        except Exception as e:
            print(f"  Error processing {pcap_file}: {e}")
            continue

        # Extract features from each flow
        for flow in engine.flow_tracker.get_all_flows():
            ft = flow.five_tuple
            samples = payload_samples.get(ft, [])
            feats = extract_flow_features(flow, samples)
            all_features.append(feats)

            # Determine label
            if labels and pcap_file in labels:
                all_labels.append(labels[pcap_file].value)
            else:
                all_labels.append(flow.app_type.value)

            if len(all_features) >= max_flows:
                break

        print(f"  -> Extracted {len(all_features)} flows so far")

    if not all_features:
        raise ValueError("No flows extracted from PCAP files")

    df = pd.DataFrame(all_features)
    # Handle NaN/inf values
    df = df.replace([np.inf, -np.inf], 0).fillna(0)
    y = pd.Series(all_labels, name='app_type')

    return df, y


def prepare_data(
    X: pd.DataFrame, y: pd.Series,
    test_size: float = 0.2,
    random_state: int = 42,
    scale: bool = True
) -> Tuple:
    """Split data and optionally scale features.

    Returns:
        X_train, X_test, y_train, y_test, scaler (or None)
    """
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    # Stratification requires each class to have at least 2 members
    # when using test_size. Check if stratification is feasible.
    use_stratify = False
    if len(np.unique(y)) > 1:
        class_counts = y.value_counts()
        min_samples_needed = max(2, int(1 / test_size) + 1)
        if class_counts.min() >= min_samples_needed:
            use_stratify = True

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state,
        stratify=y if use_stratify else None
    )

    scaler = None
    if scale:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train.values if hasattr(X_train, 'values') else X_train)
        X_test = scaler.transform(X_test.values if hasattr(X_test, 'values') else X_test)

    return X_train, X_test, y_train, y_test, scaler


def train_classifier(
    X_train, y_train,
    model_type: str = 'random_forest',
    **kwargs
):
    """Train a traffic classification model.

    Recommended algorithms for network traffic classification:

    1. RANDOM FOREST (default):
       - Pros: Handles mixed feature types, interpretable
       - Cons: Can overfit on noisy traffic data
       - Best for: General traffic classification

    2. XGBOOST:
       - Pros: State-of-art for tabular data, handles missing values
       - Cons: More hyperparameters to tune
       - Best for: High-accuracy classification

    3. LOGISTIC REGRESSION:
       - Pros: Fast, interpretable, good baseline
       - Cons: Assumes linear decision boundary
       - Best for: Binary classification (malicious/benign)

    4. GRADIENT BOOSTING:
       - Pros: Often best accuracy, handles non-linearity
       - Cons: Slower training, more tuning
       - Best for: When accuracy is priority
    """
    if model_type == 'random_forest':
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(
            n_estimators=kwargs.get('n_estimators', 200),
            max_depth=kwargs.get('max_depth', 20),
            min_samples_split=kwargs.get('min_samples_split', 5),
            min_samples_leaf=kwargs.get('min_samples_leaf', 2),
            class_weight=kwargs.get('class_weight', 'balanced'),
            n_jobs=-1,
            random_state=42,
        )
    elif model_type == 'xgboost':
        from xgboost import XGBClassifier
        model = XGBClassifier(
            n_estimators=kwargs.get('n_estimators', 200),
            max_depth=kwargs.get('max_depth', 8),
            learning_rate=kwargs.get('learning_rate', 0.1),
            subsample=kwargs.get('subsample', 0.8),
            colsample_bytree=kwargs.get('colsample_bytree', 0.8),
            eval_metric='mlogloss',
            random_state=42,
            verbosity=0,
        )
    elif model_type == 'logistic_regression':
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(
            max_iter=kwargs.get('max_iter', 1000),
            class_weight=kwargs.get('class_weight', 'balanced'),
            multi_class='multinomial',
            n_jobs=-1,
            random_state=42,
        )
    elif model_type == 'gradient_boosting':
        from sklearn.ensemble import GradientBoostingClassifier
        model = GradientBoostingClassifier(
            n_estimators=kwargs.get('n_estimators', 200),
            max_depth=kwargs.get('max_depth', 6),
            learning_rate=kwargs.get('learning_rate', 0.1),
            subsample=kwargs.get('subsample', 0.8),
            random_state=42,
        )
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    print(f"  Training {model_type}...")
    start = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - start
    print(f"  Trained in {elapsed:.2f}s")

    return model


def train_anomaly_detector(
    X_train,
    model_type: str = 'isolation_forest',
    **kwargs
):
    """Train an anomaly/outlier detection model.

    Use case: Detect malicious traffic, zero-day attacks, or
    traffic that deviates from normal patterns.

    1. ISOLATION FOREST:
       - Works by randomly isolating observations
       - Anomalies are easier to isolate (shorter paths)
       - Fast, handles high-dimensional data

    2. ONE-CLASS SVM:
       - Finds a boundary around normal data
       - Better for well-defined normal patterns
       - Scales poorly with data size

    3. AUTOENCODER (via sklearn):
       - Neural network reconstructs normal traffic
       - Anomalies have high reconstruction error
       - Requires more data and tuning
    """
    if model_type == 'isolation_forest':
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(
            n_estimators=kwargs.get('n_estimators', 200),
            contamination=kwargs.get('contamination', 0.1),
            random_state=42,
            n_jobs=-1,
        )
    elif model_type == 'one_class_svm':
        from sklearn.svm import OneClassSVM
        model = OneClassSVM(
            nu=kwargs.get('nu', 0.1),
            kernel=kwargs.get('kernel', 'rbf'),
            gamma=kwargs.get('gamma', 'auto'),
        )
    else:
        raise ValueError(f"Unknown anomaly model: {model_type}")

    print(f"  Training {model_type} anomaly detector...")
    start = time.time()
    model.fit(X_train)
    elapsed = time.time() - start
    print(f"  Trained in {elapsed:.2f}s")

    return model


def evaluate_classifier(model, X_test, y_test, label_names: Optional[List[str]] = None) -> Dict:
    """Comprehensive evaluation of classification model.

    Returns dictionary with:
    - accuracy, precision, recall, f1 (macro, micro, weighted)
    - confusion matrix
    - classification report
    - per-class metrics
    """
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report
    )

    y_pred = model.predict(X_test)

    results = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision_macro': precision_score(y_test, y_pred, average='macro', zero_division=0),
        'recall_macro': recall_score(y_test, y_pred, average='macro', zero_division=0),
        'f1_macro': f1_score(y_test, y_pred, average='macro', zero_division=0),
        'precision_weighted': precision_score(y_test, y_pred, average='weighted', zero_division=0),
        'recall_weighted': recall_score(y_test, y_pred, average='weighted', zero_division=0),
        'f1_weighted': f1_score(y_test, y_pred, average='weighted', zero_division=0),
    }

    cm = confusion_matrix(y_test, y_pred)
    results['confusion_matrix'] = cm.tolist()

    # Only include labels that actually appear in the test set
    present_labels = sorted(set(y_test) | set(y_pred))
    present_names = (
        [label_names[i] for i in present_labels]
        if label_names and max(present_labels) < len(label_names)
        else None
    )
    report = classification_report(
        y_test, y_pred,
        labels=present_labels,
        target_names=present_names,
        output_dict=True,
        zero_division=0,
    )
    results['classification_report'] = report

    print(f"\n  Accuracy:  {results['accuracy']:.4f}")
    print(f"  Precision (macro): {results['precision_macro']:.4f}")
    print(f"  Recall (macro):    {results['recall_macro']:.4f}")
    print(f"  F1-Score (macro):  {results['f1_macro']:.4f}")
    print(f"\n{classification_report(y_test, y_pred, labels=present_labels, target_names=present_names, zero_division=0)}")

    return results


def evaluate_anomaly_detector(model, X_test, y_test) -> Dict:
    """Evaluate anomaly detection model.

    For anomaly detection:
    - model.predict() returns 1 for normal, -1 for anomaly
    - Convert to binary: 1 = normal, 0 = anomaly
    """
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score
    )

    y_pred = model.predict(X_test)
    y_pred_binary = np.where(y_pred == -1, 0, 1)
    y_test_binary = np.where(y_test > 0, 1, 0)  # Assume class 0 is anomaly

    # For AUC-ROC, use decision function or score_samples
    try:
        y_score = model.decision_function(X_test)
    except AttributeError:
        try:
            y_score = model.score_samples(X_test)
            y_score = -y_score  # anomaly detectors return lower scores for anomalies
        except AttributeError:
            y_score = y_pred  # fallback

    results = {
        'accuracy': accuracy_score(y_test_binary, y_pred_binary),
        'precision': precision_score(y_test_binary, y_pred_binary, zero_division=0),
        'recall': recall_score(y_test_binary, y_pred_binary, zero_division=0),
        'f1': f1_score(y_test_binary, y_pred_binary, zero_division=0),
    }

    try:
        results['auc_roc'] = roc_auc_score(y_test_binary, y_score)
    except Exception:
        results['auc_roc'] = 0.0

    cm = confusion_matrix(y_test_binary, y_pred_binary)
    results['confusion_matrix'] = cm.tolist()

    print(f"\n  Anomaly Detection Results:")
    print(f"  Accuracy:  {results['accuracy']:.4f}")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall:    {results['recall']:.4f}")
    print(f"  F1-Score:  {results['f1']:.4f}")
    print(f"  AUC-ROC:   {results['auc_roc']:.4f}")

    return results


def save_model(model, scaler, metadata: Dict, filepath: str):
    """Save trained model, scaler, and metadata to disk.

    Uses pickle format for simplicity. For production, consider ONNX.
    """
    save_data = {
        'model': model,
        'scaler': scaler,
        'metadata': metadata,
        'feature_names': FEATURE_NAMES,
    }
    with open(filepath, 'wb') as f:
        pickle.dump(save_data, f)
    print(f"  Model saved to: {filepath}")


def load_model(filepath: str) -> Dict:
    """Load a trained model from disk."""
    with open(filepath, 'rb') as f:
        data = pickle.load(f)
    print(f"  Model loaded from: {filepath}")
    return data


def _our_to_cic_features(our_feats: Dict[str, float], cic_columns: List[str]) -> np.ndarray:
    """Convert our 86 features to CIC-IDS2017 feature format."""
    try:
        from cic_ids import CIC_TO_OUR_FEATURES
        cic_to_our = CIC_TO_OUR_FEATURES
    except ImportError:
        cic_to_our = {}
    our_to_cic = {v: k for k, v in cic_to_our.items()}
    arr = np.zeros((1, len(cic_columns)), dtype=np.float64)
    for i, col in enumerate(cic_columns):
        val = 0.0
        if col in cic_to_our and cic_to_our[col] in our_feats:
            val = our_feats[cic_to_our[col]]
        arr[0, i] = val
    return arr


def predict_flow(
    model_data: Dict,
    flow: FlowState,
    payload_samples: Optional[List[bytes]] = None
) -> Dict:
    """Predict the application type of a flow using the trained model.

    The full ML inference pipeline:
    1. Extract features from flow
    2. Scale features (using training scaler)
    3. Predict with model
    4. Return prediction + confidence
    """
    feats = extract_flow_features(flow, payload_samples)
    feature_columns = model_data.get('feature_columns')
    if feature_columns:
        feature_vector = _our_to_cic_features(feats, feature_columns)
    else:
        feature_vector = np.array([[feats[k] for k in FEATURE_NAMES]], dtype=np.float64)

    scaler = model_data.get('scaler')
    if scaler:
        feature_vector = scaler.transform(feature_vector)

    model = model_data['model']
    prediction = model.predict(feature_vector)[0]

    # Get prediction probabilities
    try:
        probabilities = model.predict_proba(feature_vector)[0]
        confidence = float(np.max(probabilities))
        class_probs = {
            str(model_data['metadata'].get('label_names', [])[i] if 'label_names' in model_data['metadata'] else i): float(p)
            for i, p in enumerate(probabilities)
        }
    except (AttributeError, KeyError):
        confidence = 1.0
        class_probs = {}

    label_names = model_data.get('metadata', {}).get('label_names', [])
    if label_names and isinstance(prediction, (int, np.integer)) and prediction < len(label_names):
        predicted_label = label_names[int(prediction)]
    else:
        try:
            predicted_label = AppType(int(prediction)).name if isinstance(prediction, (int, np.integer)) else AppType[prediction].name
        except (ValueError, KeyError):
            predicted_label = str(prediction)

    return {
        'predicted_app': predicted_label,
        'confidence': confidence,
        'class_probabilities': class_probs,
        'features': {k: float(v) for k, v in feats.items()},
        'features_used': len(feature_vector[0]),
    }


def predict_pcap(
    model_data: Dict,
    pcap_path: str,
    max_flows: int = 1000
) -> pd.DataFrame:
    """Run ML inference on an entire PCAP file.

    Returns a DataFrame with per-flow predictions.
    """
    from collections import defaultdict

    engine = DPIEngine()
    payload_samples: Dict[FiveTuple, List[bytes]] = defaultdict(list)

    with PcapReader(pcap_path) as reader:
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

    results = []
    for flow in engine.flow_tracker.get_all_flows():
        ft = flow.five_tuple
        samples = payload_samples.get(ft, [])
        pred = predict_flow(model_data, flow, samples)
        results.append({
            'src_ip': ft.src_ip,
            'dst_ip': ft.dst_ip,
            'src_port': ft.src_port,
            'dst_port': ft.dst_port,
            'protocol': ft.protocol,
            'duration': flow.duration,
            'total_packets': flow.total_packets,
            'sni': flow.sni or '',
            'ground_truth': flow.app_type.name,
            'predicted': pred['predicted_app'],
            'confidence': pred['confidence'],
        })

    df = pd.DataFrame(results)
    return df
