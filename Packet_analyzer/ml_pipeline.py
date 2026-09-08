#!/usr/bin/env python3
"""
ML Pipeline — End-to-end machine learning for network traffic analysis.

This is the main entry point for the AI-powered DPI system.

Workflow:
1. Generate dataset from PCAP files
2. Feature extraction and preprocessing
3. Train classification model
4. Train anomaly detection model
5. Evaluate models
6. Save models for deployment
7. Visualize results

Usage:
    # Train models using labeled PCAP files
    python ml_pipeline.py train --pcap data/*.pcap --output model.pkl

    # Evaluate on a test PCAP
    python ml_pipeline.py evaluate --model model.pkl --pcap test.pcap

    # Export dataset to CSV for analysis
    python ml_pipeline.py export --pcap data/*.pcap --output dataset.csv

    # Quick test with included test PCAP
    python ml_pipeline.py demo
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from ml_features import extract_flow_features, get_feature_names, FEATURE_NAMES, compute_statistics, shannon_entropy
from ml_train import (
    generate_dataset_from_pcaps, prepare_data,
    train_classifier, train_anomaly_detector,
    evaluate_classifier, evaluate_anomaly_detector,
    save_model, load_model,
)
from models import AppType


def cmd_train(args):
    """Train a new model from PCAP files."""
    pcap_files = []
    for pattern in args.pcap:
        if os.path.isfile(pattern):
            pcap_files.append(pattern)
        else:
            from glob import glob
            pcap_files.extend(glob(pattern))

    if not pcap_files:
        print("Error: No PCAP files found")
        sys.exit(1)

    print(f"Found {len(pcap_files)} PCAP files")
    for f in pcap_files:
        print(f"  {os.path.basename(f)}")

    print("\nExtracting features from PCAP files...")
    X, y = generate_dataset_from_pcaps(pcap_files, max_flows=args.max_flows)

    print(f"\nDataset shape: {X.shape}")
    print(f"Classes: {len(np.unique(y))}")
    class_dist = y.value_counts()
    for app_id, count in class_dist.head(15).items():
        try:
            app_name = AppType(app_id).name
        except (ValueError, TypeError):
            app_name = str(app_id)
        print(f"  {app_name}: {count}")

    print("\nSplitting into train/test sets...")
    X_train, X_test, y_train, y_test, scaler = prepare_data(
        X, y, test_size=args.test_size, scale=True
    )

    print(f"  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    label_names = [a.name for a in AppType]

    print(f"\nTraining {args.model_type} classifier...")
    model = train_classifier(
        X_train, y_train,
        model_type=args.model_type,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
    )

    print("\nEvaluating classifier...")
    results = evaluate_classifier(model, X_test, y_test, label_names)

    print(f"\nTraining {args.anomaly_model} anomaly detector...")
    anomaly_model = train_anomaly_detector(
        X_train, model_type=args.anomaly_model,
        contamination=args.contamination,
    )

    print("\nEvaluating anomaly detector...")
    anomaly_results = evaluate_anomaly_detector(anomaly_model, X_test, y_test)

    metadata = {
        'model_type': args.model_type,
        'anomaly_model': args.anomaly_model,
        'feature_count': len(FEATURE_NAMES),
        'class_count': len(np.unique(y)),
        'label_names': label_names,
        'training_samples': len(X_train),
        'test_samples': len(X_test),
        'accuracy': results['accuracy'],
        'f1_macro': results['f1_macro'],
        'anomaly_auc_roc': anomaly_results.get('auc_roc', 0),
        'timestamp': time.time(),
    }

    save_model(model, scaler, metadata, args.output)

    # Save evaluation results
    eval_path = args.output.replace('.pkl', '_eval.json')
    with open(eval_path, 'w') as f:
        json.dump({
            'classification': results,
            'anomaly_detection': anomaly_results,
            'metadata': metadata,
        }, f, indent=2)
    print(f"Evaluation results saved to: {eval_path}")

    print("\nDone! Model ready for deployment.")
    print(f"  Run: python api_server.py --model {args.output}")


def cmd_evaluate(args):
    """Evaluate a trained model against a PCAP file."""
    model_data = load_model(args.model)

    pcap_files = []
    for pattern in args.pcap:
        if os.path.isfile(pattern):
            pcap_files.append(pattern)
        else:
            from glob import glob
            pcap_files.extend(glob(pattern))

    print(f"\nRunning inference on {len(pcap_files)} PCAP files...")
    all_results = []

    for pcap in pcap_files:
        from ml_train import predict_pcap
        df = predict_pcap(model_data, pcap, max_flows=args.max_flows)
        all_results.append(df)
        print(f"  {os.path.basename(pcap)}: {len(df)} flows analyzed")

    combined = pd.concat(all_results, ignore_index=True)

    # Calculate accuracy if ground truth available
    if 'ground_truth' in combined.columns and 'predicted' in combined.columns:
        correct = (combined['ground_truth'] == combined['predicted']).sum()
        total = len(combined)
        if total > 0:
            print(f"\n  Accuracy: {correct}/{total} = {correct/total:.4f}")

    # Summary statistics
    print(f"\n  Total flows analyzed: {len(combined)}")
    print(f"  Average confidence: {combined['confidence'].mean():.4f}")

    # Distribution of predictions
    pred_dist = combined['predicted'].value_counts()
    print("\n  Prediction distribution:")
    for app, count in pred_dist.head(10).items():
        print(f"    {app}: {count}")


def cmd_export(args):
    """Export features from PCAP files to CSV."""
    pcap_files = []
    for pattern in args.pcap:
        if os.path.isfile(pattern):
            pcap_files.append(pattern)
        else:
            from glob import glob
            pcap_files.extend(glob(pattern))

    X, y = generate_dataset_from_pcaps(pcap_files, max_flows=args.max_flows)
    X['app_type'] = y.map(lambda v: AppType(int(v)).name if isinstance(v, (int, np.integer)) else str(v))

    X.to_csv(args.output, index=False)
    print(f"Dataset exported to: {args.output}")
    print(f"Shape: {X.shape}")


def cmd_demo(args):
    """Quick demo using the included test PCAP."""
    test_pcap = 'test_dpi.pcap'

    if not os.path.exists(test_pcap):
        print("Error: test_dpi.pcap not found in current directory")
        print("Copy it from the original project or run generate_test_pcap.py")
        sys.exit(1)

    print("=" * 60)
    print("  DPI ML Pipeline — Demo Mode")
    print("=" * 60)

    print("\n1. Generating dataset from test PCAP...")
    X, y = generate_dataset_from_pcaps([test_pcap], max_flows=200)
    print(f"   Dataset: {len(X)} flows, {len(X.columns)} features")

    print("\n2. Training Random Forest classifier...")
    X_train, X_test, y_train, y_test, scaler = prepare_data(X, y, test_size=0.3)
    model = train_classifier(
        X_train, y_train, model_type='random_forest',
        n_estimators=100, max_depth=10,
    )

    print("\n3. Evaluating...")
    label_names = [a.name for a in AppType]
    results = evaluate_classifier(model, X_test, y_test, label_names)

    print("\n4. Saving model...")
    metadata = {
        'model_type': 'random_forest',
        'feature_count': len(FEATURE_NAMES),
        'class_count': len(np.unique(y)),
        'label_names': label_names,
        'training_samples': len(X_train),
        'test_samples': len(X_test),
        'accuracy': results['accuracy'],
        'timestamp': time.time(),
    }
    os.makedirs('models', exist_ok=True)
    save_model(model, scaler, metadata, 'models/demo_model.pkl')

    print("\n5. Running inference on test PCAP...")
    from ml_train import predict_pcap
    model_data = load_model('models/demo_model.pkl')
    df = predict_pcap(model_data, test_pcap)

    print(f"\n   Results ({len(df)} flows):")
    print(f"   {'SRC IP':<16} {'DST IP':<16} {'APP':<15} {'PREDICTED':<15} {'CONF':<8}")
    print(f"   {'-'*16} {'-'*16} {'-'*15} {'-'*15} {'-'*8}")
    for _, row in df.head(20).iterrows():
        print(f"   {row['src_ip']:<16} {row['dst_ip']:<16} "
              f"{row['ground_truth']:<15} {row['predicted']:<15} "
              f"{row['confidence']:<8.4f}")

    correct = (df['ground_truth'] == df['predicted']).sum()
    total = len(df)
    print(f"\n  Inference accuracy: {correct}/{total} = {correct/total:.4f}")

    print(f"\n  Model saved: models/demo_model.pkl")
    print(f"  Run API: python api_server.py --model models/demo_model.pkl")


# ---------------------------------------------------------------------------
# CIC-IDS2017 commands
# ---------------------------------------------------------------------------

def cmd_cic_download(args):
    """Download CIC-IDS2017 CSV files."""
    from cic_ids import download_all_csvs
    download_all_csvs(force=args.force, max_files=args.max_files)
    print("\n  Done. Run 'python ml_pipeline.py cic-info --stats' to verify.")


def cmd_cic_info(args):
    """Show statistics about the downloaded CIC-IDS2017 dataset."""
    from cic_ids import load_all_csvs, normalize_labels, get_label_distribution

    X, y = load_all_csvs(
        data_dir=args.data_dir,
        sample_frac=args.sample,
        verbose=True,
    )
    print(f"\n  Raw dataset shape: {X.shape}")
    print(f"  Feature columns: {len(X.columns)}")

    y_norm = normalize_labels(y, attack_groups=True, binary=args.binary)
    counts = get_label_distribution(y_norm)
    print(f"\n  Total flows: {len(y_norm):,}")


def cmd_cic_train(args):
    """Train on CIC-IDS2017 using the full pipeline."""
    from cic_ids import run_full_pipeline

    run_full_pipeline(
        data_dir=args.data_dir,
        model_type=args.model_type,
        test_size=args.test_size,
        sample_frac=args.sample if args.sample > 0 else None,
        balance=args.balance,
        binary=args.binary,
        attack_groups=not args.no_groups,
        drop_correlated=args.drop_correlated,
        output_model=args.output,
        verbose=True,
    )


def cmd_cic_evaluate(args):
    """Evaluate a trained CIC-IDS2017 model."""
    import pickle
    from cic_ids import load_all_csvs, normalize_labels, prepare_feature_matrix
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    print(f"\n  Loading model from: {args.model}")
    with open(args.model, 'rb') as f:
        model_data = pickle.load(f)

    model = model_data['model']
    scaler = model_data.get('scaler')
    metadata = model_data.get('metadata', {})
    feature_columns = model_data.get('feature_columns', model_data.get('feature_names', []))

    if not feature_columns:
        print("  Error: No feature columns found in model")
        return

    print(f"  Model: {metadata.get('model_type', 'unknown')}")
    print(f"  Trained on: {metadata.get('dataset', 'unknown')}")
    print(f"  Classes: {metadata.get('class_count', 0)}")

    X, y = load_all_csvs(
        data_dir=args.data_dir,
        sample_frac=args.sample if args.sample > 0 else None,
        verbose=True,
    )

    X = prepare_feature_matrix(X, selected_features=feature_columns, verbose=True)
    y = normalize_labels(y, attack_groups=not args.no_groups, binary=False)

    from sklearn.preprocessing import LabelEncoder
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=args.test_size, random_state=42,
        stratify=y_encoded,
    )

    if scaler:
        X_test_scaled = scaler.transform(X_test)
    else:
        X_test_scaled = X_test.values

    from cic_ids import evaluate_cic_ids
    evaluate_cic_ids(
        model, X_test_scaled, y_test,
        label_names=[str(c) for c in label_encoder.classes_],
        verbose=True,
    )


def cmd_cic_pcap(args):
    """Process a PCAP through our pipeline and match to CIC-IDS2017 labels."""
    from cic_ids import match_pcap_flows_to_csv_labels, get_dataset_dir

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"  Error: PCAP file not found: {pcap_path}")
        return

    csv_path = Path(args.csv) if args.csv else None

    df = match_pcap_flows_to_csv_labels(
        pcap_path, csv_path=csv_path, verbose=True,
    )

    if args.output:
        df.to_csv(args.output, index=False)
        print(f"\n  Results saved to: {args.output}")

    if 'cic_label' in df.columns:
        matched = df[df['cic_label'] != 'UNKNOWN']
        print(f"\n  Matched flows: {len(matched)}/{len(df)}")
        if len(matched) > 0:
            print("\n  Label distribution:")
            for label, count in matched['cic_label'].value_counts().items():
                print(f"    {label}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description='DPI ML Pipeline — Train, evaluate, and deploy ML models for network traffic analysis',
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Train command
    train_parser = subparsers.add_parser('train', help='Train a new model on PCAP data')
    train_parser.add_argument('--pcap', '-p', nargs='+', required=True,
                              help='PCAP files or glob patterns')
    train_parser.add_argument('--output', '-o', default='model.pkl',
                              help='Output model file (default: model.pkl)')
    train_parser.add_argument('--model-type', default='random_forest',
                              choices=['random_forest', 'xgboost', 'logistic_regression', 'gradient_boosting'],
                              help='Classifier type')
    train_parser.add_argument('--anomaly-model', default='isolation_forest',
                              choices=['isolation_forest', 'one_class_svm'],
                              help='Anomaly detection model')
    train_parser.add_argument('--test-size', type=float, default=0.2,
                              help='Test set ratio (default: 0.2)')
    train_parser.add_argument('--n-estimators', type=int, default=200,
                              help='Number of trees/estimators')
    train_parser.add_argument('--max-depth', type=int, default=20,
                              help='Max tree depth')
    train_parser.add_argument('--contamination', type=float, default=0.1,
                              help='Expected anomaly ratio (default: 0.1)')
    train_parser.add_argument('--max-flows', type=int, default=10000,
                              help='Max flows to extract (default: 10000)')

    # Evaluate command
    eval_parser = subparsers.add_parser('evaluate', help='Evaluate a trained model')
    eval_parser.add_argument('--model', '-m', required=True, help='Trained model file')
    eval_parser.add_argument('--pcap', '-p', nargs='+', required=True,
                             help='PCAP files for evaluation')
    eval_parser.add_argument('--max-flows', type=int, default=5000,
                             help='Max flows to analyze')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export features to CSV')
    export_parser.add_argument('--pcap', '-p', nargs='+', required=True,
                               help='PCAP files to process')
    export_parser.add_argument('--output', '-o', default='dataset.csv',
                               help='Output CSV file')
    export_parser.add_argument('--max-flows', type=int, default=10000,
                               help='Max flows to extract')

    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run quick demo with test PCAP')

    # === CIC-IDS2017 commands ===

    # CIC Download
    cic_dl = subparsers.add_parser('cic-download', help='Download CIC-IDS2017 CSV files')
    cic_dl.add_argument('--force', action='store_true', help='Re-download existing files')
    cic_dl.add_argument('--max-files', type=int, default=None,
                        help='Max files to download (for testing)')

    # CIC Info
    cic_info = subparsers.add_parser('cic-info', help='Show CIC-IDS2017 dataset statistics')
    cic_info.add_argument('--data-dir', default=None, help='CSV data directory')
    cic_info.add_argument('--sample', type=float, default=None,
                          help='Sample fraction for quick testing')
    cic_info.add_argument('--binary', action='store_true',
                          help='Show binary (BENIGN/ATTACK) distribution')

    # CIC Train
    cic_train = subparsers.add_parser('cic-train', help='Train on CIC-IDS2017')
    cic_train.add_argument('--data-dir', default=None, help='CSV data directory')
    cic_train.add_argument('--model-type', default='random_forest',
                           choices=['random_forest', 'xgboost'],
                           help='Classifier type (default: random_forest)')
    cic_train.add_argument('--output', '-o', default='cic_ids_model.pkl',
                           help='Output model file')
    cic_train.add_argument('--test-size', type=float, default=0.2,
                           help='Test set ratio')
    cic_train.add_argument('--sample', type=float, default=0,
                           help='Sample fraction (0=all data, 0.1=10 percent)')
    cic_train.add_argument('--balance', default='none',
                           choices=['none', 'undersample', 'smote', 'smoteenn'],
                           help='Class balancing strategy')
    cic_train.add_argument('--binary', action='store_true',
                           help='Binary classification (BENIGN vs ATTACK)')
    cic_train.add_argument('--no-groups', action='store_true',
                           help='Use raw attack labels instead of grouped categories')
    cic_train.add_argument('--drop-correlated', action='store_true',
                           help='Remove highly correlated features')

    # CIC Evaluate
    cic_eval = subparsers.add_parser('cic-evaluate', help='Evaluate CIC-IDS2017 model')
    cic_eval.add_argument('--model', '-m', required=True, help='Trained model file')
    cic_eval.add_argument('--data-dir', default=None, help='CSV data directory')
    cic_eval.add_argument('--test-size', type=float, default=0.2,
                          help='Test set ratio')
    cic_eval.add_argument('--sample', type=float, default=0,
                          help='Sample fraction for quick eval')
    cic_eval.add_argument('--no-groups', action='store_true',
                          help='Use raw attack labels')

    # CIC PCAP matching
    cic_pcap = subparsers.add_parser('cic-pcap',
                                     help='Process PCAP through pipeline & match to CIC labels')
    cic_pcap.add_argument('--pcap', required=True, help='PCAP file to process')
    cic_pcap.add_argument('--csv', default=None, help='CIC CSV for label matching')
    cic_pcap.add_argument('--output', '-o', default=None,
                          help='Save matched flows to CSV')

    args = parser.parse_args()

    if args.command == 'train':
        cmd_train(args)
    elif args.command == 'evaluate':
        cmd_evaluate(args)
    elif args.command == 'export':
        cmd_export(args)
    elif args.command == 'demo':
        cmd_demo(args)
    elif args.command == 'cic-download':
        cmd_cic_download(args)
    elif args.command == 'cic-info':
        cmd_cic_info(args)
    elif args.command == 'cic-train':
        cmd_cic_train(args)
    elif args.command == 'cic-evaluate':
        cmd_cic_evaluate(args)
    elif args.command == 'cic-pcap':
        cmd_cic_pcap(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
