import json
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, str(Path(__file__).parent.parent))

from cic_ids import load_all_csvs, normalize_labels, prepare_feature_matrix

OUTPUT_DIR = Path(__file__).parent
MODEL_PATH = Path(__file__).parent.parent / 'models' / 'cic_rf_model.pkl'
EVAL_PATH = OUTPUT_DIR / 'cic_rf_model_eval.json'

LABELS = [
    'BENIGN', 'BOT', 'BRUTE_FORCE', 'DDoS',
    'DoS', 'INFILTRATION', 'PORT_SCAN', 'WEB_ATTACK'
]

def plot_confusion_matrix():
    with open(EVAL_PATH) as f:
        data = json.load(f)
    cm = np.array(data['confusion_matrix'])
    plt.figure(figsize=(10, 8))
    plt.imshow(cm, interpolation='nearest', cmap='Blues')
    plt.title('Confusion Matrix', fontsize=14, fontweight='bold')
    plt.colorbar(shrink=0.8)
    tick_marks = np.arange(len(LABELS))
    plt.xticks(tick_marks, LABELS, rotation=45, ha='right', fontsize=9)
    plt.yticks(tick_marks, LABELS, fontsize=9)
    thresh = cm.max() / 2
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            color = 'white' if cm[i, j] > thresh else 'black'
            plt.text(j, i, format(cm[i, j], ','), ha='center', va='center', fontsize=8, color=color)
    plt.ylabel('True Label', fontsize=11)
    plt.xlabel('Predicted Label', fontsize=11)
    plt.tight_layout()
    path = OUTPUT_DIR / 'confusion_matrix.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f'  Saved: {path}')


def plot_roc_curve():
    print('  Loading model and data for ROC curve...')
    with open(MODEL_PATH, 'rb') as f:
        model_data = pickle.load(f)
    model = model_data['model']
    scaler = model_data.get('scaler')
    feature_cols = model_data.get('feature_columns', model_data.get('feature_names', []))

    X, y = load_all_csvs(data_dir=None, sample_frac=0.2, verbose=False)
    X = prepare_feature_matrix(X, selected_features=feature_cols, verbose=False)
    y = normalize_labels(y, attack_groups=True, binary=False)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    if scaler:
        X_test_scaled = scaler.transform(X_test)
    else:
        X_test_scaled = X_test.values

    y_score = model.predict_proba(X_test_scaled)
    n_classes = len(le.classes_)
    y_test_bin = label_binarize(y_test, classes=range(n_classes))

    plt.figure(figsize=(10, 8))
    for i in range(n_classes):
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_score[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, lw=2, label=f'{LABELS[i]} (AUC = {roc_auc:.4f})')

    plt.plot([0, 1], [0, 1], 'k--', lw=1, label='Random (AUC = 0.5)')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curves (Multi-class One-vs-Rest)', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=9)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    path = OUTPUT_DIR / 'roc_curve.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f'  Saved: {path}')


def plot_feature_importance():
    print('  Loading model for feature importance...')
    with open(MODEL_PATH, 'rb') as f:
        model_data = pickle.load(f)
    model = model_data['model']
    feature_cols = model_data.get('feature_columns', model_data.get('feature_names', []))

    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    elif hasattr(model, 'coef_'):
        importances = np.abs(model.coef_).sum(axis=0)
    else:
        print('  Model does not expose feature importances.')
        return

    indices = np.argsort(importances)[::-1]
    top_n = min(20, len(importances))

    plt.figure(figsize=(12, 8))
    colors = plt.cm.viridis(np.linspace(0.8, 0.2, top_n))
    bars = plt.barh(range(top_n), importances[indices[:top_n]][::-1], color=colors[::-1])
    plt.yticks(range(top_n), [feature_cols[i] for i in indices[:top_n]][::-1], fontsize=9)
    plt.xlabel('Importance', fontsize=12)
    plt.title('Top 20 Feature Importances', fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    for bar, val in zip(bars, importances[indices[:top_n]][::-1]):
        plt.text(bar.get_width() + 0.001, bar.get_y() + bar.get_height()/2,
                 f'{val:.4f}', va='center', fontsize=8)
    plt.tight_layout()
    path = OUTPUT_DIR / 'feature_importance.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f'  Saved: {path}')


def plot_shap_summary():
    print('  Loading data for SHAP summary plot...')
    try:
        import shap
    except ImportError:
        print('  SHAP not installed. Run: pip install shap')
        return

    with open(MODEL_PATH, 'rb') as f:
        model_data = pickle.load(f)
    model = model_data['model']
    scaler = model_data.get('scaler')
    feature_cols = model_data.get('feature_columns', model_data.get('feature_names', []))

    X, y = load_all_csvs(data_dir=None, sample_frac=0.05, verbose=False)
    X = prepare_feature_matrix(X, selected_features=feature_cols, verbose=False)

    if scaler:
        X_scaled = scaler.transform(X)
    else:
        X_scaled = X.values

    X_display = pd.DataFrame(X_scaled, columns=feature_cols).sample(min(500, len(X)), random_state=42)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_display)

    if isinstance(shap_values, list):
        shap_values = shap_values[0]

    plt.figure(figsize=(14, 10))
    shap.summary_plot(shap_values, X_display, feature_names=feature_cols, show=False, max_display=20)
    plt.title('SHAP Summary Plot', fontsize=14, fontweight='bold')
    plt.tight_layout()
    path = OUTPUT_DIR / 'shap_summary.png'
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {path}')


def main():
    print('Generating evaluation plots...')
    print()
    plot_confusion_matrix()
    plot_roc_curve()
    plot_feature_importance()
    plot_shap_summary()
    print()
    print('Done! All plots saved to:', OUTPUT_DIR)


if __name__ == '__main__':
    main()
