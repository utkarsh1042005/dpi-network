import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from cic_ids import load_all_csvs, normalize_labels, get_label_distribution

OUTPUT_DIR = Path(__file__).parent

LABELS = ['BENIGN', 'BOT', 'BRUTE_FORCE', 'DDoS', 'DoS', 'INFILTRATION', 'PORT_SCAN', 'WEB_ATTACK']
COLORS = plt.cm.tab10(np.linspace(0, 1, 8))


def plot_class_distribution():
    print('  Loading data for class distribution...')
    X, y = load_all_csvs(data_dir=None, verbose=False)
    y = normalize_labels(y, attack_groups=True, binary=False)
    counts = y.value_counts()

    plt.figure(figsize=(12, 6))
    colors = ['#2ecc71' if c == 'BENIGN' else '#e74c3c' for c in counts.index]
    bars = plt.bar(range(len(counts)), counts.values, color=colors, edgecolor='white', linewidth=0.5)
    plt.xticks(range(len(counts)), counts.index, rotation=45, ha='right', fontsize=10)
    plt.ylabel('Number of Flows', fontsize=12)
    plt.title('CIC-IDS2017 Class Distribution', fontsize=14, fontweight='bold')

    total = counts.sum()
    for bar, val in zip(bars, counts.values):
        pct = val / total * 100
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + total*0.01,
                 f'{val:,}\n({pct:.2f}%)', ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    path = OUTPUT_DIR / 'class_distribution.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f'  Saved: {path}')


def plot_class_distribution_pie():
    print('  Creating pie chart...')
    X, y = load_all_csvs(data_dir=None, verbose=False)
    y = normalize_labels(y, attack_groups=True, binary=False)
    counts = y.value_counts()

    plt.figure(figsize=(10, 8))
    explode = [0.05 if c != 'BENIGN' else 0 for c in counts.index]
    wedges, texts, autotexts = plt.pie(
        counts.values, labels=counts.index, autopct='%1.1f%%',
        colors=COLORS, explode=explode, startangle=90,
        textprops={'fontsize': 9}
    )
    for at in autotexts:
        at.set_fontsize(8)
    plt.title('CIC-IDS2017 — Class Proportions', fontsize=14, fontweight='bold')
    plt.tight_layout()
    path = OUTPUT_DIR / 'class_distribution_pie.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f'  Saved: {path}')


def plot_feature_distributions():
    print('  Loading 20% sample for feature distributions...')
    X, y = load_all_csvs(data_dir=None, sample_frac=0.2, verbose=False)
    y = normalize_labels(y, attack_groups=True, binary=False)

    numeric_cols = X.select_dtypes(include=[np.number]).columns
    key_features = [
        ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
        'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
        ' Fwd Packet Length Mean', ' Bwd Packet Length Mean',
        ' Flow Bytes/s', ' Flow Packets/s',
        ' Flow IAT Mean', ' SYN Flag Count',
        ' Init_Win_bytes_forward', ' Init_Win_bytes_backward',
    ]
    key_features = [c for c in key_features if c in X.columns]

    fig, axes = plt.subplots(5, 3, figsize=(16, 18))
    axes = axes.flatten()
    for i, feat in enumerate(key_features):
        if i >= len(axes):
            break
        ax = axes[i]
        benign = X[y == 'BENIGN'][feat].dropna()
        attack = X[y != 'BENIGN'][feat].dropna()
        benign = benign[benign > 0]
        attack = attack[attack > 0]
        for d, label, color in [(benign, 'BENIGN', '#2ecc71'), (attack, 'ATTACK', '#e74c3c')]:
            if len(d) > 1000:
                d = d.sample(1000, random_state=42)
            if len(d) > 0:
                ax.hist(np.log1p(d.values), bins=50, alpha=0.6, label=label, color=color)
        ax.set_title(feat.strip()[:30], fontsize=9)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7)

    for j in range(i + 1, len(axes)):
        fig.delaxes(axes[j])

    fig.suptitle('Feature Distributions (BENIGN vs ATTACK) — log-scaled', fontsize=14, fontweight='bold', y=1.01)
    plt.tight_layout()
    path = OUTPUT_DIR / 'feature_distributions.png'
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {path}')


def plot_correlation_heatmap():
    print('  Loading 10% sample for correlation heatmap...')
    X, y = load_all_csvs(data_dir=None, sample_frac=0.1, verbose=False)

    corr_cols = [c for c in X.columns if c in X.select_dtypes(include=[np.number]).columns][:30]
    X_subset = X[corr_cols].sample(min(50000, len(X)), random_state=42)
    corr = X_subset.corr()

    mask = np.triu(np.ones_like(corr, dtype=bool), k=1)
    plt.figure(figsize=(16, 13))
    sns.heatmap(corr, mask=mask, cmap='RdBu_r', center=0, vmin=-1, vmax=1,
                square=True, linewidths=0.3, cbar_kws={'shrink': 0.7})
    plt.title('Feature Correlation Heatmap (Top 30 Features)', fontsize=14, fontweight='bold')
    plt.tight_layout()
    path = OUTPUT_DIR / 'correlation_heatmap.png'
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {path}')


def plot_attack_timeline():
    print('  Creating attack timeline...')
    X, y = load_all_csvs(data_dir=None, verbose=False)
    y = normalize_labels(y, attack_groups=True, binary=False)

    attack_counts = y.value_counts()
    attack_types = [c for c in attack_counts.index if c != 'BENIGN']

    day_map = {
        'Monday': 'Monday (Benign only)',
        'Tuesday': 'Tuesday (Brute Force)',
        'Wednesday': 'Wednesday (DoS)',
        'Thursday': 'Thursday (Web + Infiltration)',
        'Friday': 'Friday (Bot, PortScan, DDoS)',
    }

    plt.figure(figsize=(10, 5))
    days = list(day_map.keys())
    colors_days = ['#3498db', '#e74c3c', '#f39c12', '#9b59b6', '#2ecc71']
    bars = plt.barh(list(day_map.values()), [1]*len(days), color=colors_days, height=0.6)
    for i, (day, desc) in enumerate(day_map.items()):
        plt.text(0.5, i, day, ha='center', va='center', fontsize=11, fontweight='bold', color='white')
    plt.xlim(0, 1)
    plt.title('CIC-IDS2017 — 5-Day Attack Schedule', fontsize=14, fontweight='bold')
    plt.tight_layout()
    path = OUTPUT_DIR / 'attack_timeline.png'
    plt.savefig(path, dpi=150)
    plt.close()
    print(f'  Saved: {path}')


def main():
    print('Generating dataset visualizations...')
    print()
    plot_class_distribution()
    plot_class_distribution_pie()
    plot_feature_distributions()
    plot_correlation_heatmap()
    plot_attack_timeline()
    print()
    print('Done! All plots saved to:', OUTPUT_DIR)


if __name__ == '__main__':
    main()
