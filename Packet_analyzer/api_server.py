"""
Flask REST API for ML-powered Network Traffic Analysis.

Supports both:
1. Our custom DPI models (trained via `ml_pipeline.py train`)
2. CIC-IDS2017 models (trained via `ml_pipeline.py cic-train`)

The API is model-agnostic — it reads feature names and label names
from the saved model file, so any trained model works without code changes.

Endpoints:
  GET  /health          — Health check & model info
  GET  /features        — List features the model expects
  POST /predict         — Predict from flow features (JSON)
  POST /predict_pcap    — Analyze an uploaded PCAP file
  GET  /stats           — API usage statistics
  GET  /dashboard       — HTML dashboard
"""

import json
import os
import pickle
import tempfile
import time
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from flask import Flask, jsonify, request, render_template_string

from ml_features import extract_flow_features, FEATURE_NAMES
from models import FlowState, FiveTuple, AppType
from pcap_reader import PcapReader
from packet_parser import PacketParser
from flow_tracker import DPIEngine


app = Flask(__name__)

# Global model data (loaded at startup)
_model_data: Optional[Dict] = None
_api_stats = {
    'requests_total': 0,
    'predictions_total': 0,
    'uptime': time.time(),
}


def load_model_at_startup(model_path: str):
    """Load a trained model from disk.

    Supports both formats:
    - Our DPI pipeline models (with 'feature_names' = FEATURE_NAMES)
    - CIC-IDS2017 models (with 'feature_columns' = CICFlowMeter columns)
    """
    global _model_data
    if not os.path.exists(model_path):
        print(f"  Warning: Model not found at {model_path}")
        print("  Run 'python ml_pipeline.py train' or 'python ml_pipeline.py cic-train' first")
        return

    with open(model_path, 'rb') as f:
        _model_data = pickle.load(f)

    metadata = _model_data.get('metadata', {})

    # Determine feature names from model data
    feature_names = _model_data.get(
        'feature_columns',
        _model_data.get('feature_names', [])
    )
    _model_data['feature_names'] = feature_names

    dataset = metadata.get('dataset', 'custom')
    model_type = metadata.get('model_type', 'unknown')
    n_features = len(feature_names)
    n_classes = metadata.get('class_count', 0)
    label_names = metadata.get('label_names', [])

    print(f"  Model loaded: {model_path}")
    print(f"  Dataset:      {dataset}")
    print(f"  Model type:   {model_type}")
    print(f"  Features:     {n_features}")
    print(f"  Classes:      {n_classes}")
    if label_names:
        print(f"  Labels:       {', '.join(label_names[:10])}{'...' if len(label_names) > 10 else ''}")

    if 'label_encoder' in _model_data:
        print(f"  Label encoder: present")
        # Convert numpy types in label_encoder classes_ for JSON serialization
        le = _model_data['label_encoder']
        le_classes = [str(c) for c in le.classes_]
        _model_data['label_classes'] = le_classes


def get_active_features() -> List[str]:
    """Get the feature names expected by the loaded model."""
    if _model_data:
        return _model_data.get('feature_names', FEATURE_NAMES)
    return FEATURE_NAMES


def validate_features(feature_dict: Dict) -> Optional[str]:
    """Validate that all required features for the loaded model are present."""
    if _model_data is None:
        return "No model loaded"

    feature_names = get_active_features()
    missing = [f for f in feature_names if f not in feature_dict]
    if missing:
        return (
            f"Missing {len(missing)}/{len(feature_names)} features. "
            f"Missing examples: {missing[:5]}..."
        )
    return None


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint — shows model info and uptime."""
    uptime = time.time() - _api_stats['uptime']
    metadata = _model_data.get('metadata', {}) if _model_data else {}
    feature_names = get_active_features()

    return jsonify({
        'status': 'healthy',
        'model_loaded': _model_data is not None,
        'uptime_seconds': round(uptime, 2),
        'features_count': len(feature_names),
        'model_type': metadata.get('model_type', 'N/A'),
        'dataset': metadata.get('dataset', 'N/A'),
        'class_count': metadata.get('class_count', 0),
    })


@app.route('/features', methods=['GET'])
def list_features():
    """List all features expected by the loaded model."""
    feature_names = get_active_features()
    metadata = _model_data.get('metadata', {}) if _model_data else {}

    return jsonify({
        'feature_count': len(feature_names),
        'features': feature_names,
        'dataset': metadata.get('dataset', 'custom'),
        'model_type': metadata.get('model_type', 'unknown'),
    })


def _predict_from_features(feature_dict: Dict) -> Dict:
    """Core prediction logic: convert feature dict → prediction + probabilities.

    This is model-agnostic — works for both our DPI models and CIC-IDS2017 models.
    """
    feature_names = get_active_features()
    feature_vector = np.array(
        [[feature_dict.get(f, 0.0) for f in feature_names]],
        dtype=np.float64,
    )

    scaler = _model_data.get('scaler')
    if scaler is not None:
        feature_vector = scaler.transform(feature_vector)

    model = _model_data['model']
    prediction = model.predict(feature_vector)[0]

    # Get probabilities if available
    try:
        probabilities = model.predict_proba(feature_vector)[0]
        confidence = float(np.max(probabilities))
    except (AttributeError, NotImplementedError):
        confidence = 1.0
        probabilities = None

    # Map prediction to label name
    label_encoder = _model_data.get('label_encoder')
    if label_encoder is not None:
        try:
            predicted_label = str(label_encoder.inverse_transform([int(prediction)])[0])
        except Exception:
            predicted_label = str(prediction)
    else:
        label_names = _model_data.get('metadata', {}).get('label_names', [])
        if label_names and isinstance(prediction, (int, np.integer)):
            if prediction < len(label_names):
                predicted_label = label_names[prediction]
            else:
                predicted_label = str(prediction)
        else:
            predicted_label = str(prediction)

    _api_stats['predictions_total'] += 1

    response = {
        'predicted_label': predicted_label,
        'confidence': round(confidence, 6),
        'features_used': len(feature_names),
    }

    if probabilities is not None:
        label_encoder = _model_data.get('label_encoder')
        label_names = _model_data.get('metadata', {}).get('label_names', [])

        if label_encoder is not None:
            classes = _model_data.get('label_classes', [str(c) for c in label_encoder.classes_])
            response['probabilities'] = {
                str(classes[i]): round(float(p), 6)
                for i, p in enumerate(probabilities)
                if p > 0.01
            }
        elif label_names and len(label_names) == len(probabilities):
            response['probabilities'] = {
                str(label_names[i]): round(float(p), 6)
                for i, p in enumerate(probabilities)
                if p > 0.01
            }
        else:
            response['probabilities'] = {
                f'class_{i}': round(float(p), 6)
                for i, p in enumerate(probabilities)
                if p > 0.01
            }

    return response


@app.route('/predict', methods=['POST'])
def predict():
    """Predict traffic label from flow features.

    Accepts JSON with flow features as key-value pairs.
    Works with both DPI models and CIC-IDS2017 models.

    CIC-IDS2017 example:
    {
        " Flow Duration": 12345678,
        " Total Fwd Packets": 10,
        " Total Backward Packets": 8,
        " Fwd Packet Length Mean": 450.5,
        ...
    }

    Our DPI model example:
    {
        "flow_duration": 12.5,
        "fwd_packets": 10,
        "fwd_pkt_len_mean": 450.5,
        ...
    }
    """
    _api_stats['requests_total'] += 1

    if _model_data is None:
        return jsonify({'error': 'No model loaded. Train a model first.'}), 503

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided. Send flow features as JSON.'}), 400

    error = validate_features(data)
    if error:
        return jsonify({'error': error}), 400

    try:
        result = _predict_from_features(data)
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500


@app.route('/summarize_pcap', methods=['POST'])
def summarize_pcap():
    """Upload a PCAP and get a plain English summary."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded. Use -F "file=@your.pcap"'}), 400
    file = request.files['file']
    tmp_path = None
    try:
        suffix = '.pcap' if file.filename.endswith('.pcap') else '.pcapng'
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp_path = tmp.name
            file.save(tmp_path)
        from ml_train import predict_pcap
        df = predict_pcap(_model_data, tmp_path)
        total = len(df)
        if total == 0:
            return jsonify({'summary': 'No TCP/UDP flows found in the PCAP file.'})
        label_col = 'predicted'
        benign_count = len(df[df[label_col].str.upper() == 'BENIGN'])
        attack_count = total - benign_count
        top_dest = df['dst_ip'].value_counts().head(5).to_dict()
        top_ports = df['dst_port'].value_counts().head(5).to_dict()
        port_desc = {80: 'HTTP web', 443: 'HTTPS web', 53: 'DNS', 22: 'SSH', 3389: 'RDP'}
        label_counts = df[label_col].value_counts().to_dict()
        avg_conf = df['confidence'].mean()
        sni_flows = df[df['sni'].str.len() > 0]
        summary_parts = [
            f"Analyzed {total} network flows from your PCAP file.",
            f"Average prediction confidence: {avg_conf:.1%}.",
        ]
        if benign_count == total:
            summary_parts.append("All traffic appears to be BENIGN (normal). No attacks detected.")
        elif attack_count > 0:
            attacks_list = [f"{k}: {v}" for k, v in label_counts.items() if k.upper() != 'BENIGN']
            summary_parts.append(f"Detected {attack_count} potentially malicious flows: {', '.join(attacks_list)}.")
        top_dest_str = ', '.join([f"{ip} ({cnt} flows)" for ip, cnt in list(top_dest.items())[:3]])
        summary_parts.append(f"Top destination: {top_dest_str}.")
        top_ports_str = ', '.join([f"port {p}{' (' + port_desc.get(p, '') + ')' if p in port_desc else ''} ({c} flows)" for p, c in list(top_ports.items())[:3]])
        summary_parts.append(f"Main traffic on {top_ports_str}.")
        if len(sni_flows) > 0:
            top_sni = sni_flows['sni'].value_counts().head(3).to_dict()
            sni_str = ', '.join([f"{s}" for s in list(top_sni.keys())])
            summary_parts.append(f"Detected services: {sni_str}.")
        return jsonify({
            'summary': ' '.join(summary_parts),
            'total_flows': total,
            'class_distribution': {str(k): int(v) for k, v in label_counts.items()},
            'avg_confidence': round(float(avg_conf), 4),
            'top_destinations': top_dest,
            'top_ports': top_ports,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.route('/predict_pcap', methods=['POST'])
def predict_pcap_endpoint():
    """Analyze an uploaded PCAP file and predict per-flow labels.

    Expects multipart form with 'file' field containing a PCAP file.
    Processes it through our existing DPI pipeline (pcap_reader →
    packet_parser → flow_tracker → feature_extraction → model).
    """
    _api_stats['requests_total'] += 1

    if _model_data is None:
        return jsonify({'error': 'No model loaded'}), 503

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided (use multipart form with "file" field)'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    max_flows = request.form.get('max_flows', 1000, type=int)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            file.save(tmp.name)
            tmp_path = tmp.name

        # Process PCAP through our pipeline
        engine = DPIEngine()
        payload_samples = defaultdict(list)

        with PcapReader(tmp_path) as reader:
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

        # Extract features for each flow and predict
        feature_names = get_active_features()
        results = []
        for flow in engine.flow_tracker.get_all_flows()[:max_flows]:
            ft = flow.five_tuple
            samples = payload_samples.get(ft, [])

            # Build feature dict from our extracted features
            feats = extract_flow_features(flow, samples)

            # Map our feature names to model's expected feature names
            feature_dict = {}
            for fn in feature_names:
                feature_dict[fn] = feats.get(fn, 0.0)

            pred = _predict_from_features(feature_dict)

            results.append({
                'src_ip': ft.src_ip,
                'dst_ip': ft.dst_ip,
                'src_port': ft.src_port,
                'dst_port': ft.dst_port,
                'protocol': 'TCP' if ft.protocol == 6 else 'UDP' if ft.protocol == 17 else str(ft.protocol),
                'flow_duration': round(flow.duration, 4),
                'total_packets': flow.total_packets,
                'sni': flow.sni or '',
                'predicted_label': pred['predicted_label'],
                'confidence': pred['confidence'],
            })

        _api_stats['predictions_total'] += len(results)

        return jsonify({
            'total_flows': len(results),
            'model_dataset': _model_data.get('metadata', {}).get('dataset', 'custom'),
            'model_type': _model_data.get('metadata', {}).get('model_type', 'unknown'),
            'predictions': results,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get API usage statistics."""
    return jsonify({
        'requests_total': _api_stats['requests_total'],
        'predictions_total': _api_stats['predictions_total'],
        'uptime_seconds': round(time.time() - _api_stats['uptime'], 2),
        'model_loaded': _model_data is not None,
    })


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Interactive HTML dashboard showing model status and predictions."""
    uptime = time.time() - _api_stats['uptime']
    metadata = _model_data.get('metadata', {}) if _model_data else {}
    feature_names = get_active_features()
    dataset = metadata.get('dataset', 'N/A')
    model_type = metadata.get('model_type', 'N/A')
    class_count = metadata.get('class_count', 0)
    label_names = metadata.get('label_names', [])

    metrics = []
    if metadata.get('accuracy'):
        metrics.append(('Accuracy', f"{metadata['accuracy']:.4f}"))
    if metadata.get('f1_macro'):
        metrics.append(('F1 (macro)', f"{metadata['f1_macro']:.4f}"))
    if metadata.get('roc_auc_macro'):
        metrics.append(('ROC-AUC', f"{metadata['roc_auc_macro']:.4f}"))

    classes_str = ', '.join(label_names[:8])
    if len(label_names) > 8:
        classes_str += f' ... ({len(label_names)} total)'

    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DPI ML Dashboard</title>
        <style>
            body {{ font-family: monospace; margin: 40px; background: #1e1e1e; color: #d4d4d4; }}
            h1 {{ color: #569cd6; border-bottom: 1px solid #3c3c3c; padding-bottom: 10px; }}
            h2 {{ color: #4ec9b0; }}
            .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 20px 0; }}
            .stat {{ background: #2d2d2d; padding: 16px; border-radius: 8px; border-left: 3px solid #569cd6; }}
            .stat-value {{ font-size: 24px; color: #4ec9b0; font-weight: bold; }}
            .stat-label {{ font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
            .section {{ background: #252526; padding: 16px; border-radius: 8px; margin: 16px 0; }}
            .endpoint {{ background: #1e1e1e; padding: 8px 12px; margin: 4px 0; border-radius: 4px; font-size: 13px; }}
            .endpoint code {{ color: #ce9178; }}
            .endpoint .desc {{ color: #888; }}
            .try-btn {{ background: #0e639c; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-family: monospace; }}
            .try-btn:hover {{ background: #1177bb; }}
            textarea {{ width: 100%; background: #1e1e1e; color: #d4d4d4; border: 1px solid #3c3c3c; border-radius: 4px; padding: 8px; font-family: monospace; }}
            .result {{ background: #1e1e1e; padding: 8px; border-radius: 4px; margin-top: 8px; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>DPI ML Dashboard</h1>

        <div class="stat-grid">
            <div class="stat">
                <div class="stat-value">{int(uptime)}s</div>
                <div class="stat-label">Uptime</div>
            </div>
            <div class="stat">
                <div class="stat-value">{_api_stats['requests_total']}</div>
                <div class="stat-label">API Requests</div>
            </div>
            <div class="stat">
                <div class="stat-value">{_api_stats['predictions_total']}</div>
                <div class="stat-label">Predictions</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(feature_names)}</div>
                <div class="stat-label">Features</div>
            </div>
        </div>

        <div class="section">
            <h2>Model Information</h2>
            <table style="width:100%; border-collapse: collapse;">
                <tr><td style="padding:4px 8px;color:#888;">Dataset</td><td>{dataset}</td></tr>
                <tr><td style="padding:4px 8px;color:#888;">Model Type</td><td>{model_type}</td></tr>
                <tr><td style="padding:4px 8px;color:#888;">Classes</td><td>{class_count}</td></tr>
                <tr><td style="padding:4px 8px;color:#888;">Labels</td><td>{classes_str}</td></tr>
    '''
    for name, value in metrics:
        html += f'<tr><td style="padding:4px 8px;color:#888;">{name}</td><td style="color:#4ec9b0;font-weight:bold;">{value}</td></tr>\n'

    html += '''
            </table>
        </div>

        <div class="section">
            <h2>Analyze PCAP File</h2>
            <p style="color:#888;font-size:12px;">Upload a PCAP file and get a plain-English summary of the traffic.</p>
            <input type="file" id="pcapFile" accept=".pcap,.pcapng">
            <br><br>
            <button class="try-btn" onclick="analyzePcap()">Analyze</button>
            <div id="pcapResult" class="result" style="line-height:1.6;"></div>
        </div>

        <div class="section">
            <h2>API Endpoints</h2>
            <div class="endpoint"><code>GET /health</code> <span class="desc">— Health check & model info</span></div>
            <div class="endpoint"><code>GET /features</code> <span class="desc">— List model features</span></div>
            <div class="endpoint"><code>GET /stats</code> <span class="desc">— API statistics</span></div>
            <div class="endpoint"><code>POST /predict</code> <span class="desc">— Predict from JSON features</span></div>
            <div class="endpoint"><code>POST /predict_pcap</code> <span class="desc">— Analyze uploaded PCAP file (raw JSON)</span></div>
            <div class="endpoint"><code>POST /summarize_pcap</code> <span class="desc">— Upload PCAP for plain-English summary</span></div>
            <div class="endpoint"><code>GET /dashboard</code> <span class="desc">— This dashboard</span></div>
        </div>

        <script>
            async function analyzePcap() {
                const file = document.getElementById('pcapFile').files[0];
                if (!file) { document.getElementById('pcapResult').textContent = 'Please select a PCAP file first.'; return; }
                const formData = new FormData();
                formData.append('file', file);
                document.getElementById('pcapResult').innerHTML = 'Analyzing...';
                try {
                    const resp = await fetch('/summarize_pcap', { method: 'POST', body: formData });
                    const result = await resp.json();
                    if (result.summary) {
                        let html = '<strong>Analysis Result</strong><br><br>';
                        html += result.summary.replace(/\. /g, '.<br>');
                        html += '<br><br><strong>Details:</strong><br>';
                        html += 'Total flows: ' + result.total_flows + '<br>';
                        html += 'Avg confidence: ' + (result.avg_confidence * 100).toFixed(1) + '%<br>';
                        if (result.class_distribution) {
                            html += 'Classification breakdown:<br>';
                            for (const [cls, cnt] of Object.entries(result.class_distribution)) {
                                html += '  ' + cls + ': ' + cnt + '<br>';
                            }
                        }
                        document.getElementById('pcapResult').innerHTML = html;
                    } else {
                        document.getElementById('pcapResult').textContent = JSON.stringify(result, null, 2);
                    }
                } catch(e) {
                    document.getElementById('pcapResult').textContent = 'Error: ' + e;
                }
            }
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)


def run_api(host: str = '0.0.0.0', port: int = 5000, model_path: str = 'model.pkl'):
    """Start the Flask API server."""
    load_model_at_startup(model_path)
    metadata = _model_data.get('metadata', {}) if _model_data else {}
    dataset = metadata.get('dataset', 'custom')
    n_features = len(get_active_features())

    print(f"\n  DPI ML API Server")
    print(f"  {'=' * 40}")
    print(f"  Model: {dataset} ({n_features} features)")
    print(f"  Running on http://{host}:{port}")
    print(f"  Dashboard: http://localhost:{port}/dashboard")
    print(f"  Health:    http://localhost:{port}/health")
    print(f"  Predict:   POST http://localhost:{port}/predict")
    print()
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='DPI ML API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--model', default='model.pkl', help='Path to trained model')
    args = parser.parse_args()
    run_api(args.host, args.port, args.model)
