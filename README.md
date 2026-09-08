# DPI Network - Deep Packet Inspection Engine

A comprehensive network traffic analyzer that combines traditional DPI with machine learning for intrusion detection and traffic classification.

## Features

- **Packet Parsing**: Ethernet, IPv4, TCP, UDP, ICMP protocol dissection
- **Flow Tracking**: 5-tuple connection state management
- **TLS SNI Extraction**: Identify HTTPS domains from Client Hello
- **Application Classification**: Detect YouTube, Facebook, Google, Netflix, etc.
- **Rule Engine**: Block IPs, ports, domains, or application types
- **ML-Based Detection**: Random Forest & XGBoost classifiers for intrusion detection
- **CIC-IDS2017 Integration**: Industry benchmark dataset support
- **Flask API**: REST endpoints for real-time predictions

## Project Structure

```
Packet_analyzer/
├── main.py              # CLI entry point
├── pcap_reader.py       # PCAP file parser
├── packet_parser.py     # Protocol header dissection
├── flow_tracker.py      # Flow state machine & DPI engine
├── sni_extractor.py     # TLS SNI & HTTP Host extraction
├── models.py            # Data classes & enums
├── rules.py             # Rule engine for blocking
├── utils.py             # PCAP write utilities
├── ml_features.py       # ML feature extraction
├── ml_train.py          # Model training
├── ml_pipeline.py       # End-to-end ML pipeline
├── cic_ids.py           # CIC-IDS2017 dataset loader
├── api_server.py        # Flask REST API
├── Dockerfile           # Container deployment
└── requirements.txt     # Python dependencies
```

## Quick Start

### Analyze a PCAP file

```bash
python main.py input.pcap --verbose
```

### Block traffic with rules

```bash
python main.py input.pcap --block-ip 192.168.1.100 --block-port 22 --output filtered.pcap
```

### Train ML model

```bash
python ml_pipeline.py cic-train --model-type random_forest --output model.pkl
```

### Run API server

```bash
python api_server.py --model cic_rf_model.pkl
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/predict` | POST | Classify network flow from JSON features |
| `/predict_pcap` | POST | Classify flows from PCAP file upload |
| `/health` | GET | Health check |

## Requirements

```
flask>=2.0
numpy>=1.21
pandas>=1.3
scikit-learn>=1.0
matplotlib>=3.5
seaborn>=0.11
shap>=0.40
xgboost>=1.5
imbalanced-learn>=0.8
requests>=2.25
```

## How It Works

1. **Read**: PCAP file is parsed packet by packet
2. **Parse**: Ethernet → IP → TCP/UDP headers extracted
3. **Track**: Flows identified by 5-tuple (src IP, dst IP, src port, dst port, protocol)
4. **Classify**: First packet of flow triggers DPI (SNI extraction, app detection)
5. **Decide**: Rules and/or ML model determine forward/drop
6. **Output**: Filtered PCAP written with allowed packets only

## License

MIT
