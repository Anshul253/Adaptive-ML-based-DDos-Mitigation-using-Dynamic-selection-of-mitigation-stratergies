# AI-Based Adaptive DDoS Mitigation in Software Defined Networks (SDN)

> **Research Contribution**: An intelligent, context-aware SDN mitigation framework that dynamically selects optimal mitigation strategies (Dynamic Blocking, Rate Limiting, Controller Migration / Safe Proxy) based on real-time attack intensity, network congestion, and classification confidence to minimize legitimate traffic loss and latency while maintaining rigorous DDoS suppression.

---

## 1. Research Overview & Motivation

Traditional Software-Defined Networking (SDN) DDoS defense systems rely on **static aggressive port/flow blocking**. When a machine learning detector flags an attack, the controller immediately drops all packets from the source port or IP flow.

### The Problem with Static Blocking:
- **High Legitimate Traffic Loss (~42%)**: Aggressive port blocking drops legitimate co-located user traffic originating from the same switch port.
- **Queue Congestion & Latency**: Indiscriminate rate limiting under heavy flood conditions leads to buffer bloat and excessive waiting times (RTT).
- **Resource Exhaustion**: Rate limiting allows severe attack floods to continue consuming core SDN link bandwidth.

### The Proposed Adaptive Solution:
Instead of applying a single fixed response to every detected DDoS flow, our **Adaptive Mitigation Decision Engine** evaluates multi-dimensional telemetry (packet rate, byte rate, classification confidence, network load %) to select the most appropriate response:

```
Traffic Stream
   │
   ▼
Ryu SDN Controller (OpenFlow 1.3)
   │
   ▼
Telemetry & Flow Feature Collection
   │
   ▼
Random Forest DDoS Detector
   │
   ▼
DDoS Prediction & Confidence Score
   │
   ▼
[ ADAPTIVE MITIGATION DECISION ENGINE ]
   ├── 1. Dynamic Blocking (OpenFlow DROP rule)
   ├── 2. Rate Limiting (OpenFlow Meter / Queue Cap)
   └── 3. Controller Migration / Safe Proxy Inspection
   │
   ▼
Performance Monitoring & Evaluation Dashboard
```

---

## 2. Decision Logic Matrix

| Attack Prediction | Attack Intensity (pps) | Network Load (%) | Classification Confidence | Selected Mitigation Strategy | Action & Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Normal** | Any | Any | Any | **`NO_ACTION`** | Normal forwarding; no intervention required. |
| **DDoS** | High ($\ge$ 20,000 pps) | High ($\ge$ 75%) | High ($\ge$ 85%) | **`DYNAMIC_BLOCKING`** | Install OpenFlow DROP rule to immediately protect target link. |
| **DDoS** | Medium (5k-20k pps) | Medium/High | Moderate | **`CONTROLLER_MIGRATION`** | Redirect traffic to safe inspection proxy port to avoid queue congestion. |
| **DDoS** | Low (< 5,000 pps) | Low (< 40%) | Moderate | **`RATE_LIMITING`** | Apply rate cap meter (1000 kbps) to preserve legitimate traffic flows. |

---

## 3. Empirical Research Evaluation Results

We conducted systematic experiments comparing the **Original System (Static Aggressive Blocking)** against the proposed **Adaptive System** across UDP, TCP SYN, and ICMP flood attacks at Low, Medium, and High severities:

| Metric | Original System (Baseline) | Adaptive System (Proposed) | Research Improvement |
| :--- | :---: | :---: | :---: |
| **Legitimate Packet Loss (%)** | 42.00% | **4.33%** | **+37.67% Reduction in Legitimate Loss** |
| **Average RTT / Latency (ms)** | 94.33 ms | **16.67 ms** | **+77.67 ms Reduction in Latency** |
| **Network Congestion Load (%)** | 10.23% | **8.67%** | **+1.56% Overhead Reduction** |
| **Attack Packets Served (%)** | 5.00% | **6.33%** | Controlled suppression with rate capping |
| **Mitigation Response Time (s)** | 0.045 s | **0.005 s** | **Near-instantaneous decision dispatch** |
| **Composite Adaptive Score** | 48.36 / 100 | **68.93 / 100** | **+20.57 Gain in overall trade-off score** |

---

## 4. Project Directory Structure

```
📁 DDoS-Attack-Detection-and-Mitigation
├── 📁 Codes/
│   ├── 📁 controller/
│   │   ├── controller.py         # Ryu SDN Controller supporting --mode baseline/adaptive
│   │   ├── adaptive_mitigation.py# Adaptive Mitigation Engine (RuleBased & ML Selector)
│   │   └── traffic_monitor.py    # Telemetry, packet rate, link load & RTT monitor
│   ├── 📁 Mitigation/
│   │   ├── blocking.py           # Dynamic Blocking strategy
│   │   ├── rate_limiting.py      # Rate Limiting meter strategy
│   │   └── migration.py          # Controller Migration / Safe Proxy strategy
│   ├── 📁 ml/
│   │   ├── ML.py                 # Machine Learning model benchmark suite
│   │   ├── RF.py                 # Random Forest classifier
│   │   ├── create_sample_dataset.py # Realistic flow dataset generator
│   │   └── FlowStatsfile.csv     # OpenFlow flow statistics dataset
│   ├── 📁 mininet/
│   │   ├── topology.py           # Custom Mininet SDN network topology
│   │   ├── generate_legitimate_traffic.py # Legitimate background traffic simulator
│   │   └── generate_attack_traffic.py     # Controlled UDP/SYN/ICMP DDoS attack generator
│   └── 📁 utils/
│       ├── metrics.py            # Objective metric evaluation engine
│       └── logger.py             # Real-time CLI explainability dashboard
├── 📁 config/
│   ├── adaptive_mitigation.json  # Configurable decision thresholds
│   └── config.py                 # JSON configuration loader
├── 📁 results/                    # Auto-generated CSVs, JSON, and comparison charts
│   ├── comparison_metrics.png
│   ├── experiment_results.csv
│   └── overall_summary_results.json
└── run_experiment.py             # Automated experiment runner
```

---

## 5. Quickstart & Usage Instructions

### Prerequisites
- Python 3.9+
- Dependencies: `pandas`, `scikit-learn`, `matplotlib`, `numpy`, `seaborn`, `scapy`

### 1. Generate Sample Telemetry Dataset
```bash
python Codes/ml/create_sample_dataset.py
```

### 2. Train & Benchmark Machine Learning Classifiers
```bash
python -c "import matplotlib; matplotlib.use('Agg'); import Codes.ml.ML as ML; ML.main()"
```

### 3. Run Experimental Evaluation Suite
Run side-by-side comparison between Baseline and Adaptive systems across all attack types and severity levels:
```bash
python run_experiment.py --mode both --attack all --severity all
```

Run specific scenario tests:
```bash
# Evaluate Adaptive Mode on High-Severity UDP Flood
python run_experiment.py --mode adaptive --attack udp --severity high

# Evaluate Baseline Mode on Medium-Severity SYN Flood
python run_experiment.py --mode baseline --attack syn --severity medium
```

### 4. Run Ryu Controller & Mininet Topology
In Mininet / Linux environment:
```bash
# Start Ryu Controller in Adaptive Mode
ryu-manager Codes/controller/controller.py

# In a separate terminal, launch Mininet Topology
sudo python Codes/mininet/topology.py
```

---

## 6. Real-Time Explainability Dashboard

When an attack event occurs, the decision engine logs transparent rationale to the CLI:

```
=================================================================
       [ADAPTIVE DDoS DECISION ENGINE - 2026-10-01 11:22:38]
=================================================================
 Attack Status:       DETECTED DDoS
 Confidence Score:    96.0%
 Packet Rate:         12,000 pps
 Current Network Load: 65.0%
 Legitimate Traffic:  1,800 pps
-----------------------------------------------------------------
 SELECTED STRATEGY:   [CONTROLLER_MIGRATION]
 EXPLANATION REASON:  High network load (65.0%) detected with medium flood (12,000 pps). Avoid rate limiting to prevent queue congestion; redirecting to safe proxy inspection.
=================================================================
```

---

## 7. Limitations & Future Research Directions

1. **Hardware Switch Integration**: Current OpenFlow meter tables are tested in Open vSwitch (OVS). Physical hardware switches may require vendor-specific rate-limiting tables.
2. **Reinforcement Learning (RL) Decision Policies**: The system includes an abstract `MLSelector` interface to allow seamless integration of Deep Q-Networks (DQN) or PPO reinforcement learning agents in future iterations.
