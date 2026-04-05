# FusionIDS: Decentralized Hybrid Intrusion Detection System with PBFT Blockchain Consensus

## Thumbnail

![FusionIDS Thumbnail](fusionids_thumbnail.png)

*(64×64 thumbnail for IEEE NITK website)*

---

## Summary

FusionIDS is a decentralized network intrusion detection system that combines a high-speed C++ packet capturer, ensemble machine learning inference (LightGBM, XGBoost, Random Forest) alongside an unsupervised anomaly detector, and an immutable PBFT blockchain ledger for tamper-proof alert storage.

---

## Aim

To design and implement a fully decentralized, real-time Intrusion Detection System (IDS) that addresses the critical vulnerabilities of traditional centralized IDS architectures — namely single points of failure and log tampering — by fusing high-throughput native packet capture, dual-layer machine learning (supervised + unsupervised), and cryptographically secured distributed ledger consensus.

---

## Introduction

Modern network infrastructures face increasingly sophisticated cyber threats ranging from known attack vectors such as Distributed Denial-of-Service (DDoS), Brute Force, and Botnet infiltration, to completely novel zero-day exploits with no prior signature. Traditional centralized Intrusion Detection Systems, while effective at detecting known patterns, suffer from two fundamental weaknesses:

1. **Single Point of Failure:** A centralized IDS server, once compromised, renders the entire monitoring pipeline inoperable. The attacker gains complete control over what is logged and what is silently discarded.

2. **Log Tampering:** Even if the IDS detects malicious activity before being neutralized, a sophisticated attacker can retroactively delete or modify the alert logs stored on the same centralized infrastructure, effectively erasing all evidence of the intrusion.

FusionIDS addresses both weaknesses through a three-tier architecture:

- **Tier 1 — Native C++ Flow Capturer:** A high-performance packet capture engine built in C++ that hooks directly into the network interface (eth0) via `libpcap`. It assembles raw Ethernet frames into bidirectional network flows and computes 63 optimized statistical features in real-time with sub-millisecond latency.

- **Tier 2 — Hybrid ML Inference Engine:** A FastAPI-based microservice architecture running dual-layer machine learning. The supervised ensemble layer (LightGBM, XGBoost, Random Forest) detects known attack signatures with near-perfect accuracy, while a dedicated unsupervised Isolation Forest anomaly detector flags previously unseen traffic patterns that deviate from normal behavior — catching zero-day threats that bypass all signature databases.

- **Tier 3 — PBFT Blockchain Consensus Network:** When the ML engine raises an alert, it is not immediately trusted. The alert is submitted to a network of N distributed nodes running a leaderless Practical Byzantine Fault Tolerance (PBFT) consensus protocol. Each peer node independently re-validates the alert using its own local ML model. Only when 2f+1 nodes cryptographically agree does the alert get permanently committed to an immutable blockchain ledger. This guarantees that even if an attacker compromises a single node, they cannot delete or forge intrusion records.

The entire system is containerized using Docker and orchestrated via Docker Compose, enabling rapid deployment of multi-node IDS clusters with heterogeneous model configurations per node.

---

## Literature Survey and Technologies Used

### Literature Survey

| # | Reference | Key Contribution | Relevance to FusionIDS |
|---|---|---|---|
| 1 | Sharafaldin et al. (2018) | CSE-CIC-IDS2018 dataset & CICFlowMeter | Training data + C++ capturer design |
| 2 | Ferrag et al. (2020) | ML/DL survey for NIDS | Justified ensemble over deep learning |
| 3 | Castro & Liskov (1999) | PBFT consensus protocol | Blockchain consensus foundation |
| 4 | Liu, Ting & Zhou (2008) | Isolation Forest algorithm | Zero-day anomaly detection layer |
| 5 | Alexopoulos et al. (2020) | Blockchain-based IDS | Tamper-proof alert ledger design |

#### Detailed Summaries

**1. Sharafaldin et al. (2018) — "Toward Generating a New Intrusion Detection Dataset and Intrusion Detection Using Machine Learning Techniques"**

This seminal paper introduced the CSE-CIC-IDS2018 dataset, which remains one of the most widely used benchmarks for network intrusion detection research. The authors developed CICFlowMeter, a Java-based tool that captures raw network packets and assembles them into bidirectional flows, computing up to 80 statistical features per flow including inter-arrival times, packet length distributions, TCP flag counts, and active/idle period statistics. Their work demonstrated that flow-level statistical features — rather than raw packet payloads — provide sufficient discriminative power for accurate multi-class traffic classification. We adopted this dataset as our primary training source and built a custom C++ flow extraction engine that replicates CICFlowMeter's feature computation logic natively, achieving significantly higher throughput by eliminating the JVM overhead that limits CICFlowMeter's real-time performance.

**2. Ferrag et al. (2020) — "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study"**

This comprehensive survey evaluated over 35 deep learning and traditional machine learning approaches for network-based intrusion detection across multiple standard datasets. A key finding was that for tabular flow-level data (as opposed to raw packet bytes), gradient boosting ensemble methods (such as XGBoost and LightGBM) consistently matched or outperformed deep learning architectures like CNNs and LSTMs, while training orders of magnitude faster and requiring less computational resources. The survey also highlighted that no single model achieves perfect generalization across all attack categories, motivating ensemble and multi-model strategies. This insight directly influenced our decision to deploy a heterogeneous ensemble of three gradient boosting classifiers (LightGBM, XGBoost, Random Forest) with majority voting, rather than relying on a single deep learning model.

**3. Castro & Liskov (1999) — "Practical Byzantine Fault Tolerance"**

The original PBFT paper presented the first practical state machine replication protocol that tolerates Byzantine (arbitrary) faults while maintaining acceptable performance for real-world distributed systems. The protocol guarantees safety and liveness provided that no more than f out of 3f+1 total nodes are Byzantine, using a three-phase consensus mechanism (PRE-PREPARE → PREPARE → COMMIT). Each phase requires collecting 2f+1 matching votes before advancing, ensuring that even if malicious nodes send conflicting messages, the honest majority will converge on a single consistent decision. We implemented a leaderless variant of PBFT for our blockchain layer where any node can propose a block at any time. The key adaptation is that during the PREPARE phase, each peer node independently re-validates the proposed alert by running its own local ML model on the raw flow features — consensus is thus not merely a vote on message ordering but a cryptographic agreement that the threat is real.

**4. Liu, Ting & Zhou (2008) — "Isolation Forest"**

The Isolation Forest algorithm introduced a fundamentally different approach to anomaly detection based on the principle that anomalies are "few and different" — they are easier to isolate via random partitioning than normal observations. Unlike distance-based or density-based methods that explicitly model normal behavior, Isolation Forest builds an ensemble of random trees (Isolation Trees) that recursively partition the feature space along random dimensions. Anomalous points, being sparse and dissimilar, require fewer random splits to isolate, resulting in shorter average path lengths through the trees. This path length becomes the anomaly score. The algorithm scales linearly with data size and requires no assumptions about the distribution of normal data. We trained our Isolation Forest exclusively on benign traffic flows, allowing it to learn the statistical manifold of legitimate network behavior. During inference, any flow that deviates significantly from this manifold receives a low anomaly score (< -0.45), triggering a zero-day alert even when the supervised signature models classify it as benign.

**5. Alexopoulos et al. (2020) — "Blockchain-based Intrusion Detection Systems"**

This study proposed integrating blockchain technology with intrusion detection to solve the critical problem of log integrity in adversarial environments. The authors demonstrated that storing IDS alerts on a distributed, append-only ledger prevents attackers from retroactively modifying or deleting evidence of their intrusion after compromising the monitoring infrastructure. Their architecture used a permissioned blockchain where each IDS node acts as both a detector and a validator. We extended this concept significantly in FusionIDS by adding a peer re-validation mechanism during the consensus phase — rather than blindly trusting alerts from any single node, each peer independently re-runs its own ML model on the original flow features before voting to accept the alert. This prevents a compromised node from flooding the ledger with false alerts and ensures that only threats confirmed by the network majority are permanently recorded.

### Technologies Used

| Component | Technology | Purpose |
|---|---|---|
| Packet Capture | C++17, libpcap, Boost, nlohmann-json | Native high-speed network flow extraction |
| ML Inference | Python 3.11, LightGBM, XGBoost, scikit-learn | Supervised ensemble classification |
| Anomaly Detection | scikit-learn Isolation Forest | Unsupervised zero-day threat detection |
| API Server | FastAPI, Uvicorn, Pydantic | ML inference microservice endpoints |
| Blockchain | Python, ECDSA (secp256k1), SHA-256, Flask | PBFT consensus and alert ledger |
| Persistence | SQLite | Per-node blockchain storage |
| Containerization | Docker, Docker Compose, supervisord | Multi-node orchestration |
| Data Pipeline | Pandas, NumPy, joblib | Feature engineering and model serialization |
| Dashboard | React (Vite), TailwindCSS, FastAPI backend | Real-time monitoring UI |
| Feature Selection | Mutual Information + RF Importance | Dimensionality reduction (68 → 63 features) |

---

## Methodology

### 1. Data Preprocessing Pipeline

The raw CSE-CIC-IDS2018 dataset undergoes a rigorous multi-step preprocessing pipeline:

1. **Merging:** Raw CSV files from multiple capture sessions are merged into a unified dataset (`step1_merge.py`).
2. **Cleaning:** Infinite values, NaN entries, and constant-value columns are removed. Duplicate flows are eliminated (`step2_clean.py`).
3. **Label Encoding:** Attack categories are encoded into 7 integer classes — Benign (0), BruteForce (1), DoS (2), PortScan (3), Bot (4), WebAttack (5), Infiltration (6) (`step2_encode.py`).
4. **Stratified Sampling & Splitting:** The cleaned dataset is split into train/validation/test sets with stratified sampling to preserve class distributions (`step3_sample.py`).
5. **Feature Selection:** A union of Random Forest importance (threshold > 0.001) and Mutual Information (top 90th percentile) yields the final 63 optimized features, eliminating 5 low-signal columns (`step4_feature_selection.py`).

### 2. Native C++ Flow Capture Engine

The C++ traffic capturer is the system's front-line component, designed for zero-packet-loss performance:

- **Packet Sniffing:** Uses `libpcap` to capture raw Ethernet frames on the monitored interface with kernel-level buffering.
- **Flow Tracking:** Maintains a hash map of active bidirectional flows keyed by the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). Each packet is assigned to its parent flow.
- **Statistical Feature Computation:** For each flow, the engine computes 68 statistical features across multiple dimensions:
  - **Length Statistics:** Forward/backward packet length (min, max, mean, std, variance)
  - **Inter-Arrival Time (IAT):** Flow/forward/backward IAT statistics
  - **Header Analysis:** Forward/backward header lengths, TCP flag counts (SYN, ACK, PSH, FIN, RST, URG, ECE)
  - **Rate Metrics:** Bytes/s, packets/s, forward/backward rates
  - **Activity Tracking:** Active/idle period statistics
- **Flow Expiration:** Flows are expired after a configurable timeout. Upon expiration, the 68-feature vector is serialized as JSON and POSTed to the ML server via `libcurl`.

### 3. Hybrid Machine Learning Architecture

The ML inference layer implements a dual-strategy detection approach:

#### 3a. Supervised Signature Ensemble

Three gradient boosting classifiers are trained independently:

- **LightGBM:** 500 estimators, 127 leaves, max_depth=8, balanced class weights, early stopping
- **XGBoost:** Similar hyperparameter configuration with GPU acceleration support
- **Random Forest:** Sklearn implementation with balanced subsample weighting

Each Docker node loads a configurable subset of these models (controlled by `ENABLED_MODELS` environment variable). Node 3 runs all three simultaneously and uses **majority voting** — if 2/3 models agree on a label, that prediction wins with averaged confidence. If all three disagree, the highest-confidence individual prediction is used.

#### 3b. Unsupervised Anomaly Detection

An **Isolation Forest** model is trained on benign-only traffic. During inference, it produces an anomaly score for each flow. Flows with scores below the threshold (default: -0.45) are flagged as anomalous regardless of the supervised model's opinion.

#### 3c. Fusion Engine

The `FusionEngine` class implements a 5-case decision matrix that combines the signature and anomaly results:

| Case | Signature | Anomaly | Result | Severity |
|---|---|---|---|---|
| 1 | Attack detected (conf ≥ 40%) | Strong anomaly (score ≤ -0.55) | Attack name | **Critical** |
| 2 | Attack detected (conf ≥ 40%) | Normal | Attack name | Medium |
| 3 | Benign | Strong anomaly (score ≤ -0.55) | Unknown Attack | High |
| 4 | Benign (low conf < 80%) | Weak anomaly (score ≤ -0.45) | Suspicious | Unknown |
| 5 | Weak attack (20-40% conf) | Weak anomaly | Suspicious (attack name) | Low |

This fusion strategy ensures that **no threat goes undetected** — known attacks are caught by signatures, while novel zero-day threats are flagged by the anomaly detector.

### 4. PBFT Blockchain Consensus

When the ML engine produces a non-null alert, the flow enters the blockchain consensus pipeline:

1. **Alert Creation & Signing:** The originating node creates an `AlertTransaction` containing the alert type, detector outputs (model confidences), and raw flow features. The transaction is signed using ECDSA (secp256k1) and assigned a unique `tx_id` via SHA-256.

2. **Block Proposal:** The signed alert is wrapped in a `Block` (one alert per block) and added to the `PendingBlockPool`. The pool is deterministically sorted by alert timestamp to ensure all honest nodes agree on processing order.

3. **Leaderless PBFT Consensus:**
   - **PRE-PREPARE:** The proposing node broadcasts the block to all peers.
   - **PREPARE:** Each receiving node independently re-runs its local ML model on the raw flow features (`/validate` endpoint). If the local model also flags the traffic as non-benign, the node sends a PREPARE vote.
   - **COMMIT:** Once 2f+1 PREPARE votes are collected, nodes send COMMIT messages.
   - **DECIDED:** After 2f+1 COMMIT votes, the block is permanently appended to the chain.

4. **Immutable Storage:** Each committed block is persisted to a local SQLite database. The chain maintains cryptographic linkage — each block's hash includes the previous block's hash, making retroactive tampering computationally infeasible.

### 5. Containerized Deployment

The entire system is packaged as a multi-stage Docker image:
- **Stage 1 (cpp-builder):** Compiles the C++ capturer using CMake on Ubuntu 22.04
- **Stage 2 (runtime):** Copies the compiled binary, Python ML models, and blockchain code into a slim runtime image

Docker Compose orchestrates N nodes, each with:
- A C++ packet capturer process
- A FastAPI ML inference server (port 8000)
- A Flask blockchain node (port 5000)
- A target server for attack simulation (port 9000+)

All processes within a single container are managed by `supervisord`.

---

## Results

### Model Performance

The supervised models were trained on the CSE-CIC-IDS2018 dataset with 63 selected features and evaluated on a held-out test split:

| Model | Test Accuracy | Best Iteration | Notes |
|---|---|---|---|
| LightGBM | 99.8%+ | ~200 (early stopped from 500) | Primary model for most nodes |
| XGBoost | 99.7%+ | Similar early stopping | GPU-accelerated alternative |
| Random Forest | 99.5%+ | N/A (no boosting) | Bagging-based diversity |

### Classification Categories

The system successfully classifies traffic into 7 categories:
- **Benign** — Normal network traffic
- **BruteForce** — Credential stuffing / password guessing attacks
- **DoS** — Denial-of-Service flooding
- **PortScan** — Network reconnaissance via port enumeration
- **Bot** — Botnet command-and-control beaconing
- **WebAttack** — SQL injection, XSS, and web exploitation
- **Infiltration** — Slow data exfiltration over persistent connections

### System Performance

| Metric | Value |
|---|---|
| Feature Extraction Latency | Sub-millisecond (C++ native) |
| ML Inference Latency | < 2ms per flow |
| PBFT Consensus Time | < 500ms (5-node cluster) |
| Blockchain Block Size | 1 alert per block (granular audit trail) |
| Fault Tolerance | Up to f Byzantine nodes (f=1 for 5 nodes) |

### Attack Simulation Validation

The custom `attack_simulator.py` generates CIC-IDS2018-style traffic patterns to validate the live pipeline:

| Attack Type | Simulation Method | Expected Flow Signature |
|---|---|---|
| BruteForce | 3 persistent connections × 200 PSH/ACK exchanges | High PSH count, bidirectional, ~2s duration |
| DoS | 3 connections flooding for 20s | Thousands of packets, high byte rate |
| PortScan | 500 connection attempts (1 per port) | Many short flows, 1 packet each |
| Bot | 1 long-lived connection with periodic beacons | High idle mean, periodic active bursts |
| Infiltration | 1 connection with 140KB sustained transfer | High TotLen Fwd, many PSH flags |

---

## Conclusions / Future Scope

### Conclusions

1. **Decentralization eliminates single-point-of-failure:** By distributing the IDS across N independent nodes with PBFT consensus, the system remains operational and trustworthy even if individual nodes are compromised.

2. **Dual-layer ML provides complete threat coverage:** The combination of supervised ensemble models (for known signatures) and unsupervised anomaly detection (for zero-day threats) ensures that no category of attack can bypass the system entirely.

3. **Native C++ capture ensures zero packet loss:** By implementing the flow extraction engine in C++ with direct `libpcap` bindings, the system achieves sub-millisecond feature computation without the overhead of interpreted language runtimes.

4. **Blockchain immutability prevents evidence tampering:** ECDSA-signed alerts committed through PBFT consensus create a cryptographically verifiable audit trail that attackers cannot retroactively modify.

5. **Heterogeneous node configurations add diversity:** Each Docker node can run a different combination of ML models, preventing a single model vulnerability from compromising the entire network's detection capability.

### Future Scope

1. **Deep Learning Integration:** Incorporate transformer-based or 1D-CNN architectures for payload-level inspection alongside the current flow-level statistical analysis.

2. **Federated Learning:** Enable nodes to collaboratively improve their local models by sharing gradient updates rather than raw data, preserving privacy across organizational boundaries.

3. **Smart Contract Enforcement:** Extend the blockchain layer with programmable smart contracts that can automatically trigger network isolation (firewall rules) when consensus confirms a critical-severity alert.

4. **Horizontal Scalability:** Implement sharding or layer-2 protocols to scale the blockchain beyond the current PBFT limit of approximately 20 nodes while maintaining Byzantine fault tolerance.

5. **Real-time Dashboard Enhancements:** Expand the React/Vite monitoring dashboard with live attack visualizations, historical trend analysis, and automated report generation for security operations centers.

---

## References / Links

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion Detection Using Machine Learning Techniques." *International Conference on Information Systems Security and Privacy (ICISSP).*
2. Castro, M., & Liskov, B. (1999). "Practical Byzantine Fault Tolerance." *Proceedings of the Third Symposium on Operating Systems Design and Implementation (OSDI).*
3. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). "Isolation Forest." *Eighth IEEE International Conference on Data Mining.*
4. Ferrag, M. A., et al. (2020). "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study." *Journal of Information Security and Applications.*
5. Ke, G., et al. (2017). "LightGBM: A Highly Efficient Gradient Boosting Decision Tree." *Advances in Neural Information Processing Systems (NeurIPS).*

**GitHub Repository:** https://github.com/SteganoSage/FusionIDS

---

## Mentors / Mentees Details

| Role | Name |
|---|---|
| Mentor | Shubrohdipto De, Saksham Singh, Nakul Aggarwal|
| Mentee | Dhruv Mohan Anand, Rajsimha M.V. , Paranthi Udaya Kumar, Hyder Khan |

---

*Report prepared for IEEE NITK Virtual Expo 2026*
