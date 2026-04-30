# Supervisor Isolation Forest Demo Brief

## Purpose of This Document

This brief is a supervisor-facing companion to `SUPERVISOR_DEMO_BRIEF.md`,
focused specifically on the Isolation Forest (IF) path in this SDN IDS/IPS.

It explains:

- where IF is implemented in this repository
- how IF is trained and serialized
- how IF is loaded and used during live controller runtime
- how IF contributes to hybrid alerting and quarantine/block decisions
- which dashboard/API fields expose IF evidence
- how to demonstrate IF behavior clearly during a live presentation

The key message for a demo:

> Isolation Forest is not an isolated offline experiment here. It is integrated
> into the live controller pipeline, contributes anomaly evidence at runtime,
> and participates in hybrid block decisions when configured policy conditions
> are met.

## 1. Isolation Forest Role in This Architecture

The project remains threshold-led, but ML can assist:

1. Threshold IDS (`security/ids.py`) remains deterministic baseline.
2. Random Forest contributes supervised malicious classification.
3. Isolation Forest contributes unsupervised anomaly scoring.
4. Hybrid policy in `ml/pipeline.py` combines threshold + RF + IF signals.

In operational terms:

- IF helps detect behaviors that look abnormal relative to recent host baseline.
- IF evidence is represented with `is_anomalous` and `anomaly_score`.
- Hybrid policy can keep IF as alert-only, or escalate IF-supported cases to
  quarantine/block depending on configuration and repeat/context rules.

## 2. Implementation Map (Isolation Forest-Centric)

### 2.1 Runtime model structures

- `ml/anomaly.py`
  - `RuntimeIsolationTree`
  - `RuntimeIsolationForestModel`
  - `AnomalyPrediction`
  - `AnomalyInferenceEngine`
  - `export_isolation_forest_model()` to export a sklearn IF into portable
    runtime tree arrays.

### 2.2 Runtime inference orchestration

- `ml/inference.py`
  - `ModelInferenceEngine`
  - supported inference modes:
    - `classifier_only`
    - `anomaly_only`
    - `combined`
  - IF is enabled/disabled via `enable_isolation_forest`.
  - Combined mode merges RF and IF evidence into one `MLPrediction`.

### 2.3 Hybrid decision logic

- `ml/pipeline.py`
  - `MLIDSPipeline.inspect()` consumes live feature snapshots.
  - `_build_alert()` computes hybrid decision, final action, and reasons.
  - `_evaluate_hybrid_block_support()` enforces policy gates for block
    escalation.
  - `_hybrid_block_decision()` maps signal combinations to decision labels:
    - `threshold_rf_block`
    - `threshold_if_block`
    - `rf_if_consensus_block`
    - `full_hybrid_block`
    - `anomaly_only_block`
    - fallback `ml_only_block`
  - `_resolve_alert_type()` maps detector combinations to stable alert types:
    - `isolation_forest_detected`
    - `hybrid_threshold_if_detected`
    - `hybrid_rf_if_detected`
    - `hybrid_full_detected`
    - and related threshold/RF labels.

### 2.4 Controller integration

- `controller/main.py`
  - `packet_in_handler()` path:
    1. parse packet
    2. threshold inspect
    3. `self.ml_pipeline.inspect(...)`
    4. handle threshold alerts
    5. handle ML alerts (`_handle_ml_alert`)
    6. mitigation/quarantine when `alert.should_mitigate` and policy allows
  - `_handle_ml_alert()` records IF/RF/hybrid details in logs and metrics.
  - mitigation uses existing shared path, not a separate IF-only firewall.

### 2.5 Quarantine and flow enforcement

- `security/mitigation.py`
  - `MitigationService.handle_alert()` delegates to firewall quarantine.
- `security/firewall.py`
  - `add_quarantine()` creates/updates quarantine record.
  - stores `detector`, `latest_detector`, `contributing_detectors`, and capture
    links.
  - installs source-drop rules through `flow_manager.install_source_block(...)`.
- `core/flow_manager.py`
  - sends OpenFlow `OFPFlowMod` drop rules.

### 2.6 Monitoring/API exposure

- `monitoring/state.py`
  - includes recent ML predictions, hybrid events, and summary counters.
  - surfaces IF fields such as anomaly score/status through ML payloads.
- `monitoring/api.py`
  - endpoints: `/api/ml-ids`, `/api/alerts`, `/api/blocked-hosts`,
    `/api/events`, `/api/dashboard`.

## 3. Runtime Feature Space Used by Isolation Forest

From `ml/feature_extractor.py`, IF consumes the same runtime feature vector used
in the ML pipeline:

- `packet_count`
- `byte_count`
- `unique_destination_ports`
- `unique_destination_ips`
- `destination_port_fanout_ratio`
- `connection_rate`
- `syn_rate`
- `icmp_rate`
- `udp_rate`
- `tcp_rate`
- `average_packet_size`
- `observation_window_seconds`
- `packet_rate`
- `bytes_per_second`
- `failed_connection_rate`
- `unanswered_syn_rate`
- `unanswered_syn_ratio`

Why this matters for defense validity:

- these features are controller-observable at runtime (no unavailable CIC-only
  fields needed)
- IF and RF use a shared runtime-compatible schema
- the same feature family is reused for both training and live inference paths

## 4. Isolation Forest Training Pipeline

### 4.1 Training script

- `scripts/train_anomaly_model.py`

Key behavior:

1. loads merged/runtime parquet input
2. builds runtime-compatible feature frame using
   `build_runtime_training_frame(...)`
3. selects benign rows for IF fitting
4. trains sklearn `IsolationForest`
5. exports a portable runtime IF model (`export_isolation_forest_model`)
6. saves a model bundle with metadata using `save_model_bundle(...)`
7. optionally writes metrics JSON

### 4.2 Practical training command

```bash
python3 scripts/train_anomaly_model.py \
  --merged-runtime-data datasets/merged_runtime_dataset.parquet \
  --model-out models/isolation_forest_runtime.joblib \
  --metrics-out models/isolation_forest_runtime_metrics.json \
  --window-seconds 3 \
  --n-estimators 100 \
  --contamination auto \
  --random-state 42
```

### 4.3 Existing workspace artifacts

Current `models/` includes IF artifacts, for example:

- `models/isolation_forest_benign_heavy_20260417.joblib`
- `models/isolation_forest_benign_heavy_20260417b.joblib`
- paired metrics JSON files

## 5. Runtime Configuration for Isolation Forest

Relevant config definitions are in `config/settings.py` (`MLConfig`) and
environment overlays in `.env`, `.env.example`, and `docker-compose.yml`.

Important knobs:

- `SDN_ML_ENABLE_ISOLATION_FOREST=true|false`
- `SDN_ML_ANOMALY_MODEL_PATH=<path>`
- `SDN_ML_INFERENCE_MODE=classifier_only|anomaly_only|combined`
- `SDN_IDS_MODE=threshold|ml|hybrid` (normalized internally)
- `SDN_ML_HYBRID_POLICY=alert_only|high_confidence_block|consensus_severity|layered_consensus`
- `SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_ENABLED=true|false`
- `SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_THRESHOLD=<float>`
- `SDN_ML_REQUIRE_THRESHOLD_FOR_ML_BLOCK=true|false`

Example operational hybrid settings in README/.env include:

- `SDN_IDS_MODE=hybrid`
- `SDN_ML_INFERENCE_MODE=combined`
- `SDN_ML_ANOMALY_MODEL_PATH=models/isolation_forest_benign_heavy_20260417b.joblib`

## 6. End-to-End Isolation Forest Runtime Path

The live IF path is:

1. OpenFlow switch emits `PacketIn` for traffic needing controller handling.
2. `controller/main.py:packet_in_handler()` parses packet metadata.
3. `ml/pipeline.py:inspect()` updates live per-host rolling features.
4. `ml/inference.py:ModelInferenceEngine.predict()` runs IF (and RF in combined mode).
5. `MLPrediction` carries `is_anomalous` and `anomaly_score`.
6. `ml/pipeline.py:_build_alert()` determines decision and final action.
7. `controller/main.py:_handle_ml_alert()` logs and records ML alert.
8. `security/mitigation.py` + `security/firewall.py` quarantine source if mitigation enabled.
9. `core/flow_manager.py` installs source-drop `OFPFlowMod` rules.
10. `monitoring/state.py` publishes updated dashboard/API state.

## 7. Hybrid Decision Semantics to Explain in a Demo

Use these exact labels from `ml/pipeline.py` during explanation:

- `anomaly_only_alert`: IF anomaly observed, alert/watchlist path
- `anomaly_only_block`: IF-only escalation path when enabled and strong enough
- `threshold_if_block`: threshold context + IF support
- `rf_if_consensus_block`: RF + IF support without threshold trigger
- `full_hybrid_block`: threshold + RF + IF all support block

Detector attribution labels:

- `isolation_forest_detected`
- `hybrid_threshold_if_detected`
- `hybrid_rf_if_detected`
- `hybrid_full_detected`

This gives a supervisor a clear answer to:
"Was it threshold only, IF only, or true hybrid consensus?"

## 8. What to Show Live on Dashboard/API

### 8.1 ML evidence fields

From ML alert details and recent prediction state:

- `is_anomalous`
- `anomaly_score`
- `isolation_forest_anomalous`
- `isolation_forest_anomaly_score`
- `detection_sources`
- `final_action`
- `block_decision_path`
- `correlation_status`

### 8.2 State and enforcement evidence

- `/sdn-security/api/alerts`
  - alert rows, detector, reason, decision context
- `/sdn-security/api/blocked-hosts`
  - active quarantines and detector attribution
- `/sdn-security/api/ml-ids`
  - recent ML predictions and hybrid counters
- `/sdn-security/api/events`
  - alerts + controller activity + ML/hybrid streams

Controller logs to cite:

- `event=ml action=ml_alert ... anomaly_score=...`
- `event=security action=host_quarantined ... detector=ml`

## 9. Supervisor Demo Script (IF-Focused)

### 9.1 Startup

```bash
docker compose up -d controller dashboard mininet
```

In Mininet container:

```bash
./scripts/run_topology.sh
```

Baseline:

```text
mininet> pingall
```

### 9.2 Generate suspicious behavior

Examples:

```text
mininet> h1 nmap -Pn -sS -T2 -f --randomize-host 10.0.0.2
mininet> h2 hping3 -A --flood -V 10.0.0.2
```

### 9.3 Observe IF and hybrid outputs

From host shell or dashboard backend host:

```bash
curl -s http://127.0.0.1:8080/sdn-security/api/ml-ids
curl -s http://127.0.0.1:8080/sdn-security/api/alerts
curl -s http://127.0.0.1:8080/sdn-security/api/blocked-hosts
```

Flow enforcement evidence:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Look for source-drop style rules matching quarantined source IPs.

## 10. Likely Supervisor Questions and Strong Answers

### Q1: Why use Isolation Forest in this project?

A: It adds unsupervised anomaly detection for unknown/novel traffic patterns and
provides an additional signal beyond static thresholds and supervised labels.

### Q2: Is IF really integrated, or only trained offline?

A: Integrated. `controller/main.py` calls `ml_pipeline.inspect()`, which runs
`ModelInferenceEngine.predict()` in live traffic. IF output directly affects
`MLAlert` decisions and can trigger mitigation via the same quarantine path.

### Q3: Can IF trigger blocking, or only alert?

A: Both are supported by policy. By default anomaly-only block is conservative,
but hybrid policy can escalate IF-supported cases (`threshold_if_block`,
`rf_if_consensus_block`, `anomaly_only_block`) when configured conditions are
met.

### Q4: How do you avoid unsafe IF blocks?

A: Guardrails include threshold-led policy options, configurable anomaly
thresholds, repetition/context checks, protected-address suppression, and shared
mitigation controls with manual unblock.

## 11. Final Talking Point

For your presentation, close with:

> The Isolation Forest path in this repository is operationally wired into the
> SDN controller, not a disconnected notebook result. It contributes runtime
> anomaly evidence to the hybrid IDS/IPS decision process, is visible through
> logs and dashboard APIs, and can participate in OpenFlow-enforced quarantine
> when configured policy allows it.
