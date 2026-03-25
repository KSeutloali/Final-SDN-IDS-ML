# Supervisor ML Model Explanation

## 1. Executive Summary

This project uses a machine learning intrusion-detection path as an **optional extension** to the main SDN security system, not as a replacement for the threshold IDS. The threshold IDS in `security/ids.py` remains the primary deterministic baseline. The ML subsystem in `ml/` adds a second detection path based on a **Random Forest classifier** trained on **runtime-compatible traffic features** collected from the actual Mininet and Ryu SDN lab.

The most important current runtime model artifact is:

- `models/random_forest_runtime_final.joblib`

That model was trained from:

- `datasets/merged_runtime_dataset.parquet`

The saved metrics in `models/random_forest_runtime_final_metrics.json` show that the final model uses:

- `RandomForestClassifier`
- `300` trees
- `max_depth=20`
- `min_samples_split=5`
- `min_samples_leaf=2`
- `class_weight="balanced"`
- `random_state=42`
- `window_seconds=3`
- `split_mode="grouped"`

The raw merged runtime parquet contains **56,843 rows**:

- `54,248` malicious
- `2,595` benign

However, the trainer does not learn directly from raw packet rows. It converts them into **793 host-window training samples**:

- `496` malicious
- `297` benign

Those host-window samples are then split into:

- `679` training rows
- `114` test rows

This distinction matters. The project deliberately moved toward **runtime-generated SDN data** because the deployed controller can only classify traffic using features it can actually observe from `PacketIn` events and short rolling windows. In academic terms, this improves **construct validity** and **deployment realism**.

## 2. Files Inspected

### Core ML implementation

- `ml/feature_extractor.py`
- `ml/inference.py`
- `ml/model_loader.py`
- `ml/pipeline.py`
- `ml/runtime_forest.py`
- `ml/dataset_recorder.py`

### Training and data scripts

- `scripts/train_random_forest.py`
- `merge_runtime_datasets.py`
- `scripts/collect_runtime_dataset.py`
- `scripts/set_dataset_label.py`
- `scripts/export_runtime_dataset.py`
- `scripts/export_runtime_model.py`

### Runtime integration and monitoring

- `controller/main.py`
- `monitoring/state.py`
- `monitoring/metrics.py`
- `monitoring/static/dashboard.js`
- `monitoring/templates/ml_ids.html`

### Configuration and documentation

- `config/settings.py`
- `docker-compose.yml`
- `.env`
- `README.md`

### Model and dataset artifacts

- `models/random_forest_runtime_final.joblib`
- `models/random_forest_runtime_final_metrics.json`
- `models/random_forest_runtime_final_features.json`
- `models/random_forest_ids.runtime.joblib`
- `models/runtime_scan_aware_20260320.runtime.joblib`
- `models/collected_runtime_model_20260312_122214.runtime.joblib`
- `datasets/merged_runtime_dataset.parquet`
- `datasets/scan_heavy_runtime_20260321.parquet`
- `datasets/collected_runtime_dataset_20260312_120629.parquet`
- `datasets/collected_runtime_dataset_20260312_121650.parquet`
- `datasets/collected_runtime_dataset_20260312_122214.parquet`
- `datasets/live_smoke_collection.parquet`
- `cic-collection.parquet`

## 3. Exact Training Pipeline

### 3.1 Runtime data collection

The training pipeline begins with **runtime data collection from the actual SDN lab**.

This is orchestrated by:

- `scripts/collect_runtime_dataset.py`

The collector recreates the controller with dataset recording enabled, runs labeled benign and malicious scenarios from Mininet, then exports the recorded JSONL data to parquet.

The collector supports three profiles:

- `balanced`
- `scan_heavy`
- `flood_heavy`

The current runtime dataset work is centered on `scan_heavy`, which increases the diversity of scan and sweep behavior while preserving flood scenarios.

### 3.2 Runtime labeling

Labeling is handled by:

- `scripts/set_dataset_label.py`

This writes a live label file consumed by the controller-side recorder. The label payload includes:

- `label`
- `scenario`
- `scenario_id`
- `scenario_family`
- `scenario_variant`
- `traffic_class`
- `run_id`
- `collection_id`
- `src_host`
- `dst_host`
- `dst_service`
- `duration_seconds`
- `rate_parameter`
- `concurrency_level`
- `capture_file`
- `note`

This is important because the dataset is not just labeled as benign or malicious. It also records the scenario context needed for traceability and grouped evaluation.

### 3.3 Controller-side recording

The controller records data through:

- `ml/dataset_recorder.py`

`RuntimeDatasetRecorder.record()` writes JSONL rows containing:

- packet-observed fields such as `Src IP`, `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`
- simple packet statistics such as `Total Packets`, `Total Bytes`, `SYN Flag Count`, `RST Flag Count`
- runtime feature values written as `Runtime <feature_name>`

The key methodological strength is that the recorder uses the same **live-compatible feature space** as the actual ML runtime path.

### 3.4 JSONL to parquet export

Recorded JSONL is converted to parquet by:

- `scripts/export_runtime_dataset.py`

This script:

- loads JSONL rows
- converts `Timestamp` to a real datetime column
- sorts by time
- writes a parquet file for offline training

### 3.5 Merge step

The approved runtime merge script is:

- `merge_runtime_datasets.py`

By default it merges exactly these four files:

- `datasets/scan_heavy_runtime_20260321.parquet`
- `datasets/collected_runtime_dataset_20260312_120629.parquet`
- `datasets/collected_runtime_dataset_20260312_121650.parquet`
- `datasets/collected_runtime_dataset_20260312_122214.parquet`

The script:

- loads all four parquet files
- aligns schemas to a canonical set of metadata and runtime feature columns
- normalizes labels to `benign` or `malicious`
- adds a `Source File` column
- removes exact duplicates using a stable key if possible
- writes `datasets/merged_runtime_dataset.parquet`

The checked merge summary shows:

- merged rows: `56,843`
- duplicates removed: `0`

### 3.6 Offline training

Offline training is performed by:

- `scripts/train_random_forest.py`

This script is explicit that the live controller only performs:

1. rolling-window feature extraction
2. model loading
3. inference

Training is therefore intentionally offline.

The trainer:

1. loads parquet input
2. resolves the schema using `resolve_schema_columns()`
3. validates whether the schema is compatible with live SDN runtime expectations
4. normalizes labels using `_binary_label_series()`
5. builds a runtime-compatible feature frame using `build_runtime_training_frame()`
6. performs grouped or random splitting through `split_training_frame()`
7. trains a `RandomForestClassifier`
8. evaluates the model using `classification_report`
9. exports a portable runtime model using `export_random_forest_model()`
10. saves the model bundle with `save_model_bundle()`
11. optionally writes metrics and feature manifest JSON files

### 3.7 Label normalization

Label normalization is explicit in `_binary_label_series()`:

- labels containing `benign`, `normal`, or `background` become `benign`
- all other labels become `malicious`

This gives the project a binary classifier:

- `benign`
- `malicious`

### 3.8 Splitting strategy

The final model uses:

- `split_mode = grouped`

This is important. The trainer does not simply shuffle rows randomly. It prefers grouped splitting by:

- `Run ID`
- or fallback scenario identifiers if needed

For the final model, the saved metadata shows:

- `group_split_column = "Run ID"`
- `group_count = 64`

That is much more defensible than random row shuffling because it reduces leakage across repeated samples from the same scenario run.

### 3.9 Final training command

The current final model was produced using the newer workflow that supports merged runtime data and explicit metrics output. The final-style command aligned with the saved artifact is:

```bash
./.venv-ml310/bin/python scripts/train_random_forest.py \
  --merged-runtime-data datasets/merged_runtime_dataset.parquet \
  --label-column Label \
  --model-out models/random_forest_runtime_final.joblib \
  --metrics-out models/random_forest_runtime_final_metrics.json \
  --feature-manifest-out models/random_forest_runtime_final_features.json \
  --random-state 42 \
  --test-size 0.2 \
  --split-mode grouped \
  --window-seconds 3 \
  --n-estimators 300 \
  --max-depth 20 \
  --min-samples-split 5 \
  --min-samples-leaf 2 \
  --class-weight balanced
```

The metrics file confirms those values.

## 4. Algorithm Used and Rationale

The exact algorithm is:

- `sklearn.ensemble.RandomForestClassifier`

The deployed runtime model is exported into:

- `ml.runtime_forest.RuntimeRandomForestModel`

The current final artifact metadata shows:

- `tree_count = 300`
- `runtime_model_type = "portable_random_forest"`

### Why Random Forest was chosen

This repository gives both explicit and implicit reasons.

The explicit reasons appear in `README.md`, which describes Random Forest as appropriate because it is:

- explainable
- fast at inference time
- effective on tabular network statistics
- suitable without heavy infrastructure

The implicit reasons are visible in the implementation:

1. The model uses **structured host-window features**, not raw payloads.
2. The project needs **lightweight controller-side inference**.
3. The deployed controller avoids shipping the full sklearn training stack.
4. The repo includes a custom runtime export path for Random Forest in `ml/runtime_forest.py`.

Taken together, these strongly support the project decision to use Random Forest.

### Why Random Forest fits an SDN IDS project

Random Forest is well suited here because the feature space is:

- low-dimensional
- numeric
- structured
- heterogeneous
- partly nonlinear

Features such as:

- `unique_destination_ports`
- `destination_port_fanout_ratio`
- `syn_rate`
- `failed_connection_rate`
- `unanswered_syn_rate`

interact in ways that are not purely linear. Random Forest can capture those interactions without requiring complex feature engineering or deep neural infrastructure.

### Why it fits a final-year academic project

For a final-year project, the model needs to be:

- accurate enough to demonstrate practical value
- simple enough to explain clearly
- lightweight enough to integrate into the controller
- easy to defend methodologically

Random Forest fits those constraints better than a much more complex model would.

## 5. Why Random Forest Over Other Algorithms

The repository does **not** contain a formal multi-algorithm benchmark. So the comparisons below are careful, project-specific justifications rather than claims of tested superiority.

### Random Forest vs Decision Tree

A single decision tree would be simpler, but it is also more likely to overfit repeated lab patterns. This project contains repeated scenario families with parameter variation, and Random Forest reduces variance by averaging many trees rather than relying on one tree structure.

### Random Forest vs Logistic Regression

The current feature set is not naturally linear. Scan-like behavior depends on combinations of:

- port diversity
- host diversity
- SYN intensity
- silence or lack of response

Random Forest can model those interactions more naturally than Logistic Regression.

### Random Forest vs Support Vector Machine

SVM would make the project harder to justify operationally because:

- it is more sensitive to feature scaling and kernel choice
- it is less naturally portable into the lightweight runtime path used here
- it is less straightforward to explain in a supervisor defense

### Random Forest vs K-Nearest Neighbors

KNN would move more complexity into runtime inference because it depends on stored training examples and similarity comparisons at prediction time. That is a poor fit for a controller that should remain lightweight and predictable.

### Random Forest vs Naive Bayes

Naive Bayes assumes stronger feature independence than is realistic for this project. Packet rate, SYN rate, failed connection rate, unanswered SYN rate, and port fanout are correlated network behaviors. Random Forest is more robust for correlated tabular features.

### Random Forest vs XGBoost or gradient boosting

Gradient boosting methods are strong classifiers, but this repository already contains a clean export path for Random Forest into a custom portable runtime representation. There is no equivalent boosting-runtime export path in the codebase. That matters because this project values runtime simplicity and explainability.

### Random Forest vs deep learning

This project does not use raw packet payloads, sequences, or image-like representations. It uses explicit host-window statistics. Deep learning would add complexity that does not align with the available feature space, dataset size, or deployment architecture.

### Academic defense summary

The strongest supervisor-facing answer is:

> Random Forest was chosen because the project uses structured, runtime-observable SDN traffic features rather than raw packets. It provides a good balance of accuracy, robustness, explainability, and lightweight deployment. It is also easier to justify and integrate in a final-year SDN security project than more complex alternatives.

## 6. Runtime Data vs CIC Dataset Decision

This is one of the most important design decisions in the repository.

The repo contains a very large offline dataset:

- `cic-collection.parquet`

That file contains:

- `9,167,581` rows

with many attack labels such as:

- `DDoS-LOIC-HTTP`
- `DoS-Hulk`
- `Portscan`
- `Botnet`
- `Infiltration`

and `7,186,189` benign rows labeled `Benign`.

However, the final deployed runtime model does **not** use that CIC parquet directly.

### Why not use CIC directly

The answer is explicit in `ml/feature_extractor.py`:

> The controller cannot reproduce every flow feature available in offline datasets such as CIC.

The trainer enforces the same idea. In `scripts/train_random_forest.py`, `resolve_schema_columns()` checks whether the dataset preserves the fields needed to reconstruct a live-compatible SDN feature space:

- source IP
- destination IP
- destination port
- protocol
- timestamp

If those fields are missing, the trainer rejects the dataset by default unless `--allow-degraded-training` is used.

### Evidence from the older CIC-derived runtime model

The older deployed artifact:

- `models/random_forest_ids.runtime.joblib`

was trained from:

- `cic-collection.parquet`

Its metadata shows a mismatch between offline source columns and live runtime needs:

- `src_ip: null`
- `dst_ip: null`
- `dst_port: null`
- `protocol: null`
- `timestamp: null`

It still achieved a strong offline accuracy, about `0.9309`, but it used a less deployment-valid feature mapping and only `14` features.

### Why runtime-generated SDN data is more appropriate

The final project chose to train the deployed model from controller-generated runtime data because:

1. it matches the actual `PacketIn` telemetry seen by the controller
2. it matches the rolling-window feature extractor used online
3. it reduces schema mismatch
4. it is easier to defend academically
5. it avoids claiming live performance from offline-only feature spaces

This is a validity-driven decision, not just a convenience decision.

### Why threshold IDS still remains the baseline

Even with ML integrated, the threshold IDS remains the primary baseline because it is:

- deterministic
- explainable
- low risk
- immediately tied to packet windows seen at runtime

That makes the combined architecture stronger:

- threshold IDS handles clear, explainable policy enforcement
- ML adds probabilistic classification and correlation

## 7. Dataset Sizes and Class Balance

### 7.1 Runtime datasets in the repository

| Dataset | Rows | Benign | Malicious |
|---|---:|---:|---:|
| `datasets/scan_heavy_runtime_20260321.parquet` | 53,946 | 1,830 | 52,116 |
| `datasets/collected_runtime_dataset_20260312_120629.parquet` | 813 | 135 | 678 |
| `datasets/collected_runtime_dataset_20260312_121650.parquet` | 1,000 | 258 | 742 |
| `datasets/collected_runtime_dataset_20260312_122214.parquet` | 1,084 | 372 | 712 |
| `datasets/generated_runtime_dataset_20260312.parquet` | 64 | 36 | 28 |
| `datasets/live_smoke_collection.parquet` | 7,360 | 168 | 7,192 |
| `datasets/merged_runtime_dataset.parquet` | 56,843 | 2,595 | 54,248 |

### 7.2 Merged runtime dataset

The approved merged training base is:

- `datasets/merged_runtime_dataset.parquet`

This file was built from exactly:

- `datasets/scan_heavy_runtime_20260321.parquet`
- `datasets/collected_runtime_dataset_20260312_120629.parquet`
- `datasets/collected_runtime_dataset_20260312_121650.parquet`
- `datasets/collected_runtime_dataset_20260312_122214.parquet`

Merge result:

- total rows: `56,843`
- duplicates removed: `0`
- benign: `2,595`
- malicious: `54,248`

Raw class ratio:

- about `20.9:1` malicious to benign

So yes, the raw runtime dataset is still attack-heavy.

### 7.3 Effective training balance

The final model metrics file shows that the trainer converted the raw parquet into **host-window training rows**:

- `runtime_training_rows = 793`
- `class_balance = {"benign": 297, "malicious": 496}`

This is a much healthier effective balance than the raw packet-level data.

### 7.4 Final presented model

The most likely final presented model is:

- `models/random_forest_runtime_final.joblib`

because:

- it is now the code default in `config/settings.py`
- it is also the current default in `docker-compose.yml`
- it has matching metrics and feature manifest files
- it is the artifact aligned with the updated runtime settings and recent live validation work

One repo nuance should be stated honestly:

- `.env` still points to `models/random_forest_ids.runtime.joblib`
- but `config/settings.py` and `docker-compose.yml` default to `models/random_forest_runtime_final.joblib`

So the effective runtime model depends on whether `.env` is allowed to override the code defaults.

## 8. Features Used by the Model

The exact runtime feature names are defined in `ml/feature_extractor.py` and repeated in `models/random_forest_runtime_final_features.json`:

```text
packet_count
byte_count
unique_destination_ports
unique_destination_ips
destination_port_fanout_ratio
connection_rate
syn_rate
icmp_rate
udp_rate
tcp_rate
average_packet_size
observation_window_seconds
packet_rate
bytes_per_second
failed_connection_rate
unanswered_syn_rate
unanswered_syn_ratio
```

### 8.1 How they are computed

The live extractor in `ml/feature_extractor.py` maintains rolling windows keyed by source IP. It tracks:

- packet timestamps
- packet lengths
- protocol labels
- destination IPs
- destination ports
- whether a packet is a SYN-only attempt
- whether it looks like a connection attempt

From that state it computes:

- volume features such as packet and byte counts
- diversity features such as unique destination ports and IPs
- protocol rate features
- failure-related features
- unanswered SYN features

### 8.2 Packet-level vs window-level

Packet-level inputs include:

- packet length
- protocol
- destination IP
- destination port
- SYN-only flag
- RST flag

Window-level features include:

- `packet_count`
- `byte_count`
- `unique_destination_ports`
- `unique_destination_ips`
- `packet_rate`
- `bytes_per_second`
- `connection_rate`
- `syn_rate`
- `failed_connection_rate`
- `unanswered_syn_rate`

### 8.3 Host-level nature

These are not full bidirectional completed-flow features. They are **per-source-host rolling-window features**. That is consistent with the controller’s observability model.

### 8.4 Why `unanswered_syn_rate` matters

This feature was added to improve scan realism.

Scans often do not fail with obvious RST responses. Many filtered scans produce silence. The extractor therefore tracks pending SYN attempts and counts them as unanswered if no reverse response appears within the configured timeout. This helps distinguish:

- ordinary traffic
- explicit failures
- silent probing behavior

### 8.5 What was intentionally excluded

The project intentionally excludes richer offline-only features that are not reproducible from live controller telemetry, including:

- deeper application-layer content
- exact completed-flow summaries that require telemetry the controller does not have
- richer bidirectional timing statistics not recoverable from simple `PacketIn` events

This is one of the main reasons the final project moved toward runtime-generated data.

## 9. Runtime Integration and Hybrid-Mode Proof

### 9.1 Where the model is loaded

The controller creates the ML pipeline in:

- `controller/main.py`

The pipeline loads the model through:

- `ml/model_loader.py`

`load_model()` returns a `ModelBundle` containing:

- the model object
- feature names
- positive labels
- metadata
- source path
- any load error

### 9.2 How inference runs

Inference is performed by:

- `ml/inference.py`

`ModelInferenceEngine.predict()`:

1. converts the current `FeatureSnapshot` into the expected feature vector order
2. runs `predict()`
3. runs `predict_proba()` if available
4. computes a malicious score
5. compares that score against `confidence_threshold`
6. returns an `MLPrediction`

### 9.3 How runtime decisions are made

The orchestration is in:

- `ml/pipeline.py`

The pipeline supports:

- `threshold_only`
- `ml_only`
- `hybrid`

In `ml_only`:

- threshold IDS is bypassed
- the ML path alone determines alerts and, if configured, mitigation

In `hybrid`:

- threshold and ML both run
- threshold alerts remain operationally important
- hybrid correlation events are tracked

### 9.4 How threshold mode works

The threshold IDS in:

- `security/ids.py`

detects:

- packet floods
- SYN floods
- port scans
- host scans
- repeated failed connections

It uses sliding windows and explicit thresholds on host behavior.

### 9.5 How hybrid correlation is tracked

`ml/pipeline.py` maintains:

- pending threshold alerts
- pending ML alerts
- recent prediction state

It emits correlation events with status:

- `agreement`
- `disagreement`
- `threshold_only`
- `ml_only`

Those are recorded by:

- `monitoring/metrics.py`

### 9.6 How the dashboard proves ML is active

The dashboard state in `monitoring/state.py` includes:

- `ml_predictions_total`
- `ml_malicious_predictions_total`
- `ml_benign_predictions_total`
- `ml_alerts_total`
- `hybrid_agreements_total`
- `hybrid_disagreements_total`
- `threshold_only_detections_total`
- `ml_only_detections_total`
- `recent_ml_predictions`
- `recent_hybrid_events`

The ML page in:

- `monitoring/templates/ml_ids.html`

and:

- `monitoring/static/dashboard.js`

renders:

- model loaded status
- prediction totals
- malicious and benign prediction split
- recent prediction table
- hybrid agreement and disagreement counters
- threshold-only and ML-only detection counters

### 9.7 Supervisor-facing proof statement

The strongest way to prove ML is active in hybrid mode is not to point at a block and say "ML must have helped." The stronger proof is:

- `ml_predictions_total` increases
- `recent_predictions` updates even on benign traffic
- `threshold_only` and `ml_only` counters distinguish whether threshold or ML fired independently

So hybrid mode does not hide ML activity. The monitoring layer exposes it directly.

## 10. Evaluation Results

The main evaluation artifact is:

- `models/random_forest_runtime_final_metrics.json`

That file reports:

- `combined_rows = 56843`
- `runtime_training_rows = 793`
- `train_rows = 679`
- `test_rows = 114`
- `group_count = 64`
- `split_mode = grouped`

Classification report:

- accuracy: `1.0`
- benign precision: `1.0`
- benign recall: `1.0`
- benign F1: `1.0`
- malicious precision: `1.0`
- malicious recall: `1.0`
- malicious F1: `1.0`

### How to interpret these metrics carefully

These are strong results, but they should not be overstated.

Limitations of the evaluation:

- the evaluation is still based on the same SDN lab family of traffic
- the test size is only `114` grouped host-window samples
- the topology is small and controlled
- the merged runtime dataset is still built from repeated scenario families
- there is no checked-in external hold-out dataset

So the correct academic interpretation is:

- the model is well aligned with the current lab and current feature space
- the results are promising
- but they do not eliminate the need for caution about generalization

### Evidence from older artifacts

Older artifacts in the repository show the model history more honestly:

- `models/random_forest_ids.runtime.joblib`
  - trained from `cic-collection.parquet`
  - `14` features
  - offline accuracy about `0.9309`
  - less live-compatible

- `models/runtime_scan_aware_20260320.runtime.joblib`
  - `17` features
  - grouped split
  - accuracy `0.5`
  - intermediate scan-aware stage

- `models/live_smoke_collection_model.joblib`
  - grouped split
  - accuracy `0.25`
  - very small smoke dataset

This history is useful in a defense because it shows that the project did not simply obtain high results automatically. Better results came after improving:

- runtime feature realism
- scan-aware features
- runtime data collection
- grouped evaluation

## 11. Limitations

The current ML subsystem is strong for the scope of this project, but it still has clear limitations.

### 11.1 Dataset imbalance

The raw merged runtime dataset is still highly malicious-heavy:

- `54,248` malicious
- `2,595` benign

This creates a risk of an over-eager model if benign diversity is not expanded further.

### 11.2 Runtime observability limits

The controller only sees what reaches the control-plane observation path. That means the ML subsystem cannot use every feature an offline packet-analysis pipeline could use.

### 11.3 Feature drift

If the network topology, service behavior, or traffic mix changes substantially, the runtime-generated model may drift away from the conditions it was trained on.

### 11.4 Mininet realism limits

Mininet is useful and appropriate for a final-year project, but it is still an emulated environment. Timing, contention, and traffic patterns may differ from a production deployment.

### 11.5 False positives and false negatives

Even with strong reported metrics, there is still a risk of:

- false positives on bursty but legitimate traffic
- false negatives on new attack variants or low-volume attacks

### 11.6 Threshold IDS still matters

Threshold IDS remains important because it provides:

- deterministic detection
- explainable policy decisions
- low-latency baseline protection
- a fallback when ML is unavailable or uncertain

This is why the architecture treats ML as an extension rather than as the sole security mechanism.

## 12. Supervisor Q&A Cheat Sheet

### Why Random Forest?

Because the project uses structured, controller-observable runtime features rather than raw packet payloads. Random Forest works well on that type of tabular data, is fast at inference time, and is simple enough to explain and deploy in a final-year SDN project.

### Why not a single decision tree?

A single tree is easier to overfit on repeated lab scenarios. Random Forest is more robust because it averages many trees.

### Why not SVM?

SVM would be harder to tune, harder to explain, and less convenient to export into the lightweight runtime path used in this controller.

### Why not deep learning?

The project does not use raw sequence or payload data. It uses explicit host-window features. Deep learning would add complexity without matching the actual feature design or deployment constraints.

### Why did you not use the CIC dataset directly?

Because the live SDN controller cannot reproduce many offline flow-style features reliably at runtime. The final deployed model needed to be trained on features the controller can actually compute from `PacketIn` telemetry.

### How many rows are in the dataset?

The final merged runtime parquet has **56,843 raw rows**. After runtime host-window aggregation, the model actually trains on **793 host-window samples**.

### How balanced is the dataset?

Raw rows are still heavily skewed toward malicious traffic, but after host-window aggregation the effective training balance improves to **496 malicious** and **297 benign**.

### How did you label the runtime data?

The project used `scripts/set_dataset_label.py` to set live labels and scenario metadata, and the controller recorded those labels together with packet and runtime feature values through `ml/dataset_recorder.py`.

### How do you know the ML model is active in hybrid mode?

Because the dashboard shows prediction totals, recent prediction records, hybrid agreements, threshold-only detections, and ML-only detections. If those counters are changing, the ML subsystem is actively running.

### What are the main risks of bias in the model?

The main risks are:

- attack-heavy raw data
- limited benign diversity
- repeated scenario families
- dependence on Mininet-specific traffic behavior

### What would you improve next?

The next improvement would be to collect more benign runtime data with greater behavioral diversity, preserve grouped evaluation by run, and continue retraining on live-compatible SDN data rather than relying on richer offline-only schemas.

## 13. Final Supervisor-Facing Summary

The machine learning component of this project is a **Random Forest-based IDS extension** designed specifically for the live SDN environment implemented in the repository. It was trained offline using **runtime-generated parquet datasets** collected from the actual Mininet and Ryu lab, then exported into a lightweight pure-Python runtime format so that the controller can perform inference without the full offline training stack.

The final checked-in model, `models/random_forest_runtime_final.joblib`, was trained from `datasets/merged_runtime_dataset.parquet`, which contains **56,843 raw runtime rows** merged from four approved runtime datasets. Those raw rows were converted into **793 host-window training samples** using the same runtime-compatible feature logic that the controller uses online. The final grouped split produced **679 training rows** and **114 test rows**.

The model uses **17 runtime-observable features**, including packet rate, byte rate, destination diversity, failed connection rate, and the newer scan-aware features `unanswered_syn_rate`, `unanswered_syn_ratio`, and `destination_port_fanout_ratio`. These were chosen because they are realistic for controller-observed traffic and are useful for distinguishing benign traffic, scans, and flood behaviors.

Random Forest was chosen because it is robust on structured tabular data, fast at inference time, explainable enough for an academic defense, and easy to export into the lightweight runtime architecture already implemented in the repository. More complex models were possible in theory, but would have been harder to justify, harder to deploy, and less aligned with the project’s goal of a modular, explainable SDN IDS.

The project did not use the downloaded CIC dataset directly as the final deployed training source because the live controller cannot reproduce many richer offline flow features reliably at runtime. Training directly on runtime-generated SDN data therefore gives a more honest and deployment-valid model. This decision is one of the strongest methodological choices in the repository because it aligns the training feature space with the live inference feature space.

The threshold IDS remains the primary baseline, while the ML subsystem provides optional `ml_only` and `hybrid` modes. In hybrid mode, the dashboard exposes prediction counts, recent predictions, and hybrid agreement or disagreement events, so it is possible to prove that the ML model is active rather than idle.
