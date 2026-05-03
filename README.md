# SDN-based Security & Intrusion Detection

This repository provides a modular SDN security testbed built around Mininet and Ryu v4.30. The current implementation includes OpenFlow 1.3 forwarding, static firewall policy, threshold-based IDS, optional ML-assisted IDS, continuous packet capture with preserved alert snapshots, and a lightweight Flask dashboard backed by shared controller state snapshots.

## Documentation

Use these project documents for setup, testing, and report support:

- [playbook.md](playbook.md)
- [sdn_firewall_ids_test_playbook.md](sdn_firewall_ids_test_playbook.md)
- [appendix_recon_findings.md](appendix_recon_findings.md)
- [experiments/README.md](experiments/README.md)

## Repository Layout

```text
.
├── .dockerignore
├── .env.example
├── .gitignore
├── Dockerfile
├── Dockerfile.mininet
├── README.md
├── attacks/
│   ├── dos_flood.sh
│   ├── normal_traffic.sh
│   └── port_scan.sh
├── captures/
│   ├── capture_manager.py
│   └── output/
├── config/
│   └── settings.py
├── controller/
│   ├── app.py
│   ├── events.py
│   └── main.py
├── core/
│   ├── command_queue.py
│   ├── flow_manager.py
│   ├── logging_utils.py
│   ├── packet_parser.py
│   └── state.py
├── datasets/
│   └── ... generated and imported parquet datasets ...
├── docker/
│   └── mininet/
│       └── entrypoint.sh
├── docker-compose.yml
├── experiments/
│   ├── README.md
│   ├── common.py
│   ├── extract_results.py
│   ├── live_ids_replay.py
│   ├── report_sections.md
│   ├── report_table_template.csv
│   ├── results/
│   ├── run_evaluation.py
│   ├── run_evaluation.sh
│   └── run_scenario.sh
├── logs/
├── ml/
│   ├── base.py
│   ├── dataset_recorder.py
│   ├── feature_extractor.py
│   ├── inference.py
│   ├── model_loader.py
│   ├── pipeline.py
│   └── runtime_forest.py
├── models/
│   └── ... trained and portable runtime models ...
├── monitoring/
│   ├── api.py
│   ├── logger.py
│   ├── metrics.py
│   ├── state.py
│   ├── static/
│   │   ├── dashboard.js
│   │   └── styles.css
│   ├── templates/
│   │   ├── alerts.html
│   │   ├── base.html
│   │   ├── blocked_hosts.html
│   │   ├── captures.html
│   │   ├── dashboard.html
│   │   ├── ml_ids.html
│   │   ├── performance.html
│   │   ├── settings.html
│   │   └── traffic.html
│   ├── web.py
│   └── webapp.py
├── requirements-ml.txt
├── requirements.txt
├── runtime/
│   └── ... live state, capture events, and generated datasets ...
├── ryu_apps/
│   └── security_controller.py
├── scripts/
│   ├── collect_runtime_dataset.py
│   ├── export_runtime_dataset.py
│   ├── export_runtime_model.py
│   ├── inspect_dataset.py
│   ├── integration_dashboard_smoke.py
│   ├── integration_security_workflow.py
│   ├── run_topology.sh
│   ├── set_dataset_label.py
│   ├── start_captures.sh
│   ├── stop_captures.sh
│   └── train_random_forest.py
├── security/
│   ├── firewall.py
│   ├── ids.py
│   ├── mitigation.py
│   └── packet_parser.py
├── tests/
│   ├── test_config.py
│   ├── test_dataset_recorder.py
│   ├── test_experiment_extract_results.py
│   ├── test_ids.py
│   ├── test_inspect_dataset.py
│   ├── test_ml_pipeline.py
│   ├── test_monitoring_state.py
│   ├── test_runtime_forest.py
│   └── test_train_random_forest.py
├── topology/
│   └── custom_topology.py
└── traffic/
    └── benign_traffic.sh
```

## Module Responsibilities

- `ryu_apps/`: Ryu entry points. `security_controller.py` is the app started by `ryu-manager`.
- `controller/`: Main Ryu application plus controller state/event helpers.
- `core/`: Shared flow install helpers and packet parsing utilities.
- `security/`: Static and temporary firewall policy logic plus the threshold IDS baseline and mitigation support.
- `monitoring/`: Structured logging, metrics collection, shared dashboard state, Flask API routes, and the web dashboard UI.
- `ml/`: Optional ML-based IDS feature extraction, model loading, inference, and mode-aware orchestration. The threshold IDS remains the primary baseline.
- `captures/`: Continuous rolling packet capture plus preserved forensic snapshots using `tcpdump`.
- `scripts/`: Host-side helpers for starting the topology, managing packet captures, and offline ML model training.
- `config/`: Centralized runtime configuration for thresholds, ports, timeouts, and logging.
- `topology/`: Custom Mininet topology for normal and attack traffic.
- `attacks/`: Reproducible attack helper scripts for flooding and port scanning.
- `traffic/`: Benign traffic generation used for baseline and comparison experiments.
- `experiments/`: Repeatable scenario replay, evaluation automation, CSV/JSON export, and report assets.
- `models/`: Default location for saved offline-trained Random Forest bundles.
- `tests/`: Unit coverage for config, IDS, ML pipeline, monitoring state, dataset tooling, and evaluation extractors.
- `Dockerfile`, `Dockerfile.mininet`, and `docker-compose.yml`: Reproducible controller and lab runtime for the Ryu controller plus an optional Mininet/OVS container.

## How the Modules Fit Together

1. `controller.main.SecurityController` is the active OpenFlow 1.3 Ryu app. It handles switch join/leave events and `PacketIn` processing.
2. `controller.events` maintains datapath registration, MAC learning tables, and host state.
3. `core.packet_parser.PacketParser` converts raw packets into protocol-aware metadata for ARP, IPv4, TCP, UDP, and ICMP.
4. `security.firewall.FirewallPolicy` evaluates each packet against static policy, internal subnet rules, ICMP policy, restricted ports, and temporary source blocks.
5. `core.flow_manager.FlowManager` installs the table-miss rule, learned forwarding flows, and high-priority drop flows that enforce firewall decisions in the switch.
6. `monitoring.logger.StructuredLogger` records concise controller, flow, traffic, and security events with timestamps.
7. `monitoring.state.DashboardStateWriter` writes throttled JSON snapshots that the Flask dashboard can read from a separate process without sharing controller memory directly.
8. `monitoring.webapp` serves the dashboard and `monitoring.api` exposes JSON polling endpoints for the frontend.
9. `ml.pipeline.MLIDSPipeline` optionally adds Random Forest inference on controller-observed rolling-window features without replacing the threshold IDS.
10. `captures.capture_manager.PacketCaptureManager` maintains continuous rolling captures and preserves event-specific packet evidence when alerts fire.
11. `core.command_queue.ControllerCommandQueue` lets the dashboard request analyst actions such as manual unblocking without embedding controller logic in Flask.

## Policy Management Model

This project does not implement a full firewall-rule editor UI. Policy management is intentionally split into two clear layers that are easier to explain and defend in the report:

1. **Configuration-driven baseline policy**
   - Baseline firewall, IDS, ML, capture, and dashboard behavior are defined in [config/settings.py](config/settings.py).
   - Docker and experiment runs can override those values through `.env` or per-run environment variables.
   - This is where you define restricted ports, IDS thresholds, ML mode, capture retention, and mitigation behavior.

2. **Manual analyst actions at runtime**
   - The dashboard is used to observe alerts, inspect captures, and manually release quarantined hosts after review.
   - Quarantines are administrative holds, not self-expiring timers.
   - This keeps the enforcement logic inside the controller while still giving the operator a clear workflow.

In other words: **policy definition is config-driven, and policy operations are analyst-driven**. That framing is a good fit for a final-year project because it keeps the system modular and explainable without pretending to be a full enterprise policy platform.

## Administrative Workflow

The intended operator workflow is:

1. Start the controller, dashboard, and topology.
2. Apply the desired policy mode through `.env`, Docker overrides, or the experiment harness.
3. Observe live alerts, blocked hosts, and packet captures from the dashboard.
4. Review preserved capture evidence for suspicious hosts.
5. Manually unblock a quarantined host from the dashboard only after analysis.

For report wording, you can describe this as:

> The system supports policy management through centralized configuration and analyst-supervised runtime actions. Static policy, IDS thresholds, ML mode, and capture behavior are configured centrally, while the operator supervises detection outcomes, forensic evidence, and manual host release.

## Runtime Notes

- Python target: `3.8`
- Controller framework: `Ryu v4.30`
- The repository now includes a project `Dockerfile` that stays close to the required Alpine-based Ryu image while copying in the modular controller code and enabling packet capture support through `tcpdump`.
- The dashboard runs as a separate Flask service by default, which is safer than embedding a web server inside the Ryu process.
- No extra Python package has been introduced beyond what is already required by the provided Ryu build pattern.
- Allowed per-packet traffic logs are disabled by default to keep the controller output focused on flow installs, alerts, and block events. Set `SDN_LOG_ALLOWED_TRAFFIC=true` if you need full packet-level allow tracing.
- The ML IDS path is optional and disabled by default. If the configured model file is missing, the controller falls back cleanly to threshold-based IDS behavior.

## Docker Usage

Build the controller image:

```bash
docker build -t sdn-security-controller .
```

Run the controller container directly:

```bash
docker run --rm \
  -p 6633:6633 \
  -v "$(pwd)/logs:/ryu-apps/logs" \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  sdn-security-controller
```

Or use Compose:

```bash
docker compose up --build
```

The default container command starts:

```bash
ryu-manager controller.main
```

## Suggested Run Flow

Build both images:

```bash
docker compose build
```

Compose also reads project-level values from `.env`. This workspace is configured to
start the controller in `hybrid` ML mode by default using the portable runtime model:

```dotenv
SDN_ML_ENABLED=true
SDN_IDS_MODE=hybrid
SDN_ML_MODE=hybrid
SDN_ML_HYBRID_POLICY=layered_consensus
SDN_ML_MODEL_PATH=models/random_forest_runtime_final.joblib
SDN_ML_ANOMALY_MODEL_PATH=models/isolation_forest_benign_heavy_20260417b.joblib
SDN_ML_INFERENCE_MODE=combined
SDN_ML_FEATURE_WINDOW_SECONDS=3
SDN_ML_CONFIDENCE_THRESHOLD=0.65
SDN_ML_MITIGATION_THRESHOLD=0.80
```

Start the controller, dashboard, and Mininet containers:

```bash
docker compose up -d controller dashboard mininet
```

If `6633` is already in use on your machine, override the host port:

```bash
SDN_OPENFLOW_PORT_HOST=16633 SDN_DASHBOARD_PORT_HOST=18080 docker compose up -d controller dashboard mininet
```

If you want to temporarily return to threshold-only mode for a comparison run, override the
ML environment at launch time:

```bash
SDN_ML_ENABLED=false SDN_IDS_MODE=threshold docker compose up -d --force-recreate controller dashboard
```

Open the monitoring UI:

```text
http://127.0.0.1:8080/sdn-security
```

Launch the multi-switch topology inside the Mininet container:

```bash
./scripts/run_topology.sh
```

From the Mininet CLI, run baseline or attack traffic:

```text
mininet> h1 sh /workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80
mininet> h4 sh /workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.5 8080
mininet> h3 sh /workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2
mininet> h3 sh /workspace/ryu-apps/attacks/dos_flood.sh 10.0.0.2 80 300
```

Start and stop manual packet-capture sessions from another terminal:

```bash
./scripts/start_captures.sh benign
./scripts/stop_captures.sh
```

Continuous rolling capture also runs in the background when the topology starts. The
manual capture scripts are still useful when you want a named capture session for a
specific scenario in addition to the always-on forensic capture.

## ML IDS Extension

The project now includes an optional ML-based IDS extension that sits alongside the threshold IDS instead of replacing it.

- `threshold_only`: only the threshold IDS is active.
- `ml_only`: only the ML path is used, but if the model file is unavailable the controller falls back safely to threshold IDS.
- `hybrid`: threshold detections remain authoritative, while ML adds suspicion scores, separate `event=ml` logs, and optional mitigation for high-confidence predictions.

The default hybrid policy is `layered_consensus`, which means:

- threshold detections trigger immediate mitigation
- threshold-near-miss recon can be elevated into blocking when classifier confidence and supporting context are strong enough
- anomaly-only outcomes remain alert/watchlist-oriented unless you explicitly enable the narrow anomaly-only block path
- you can still force a more permissive ML-led posture with `SDN_ML_HYBRID_POLICY=high_confidence_block`

For consistent stealth-scan validation from Mininet, prefer `-Pn` so Nmap does not stop at host discovery before the TCP scan phase:

```text
mininet> h1 nmap -Pn -sS -T2 -f --randomize-host 10.0.0.2
```

### Offline Training

Use a separate offline environment for training and evaluation:

```bash
python3 -m venv .venv-ml
. .venv-ml/bin/activate
pip install -r requirements-ml.txt
```

Expected dataset placement:

- `datasets/cicids2018.parquet` is the preferred default
- or another CICIDS2018-style parquet path passed with `--dataset`

Train the current runtime-compatible Random Forest model from the merged runtime dataset:

```bash
python3 scripts/train_random_forest.py \
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

If you want to merge the approved runtime parquet files before training, run:

```bash
python3 merge_runtime_datasets.py \
  --output datasets/merged_runtime_dataset.parquet
```

Inspect a parquet file or a whole dataset folder before training:

```bash
python3 scripts/inspect_dataset.py archive\\(1\\)
```

The inspector reports which live-compatible fields are present or missing for
each parquet file and exits non-zero if the dataset is not suitable for live
SDN ML training.

Generate a compatible dataset directly from this SDN lab:

```bash
SDN_ML_DATASET_RECORDING_ENABLED=true docker compose up -d --force-recreate controller
python3 scripts/set_dataset_label.py benign --scenario baseline_http
python3 scripts/set_dataset_label.py malicious --scenario port_scan
python3 scripts/set_dataset_label.py --clear
```

The controller appends JSONL rows to `runtime/ml_dataset.jsonl` using live
controller-observed fields such as `Src IP`, `Dst IP`, `Dst Port`, `Protocol`,
`Timestamp`, `Label`, `Total Packets`, `Total Bytes`, `SYN Flag Count`, and
`RST Flag Count`. Export that recording to parquet with:

```bash
python3 scripts/export_runtime_dataset.py \
  --input runtime/ml_dataset.jsonl \
  --output datasets/runtime_lab_dataset.parquet
```

That parquet is live-compatible by construction because it originates from the
same `PacketIn` telemetry and rolling-window feature space used by the
controller.

For a larger one-command collection pass across several benign, scan, and DoS
scenarios, use:

```bash
python3 scripts/collect_runtime_dataset.py --restore-controller
```

This collector:
- recreates the controller with dataset recording enabled
- labels and runs multiple benign HTTP scenarios
- labels and runs a port scan, SYN flood, and closed-port failed-connection flood
- exports the final JSONL recording to parquet
- verifies the parquet schema with `inspect_dataset.py`

## Integration Validation

Beyond the unit tests in `tests/`, the repository now includes two lightweight
end-to-end validation scripts for demo readiness:

1. Dashboard and API smoke test:

```bash
python3 scripts/integration_dashboard_smoke.py
```

This checks that the main monitoring endpoints respond and expose the expected
dashboard sections.

2. Security workflow validation:

```bash
python3 scripts/integration_security_workflow.py
```

This runs a real attack workflow against the live lab and verifies that:
- a malicious host is quarantined
- a preserved capture snapshot appears
- the dashboard blocked-hosts API updates
- manual unblock works through the dashboard API path

These scripts are intended as practical integration checks before demos,
recordings, or evaluation runs.

The trainer writes a pickle-compatible model bundle so the live controller can
load it without pulling the offline training stack into the runtime image.

The trainer now refuses to build a runtime model by default if the parquet
schema does not contain the columns needed to approximate live SDN telemetry:

- source IP
- destination IP
- destination port
- protocol
- timestamp

This is deliberate. A dataset that lacks those fields may still produce good
offline accuracy while failing completely in the live controller. Use
`--allow-degraded-training` only for exploratory offline experiments, not for
runtime evaluation.

### Runtime Feature Mapping

The runtime model only consumes features that the controller can observe or approximate from short rolling windows:

- packet count
- byte count
- unique destination ports
- unique destination IPs
- connection rate
- SYN rate
- ICMP rate
- UDP rate
- TCP rate
- average packet size
- observation window duration
- packet rate and bytes per second
- failed connection rate approximation

Features commonly present in CIC datasets but not fully reproducible from live `PacketIn` telemetry are intentionally excluded or approximated. These include rich bidirectional timing statistics, exact completed-flow features, and deeper application-layer signals.

Dataset recommendation for this project:

- Preferred primary ML dataset: CICIDS2018-style flow data exported to parquet with `Src IP`, `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`, and `Label` preserved.
- Acceptable fallback: your own Mininet/Ryu-generated labeled flow dataset from this exact lab.
- Not recommended as the primary runtime-training dataset: NSL-KDD, because its feature space is older and does not align cleanly with controller-observed host-window statistics.
- Not suitable for live-compatible training without overrides: parquet files that only contain aggregate flow summaries such as `Flow Duration`, `Flow Bytes/s`, and `Flow Packets/s` but omit source/destination identifiers.

### Academic Notes and Limitations

- Random Forest is a suitable baseline because it is explainable, fast at inference time, and performs well on tabular network statistics without requiring GPU infrastructure.
- CICIDS2018 is preferred over generic flow-summary parquet because it preserves identifiers and timing needed to align offline features with live SDN controller telemetry.
- Some CIC parquet exports only contain aggregate flow summaries and drop source/destination identifiers. Those exports are not sufficient for a realistic runtime model, so the trainer now rejects them by default.
- CIC parquet datasets often contain richer flow-level attributes than a live SDN controller can observe. The offline trainer therefore maps or approximates only the subset that is realistic to compute at runtime.
- False positives, false negatives, feature drift, and dataset mismatch remain important limitations for the report.
- Packet captures in `captures/` are useful for validating ML-triggered events and for future dataset generation or feature sanity-checking against controller-observed statistics.

## Mininet and Docker

The controller is containerized by default and matches the required `python:3.8-alpine` plus Ryu `v4.30` build pattern.

Mininet is still kept in a separate container. This is deliberate:

- Mininet and Open vSwitch depend on privileged kernel networking features.
- Mixing Mininet, OVS, and the controller into a single minimal Alpine image makes reproducibility worse, not better.
- The cleaner approach is to run the controller in the required Alpine image and run Mininet in a separate privileged lab container.

The included `mininet` Compose service now gives you that second container while preserving the verified controller runtime.

Inside Docker, the topology defaults to `--switch-mode user` so it can run even when the host does not expose the kernel `openvswitch` module into the container. On a native Linux host with kernel OVS support, you can switch to `--switch-mode kernel`.

## End-to-End Run On Your Machine

1. Make sure Docker Engine and Docker Compose are installed on your Linux host.
2. From the project root, build the images:

```bash
docker compose build
```

3. Start the background services:

```bash
docker compose up -d controller dashboard mininet
```

If the OpenFlow host port is busy, use a different published port:

```bash
SDN_OPENFLOW_PORT_HOST=16633 SDN_DASHBOARD_PORT_HOST=18080 docker compose up -d controller dashboard mininet
```

4. Check that both containers are running:

```bash
docker compose ps
```

The dashboard is then available at:

```text
http://127.0.0.1:8080/sdn-security
```

5. Start the Mininet topology:

```bash
./scripts/run_topology.sh
```

6. In the Mininet CLI, generate traffic:

```text
mininet> pingall
mininet> h1 sh /workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80
mininet> h3 sh /workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2
```

7. When finished, stop the lab:

```bash
docker compose down
```

## Dependency Notes

`requirements.txt` only pins the local Python-side versions that must stay aligned with the Dockerfile. Ryu itself should continue to be installed from the pinned `v4.30` git tag in the Docker image.

`requirements-ml.txt` is offline-only and is intended for training or evaluation environments, not for the live controller container.
