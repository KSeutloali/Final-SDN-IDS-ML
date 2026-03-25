# Supervisor Demo Brief

## Purpose of This Document

This document is a detailed explanation of the SDN-Based Security & Intrusion
Detection System in this repository. It is written as a study and presentation
aid for a live supervisor demonstration.

It explains:

- what the system is trying to achieve
- how the architecture is organized
- how packets move through the system
- what each major module and file is responsible for
- how the Docker environment is structured
- how the threshold IDS works
- how the ML IDS works
- how the training data was collected
- how the model was trained and deployed
- why the final deployed model was not based directly on the downloaded CIC data

The most important message to communicate during the demonstration is this:

> This is a modular SDN security system where a centralized Ryu controller
> observes traffic, applies threshold-based intrusion detection, optionally runs
> machine-learning-based inference, enforces quarantines through OpenFlow rules,
> preserves packet evidence, and exposes the whole workflow through a live
> dashboard.

## 1. Project Goal

The goal of the project is to build a modular Software Defined Networking
security testbed that can:

- monitor network traffic centrally using an SDN controller
- detect suspicious behavior such as scans and floods
- enforce mitigation dynamically through OpenFlow flow rules
- preserve packet-level evidence for later analysis
- present the full state of the system through a live monitoring dashboard

This project is intentionally designed for a final-year academic setting, so the
emphasis is on:

- modularity
- explainability
- repeatable demonstrations
- clear separation of responsibilities
- realistic live behavior rather than only offline accuracy

## 2. High-Level Architecture

The system is built from five main parts:

1. `Mininet + Open vSwitch data plane`
2. `Ryu controller control plane`
3. `Threshold IDS baseline`
4. `Optional ML IDS extension`
5. `Flask monitoring dashboard and packet-forensics layer`

The main control logic runs inside the Ryu controller. The controller receives
OpenFlow events from the switches, parses packets, updates state, runs IDS
logic, decides whether to forward or block traffic, installs flow rules, and
publishes monitoring state.

The monitoring dashboard is not embedded inside the controller. It runs as a
separate Flask process and reads shared runtime state snapshots written by the
controller.

The packet capture subsystem runs continuously and preserves forensic snapshots
when alerts are raised.

### 2.1 Implementation evidence

From [controller/main.py](controller/main.py) lines 85 to 131:

```python
restored_mode = self.ids_mode_store.current_mode(
    default=self.ml_pipeline.status().get("selected_mode_api", "threshold"),
)
restore_result = self.ml_pipeline.set_mode(restored_mode)
self._persist_ids_mode_state(
    requested_by="controller_startup",
    previous_mode=restore_result.get("previous_mode_api"),
)
...
self._dashboard_heartbeat = hub.spawn(self._dashboard_heartbeat_loop)
self._publish_dashboard_state(force=True)
```

Academic reasoning:

- This is direct implementation evidence that the architecture is integrated and
  stateful rather than a collection of disconnected scripts.
- It supports the claim that IDS mode, monitoring, and controller startup are
  part of one coherent runtime system.
- In academic terms, this improves internal consistency because the controller,
  dashboard state, and IDS mode restoration are all initialized through a single
  controlled sequence.

## 3. End-to-End Runtime Flow

The easiest way to explain the runtime behavior is as a sequence.

### 3.1 Normal forwarding path

1. A host sends a packet.
2. A switch receives the packet.
3. If the switch does not already have a suitable forwarding rule, it generates
   an OpenFlow `PacketIn`.
4. The Ryu controller receives the `PacketIn`.
5. The controller parses the packet into structured metadata.
6. The controller updates learning state and metrics.
7. The threshold IDS examines the packet and rolling traffic windows.
8. If ML is enabled, the ML pipeline also updates rolling features and may run
   inference.
9. The firewall/policy engine decides whether the traffic should be forwarded,
   blocked, or whether the source should be quarantined.
10. The flow manager installs the relevant OpenFlow rule.
11. The controller writes updated monitoring state for the dashboard.

### 3.2 Detection and mitigation path

When malicious behavior is detected:

1. The threshold IDS and/or ML pipeline raises an alert.
2. The mitigation service marks the source host as quarantined.
3. The flow manager installs high-priority source-drop flows.
4. The capture manager preserves packet evidence from the rolling capture ring.
5. The dashboard updates its alerts, blocked-host, and capture views.

### 3.3 Analyst release path

When the operator unblocks a quarantined host:

1. The dashboard sends an unblock request to the backend API.
2. The backend writes a command into the controller command queue.
3. The controller consumes that command.
4. The mitigation service removes the quarantine state.
5. The flow manager removes the relevant source-drop flows.
6. The dashboard refreshes and the host disappears from the blocked-host list.

This separation matters because it keeps the dashboard from directly modifying
controller memory. The controller remains authoritative.

## 4. Repository Structure and Module Map

This section explains the major folders and why they exist.

### 4.1 `config/`

The main configuration file is:

- `config/settings.py`

This is the central configuration source for:

- controller ports
- OpenFlow flow priorities
- forwarding timeouts
- firewall defaults
- threshold IDS windows and thresholds
- mitigation configuration
- capture configuration
- dashboard configuration
- ML configuration

If someone asks where system behavior is defined, the answer starts here.

### 4.2 `controller/`

The controller package contains the main SDN application logic.

- `controller/main.py`
- `controller/events.py`
- `controller/app.py`

#### `controller/main.py`

This is the main Ryu application entry point. It creates the
`SecurityController` and wires together:

- packet parsing
- switch and host state
- threshold IDS
- ML pipeline
- firewall decisions
- mitigation logic
- flow installation and removal
- metrics collection
- dashboard state publishing
- dataset recording
- packet capture snapshot preservation

This is the heart of the whole system.

#### `controller/events.py`

This module is responsible for event and state handling related to:

- datapath registration
- switch connect/disconnect
- host learning
- MAC-to-port learning
- host inventory cleanup when switches disappear

An important detail is that host inventory only counts host-facing access ports,
not inter-switch transit observations. That was important to prevent fake
"learned hosts" from appearing on the dashboard.

### 4.3 `core/`

This package contains reusable lower-level helpers.

- `core/packet_parser.py`
- `core/flow_manager.py`
- `core/command_queue.py`
- `core/state.py`
- `core/logging_utils.py`
- `core/ids_mode.py`

#### `core/packet_parser.py`

Parses raw packets into structured fields such as:

- source and destination IP
- ports
- transport protocol
- TCP flags
- packet size
- timestamp

The rest of the controller depends on this normalized view of traffic.

#### `core/flow_manager.py`

Handles OpenFlow 1.3 rule installation and removal.

It installs:

- the table-miss rule
- learned forwarding flows
- packet block flows
- restricted service blocks
- static source blocks
- dynamic quarantine/source-drop flows

This module is critical because enforcement in an SDN system is ultimately
realized through flow rules in the switch.

#### `core/command_queue.py`

Implements a filesystem-backed command queue used for runtime actions such as:

- manual unblock
- live IDS mode switching

This decouples the dashboard from the controller process and preserves modular
boundaries.

#### `core/ids_mode.py`

Normalizes IDS mode naming and maps between public dashboard/API mode names and
internal controller mode names.

### 4.4 `security/`

This package contains the rule-based security logic.

- `security/ids.py`
- `security/firewall.py`
- `security/mitigation.py`
- `security/packet_parser.py`

#### `security/ids.py`

This is the threshold-based IDS baseline.

It tracks rolling windows and detects:

- packet floods
- SYN floods
- port scans
- host scans
- repeated failed connections

This module is the primary baseline because it is deterministic and easy to
explain.

#### `security/firewall.py`

This is the policy evaluation layer.

It decides whether traffic:

- is allowed
- is blocked by static firewall policy
- is blocked because the destination service is restricted
- is blocked because the source is quarantined

It also defines the quarantine record model used by mitigation.

#### `security/mitigation.py`

This module translates detection outcomes into enforcement actions.

In this project:

- suspicious hosts are quarantined indefinitely
- there is no timer-based auto-unblock
- manual operator release is required

That matches the project’s analyst-supervised security workflow.

### 4.5 `monitoring/`

This package powers the dashboard.

- `monitoring/webapp.py`
- `monitoring/api.py`
- `monitoring/state.py`
- `monitoring/metrics.py`
- `monitoring/logger.py`
- `monitoring/web.py`
- `monitoring/static/`
- `monitoring/templates/`

#### `monitoring/state.py`

This builds the shared state snapshot written to
`runtime/dashboard_state.json`. It is the bridge between the controller and the
dashboard.

The dashboard state includes:

- summary counters
- switch state
- learned hosts
- blocked hosts
- security events
- capture events
- ML status
- IDS mode state
- time-series data for graphs

#### `monitoring/api.py`

This provides the JSON endpoints used by the dashboard frontend.

Key capabilities:

- live dashboard data
- alerts
- blocked-host list
- capture list
- ML status
- settings and mode state
- unblock requests
- IDS mode switch requests

#### `monitoring/webapp.py`

This is the Flask entry point for the web application.

The UI pages include:

- Overview
- Traffic Analytics
- Security Alerts
- Blocked Hosts
- Controller Performance
- Packet Capture
- ML IDS
- Settings

#### `monitoring/static/dashboard.js`

This is the frontend polling and UI update logic. The dashboard is polling-based
rather than websocket-based. That keeps the design lightweight and easier to
defend in an academic project.

### 4.6 `captures/`

- `captures/capture_manager.py`

This module manages:

- continuous rolling packet capture
- packet capture worker health
- preserved alert snapshots
- capture metadata

The project uses `tcpdump`-based ring-buffer capture and then preserves
event-specific packet files when alerts occur.

This is one of the parts that makes the project stronger than a simple "detect
and block" demonstration, because it also supports evidence and analysis.

### 4.7 `topology/`

- `topology/custom_topology.py`

This defines the Mininet lab. It also:

- starts host services
- disables offloading where needed
- launches capture workers
- writes Mininet runtime state

This means the topology module is not just a diagram on paper; it is also the
operational starting point of the live lab.

### 4.8 `ml/`

This package contains the optional machine learning subsystem.

- `ml/feature_extractor.py`
- `ml/inference.py`
- `ml/model_loader.py`
- `ml/pipeline.py`
- `ml/runtime_forest.py`
- `ml/dataset_recorder.py`
- `ml/base.py`

This subsystem is explained in detail in a dedicated section below because it is
the most technically rich part of the project.

### 4.9 `scripts/`

This folder contains operational and training scripts.

Important scripts include:

- `scripts/run_topology.sh`
- `scripts/collect_runtime_dataset.py`
- `scripts/set_dataset_label.py`
- `scripts/export_runtime_dataset.py`
- `scripts/train_random_forest.py`
- `scripts/export_runtime_model.py`
- `scripts/integration_dashboard_smoke.py`
- `scripts/integration_security_workflow.py`

These scripts are important because they make the project repeatable. They are
part of the engineering quality of the system, not just convenience.

### 4.10 `attacks/` and `traffic/`

- `attacks/port_scan.sh`
- `attacks/dos_flood.sh`
- `traffic/benign_traffic.sh`

These are reproducible traffic generators used in:

- live demonstrations
- dataset collection
- validation
- evaluation

### 4.11 `models/`, `datasets/`, and `runtime/`

These folders represent the model and data lifecycle.

- `models/`: trained model bundles and portable runtime model files
- `datasets/`: exported Parquet training datasets
- `runtime/`: live state snapshots, JSONL training rows, capture event streams,
  and other runtime artifacts

## 5. The Mininet Topology

The live lab consists of five hosts and three switches.

### Hosts

- `h1` = normal client, `10.0.0.1`
- `h2` = main server/web service, `10.0.0.2`
- `h3` = attacker, `10.0.0.3`
- `h4` = additional client, `10.0.0.4`
- `h5` = secondary/backup service host, `10.0.0.5`

### Switches

- `s1`
- `s2`
- `s3`

### Why this topology is useful

It is small enough to explain during a demo, but large enough to show:

- normal client/server traffic
- attacker behavior
- multi-switch forwarding
- different server targets
- centralized control from a single Ryu controller

## 6. The Docker Environment

The project is containerized so the controller, dashboard, and lab environment
are reproducible.

### 6.1 `docker-compose.yml`

The compose file defines three services:

#### `controller`

Runs the Ryu controller. It is built from `Dockerfile`.

Key properties:

- exposes the OpenFlow port
- mounts the repository into the container
- accepts ML and dataset-related environment variables
- runs with `NET_ADMIN` and `NET_RAW` capabilities for capture support

#### `dashboard`

Runs the Flask web application using the same image as the controller but with a
different command:

- `python -m monitoring.webapp`

This is a good design choice because it avoids embedding web serving inside the
controller process.

#### `mininet`

Runs the Mininet/Open vSwitch environment from `Dockerfile.mininet`.

It is:

- privileged
- interactive
- equipped with network tools such as `nmap`, `hping3`, `tcpdump`, and Mininet

### 6.2 `Dockerfile`

This file builds the controller/dashboard image.

Key points:

- base image: `python:3.8-alpine`
- clones and installs `Ryu v4.30`
- installs the project Python requirements
- includes `tcpdump`
- sets `PYTHONPATH=/ryu-apps`

This container is designed to stay relatively lightweight.

### 6.3 `Dockerfile.mininet`

This builds the data-plane lab container.

Key points:

- base image: `ubuntu:22.04`
- installs Mininet
- installs Open vSwitch
- installs `nmap`
- installs `hping3`
- installs `tcpdump`

This image is intentionally heavier because it needs lab and network emulation
tooling.

### 6.4 Why the split is important

The split between controller and Mininet improves:

- modularity
- clarity
- reproducibility
- explainability

The controller image remains focused on control-plane logic, while the Mininet
image provides the data-plane environment and attack tooling.

### 6.5 Implementation evidence

From [docker-compose.yml](docker-compose.yml) lines 1 to 67:

```yaml
services:
  controller:
    build:
      context: .
      dockerfile: Dockerfile
...
  dashboard:
    command: ["python", "-m", "monitoring.webapp"]
...
  mininet:
    dockerfile: Dockerfile.mininet
    privileged: true
```

Academic reasoning:

- This is concrete evidence that the project separates the control plane, the
  presentation layer, and the emulated data plane into distinct services.
- That supports claims of modularity and reproducibility. Each service has a
  clear role and can be reasoned about independently.
- This also strengthens the engineering argument that the dashboard is not
  embedded inside the controller, which reduces coupling and keeps the design
  easier to defend.

## 7. Configuration Model

The system is designed around centralized configuration plus runtime analyst
actions.

### 7.1 Centralized baseline policy

Most baseline behavior is defined in `config/settings.py`, including:

- OpenFlow priorities
- flow timeouts
- firewall policy
- IDS thresholds
- mitigation behavior
- dashboard behavior
- capture settings
- ML settings

### 7.2 Runtime analyst actions

The dashboard supports runtime operational actions such as:

- viewing alerts
- reviewing captures
- switching IDS mode
- manually unblocking quarantined hosts

This is why the project can truthfully say:

> Policy definition is config-driven, while runtime operations are
> analyst-driven.

## 8. Threshold IDS Design

The threshold IDS is the primary baseline and the most reliable enforcement
mechanism in the project.

### 8.1 What it detects

The baseline IDS detects:

- packet floods
- SYN floods
- port scans
- host scans
- failed-connection abuse

### 8.2 How it works

It uses rolling time windows per source host and counts event patterns such as:

- packets per time window
- SYN-only packets
- unique destination ports
- unique destination hosts
- repeated failed connections

Because this logic is rule-based and directly tied to observable traffic, it is:

- explainable
- deterministic
- easy to justify academically
- reliable during live demos

### 8.3 Why it remains the baseline

The threshold IDS remains the primary baseline because:

- it is transparent
- it is deterministic
- it is easier to validate
- it does not depend on model generalization

The ML subsystem does not replace this. It augments it.

## 9. Firewall and Mitigation Model

### 9.1 Firewall

The firewall evaluates each packet against:

- internal subnet rules
- ARP allowance
- ICMP allowance
- default IPv4 policy
- restricted TCP/UDP services
- static blocked sources
- quarantine state

### 9.2 Quarantine

When a host is classified as suspicious:

- the source is quarantined
- high-priority source-drop flows are installed
- the host remains blocked indefinitely

This system intentionally does not auto-release suspicious hosts. That is a
deliberate security workflow choice.

### 9.3 Manual release

Release is an analyst action:

- the user clicks unblock on the dashboard
- the dashboard enqueues a command
- the controller removes the block state and flows

That is a safer and more explainable workflow than an automatic timer.

## 10. Packet Capture and Forensics

One of the stronger features of the system is that it does not only detect and
block. It also preserves evidence.

### 10.1 Continuous capture

The capture subsystem runs rolling ring-buffer captures on selected interfaces.

Default interfaces include:

- `h1-eth0`
- `h3-eth0`
- `h2-eth0`
- `s2-eth3`

This gives visibility into:

- attacker-side traffic
- server-side traffic
- central switch path traffic

### 10.2 Preserved snapshots

When an alert fires, the capture manager preserves a snapshot from the rolling
ring files. This gives the analyst a focused forensic bundle around the event.

### 10.3 Why this matters

It allows the demo to show:

- that an alert happened
- what packets actually caused it
- that the system can support post-incident analysis

This is a major improvement over a dashboard that only shows counters.

## 11. The ML IDS: Design Philosophy

The ML subsystem is intentionally optional and secondary.

Its job is not to replace the threshold IDS. Its job is to add:

- probabilistic classification
- broader pattern recognition
- hybrid agreement/disagreement tracking
- an academic ML component that is still grounded in the live system

The design philosophy is:

1. only use features that the controller can actually compute in real time
2. keep the live runtime lightweight
3. separate offline training from online inference
4. preserve the threshold baseline as the primary enforcement path

## 12. Runtime ML Feature Extraction

The live feature extraction logic is in `ml/feature_extractor.py`.

The extractor builds short rolling-window, per-source-host features from
controller-observed packets.

### 12.1 Runtime feature set

The runtime feature names are:

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

### 12.2 Why these features were chosen

These features were chosen because they are realistically available to the SDN
controller.

The controller can observe:

- packet timing
- packet sizes
- protocols
- SYN-only behavior
- destination IP and port diversity
- presence or absence of response behavior

These are all properties that can be extracted honestly from live traffic seen
by the controller.

### 12.3 Why `unanswered_syn_rate` was important

This feature was added to improve scan detection.

Many scans, especially filtered scans, do not produce clean `RST` responses.
That means a scan may not look like a "failed connection" in the classic sense.
Instead, it looks like:

- many SYN attempts
- spread across many ports
- with little or no successful response

`unanswered_syn_rate` and `unanswered_syn_ratio` capture exactly that behavior.

This was one of the most important improvements to make the ML system better at
recognizing port scans rather than mainly floods.

### 12.4 Implementation evidence

From [ml/feature_extractor.py](ml/feature_extractor.py) lines 1 to 5 and 12 to
29:

```python
"""Live feature extraction for the optional ML-based IDS path.

The controller cannot reproduce every flow feature available in offline datasets
such as CIC. This module therefore focuses on statistics that are realistic to
compute from controller-observed packets and short rolling windows.
"""

RUNTIME_FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "unique_destination_ports",
    "unique_destination_ips",
    "destination_port_fanout_ratio",
    ...
    "failed_connection_rate",
    "unanswered_syn_rate",
    "unanswered_syn_ratio",
)
```

From [ml/feature_extractor.py](ml/feature_extractor.py) lines 153 to 184:

```python
unanswered_count = float(
    len(unanswered_window) + int(self.pending_attempt_counts.get(src_ip, 0))
)
destination_port_fanout_ratio = (
    unique_destination_ports / connection_attempts
    if connection_attempts
    else 0.0
)
unanswered_syn_ratio = (
    min(1.0, unanswered_count / syn_count)
    if syn_count
    else 0.0
)
...
"unanswered_syn_rate": unanswered_count / observation_window_seconds,
"unanswered_syn_ratio": unanswered_syn_ratio,
```

Academic reasoning:

- These lines directly support the methodological claim that the feature space
  was engineered around deployment-time observability, not around whichever
  offline features happened to be available.
- They also support the argument that scan detection required new silent-scan
  features rather than relying only on explicit failure responses such as RSTs.
- In research terms, this is a validity-driven feature-engineering decision.

## 13. Runtime Inference

Runtime inference is handled by:

- `ml/inference.py`
- `ml/model_loader.py`
- `ml/pipeline.py`

### 13.1 `ml/model_loader.py`

Loads a serialized model bundle from disk.

The model bundle includes:

- the model itself
- feature names
- positive-label definitions
- metadata such as training information

### 13.2 `ml/inference.py`

This converts a feature snapshot into a prediction:

- it builds the feature vector in the correct feature order
- it obtains the predicted label
- it obtains a malicious probability if available
- it compares the score with the configured thresholds

### 13.3 `ml/pipeline.py`

This is the orchestration layer.

It handles:

- feature extraction
- inference timing
- suppression of repeated alerts
- ML alert generation
- hybrid correlation with threshold alerts
- IDS mode behavior

## 14. IDS Modes

The project supports three IDS modes:

- `threshold`
- `ml`
- `hybrid`

### 14.1 Threshold mode

Only the threshold IDS is used for detection and mitigation.

This is the safest and most reliable demo mode.

### 14.2 ML mode

Only the ML path is used for detection decisions.

This is useful to demonstrate the model itself, but it is less dependable than
threshold mode because it depends on model quality and calibration.

### 14.3 Hybrid mode

Both threshold and ML run together.

This is the most academically interesting mode because it allows the system to
track:

- threshold-only detections
- ml-only detections
- agreements
- disagreements

Hybrid mode is often the best presentation mode because it preserves the
reliability of threshold IDS while still showcasing ML.

## 15. Why the Runtime Controller Uses a Portable Random Forest

The live controller container is intentionally kept lightweight. It does not
depend on full scikit-learn for runtime inference.

The project solves this by exporting the trained sklearn model into a portable
Python representation in `ml/runtime_forest.py`.

### 15.1 What gets exported

A trained Random Forest is converted into:

- class labels
- a list of decision trees
- each tree’s split arrays
- each tree’s thresholds
- each leaf’s class counts

### 15.2 Why this is useful

This means:

- the controller can load the model with plain Python
- the controller image stays lighter
- the runtime stack is simpler and easier to deploy
- the inference path is still deterministic and reproducible

This is a strong architectural point for the demo because it shows that the
project separates offline ML engineering from online SDN operation cleanly.

### 15.3 Implementation evidence

From [ml/runtime_forest.py](ml/runtime_forest.py) lines 1 to 6:

```python
"""Portable Random Forest runtime helpers for controller-side inference.

The live controller container intentionally stays lightweight and does not
install the full offline training stack. This module provides a small
pickle-friendly representation of a fitted scikit-learn Random Forest so the
controller can perform inference without importing sklearn.
"""
```

From [ml/runtime_forest.py](ml/runtime_forest.py) lines 89 to 111:

```python
def export_random_forest_model(classifier):
    """Convert a fitted sklearn RandomForestClassifier into a portable model."""
    ...
    return RuntimeRandomForestModel(classes_=classes, trees=trees)
```

Academic reasoning:

- These lines provide direct evidence that the runtime controller is intentionally
  deployment-oriented rather than training-oriented.
- This supports a strong systems argument: training complexity is kept offline,
  while runtime inference is simplified for stability, reproducibility, and
  operational clarity.

## 16. How Training Data Was Collected

This is one of the most important parts of the project story.

The final deployed model was trained primarily on runtime-compatible data
collected from the actual SDN lab rather than relying directly on an external
downloaded dataset.

### 16.1 Why collect runtime data?

Because the deployed controller sees a very specific view of traffic:

- controller-observed packets
- short host windows
- SDN lab traffic patterns
- the timing behavior of this specific Mininet environment

If the training data does not match that runtime view, the model can perform
poorly live even if it looks good offline.

### 16.2 How recording works

The runtime recorder in `ml/dataset_recorder.py` writes labeled JSONL rows while
the controller is running.

Each row includes:

- source IP
- destination IP
- destination port
- protocol
- packet-level metadata
- runtime-derived feature values
- scenario metadata
- the current label, such as `benign` or `malicious`

### 16.3 How labels are applied

Labels are controlled using `scripts/set_dataset_label.py`.

Before a scenario is run, a label file is written. The recorder reads that
label, so the traffic being observed during that window is tagged with:

- label
- scenario name
- scenario family
- run ID
- collection ID
- notes

### 16.4 How scenarios are automated

`scripts/collect_runtime_dataset.py` automates scenario replay.

It can:

- recreate the controller with dataset recording enabled
- run benign scenarios
- run attack scenarios
- label each scenario automatically
- export the resulting dataset to Parquet

### 16.5 Scenario types

The automated collector includes:

- benign HTTP traffic
- mixed benign HTTP and ICMP
- TCP port scans
- UDP scans
- wider scans
- multi-host scans
- ICMP sweeps
- open-port SYN floods
- failed-connection floods

### 16.6 Collection profiles

The collector supports:

- `balanced`
- `scan_heavy`
- `flood_heavy`

This is important because it lets the dataset be tuned toward the kind of
behavior the model needs to improve on.

For example:

- `scan_heavy` increases scan and sweep coverage while still retaining flood
  scenarios
- `flood_heavy` emphasizes flood behavior

That means the dataset is not static. It can be adapted to the weaknesses found
during live testing.

### 16.7 Implementation evidence

From [ml/dataset_recorder.py](ml/dataset_recorder.py) lines 24 to 31 and 58 to
76:

```python
class RuntimeDatasetRecorder(object):
    """Write controller-observed packets into a live-compatible JSONL dataset."""
...
def record(self, packet_metadata, feature_snapshot=None):
    if not self.enabled:
        return False
    ...
    record = self._build_record(packet_metadata, feature_snapshot, label)
    self._append_record(record)
    return True
```

From [ml/dataset_recorder.py](ml/dataset_recorder.py) lines 115 to 140:

```python
record = {
    "Timestamp": ...,
    "Src IP": packet_metadata.src_ip,
    "Dst IP": packet_metadata.dst_ip or "",
    "Dst Port": ...,
    "Protocol": packet_metadata.transport_protocol,
    ...
    "Label": record_label,
    "Scenario": label.scenario if label is not None else "",
    "Scenario ID": label.scenario_id if label is not None else "",
    "Run ID": label.run_id if label is not None else "",
}
for feature_name, value in feature_values.items():
    record["Runtime %s" % feature_name] = float(value)
```

From [scripts/collect_runtime_dataset.py](scripts/collect_runtime_dataset.py)
lines 435 to 456:

```python
add_scenario(
    label="malicious",
    scenario_id="attack_port_scan_tcp_h3",
    ...
    command="/workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2",
    note="tcp_syn_port_scan",
)
add_scenario(
    label="malicious",
    scenario_id="attack_port_scan_udp_h3",
    ...
    command=("nmap -sU -Pn -T4 --max-retries 0 --top-ports 12 10.0.0.2"),
    note="udp_service_probe",
)
```

Academic reasoning:

- These lines directly support the claim that the model training data was
  collected from the live SDN system itself, with explicit labels and scenario
  identities.
- That improves experimental traceability and makes the final model easier to
  justify, because the training data is visibly tied to known traffic patterns
  in the same lab environment.

## 17. How the Model Was Trained

Training is handled by `scripts/train_random_forest.py`.

### 17.1 Core training process

The script:

1. loads a Parquet dataset
2. validates the schema
3. maps the raw dataset into runtime-compatible features
4. groups traffic into source-host time windows
5. creates the training feature frame
6. splits the data into train and test sets
7. trains a Random Forest classifier
8. evaluates it
9. exports a portable runtime model bundle

### 17.2 Why the script is careful about schema validation

The training script is deliberately strict because a model is only useful if the
runtime controller can reproduce its feature space.

That is why the script checks for fields such as:

- source IP
- destination IP
- destination port
- protocol
- timestamp

If those columns are missing, the script warns that the schema is not suitable
for live-compatible SDN training.

### 17.3 Grouped splitting

The default split mode is grouped rather than purely random.

This means the trainer tries to split by:

- run ID
- scenario
- scenario family
- collection ID

The purpose is to reduce data leakage. It is more honest to test on different
runs than to randomly shuffle rows from the same run into both train and test.

This is a strong point to mention academically.

### 17.4 Model parameters

The trainer uses a `RandomForestClassifier` with settings such as:

- `n_estimators = 200`
- `max_depth = 18`
- `class_weight = balanced_subsample`

This is appropriate for tabular data with a mixture of benign and malicious
scenarios.

### 17.5 Runtime export

After training, the sklearn model is exported into the lightweight runtime
representation used by the controller.

That keeps offline training and online deployment cleanly separated.

### 17.6 Implementation evidence

From [scripts/train_random_forest.py](scripts/train_random_forest.py) lines 134
to 143:

```python
"""Resolve parquet columns and validate live-runtime compatibility.

The SDN controller computes host-window features such as unique destination
ports, unique destination IPs, protocol rates, and failed-connection rates.
Training on parquet data that lacks those identifiers creates a misleading
model: offline metrics may look acceptable, but live controller inference
cannot match that feature space. The trainer therefore refuses such schemas
by default.
"""
```

From [scripts/train_random_forest.py](scripts/train_random_forest.py) lines 527
to 610:

```python
def split_training_frame(...):
    """Split samples using whole-run grouping when available."""
...
train_groups, test_groups = train_test_split_fn(
    group_frame["group"],
    test_size=effective_test_size,
    random_state=args.random_state,
    stratify=group_frame["label"],
)
```

From [scripts/train_random_forest.py](scripts/train_random_forest.py) lines 746
to 752:

```python
classifier = RandomForestClassifier(
    n_estimators=args.n_estimators,
    max_depth=args.max_depth,
    random_state=args.random_state,
    n_jobs=-1,
    class_weight="balanced_subsample",
)
```

Academic reasoning:

- The schema-validation block is direct evidence that the training pipeline was
  designed to protect deployment validity, not just maximize offline scores.
- The grouped split supports a stronger evaluation design because it reduces the
  chance of leakage between closely related runs.
- The Random Forest configuration is appropriate for structured network-security
  features and aligns with a project goal of explainable, lightweight ML.

## 18. The Final Model Story

The model story in this project is evolutionary.

### 18.1 Early model

An earlier runtime model such as:

- `models/random_forest_ids.runtime.joblib`

worked reasonably for some flood-like behavior, but it was weaker on port scans,
especially scans that produced few explicit failure responses.

### 18.2 Scan-aware improvement

The newer scan-aware runtime model such as:

- `models/runtime_scan_aware_20260320.runtime.joblib`

was built after:

- adding `unanswered_syn_rate`
- adding `unanswered_syn_ratio`
- adding `destination_port_fanout_ratio`
- collecting more scan-heavy runtime data

This made the model more sensitive to scan behavior while still retaining flood
coverage.

### 18.3 Why this matters in a demo

It gives you a good narrative:

- the ML model was not treated as a black box
- weaknesses were observed during live testing
- the feature space and dataset were then improved
- the deployed model therefore reflects engineering iteration, not just blind
  training

## 19. Why the Downloaded CIC Data Was Not Used as the Final Deployed Model Source

This is an important design decision and should be explained clearly.

The repository contains downloaded CIC-style data in:

- `archive(1)/...`

Examples include:

- DoS
- DDoS
- botnet
- infiltration
- web attack datasets

These were useful as references and influenced some training-tool design
decisions, but they were not used directly as the final runtime model source.

### 19.1 Reason 1: feature mismatch

The SDN controller computes live, controller-observable host-window features.
Public CIC flow datasets often contain richer or differently structured offline
flow information. A model trained too directly on those fields can end up using
signals the controller cannot reproduce honestly in real time.

That creates a deployment mismatch.

### 19.2 Reason 2: runtime mismatch

This project operates inside:

- a small SDN lab
- a specific Mininet topology
- controller-observed packet events
- short rolling windows

The live deployment environment is therefore different from the environment
represented by generic CIC captures.

### 19.3 Reason 3: academic defensibility

A model trained on controller-observed data from the same SDN lab is easier to
justify during a demonstration because it directly matches the deployed feature
space and traffic patterns.

This lets you say:

> The deployed model was trained on live-compatible features collected from the
> same SDN lab environment in which inference is performed.

That is a stronger claim than saying:

> The model was trained on a public offline flow dataset whose telemetry does
> not exactly match the live controller.

### 19.6 Implementation evidence

From [scripts/train_random_forest.py](scripts/train_random_forest.py) lines 9 to
16:

```python
The CIC parquet schema can vary slightly across collections. The helpers below
therefore:
- normalize column names
- search for a set of candidate column names
- approximate runtime features when exact matches do not exist

The trained model only uses features that can be approximated from live
controller telemetry.
```

From [ml/feature_extractor.py](ml/feature_extractor.py) lines 1 to 5:

```python
The controller cannot reproduce every flow feature available in offline datasets
such as CIC. This module therefore focuses on statistics that are realistic to
compute from controller-observed packets and short rolling windows.
```

Academic reasoning:

- These lines are the clearest code-level justification for not using the
  downloaded CIC data directly as the final deployed model source.
- The project did not reject CIC data out of convenience. It recognized a
  construct-validity problem: a training feature space that cannot be reproduced
  honestly at inference time is methodologically weak.
- By collecting runtime-compatible data instead, the project improves alignment
  between training conditions and deployment conditions.

### 19.4 Reason 4: practical performance

Live testing showed that models need to respond to this project’s specific
runtime behavior, especially for:

- silent scans
- filtered scans
- short bursts
- controller-visible traffic patterns

Runtime-collected data was better suited to this than directly deploying a model
based on downloaded CIC artifacts.

### 19.5 The balanced explanation

The best way to explain the decision is:

> The downloaded CIC data was useful as a reference and for informing the design
> of the training pipeline, but the final deployed model was based on
> controller-observed, runtime-compatible features collected from the actual SDN
> lab. This decision reduced feature mismatch and improved confidence that live
> inference matched the deployment environment.

## 20. Suggested Demonstration Script

Here is a clean way to walk your supervisor through the system.

### Step 1: Start with the architecture

Explain:

- controller
- switches and hosts
- dashboard
- capture subsystem
- threshold IDS baseline
- ML extension

### Step 2: Show the healthy baseline

Show:

- topology is up
- switches are connected
- hosts are learned
- dashboard is updating

### Step 3: Show benign traffic

Demonstrate that benign traffic flows normally and the network is not blocked by
default.

### Step 4: Show a port scan

Run the port scan from `h3` to `h2` and explain:

- threshold IDS sees many destination ports in a short window
- the host is quarantined
- the alert appears on the dashboard
- a pcap snapshot is preserved

### Step 5: Show the capture evidence

Open the preserved capture and show:

- repeated TCP SYN packets
- many destination ports
- little or no normal session completion

### Step 6: Show manual release

Use the dashboard to unblock the host and explain the analyst-supervised
workflow.

### Step 7: Show ML or hybrid mode

Explain:

- threshold mode = deterministic baseline
- ml mode = purely model-led
- hybrid mode = both systems working together

If you demonstrate hybrid mode, explain agreement/disagreement tracking.

## 21. Likely Supervisor Questions and Good Answers

### "Why use SDN for this?"

Because SDN centralizes control and visibility. The controller can observe and
enforce policy consistently across the network without manually configuring each
device independently.

### "Why not just use machine learning alone?"

Because threshold IDS remains more deterministic and reliable in live SDN
operation. ML is used as an enhancement, not as the sole source of truth.

### "Why not use only public datasets?"

Because the deployed controller must classify traffic using features it can
actually compute in real time. Runtime-collected lab data better matches that
feature space.

### "What makes the architecture modular?"

Because packet parsing, flow management, threshold IDS, ML inference,
monitoring, capture, and mitigation are separated into dedicated modules rather
than being collapsed into one controller script.

### "What is the biggest strength of this project?"

A strong answer is:

> The main strength is that it combines centralized SDN enforcement, interpretable
> threshold detection, optional ML augmentation, live monitoring, and preserved
> packet evidence in one modular and demo-ready system.

### "What is the biggest limitation?"

A good honest answer is:

> The ML subsystem is still dependent on the quality and representativeness of
> runtime training data, which is why threshold IDS remains the primary baseline.

## 22. Final Summary

This project is best understood as a modular SDN security platform with five
core strengths:

1. centralized control using Ryu and OpenFlow 1.3
2. reliable threshold-based IDS baseline
3. optional ML-based IDS extension using runtime-compatible features
4. dynamic mitigation through quarantine and flow-rule enforcement
5. live monitoring and preserved packet evidence through a Flask dashboard and
   rolling capture system

The most important design decision in the ML story is that the final deployed
model is based on controller-observed, live-compatible data rather than blindly
deploying a model trained directly on external CIC artifacts.

That is what makes the ML part of this project not just a machine learning
exercise, but an SDN-aware, deployment-aware intrusion detection component.
