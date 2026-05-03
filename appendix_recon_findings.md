# Appendix Evidence Collection Report for SDN-Based Security and Intrusion Detection

## 1. Repository Identity
- repository name: `Final-SDN-IDS-ML` (derived from remote `git@github.com:KSeutloali/Final-SDN-IDS-ML.git`)
- local path: `/home/seutloali/Downloads/Project @.0/SDN Project`
- remote URL: `git@github.com:KSeutloali/Final-SDN-IDS-ML.git`
- branch: `main`
- commit hash: `d3cf14eff523f5b9e208f52ed017075a05145398`
- git status summary: two deleted tracked files detected at inspection time
  - `D broken_pingall_attempt.patch`
  - `D broken_pingall_status.txt`
- inspection date/time:
  - local: `2026-05-03T17:06:11+02:00`
  - UTC: `2026-05-03T15:06:11+00:00`
- commands used:
  - `pwd`
  - `git remote -v`
  - `git branch --show-current`
  - `git rev-parse HEAD`
  - `git status --short`
  - `date -Iseconds`
  - `date -u -Iseconds`

## 2. Executive Summary

| Appendix | Readiness | Main evidence found | Main evidence missing |
|---|---|---|---|
| System Manual | Nearly ready | Dockerfiles, Compose config, dependency files, startup/stop scripts, env defaults, topology/capture/ML workflows | Live `docker compose ps` confirmation failed due Docker socket permission; no fresh build/start logs from this recon |
| User Manual | Partial | Dashboard/API routes, command-queue workflow, blocked-host and mode-switch implementation, runtime state artifacts | Required screenshots, fresh UI session evidence from this machine/user session |
| Supporting Documentation or Data | Nearly ready | Architecture modules, runtime JSON/JSONL, capture metadata, model metrics, experiment result sets | Formal diagram assets (topology/sequence/FSM images) not present as files |
| Test Results and Test Reports | Partial | `unittest` suite verified (`183` run, `15` skipped), test files inventory, runtime validation JSON artifacts, model metrics JSON | `pytest` unavailable, no rerun of integration scripts/live scenarios in this session, limited static-firewall baseline runtime proof |
| Source Code Listing or Repository Structure | Ready | Top-level tree, key folder mapping, key file roles, entrypoints, include/exclude strategy | None critical for appendix structuring |

## 3. Evidence Classification Legend
- `VERIFIED`: confirmed by runtime output, test output, log, PCAP metadata, metric file, screenshot, or command output.
- `IMPLEMENTED`: code/config exists, but runtime proof was not found.
- `DOCUMENTED`: described in README/docs/scripts, but not verified in code/runtime.
- `PARTIAL`: some evidence exists, but not enough for a full claim.
- `MISSING`: needed evidence was not found.
- `NOT_EXECUTED`: command was not run.
- `FAILED`: command was run and failed.
- `FAILED_ENVIRONMENT`: command failed because of missing dependencies, permissions, unavailable Docker/Mininet, or similar environment constraints.
- `NOT_APPLICABLE`: not relevant to this project.
- `INFERRED_FROM_SCRIPT`: behavior inferred from script logic without executing that script.

## 4. Commands Executed During Recon

| Command ID | Command | Purpose | Result | Status |
|---|---|---|---|---|
| C01 | `pwd` | confirm workspace | `/home/seutloali/Downloads/Project @.0/SDN Project` | VERIFIED |
| C02 | `git remote -v` | identify upstream repo | `origin git@github.com:KSeutloali/Final-SDN-IDS-ML.git` | VERIFIED |
| C03 | `git branch --show-current` | identify active branch | `main` | VERIFIED |
| C04 | `git rev-parse HEAD` | lock commit ID | `d3cf14eff523f5b9e208f52ed017075a05145398` | VERIFIED |
| C05 | `git status --short` | detect local changes | two deleted tracked files shown | VERIFIED |
| C06 | `tree -a -L 2 -I ...` | top-level structure audit | `40 directories, 178 files` | VERIFIED |
| C07 | `find ... README*/LICENSE*` | docs/license discovery | README/docs found, no license file found | PARTIAL |
| C08 | `docker --version` | runtime readiness check | `Docker version 29.3.1` | VERIFIED |
| C09 | `docker compose version` | compose readiness check | `v2.32.4-desktop.1` | VERIFIED |
| C10 | `python3 --version` | interpreter check | `Python 3.12.3` | VERIFIED |
| C11 | `pytest --version` | test tool check | `/bin/bash: pytest: command not found` | FAILED_ENVIRONMENT |
| C12 | `python3 -m pytest -q` | fallback pytest check | `No module named pytest` | FAILED_ENVIRONMENT |
| C13 | `docker compose ps` | container status check | Docker socket permission denied | FAILED_ENVIRONMENT |
| C14 | `python3 -m unittest discover -s tests -p "test_*.py"` | run available test suite safely | `Ran 183 tests ... OK (skipped=15)` | VERIFIED |
| C15 | `find tests -type f -iname 'test_*.py'` | test inventory | `26` test modules listed | VERIFIED |
| C16 | `rg -n "skipIf|skipUnless" tests` | skipped-test rationale | skip guards for missing `pandas` and `Flask` found | VERIFIED |
| C17 | `rg -n "@blueprint.route" monitoring/api.py` | enumerate API endpoints | health/alerts/blocks/mode/captures/reports routes found | VERIFIED |
| C18 | `nl -ba monitoring/webapp.py` | enumerate dashboard pages/routes | 8 page definitions + capture download route found | VERIFIED |
| C19 | `nl -ba Dockerfile*` + `docker-compose.yml` | deployment assumptions | Python 3.8 Alpine controller + Ubuntu 22.04 Mininet + Compose services | VERIFIED |
| C20 | `nl -ba requirements*.txt` | dependencies | runtime and offline-ML dependencies identified | VERIFIED |
| C21 | `find captures/runtime/models/experiments ... | wc -l` | artifact volume assessment | captures `842` files, runtime `372`, experiments results `1939` | VERIFIED |
| C22 | `find ... snapshot.json / metrics.json / manifest.json` | high-value evidence discovery | snapshot metadata, metrics JSON, experiment manifests found | VERIFIED |
| C23 | `find . -maxdepth 2 -iname 'LICENSE*'` | license check | none found | MISSING |
| C24 | `find ... image/pdf/svg` | existing diagram/screenshot assets check | none found in scanned ranges | MISSING |
| C25 | `find . -iname 'pytest.ini' -o -iname 'tox.ini' -o -path '*/.github/workflows/*'` | CI config discovery | none found | PARTIAL |

## 5. System Manual Evidence

### 5.1 Installation Requirements
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Host OS expectation | Linux host for Docker/Compose workflow | `README.md` lines ~515-526 | DOCUMENTED |
| Controller base runtime | `python:3.8-alpine` | `Dockerfile` line 1 | IMPLEMENTED |
| Mininet lab runtime | `ubuntu:22.04` with Mininet/OVS toolchain | `Dockerfile.mininet` lines 1, 9-23 | IMPLEMENTED |
| Python observed locally | `Python 3.12.3` | C10 | VERIFIED |
| Ryu version pin | `git checkout tags/v4.30` | `Dockerfile` lines 36-39 | IMPLEMENTED |
| OpenFlow version | OpenFlow 1.3 | `controller/main.py` line 49 and `topology/custom_topology.py` lines 56-58 | IMPLEMENTED |
| OVS assumption | OVS userspace default in container (`SDN_MININET_SWITCH_MODE=user`) | `docker-compose.yml` line 100 and README runtime note | IMPLEMENTED |
| Mininet assumption | privileged Mininet container | `docker-compose.yml` line 91 | IMPLEMENTED |

### 5.2 Dependencies
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Runtime Python deps | `requirements.txt` (`eventlet`, `setuptools`, `Flask`, `Werkzeug`) | `requirements.txt` | IMPLEMENTED |
| Offline ML deps | `requirements-ml.txt` (`pandas`, `pyarrow`, `scikit-learn`, `joblib`) | `requirements-ml.txt` | IMPLEMENTED |
| Additional dependency manifests | `pyproject.toml`, `setup.py`, `tox.ini`, `pytest.ini` not found | C25 + manifest scan | PARTIAL |
| Linux tools in Mininet image | `ethtool hping3 iproute2 iputils-ping mininet nmap openvswitch-* tcpdump` | `Dockerfile.mininet` lines 10-23 | IMPLEMENTED |

### 5.3 Docker and Compose Setup
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Controller image build | `docker compose build` / service `controller` | `README.md` and `docker-compose.yml` | DOCUMENTED |
| Dashboard service | `command: ["python", "-m", "monitoring.webapp"]` | `docker-compose.yml` line 73 | IMPLEMENTED |
| Mininet service | privileged container sleeping until topology launch | `docker-compose.yml` lines 85-104 | IMPLEMENTED |
| Compose status check | `docker compose ps` | C13 permission denied socket | FAILED_ENVIRONMENT |
| Direct controller command | `ryu-manager controller.main` | `README.md` line ~228 and `Dockerfile` CMD | IMPLEMENTED |

### 5.4 Environment Variables
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Example env file | `.env.example` present | file listing | VERIFIED |
| Operational env file | `.env` present (values inspected; no secret-key style names found) | top-level listing + secret-name grep | VERIFIED |
| Safe/default sample vars | `SDN_ML_ENABLED=true`, `SDN_ML_MODE=hybrid`, `SDN_ML_INFERENCE_MODE=combined`, `SDN_FIREWALL_PROTECTED_SOURCE_IPS=10.0.0.254` | `.env.example` | DOCUMENTED |
| Compose defaults | extensive `SDN_*` defaults for IDS/ML/capture/firewall/mode state | `docker-compose.yml` lines 12-59 | IMPLEMENTED |
| Secret handling | no `SECRET/TOKEN/PASSWORD/API_KEY` variable names detected in `.env`/`.env.example` | grep check | PARTIAL |

### 5.5 Controller Startup
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Container startup | `docker compose up -d controller dashboard mininet` | README | DOCUMENTED |
| Direct startup | `ryu-manager controller.main` | README + Dockerfile CMD | IMPLEMENTED |
| Controller class | `SecurityController(app_manager.RyuApp)` | `controller/main.py` line 46 | IMPLEMENTED |
| OpenFlow table-miss + baseline install | switch-features handler installs table miss and baseline rules | `controller/main.py` lines 195-197 | IMPLEMENTED |
| Runtime controller evidence | live controller log exists with flow installs/removals/security events | `logs/controller.log` sample | VERIFIED |

### 5.6 Dashboard Startup
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Dashboard start command | `python -m monitoring.webapp` | `docker-compose.yml` line 73 | IMPLEMENTED |
| Default URL | `http://127.0.0.1:8080/sdn-security` | README and dashboard config default | DOCUMENTED |
| Base path | `/sdn-security` | `config/settings.py` line 117 | IMPLEMENTED |
| Runtime dashboard state file | `runtime/dashboard_state.json` | runtime artifact | VERIFIED |

### 5.7 Mininet Topology Startup
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Topology launcher | `./scripts/run_topology.sh` | script + README | INFERRED_FROM_SCRIPT |
| Topology module | `python3 -m topology.custom_topology` with controller args | `scripts/run_topology.sh` lines 14-20 | IMPLEMENTED |
| OpenFlow protocol in switches | `protocols="OpenFlow13"` on `s1/s2/s3` | `topology/custom_topology.py` lines 56-58 | IMPLEMENTED |
| Runtime topology state | `runtime/mininet_runtime.json` indicates `active:true` and host PIDs | runtime file | VERIFIED |

### 5.8 Packet Capture Setup
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Continuous capture manager | `PacketCaptureManager` integrated in topology and controller | `topology/custom_topology.py` lines 106-115, `controller/main.py` lines 79-83 | IMPLEMENTED |
| Capture interfaces default | `h1-eth0,h3-eth0,h2-eth0,s2-eth3` | `config/settings.py` lines 171-176 | IMPLEMENTED |
| Ring config | `ring_file_seconds=30`, `ring_file_count=12`, `snaplen=160` | `config/settings.py` lines 178-183 | IMPLEMENTED |
| Manual capture scripts | `./scripts/start_captures.sh <scenario>`, `./scripts/stop_captures.sh` | scripts + README | INFERRED_FROM_SCRIPT |
| Capture evidence volume | `captures` contains `811` `.pcap` files and `25` `snapshot.json` metadata files | capture file counts | VERIFIED |

### 5.9 ML Training and Dataset Workflow
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| RF training command | `python3 scripts/train_random_forest.py ...` | README + script args | DOCUMENTED |
| IF training command | `python3 scripts/train_anomaly_model.py ...` | script args | IMPLEMENTED |
| Runtime dataset collection | `python3 scripts/collect_runtime_dataset.py --restore-controller` | README + script | DOCUMENTED |
| Runtime JSONL export | `python3 scripts/export_runtime_dataset.py --input ... --output ...` | README + script | IMPLEMENTED |
| Runtime model export | `python3 scripts/export_runtime_model.py --input ... --output ...` | script | IMPLEMENTED |
| Dataset artifacts found | `datasets/` has `9` parquet files | dataset file count | VERIFIED |
| Model artifacts found | `models/` has runtime/joblib + metrics files | model file count | VERIFIED |

### 5.10 Shutdown and Cleanup
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Service shutdown | `docker compose down` | README | DOCUMENTED |
| Mininet cleanup in launcher | `mn -c` attempted unless `SDN_SKIP_MININET_CLEANUP=true` | `scripts/run_topology.sh` lines 7-12 | INFERRED_FROM_SCRIPT |
| Capture session stop | `scripts/stop_captures.sh` kills capture PIDs and removes session marker | script | INFERRED_FROM_SCRIPT |

### 5.11 Troubleshooting Notes
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Docker socket permission issue | `docker compose ps` denied on `/home/seutloali/.docker/desktop/docker.sock` | C13 | FAILED_ENVIRONMENT |
| Missing pytest command/module | `pytest: command not found` and `No module named pytest` | C11-C12 | FAILED_ENVIRONMENT |
| Optional deps skipped in tests | pandas/Flask guarded tests skip when unavailable | C16 | VERIFIED |
| Fallback strategy used | `python3 -m unittest discover ...` succeeded | C14 | VERIFIED |

### 5.12 Extension Points for Future Students
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| IDS thresholds and windows | `config/settings.py` IDSConfig env-mapped parameters | config file | IMPLEMENTED |
| Hybrid/ML policy tuning | `MLConfig` + `MLIDSPipeline` hybrid thresholds and escalation controls | `config/settings.py`, `ml/pipeline.py` | IMPLEMENTED |
| Dashboard report expansion | `monitoring/state.py::available_reports` + `build_report` | monitoring state | IMPLEMENTED |
| Scenario/evaluation extension | `experiments/common.py` mode/scenario dataclasses | experiments common | IMPLEMENTED |
| Capture policy extension | capture ring/snapshot parameters and interface map | capture manager + config | IMPLEMENTED |

## 6. User Manual Evidence

### 6.1 Intended User Roles
- SDN operator/analyst: monitor alerts, blocked hosts, captures, and release quarantines.
- evaluator/researcher: run scenarios and compare modes via experiments harness.
- future maintainer/student: amend thresholds/models/policies and re-run validation.

Status: `DOCUMENTED` + `IMPLEMENTED` (role behavior reflected in UI/API and scripts).

### 6.2 Starting the System
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Build services | `docker compose build` | README | DOCUMENTED |
| Start core services | `docker compose up -d controller dashboard mininet` | README | DOCUMENTED |
| Start topology | `./scripts/run_topology.sh` | README + script | INFERRED_FROM_SCRIPT |

### 6.3 Accessing the Dashboard
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Dashboard URL | `http://127.0.0.1:8080/sdn-security` | README + config default | DOCUMENTED |
| Dashboard base path config | `SDN_DASHBOARD_BASE_PATH` default `/sdn-security` | `config/settings.py` | IMPLEMENTED |
| Runtime state backing | `runtime/dashboard_state.json` | runtime artifact | VERIFIED |

### 6.4 Dashboard Pages

| Page/tab | URL/path | Purpose | Evidence source | Status |
|---|---|---|---|---|
| Overview | `/sdn-security` | high-level posture, reports, recent alerts/blocks | `monitoring/webapp.py` PAGE_DEFINITIONS | IMPLEMENTED |
| Traffic | `/sdn-security/traffic` | rates/protocols/top talkers | PAGE_DEFINITIONS | IMPLEMENTED |
| Alerts | `/sdn-security/alerts` | threshold/ML alert feed | PAGE_DEFINITIONS + template | IMPLEMENTED |
| Blocks | `/sdn-security/blocked-hosts` | quarantine inventory and release actions | PAGE_DEFINITIONS + template | IMPLEMENTED |
| Performance | `/sdn-security/performance` | flow/controller/throughput telemetry | PAGE_DEFINITIONS | IMPLEMENTED |
| Captures | `/sdn-security/captures` | ring/snapshot file management/download | PAGE_DEFINITIONS + capture download route | IMPLEMENTED |
| ML IDS | `/sdn-security/ml-ids` | ML mode/model/alerts and correlation state | PAGE_DEFINITIONS | IMPLEMENTED |
| Settings | `/sdn-security/settings` | mode selection and runtime config view | PAGE_DEFINITIONS | IMPLEMENTED |

### 6.5 Viewing Alerts
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Alert API | `GET /api/alerts` | `monitoring/api.py` | IMPLEMENTED |
| Alert UI table | alerts template columns include severity/type/source/reason/evidence | `monitoring/templates/alerts.html` | IMPLEMENTED |
| Runtime alert evidence | `runtime/dashboard_state.json` includes non-zero alert counters and recent alert events | runtime state snippet | VERIFIED |

### 6.6 Viewing and Releasing Blocked Hosts
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Block list API | `GET /api/blocked-hosts` | API route | IMPLEMENTED |
| Manual unblock API | `POST /api/blocked-hosts/<src_ip>/unblock` | API route | IMPLEMENTED |
| Processed unblock command evidence | processed command JSON with `action=unblock_host`, `status=completed` | `runtime/controller_commands/processed/...5a006030.json` | VERIFIED |
| Manual unblock runtime log evidence | `event=security action=host_manually_unblocked ... released_by=dashboard` | `logs/controller.log` | VERIFIED |

### 6.7 IDS Mode Switching
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Mode set API | `POST /api/set_ids_mode` and `/api/set-ids-mode` | API routes | IMPLEMENTED |
| Command processing | controller handles `set_ids_mode` in queue loop | `controller/main.py` lines ~669-787 | IMPLEMENTED |
| Persisted mode state | `runtime/ids_mode_state.json` shows selected/effective mode | runtime file | VERIFIED |
| Processed mode command evidence | command record with `action=set_ids_mode`, `status=completed` | `runtime/controller_commands/processed/...482b7a49.json` | VERIFIED |

### 6.8 Viewing and Downloading Captures
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Capture API | `GET /api/captures` | API route | IMPLEMENTED |
| Capture download endpoint | `/sdn-security/captures/download/<path:relative_path>` | `monitoring/webapp.py` line 196 | IMPLEMENTED |
| Snapshot metadata evidence | snapshot JSON includes source IP, detector, file list, sizes, primary file | `captures/output/snapshots/.../snapshot.json` | VERIFIED |
| Capture event history | `runtime/capture_events.jsonl` (contains `action=snapshot_preserved`) | runtime JSONL | VERIFIED |

### 6.9 Running Benign Traffic
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Benign traffic command | `mininet> h1 sh /workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80` | README + `traffic/benign_traffic.sh` | INFERRED_FROM_SCRIPT |

### 6.10 Running Controlled Attack Scenarios
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Port scan command | `mininet> h3 sh /workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2` | README + script | INFERRED_FROM_SCRIPT |
| SYN flood command | `mininet> h3 sh /workspace/ryu-apps/attacks/dos_flood.sh 10.0.0.2 80 300` | README + script | INFERRED_FROM_SCRIPT |
| Extended playbook commands | `nmap`/`hping3` sequences in `sdn_firewall_ids_test_playbook.md` | playbook docs | DOCUMENTED |
| Safety execution status in this recon | commands not executed in this session | recon policy | NOT_EXECUTED |

### 6.11 Stopping the System
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Stop services | `docker compose down` | README | DOCUMENTED |
| Stop manual captures | `./scripts/stop_captures.sh` | script | INFERRED_FROM_SCRIPT |

### 6.12 Required Screenshots

| Screenshot ID | Page/command | Purpose | Exact capture instruction | Status |
|---|---|---|---|---|
| SS-01 | `docker compose ps` | prove services are up | Capture terminal after successful `controller/dashboard/mininet` status | REQUIRED_SCREENSHOT (MISSING) |
| SS-02 | `./scripts/run_topology.sh` + Mininet prompt | prove topology launch | Capture terminal when Mininet CLI prompt appears | REQUIRED_SCREENSHOT (MISSING) |
| SS-03 | Mininet `pingall` | prove host connectivity | Capture `mininet> pingall` completion output | REQUIRED_SCREENSHOT (MISSING) |
| SS-04 | `/sdn-security` Overview | prove dashboard access | Capture overview with counters visible and timestamp | REQUIRED_SCREENSHOT (MISSING) |
| SS-05 | `/sdn-security/alerts` | prove detection feed | Capture after running one scenario with at least one alert row visible | REQUIRED_SCREENSHOT (MISSING) |
| SS-06 | `/sdn-security/blocked-hosts` | prove quarantine view | Capture blocked host row showing detector/reason/timestamp | REQUIRED_SCREENSHOT (MISSING) |
| SS-07 | Manual unblock action | prove analyst release workflow | Capture before/after unblock on blocked-hosts page | REQUIRED_SCREENSHOT (MISSING) |
| SS-08 | `/sdn-security/captures` | prove forensic capture workflow | Capture snapshots table with a preserved snapshot and download path | REQUIRED_SCREENSHOT (MISSING) |
| SS-09 | `/sdn-security/ml-ids` | prove ML/hybrid runtime state | Capture mode, model path/status, and ML alert counters | REQUIRED_SCREENSHOT (MISSING) |
| SS-10 | `/sdn-security/settings` | prove IDS mode switching controls | Capture selector + selected/effective mode indicators | REQUIRED_SCREENSHOT (MISSING) |

## 7. Supporting Documentation or Data Evidence

### 7.1 Architecture Components

| Component | File path(s) | Purpose | Inputs | Outputs | Related config | Related tests | Status |
|---|---|---|---|---|---|---|---|
| SDN Controller Core | `controller/main.py`, `controller/events.py`, `core/state.py` | OpenFlow control loop, host learning, event publishing | PacketIn, switch events, command queue | FlowMods, PacketOut, dashboard state, logs | `config/settings.py` | `tests/test_controller_events.py` | IMPLEMENTED |
| Flow Programming | `core/flow_manager.py` | Table-miss/forward/drop/source-block/port-block flows | firewall/ids decisions | OFPFlowMod/OFPPacketOut | flow priority/timeouts config | `tests/test_forwarding_policy.py` | IMPLEMENTED |
| Firewall Policy | `security/firewall.py` | static + dynamic/quarantine filtering | parsed packet metadata, static policy | allow/block decisions + drop flow installs | firewall config | `tests/test_mitigation.py`, `tests/test_config.py` | IMPLEMENTED |
| Threshold IDS | `security/ids.py` | scan/flood/failed-connection/unanswered-SYN detection | packet stream windows | `IDSAlert` objects | IDS thresholds/windows config | `tests/test_ids.py` | IMPLEMENTED |
| Mitigation/Quarantine | `security/mitigation.py` | quarantine create/duplicate/release policy | threshold/ML alerts + manual commands | quarantine records + flow delete/install | mitigation config | `tests/test_mitigation.py` | IMPLEMENTED |
| ML Inference Pipeline | `ml/pipeline.py`, `ml/inference.py`, `ml/model_loader.py`, `ml/anomaly.py` | mode-aware ML/hybrid decisioning | feature snapshots + model bundles | ML alerts, correlation events, block recommendations | ML config + model paths | `tests/test_ml_pipeline.py`, `tests/test_inference.py`, `tests/test_anomaly.py` | IMPLEMENTED |
| Dataset Recording | `ml/dataset_recorder.py`, `scripts/export_runtime_dataset.py` | runtime JSONL feature logging and parquet export | packet/features/label context | JSONL/parquet datasets | ML dataset config | `tests/test_dataset_recorder.py`, `tests/test_collect_runtime_dataset.py` | IMPLEMENTED |
| Capture Subsystem | `captures/capture_manager.py`, `scripts/start_captures.sh`, `scripts/stop_captures.sh` | rolling pcap and alert snapshot preservation | interface map, alert context | ring pcaps, snapshot pcaps, metadata JSON | capture config | `tests/test_capture_manager.py` | IMPLEMENTED |
| Dashboard/API | `monitoring/webapp.py`, `monitoring/api.py`, `monitoring/state.py` | operator UI and JSON APIs | runtime dashboard state | HTML pages, API payloads, downloadable reports | dashboard config | `tests/test_monitoring_state.py`, `tests/test_monitoring_api.py` | IMPLEMENTED |
| Experiment Harness | `experiments/run_evaluation.py`, `experiments/common.py`, `experiments/extract_results.py` | repeatable scenario execution and report aggregation | mode/scenario definitions, runtime state | manifest, per-run, summary and comparison CSV/JSON | CLI args + env modes | `tests/test_experiment_common.py`, `tests/test_experiment_extract_results.py` | IMPLEMENTED |

### 7.2 Data and Control Flow
- packet processing flow implemented and traceable in `controller/main.py`: parse packet -> threshold IDS -> ML pipeline -> dataset recorder -> mitigation/firewall -> forwarding/drop -> dashboard publish.
- command/control flow implemented through filesystem-backed queue in `core/command_queue.py` and processed in controller loop (`set_ids_mode`, `unblock_host`).
- evidence state flow verified through runtime artifacts:
  - `runtime/dashboard_state.json`
  - `runtime/ids_mode_state.json`
  - `runtime/controller_commands/processed/*.json`

Status: `IMPLEMENTED` + `VERIFIED` (for persisted state evidence).

### 7.3 Use Cases
- benign monitoring baseline (`traffic/benign_traffic.sh`) - `INFERRED_FROM_SCRIPT`
- threshold recon/flood detection and quarantine - `VERIFIED` via runtime validation JSON and logs
- ML-only and hybrid detection correlation - `VERIFIED` via `runtime/attack_validation_20260416_180530.json` and dashboard state artifacts
- analyst manual host release - `VERIFIED` via processed command records and controller logs

### 7.4 Suggested Diagrams

| Diagram ID | Diagram type | Content to show | Evidence source | Status |
|---|---|---|---|---|
| D-01 | Component architecture | controller, OVS/Mininet, capture manager, dashboard/API, ML models | code modules + compose + topology | MISSING |
| D-02 | Data flow diagram | PacketIn to IDS/ML/mitigation and dashboard state outputs | `controller/main.py` + `monitoring/state.py` | MISSING |
| D-03 | Sequence diagram | attack traffic -> alert -> quarantine -> dashboard update -> manual unblock | `security/*`, `core/command_queue.py`, API routes | MISSING |
| D-04 | IDS mode FSM | threshold / ml / hybrid selection and effective mode behavior | `ml/pipeline.py`, `core/ids_mode.py`, API set mode | MISSING |
| D-05 | Capture workflow diagram | ring capture workers and snapshot preservation on alert | `captures/capture_manager.py` | MISSING |

### 7.5 API Endpoint Table

| Endpoint | Method | Purpose | Evidence source | Status |
|---|---|---|---|---|
| `/api/health` | GET | dashboard health payload | `monitoring/api.py` | IMPLEMENTED |
| `/api/dashboard` | GET | overview payload | `monitoring/api.py` | IMPLEMENTED |
| `/api/overview` | GET | alias for overview | `monitoring/api.py` | IMPLEMENTED |
| `/api/traffic` | GET | traffic metrics | `monitoring/api.py` | IMPLEMENTED |
| `/api/alerts` | GET | alert feed | `monitoring/api.py` | IMPLEMENTED |
| `/api/blocked-hosts` | GET | blocked/quarantined hosts | `monitoring/api.py` | IMPLEMENTED |
| `/api/blocked-hosts/<src_ip>/unblock` | POST | queue manual unblock | `monitoring/api.py` | IMPLEMENTED |
| `/api/set_ids_mode` | POST | queue IDS mode change | `monitoring/api.py` | IMPLEMENTED |
| `/api/set-ids-mode` | POST | alternate mode-change route | `monitoring/api.py` | IMPLEMENTED |
| `/api/commands/<command_id>` | GET | command status polling | `monitoring/api.py` | IMPLEMENTED |
| `/api/performance` | GET | performance telemetry | `monitoring/api.py` | IMPLEMENTED |
| `/api/captures` | GET | capture state/snapshots/files | `monitoring/api.py` | IMPLEMENTED |
| `/api/captures/delete-selected` | POST | delete selected capture items | `monitoring/api.py` | IMPLEMENTED |
| `/api/captures/delete-all` | POST | delete all captures (confirmed) | `monitoring/api.py` | IMPLEMENTED |
| `/api/ml-ids` | GET | ML mode/model status and stats | `monitoring/api.py` | IMPLEMENTED |
| `/api/settings` | GET | config exposure for dashboard settings | `monitoring/api.py` | IMPLEMENTED |
| `/api/events` | GET | merged recent events | `monitoring/api.py` | IMPLEMENTED |
| `/api/timeseries` | GET | dashboard timeseries payload | `monitoring/api.py` | IMPLEMENTED |
| `/api/reports` | GET | list downloadable reports | `monitoring/api.py` | IMPLEMENTED |
| `/api/reports/<report_key>` | GET | download report in supported format | `monitoring/api.py` | IMPLEMENTED |

### 7.6 Dataset and Model Files
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Dataset files count | `9` parquet files under `datasets/` | file count | VERIFIED |
| Representative datasets | `datasets/merged_runtime_dataset.parquet`, `datasets/scan_heavy_runtime_20260321.parquet`, `datasets/benign_heavy_anomaly_20260417b_snapshot.parquet` | file listing | VERIFIED |
| Model files count | `17` files under `models/` | file count | VERIFIED |
| Metrics files | `models/random_forest_runtime_final_metrics.json`, `models/isolation_forest_benign_heavy_20260417_metrics.json`, `models/isolation_forest_benign_heavy_20260417b_metrics.json` | file listing | VERIFIED |
| Runtime feature manifest | `models/random_forest_runtime_final_features.json` | file content | VERIFIED |

### 7.7 Configuration Tables
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| Central config dataclasses | `ControllerConfig`, `FirewallConfig`, `IDSConfig`, `MitigationConfig`, `CaptureConfig`, `MLConfig` | `config/settings.py` | IMPLEMENTED |
| Dashboard defaults | host `0.0.0.0`, port `8080`, base path `/sdn-security`, state file `runtime/dashboard_state.json` | `config/settings.py` | IMPLEMENTED |
| Flow priority defaults | table-miss 0, forwarding 10, packet block 220, source block 280/300 | `config/settings.py` | IMPLEMENTED |
| IDS thresholds defaults | packet/syn/scan/failed-connection/unanswered-SYN thresholds and windows | `config/settings.py` | IMPLEMENTED |
| Capture defaults | tool `tcpdump`, ring 30s x 12 files, snapshot cooldown 10s | `config/settings.py` | IMPLEMENTED |

### 7.8 Packet Capture and Evidence Data
| Item | Value/path/command | Evidence source | Status |
|---|---|---|---|
| pcap file volume | `811` `.pcap` files under `captures/` | file count | VERIFIED |
| snapshot metadata volume | `25` snapshot metadata JSON files | file count | VERIFIED |
| sample snapshot metadata | includes alert type, source IP, files, primary file, size bytes | `captures/output/snapshots/.../snapshot.json` | VERIFIED |
| capture event stream | `runtime/capture_events.jsonl` with `action=capture_started` and `action=snapshot_preserved` rows | JSONL sample | VERIFIED |

## 8. Test Results and Test Reports Evidence

### 8.1 Test Files Found
- `26` unit/integration-support test modules found under `tests/`.
- representative coverage areas: IDS, mitigation, capture manager, monitoring API/state, ML inference/pipeline, experiment extractors.

### 8.2 Unit Test Evidence
- executed command: `python3 -m unittest discover -s tests -p "test_*.py"`
- observed: `Ran 183 tests in 1.367s` and `OK (skipped=15)`.
- skip guards found for missing optional dependencies (`pandas`, `Flask`).

### 8.3 Integration Test Evidence
- scripts present:
  - `scripts/integration_dashboard_smoke.py`
  - `scripts/integration_ids_mode_switch.py`
  - `scripts/integration_security_workflow.py`
- scripts were not run in this recon session due safety and environment constraints.

### 8.4 Experiment Harness Evidence
- harness files present and implemented (`experiments/run_evaluation.py`, `experiments/common.py`, `experiments/extract_results.py`).
- substantial result bundle found in `experiments/results/hybrid_policy_resume_v2_20260425/`.
- `experiments/results/evaluation_20260313_094548/manifest.json` exists, but corresponding full per-run artifact set is incomplete in that folder.

### 8.5 Runtime Scenario Evidence
- runtime validation artifacts present:
  - `runtime/threshold_recon_validation_20260416.json`
  - `runtime/threshold_validation_after_tuning_20260416.json`
  - `runtime/attack_validation_20260416_180530.json`
- these files include per-scenario command tails, detected/blocked booleans, and summary deltas.

### 8.6 ML Metrics Evidence
- Random Forest metrics JSON includes accuracy/precision/recall/F1 fields.
- Isolation Forest metrics JSON include anomaly detection rate and benign false positive rate (not classifier accuracy tables).

### 8.7 Packet Capture Evidence
- capture snapshots and ring captures exist with metadata linked to alert/detector/source IP.
- no independent pcap decoding run was executed during this recon.

### 8.8 Missing Test Evidence
- no `pytest` execution because `pytest` is not installed in current interpreter.
- no fresh live Docker/Mininet integration run in this session due Docker socket permission issue.
- no new screenshot set generated in this session.

### Test matrix

| Test ID | Test/scenario | Command | Purpose | Expected result | Observed result | Evidence source | Status |
|---|---|---|---|---|---|---|---|
| T-01 | repository unit suite | `python3 -m unittest discover -s tests -p "test_*.py"` | verify test baseline | tests pass or expose failures | `Ran 183`, `OK (skipped=15)` | command output | VERIFIED |
| T-02 | pytest CLI availability | `pytest --version` | verify preferred runner exists | version string | `command not found` | command output | FAILED_ENVIRONMENT |
| T-03 | pytest module availability | `python3 -m pytest -q` | verify module availability | pytest collection/run | `No module named pytest` | command output | FAILED_ENVIRONMENT |
| T-04 | optional dependency skip guards | `rg -n "skipIf|skipUnless" tests` | explain skipped tests | skip guards for optional deps | pandas/Flask skip guards found | grep output | VERIFIED |
| T-05 | dashboard smoke script | `python3 scripts/integration_dashboard_smoke.py` | API/page response validation | all checks pass | not run in this recon | script file | NOT_EXECUTED |
| T-06 | IDS mode switch integration | `python3 scripts/integration_ids_mode_switch.py` | validate runtime mode cycling | queued commands complete and mode changes | not run in this recon | script file | NOT_EXECUTED |
| T-07 | security workflow integration | `python3 scripts/integration_security_workflow.py` | verify attack->block->capture->unblock path | quarantine + snapshot + unblock observed | not run in this recon | script file | NOT_EXECUTED |
| T-08 | topology/lab availability | `docker compose ps` | verify service state for runtime tests | containers listed running | Docker socket permission denied | command output | FAILED_ENVIRONMENT |
| T-09 | threshold recon validation artifact | N/A (artifact inspection) | verify historical threshold run evidence | detected/blocked scenarios recorded | file contains per-scenario detected/blocked fields | `runtime/threshold_recon_validation_20260416.json` | VERIFIED |
| T-10 | threshold tuning validation artifact | N/A (artifact inspection) | verify historical threshold tuning evidence | mode/scenario deltas recorded | file contains `mode=threshold_only` entries and deltas | `runtime/threshold_validation_after_tuning_20260416.json` | VERIFIED |
| T-11 | mixed mode attack validation artifact | N/A (artifact inspection) | verify historical threshold+ml mode outcomes | threshold/ml mode entries with detections | file contains `threshold_only` and `ml_only` entries | `runtime/attack_validation_20260416_180530.json` | VERIFIED |
| T-12 | experiment output bundle | N/A (artifact inspection) | verify evaluation harness outputs | manifest + summary/comparison files | rich outputs present in `hybrid_policy_resume_v2_20260425` | experiments results directory | VERIFIED |
| T-13 | static firewall baseline run completeness | N/A (artifact inspection) | prove static baseline comparison outputs | full per-run artifacts for static mode | mode declared in manifest; full run outputs not clearly co-located | `evaluation_20260313_094548/manifest.json` | PARTIAL |

### ML metrics table

| Model | Metric file | Dataset/source | Split method | Test size | Accuracy | Precision | Recall | F1 | Limitations |
|---|---|---|---|---|---|---|---|---|---|
| Random Forest runtime | `models/random_forest_runtime_final_metrics.json` | `datasets/merged_runtime_dataset.parquet` | grouped by `Run ID` (`split_mode=grouped`) | `0.2` | `1.0` | `1.0` (weighted avg) | `1.0` (weighted avg) | `1.0` (weighted avg) | Perfect scores are bounded by the available controlled dataset and do not prove production generalisation. |
| Isolation Forest runtime (A) | `models/isolation_forest_benign_heavy_20260417_metrics.json` | benign-heavy snapshot + merged runtime eval input | holdout benign + malicious eval rows | `0.25` (from trainer defaults; file reports evaluated rows) | N/A (anomaly model) | N/A | anomaly detection rate `0.6601` | N/A | Not directly comparable to classifier accuracy/F1; evaluate with FPR + detection-rate context. |
| Isolation Forest runtime (B) | `models/isolation_forest_benign_heavy_20260417b_metrics.json` | benign-heavy snapshot (v2) + merged runtime eval input | holdout benign + malicious eval rows | `0.25` (from trainer defaults; file reports evaluated rows) | N/A (anomaly model) | N/A | anomaly detection rate `0.6957` | N/A | Dataset-conditioned anomaly metrics; still controlled-lab evidence only. |

Note: Perfect or near-perfect controlled-dataset outcomes should be reported cautiously as lab-bounded evidence, not production generalisation.

## 9. Source Code Listing and Repository Structure Evidence

### 9.1 Repository Tree
- top-level modules include: `controller`, `core`, `security`, `ml`, `monitoring`, `topology`, `scripts`, `experiments`, `tests`, `captures`, `runtime`, `datasets`, `models`.
- top-level tree summary command result: `40 directories, 178 files` (excluding large ignored patterns in tree command).

### 9.2 Folder Purpose Table

| Folder | Purpose | Status |
|---|---|---|
| `controller/` | Ryu app entrypoint, event handling, forwarding policy glue | IMPLEMENTED |
| `core/` | flow management, packet parsing, command queue, mode helpers | IMPLEMENTED |
| `security/` | firewall rules, threshold IDS logic, mitigation/quarantine | IMPLEMENTED |
| `ml/` | inference pipeline, model loading/export, anomaly support, feature processing | IMPLEMENTED |
| `monitoring/` | Flask dashboard app, API routes, state/report generation | IMPLEMENTED |
| `topology/` | Mininet topology startup and runtime monitoring | IMPLEMENTED |
| `scripts/` | operational scripts (topology, captures, training, integration checks) | IMPLEMENTED |
| `experiments/` | experiment harness and result extraction/reporting | IMPLEMENTED |
| `tests/` | unit and utility tests | IMPLEMENTED |
| `captures/` | capture manager + collected ring/snapshot artifacts | VERIFIED |
| `runtime/` | state files, command history, runtime validations, JSONL streams | VERIFIED |
| `datasets/` | runtime/offline parquet datasets | VERIFIED |
| `models/` | trained model bundles and metrics manifests | VERIFIED |

### 9.3 Key File Table

| File path | Role | Main classes/functions | Appendix relevance | Notes |
|---|---|---|---|---|
| `controller/main.py` | Main Ryu controller | `SecurityController`, `packet_in_handler`, `switch_features_handler`, dashboard command processors | System manual, implementation audit | OpenFlow 1.3, IDS+ML+mitigation orchestration |
| `core/flow_manager.py` | OpenFlow rule manager | `install_table_miss`, `install_source_block`, `install_service_port_block`, `send_packet` | implementation audit | Drop-flow construction and priorities |
| `security/firewall.py` | Policy + quarantine state | `FirewallPolicy.evaluate`, `add_quarantine`, `remove_quarantine` | system/manual + feature claims | static + dynamic enforcement paths |
| `security/ids.py` | Threshold IDS | `ThresholdIDS.inspect`, alert builders, sliding windows | implementation audit + test evidence | scan/flood/failed-connection/unanswered SYN detectors |
| `security/mitigation.py` | Mitigation service | `MitigationService.handle_alert`, `manual_unblock` | user manual + mitigation evidence | manual release and quarantine eligibility logic |
| `ml/pipeline.py` | IDS mode and hybrid logic | `MLIDSPipeline`, hybrid block decision helpers | ML appendix evidence | `threshold_only`, `ml_only`, `hybrid` behavior |
| `ml/inference.py` | classifier/anomaly/combined inference | `InferenceEngine.predict` and mode-specific helpers | ML implementation section | combined RF+IF reasoning paths |
| `captures/capture_manager.py` | Rolling and snapshot capture | `start_continuous_capture`, `preserve_snapshot` | packet-capture appendix evidence | writes metadata and runtime capture events |
| `monitoring/webapp.py` | Dashboard page routes | `PAGE_DEFINITIONS`, `create_app` | user manual | page list and capture download endpoint |
| `monitoring/api.py` | Dashboard API | health/alerts/blocks/mode/captures/reports endpoints | API appendix table | command queue interface for unblock/mode switch |
| `monitoring/state.py` | Runtime state adapter/report builder | payload generation, report builders | supporting docs/data | report download definitions |
| `topology/custom_topology.py` | Mininet topology | `SecurityLabTopo`, `build_network` | system manual | 3-switch OpenFlow13 topology + capture manager hookup |
| `scripts/run_topology.sh` | Topology launcher | compose exec wrapper | runbook commands | cleans stale Mininet state by default |
| `scripts/train_random_forest.py` | RF trainer | schema resolution + runtime-feature training | ML workflow | writes model bundle + metrics + feature manifest |
| `experiments/common.py` | Scenario and mode definitions | `EvaluationMode`, `EvaluationScenario`, `default_modes`, `default_scenarios` | test/report appendices | includes static firewall baseline mode definitions |

### 9.4 Recommended Source Code Appendix Strategy
- include a concise top-level tree plus focused key-file excerpts per subsystem.
- include only files needed to explain architecture, operation, and assessment claims.
- keep generated artifacts out of source listing; reference them in supporting-data appendix instead.

### 9.5 Files to Include
- controller entry and orchestration: `controller/main.py`
- flow and policy logic: `core/flow_manager.py`, `security/firewall.py`, `security/ids.py`, `security/mitigation.py`
- ML runtime logic: `ml/pipeline.py`, `ml/inference.py`, `ml/model_loader.py`
- dashboard/API: `monitoring/webapp.py`, `monitoring/api.py`, `monitoring/state.py`
- topology and operations: `topology/custom_topology.py`, `scripts/run_topology.sh`, `docker-compose.yml`, `Dockerfile`, `Dockerfile.mininet`
- tests representative set: IDS, mitigation, monitoring, ML pipeline, experiment extraction tests.

### 9.6 Files to Exclude
- generated or runtime evidence bulk: `runtime/**`, `captures/output/**`, `experiments/results/**`
- large data/model binaries: `datasets/*.parquet`, `models/*.joblib`, large JSON metrics dumps unless sampled
- local environments/caches: `.venv*`, `__pycache__`, `.pytest_cache`
- transient logs: `logs/controller.log` (include short excerpts only)
- sensitive/local-only env overrides: `.env` full contents (only safe var names/defaults in appendix)

## 10. Feature and Claim Evidence Matrix

| Claim/feature | Evidence found | Evidence type | Status | Safe wording for report |
|---|---|---|---|---|
| OpenFlow 1.3 controller | `OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]` and topology switches `protocols="OpenFlow13"` | code | IMPLEMENTED | The repository implements an OpenFlow 1.3 controller path in code and topology configuration. |
| Ryu controller operation | Ryu app class + extensive controller runtime log entries | code + runtime log | VERIFIED | The available evidence supports that the Ryu controller has run and emitted operational events in prior lab sessions. |
| firewall enforcement | static/restricted/quarantine logic in firewall + drop-flow logs | code + runtime log | VERIFIED | The available evidence supports firewall enforcement, including runtime drop-flow installation for blocked sources. |
| threshold IDS | threshold detectors in `security/ids.py` + threshold validation JSON artifacts | code + runtime artifact | VERIFIED | The repository implements threshold IDS, and historical runtime validation artifacts show threshold detections and blocks. |
| Random Forest support | RF model path/config + inference engine + RF metrics/model files | code + model/metrics artifacts | VERIFIED | The repository includes Random Forest inference support with offline training outputs present in the project artifacts. |
| Isolation Forest support | anomaly engine + IF metrics/model files | code + model/metrics artifacts | VERIFIED | The repository includes Isolation Forest anomaly support with recorded evaluation metrics in controlled datasets. |
| hybrid IDS support | `threshold_only/ml_only/hybrid` modes + hybrid correlation/block logic + runtime mode state | code + runtime state/log | VERIFIED | The available evidence supports hybrid IDS mode support and persisted runtime mode state. |
| mitigation/quarantine | mitigation service + quarantine record/flow logic + runtime logs | code + runtime log | VERIFIED | The repository implements quarantine-based mitigation and historical logs indicate quarantine events occurred. |
| manual unblock | unblock API + command queue + processed command JSON + manual-unblock log | code + runtime artifact/log | VERIFIED | The available evidence supports an analyst-triggered manual unblock workflow implemented through dashboard API and command queue. |
| packet capture snapshots | capture manager + snapshot metadata files + pcap corpus | code + metadata/files | VERIFIED | The repository implements rolling captures and preserved snapshots with metadata linking to detection context. |
| dashboard/API monitoring | Flask pages/routes + API endpoints + dashboard state file | code + runtime state file | VERIFIED | The repository implements a dashboard/API monitoring layer, with runtime state artifacts available from prior runs. |
| static firewall baseline | baseline mode defined in experiment modes/manifest | config + manifest | PARTIAL | Static-firewall comparison mode is defined in the harness; runtime proof in this recon is partial and should be treated cautiously. |
| unit test evidence | `unittest` run passed (`183` run) | test command output | VERIFIED | The available evidence supports unit-test execution in this environment via `unittest` discovery. |
| integration test evidence | integration scripts exist; not rerun in this session | script existence | PARTIAL | Integration workflows are implemented in scripts, but this recon did not execute them live. |
| ML metrics | RF and IF metrics JSON files present with values | metrics files | VERIFIED | The available evidence supports offline ML metrics in controlled datasets; interpretation should remain dataset-bounded. |
| PCAP validation | pcap files + snapshot metadata present; no decode performed in this session | files + metadata | PARTIAL | PCAP artifacts are present with metadata linkage; independent packet-level validation was not executed during this recon. |
| latency measurement | no dedicated latency report artifact identified | absence check | MISSING | Runtime verification was not found for explicit latency measurement artifacts in this recon output set. |
| dataset recording | recorder implementation + runtime JSONL/parquet artifacts | code + artifact files | VERIFIED | The available evidence supports runtime dataset recording and export workflows in the repository artifacts. |
| experiment harness | mode/scenario harness and result extraction code + result bundles | code + artifact files | VERIFIED | The repository implements a repeatable experiment harness with generated comparison outputs in results directories. |

## 11. Appendix Readiness Matrix

| Appendix | Required content | Evidence found | Evidence missing | Ready? | Notes |
|---|---|---|---|---|---|
| System Manual | install/runtime/dependency/env/startup/shutdown/troubleshooting | strong static evidence + partial runtime readiness checks + scripts | fresh successful container-status/build logs in this environment | Nearly ready | write with explicit environment caveats |
| User Manual | operator workflow/screens/pages/API/actions/screenshots | pages/routes/APIs/command queue and historical runtime artifacts present | screenshot pack and fresh live walkthrough outputs | Partial | requires capture checklist completion |
| Supporting Documentation or Data | architecture/data flow/artifacts/models/datasets/captures | rich code + runtime/model/result artifacts found | formal diagrams as image assets | Nearly ready | diagram generation still needed |
| Test Results and Test Reports | unit/integration/runtime scenario/metrics evidence | unit tests verified, metrics files, validation artifacts, experiment outputs | pytest availability + fresh integration run results + static baseline runtime completeness | Partial | avoid overclaiming; separate historical vs current-session evidence |
| Source Code Listing or Repository Structure | tree/key files/roles/include-exclude strategy | complete mapping and key-file matrix prepared | none critical | Ready | can be drafted directly from this evidence |

## 12. Missing Evidence and Follow-Up Checklist

| Priority | Missing item | Why it matters | Exact command/screenshot/action needed |
|---|---|---|---|
| High | Docker build/run success in current environment | confirms reproducibility on assessor machine/session | `docker compose build` then `docker compose up -d controller dashboard mininet` (capture terminal output) |
| High | Container status proof | required for startup verification | `docker compose ps` screenshot/output after successful startup |
| High | Controller OpenFlow handshake logs | proves switch-controller connectivity in current run | `docker compose logs --tail=200 controller` and capture lines showing datapath connect/baseline install |
| High | Mininet topology startup proof | verifies topology launch commands in current environment | run `./scripts/run_topology.sh` and capture startup terminal |
| High | Basic connectivity proof | baseline network correctness | in Mininet: `pingall` and capture output screenshot |
| High | Threshold IDS alert proof (fresh run) | validates detection claim in current session | run one threshold scenario (for example `h3 sh /workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2`) then capture `/alerts` and `/blocked-hosts` |
| High | Hybrid/ML prediction proof (fresh run) | validates ML/hybrid operational claims | set mode via settings or API then run scenario; capture `/ml-ids`, `/alerts`, and relevant API JSON |
| High | Manual unblock proof (fresh run) | validates analyst response workflow | trigger block, then unblock via `/blocked-hosts` UI; capture before/after |
| High | Drop-flow evidence in switch tables | proves enforcement at flow-rule level | in Mininet container run `ovs-ofctl -O OpenFlow13 dump-flows s1` (and s2/s3) after block; capture relevant drop entries |
| High | Snapshot metadata + pcap linkage proof (fresh) | ties alerts to forensic artifacts | collect snapshot during alert; save `snapshot.json` and optional `tcpdump -r`/`capinfos` summary |
| High | Dashboard screenshot pack | required by user-manual appendix | capture SS-01 to SS-10 checklist items |
| Medium | RF/IF metric reproduction logs | strengthens ML reproducibility | run training commands in offline env and archive console outputs + generated metric files |
| Medium | Experiment result regeneration | confirms evaluation pipeline reproducibility | `python3 experiments/run_evaluation.py --repeats 1` (or chosen modes) and archive result folder |
| Medium | Static firewall baseline runtime evidence completeness | supports baseline comparison chapter | run mode including `static_firewall` and ensure per-run outputs are saved in results folder |
| Medium | Latency measurement artifact | supports any latency claim | add explicit timestamped measurement script/report (for example scenario start-to-detect delta logs) |
| Low | License metadata | useful for repository governance appendix note | add license file if institution requires it |

## 13. Final Notes for Appendix Writer
- what can be written confidently:
  - repository architecture, module responsibilities, API surface, and command workflows are strongly evidenced from code.
  - historical runtime evidence exists for alerts, quarantines, mode switching, capture snapshots, and experiment outputs.
  - unit testing evidence is current-session verified through `unittest` discovery.
- what must be worded cautiously:
  - claims about "current environment is fully runnable" because Docker socket permissions blocked `docker compose ps` in this recon.
  - ML performance interpretation because metrics are controlled-dataset outcomes.
  - integration effectiveness unless you include fresh run logs/screenshots from this machine/session.
- what must not be claimed:
  - do not claim fresh end-to-end runtime verification from this recon for commands not executed.
  - do not claim production/generalised ML performance from offline dataset metrics.
  - do not claim latency improvements without explicit timestamped latency artifacts.
- what evidence should be moved to appendices rather than main chapters:
  - raw command outputs, runtime JSON/JSONL snapshots, selected `snapshot.json`, metrics JSON, experiment CSV/JSON, and log snippets.
  - test matrices and screenshot checklist.
- what should remain in Chapter 5 as summarised results:
  - high-level comparative findings (threshold vs ML/hybrid trends), key detection/mitigation observations, and concise interpretation.
- what belongs only in appendices as raw evidence:
  - full tables of endpoints/config vars, per-scenario result rows, command transcripts, artifact file inventories, and large runtime dumps.

| Appendix | Verdict | Reason |
|---|---|---|
| System Manual | Nearly ready | Strong static/install/config evidence exists, but current-session container runtime confirmation is blocked by Docker socket permissions. |
| User Manual | Partial | Workflows are implemented and historically evidenced, but required live screenshots and fresh UI walkthrough captures are missing. |
| Supporting Documentation or Data | Nearly ready | Rich architecture/data/model/capture artifacts are present; formal diagram image assets still need to be created. |
| Test Results and Test Reports | Partial | Unit tests are verified in-session and historical validation artifacts exist, but pytest/integration reruns and some baseline-runtime proof are incomplete. |
| Source Code Listing or Repository Structure | Ready | Repository tree, key folders/files, and inclusion/exclusion strategy are complete and evidence-backed. |
