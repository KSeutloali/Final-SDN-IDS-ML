# Experiment and Evaluation Framework

This folder contains a report-ready evaluation workflow for comparing four controller configurations:

1. `dynamic_enforcement`: SDN dynamic firewall and threshold IDS with automatic mitigation
2. `static_firewall`: static firewall policy only
3. `threshold_ids`: threshold IDS alerts only, without automatic mitigation
4. `ml_enhanced_ids`: threshold baseline plus hybrid ML IDS

The framework reuses the existing Docker, Mininet, packet capture, and monitoring-state pipeline instead of introducing a separate evaluation stack.

## Folder Layout

```text
experiments/
├── README.md
├── __init__.py
├── common.py
├── extract_results.py
├── live_ids_replay.py
├── report_sections.md
├── report_table_template.csv
├── results/
│   └── .gitkeep
├── run_evaluation.py
├── run_evaluation.sh
└── run_scenario.sh
```

## Metrics Collected

Per run, the framework exports:

- attack detection time
- mitigation time
- packets processed delta
- bytes processed delta
- packet drop or block count observed in controller logs
- flow installation count
- flow removal count
- active security-flow count after the scenario
- controller event count
- false positive estimate
- false negative estimate
- observed bytes per second
- benign latency indicators where available, such as average ping RTT
- capture session name, capture file count, and capture size

## Comparison Logic

The four requested comparisons are mapped as follows:

- `dynamic_enforcement`
  - `SDN_IDS_ENABLED=true`
  - `SDN_ML_ENABLED=false`
  - `SDN_MITIGATION_ENABLED=true`
- `static_firewall`
  - `SDN_IDS_ENABLED=false`
  - `SDN_ML_ENABLED=false`
  - static firewall rules only
- `threshold_ids`
  - `SDN_IDS_ENABLED=true`
  - `SDN_ML_ENABLED=false`
  - `SDN_MITIGATION_ENABLED=false`
- `ml_enhanced_ids`
  - `SDN_IDS_ENABLED=true`
  - `SDN_ML_ENABLED=true`
  - `SDN_ML_MODE=hybrid`
  - runtime model loaded from `--ml-model-path`

This keeps threshold IDS as the primary baseline while allowing alert-only threshold evaluation and hybrid ML comparison.

## Scenarios

Default scenarios:

- `benign`: `h1` runs `traffic/benign_traffic.sh 10.0.0.2 80`
- `port_scan`: `h3` runs `attacks/port_scan.sh 10.0.0.2`
- `dos`: `h3` runs `attacks/dos_flood.sh 10.0.0.2 80 <count>`

## Step-by-Step Evaluation Procedure

1. Start the Docker services:

```bash
docker compose up -d controller dashboard mininet
```

2. Start the Mininet topology in a dedicated terminal and keep it running:

```bash
./scripts/run_topology.sh
```

3. In another terminal, run the comparison harness:

```bash
python3 experiments/run_evaluation.py --repeats 3
```

4. Results are written to a timestamped directory such as:

```text
experiments/results/evaluation_20260313_140500/
```

5. Key outputs:

- `per_run.json`: detailed structured result for every repetition
- `per_run.csv`: plot-friendly per-run table
- `summary.json`: grouped results by mode and scenario
- `summary.csv`: grouped averages for report tables
- `runs/<mode>__<scenario>__rN/`: raw snapshots, controller log window, capture metadata, and command output

6. For report tables, copy or adapt `report_table_template.csv`.

7. For report prose, adapt `report_sections.md`.

## Example Commands

Run the full comparison with captures:

```bash
python3 experiments/run_evaluation.py --repeats 3
```

Run only the dynamic enforcement and ML comparison:

```bash
python3 experiments/run_evaluation.py \
  --modes dynamic_enforcement,ml_enhanced_ids \
  --repeats 3
```

Use a different runtime model:

```bash
python3 experiments/run_evaluation.py \
  --ml-model-path models/collected_runtime_model_20260312_122214.joblib
```

Increase the flood intensity:

```bash
python3 experiments/run_evaluation.py \
  --scenarios dos \
  --flood-count 3000 \
  --repeats 5
```

Disable packet captures during quick dry runs:

```bash
python3 experiments/run_evaluation.py --no-captures --repeats 1
```

## Outputs and Interpretation

- `attack_detection_time_seconds`:
  - first threshold IDS alert, ML alert, or hybrid agreement after the scenario begins
- `mitigation_time_seconds`:
  - first temporary block event or first static policy block observed after the scenario begins
- `false_positive_estimate`:
  - benign scenario produced an IDS or ML detection
- `false_negative_estimate`:
  - malicious scenario produced no IDS or ML detection

These values are estimators derived from controlled scenario labels and controller-observed events. They are intended for a student project report, not for production-grade benchmarking claims.

