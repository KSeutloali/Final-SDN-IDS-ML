# Methodology Draft

## Methodology

The evaluation was performed in a Docker-hosted Mininet testbed controlled by a Ryu v4.30 OpenFlow 1.3 controller. The controller implements a modular SDN security pipeline consisting of a static firewall policy, a threshold-based IDS, optional temporary mitigation, and an optional ML-enhanced IDS path. To compare defensive behavior under equivalent traffic conditions, the controller was executed in four modes: static firewall only, SDN dynamic firewall/IDS enforcement, threshold IDS without automatic mitigation, and ML-enhanced hybrid IDS. Each mode was exercised using the same benign, port-scan, and DoS scenarios.

Each experiment run started from a fresh controller instance to reduce cross-run contamination from learned flow state, alert caches, or temporary source blocks. A running Mininet topology was maintained throughout the evaluation so that switch reconnection behavior remained representative of the deployed system. For every run, the framework recorded controller-state snapshots before and after the scenario, captured controller logs generated during the scenario window, and optionally stored packet captures from selected Mininet interfaces.

The benign scenario used ICMP and HTTP traffic generated from a normal client to the web server. The port-scan scenario used `nmap` SYN probing from the attacker host, and the DoS scenario used `hping3` SYN flooding against the primary web service. These scenarios were chosen because they align with the rule-based firewall logic, the threshold IDS design, and the current ML feature set derived from controller-observed traffic windows.

## Evaluation

The primary evaluation metrics were attack detection time, mitigation time, controller-observed packet volume, packet block count, flow installation count, flow removal count, and controller event volume. When feasible, the framework also recorded benign latency indicators such as average ping RTT and command-level HTTP success. False positives and false negatives were estimated from the known scenario labels: benign runs that produced alerts or mitigation were counted as potential false positives, while malicious runs with no detection event were counted as potential false negatives.

Dynamic SDN enforcement was expected to perform best in mitigation time because threshold alerts directly trigger temporary source blocking through OpenFlow drop rules. Static firewall behavior was expected to demonstrate limited protection because it only enforces predefined policy rules such as blocked service ports and cannot identify broader attack patterns. Threshold IDS mode isolates the value of rule-based detection from the effects of automatic mitigation, while the ML-enhanced mode evaluates whether hybrid correlation and ML inference provide additional detection value beyond the threshold baseline.

The exported `per_run.csv` file is intended for detailed analysis, while `summary.csv` is intended for plots and report tables. Suggested plots include detection time by mode, mitigation time by mode, packet drops by scenario, flow installs and removals over time, and false positive/false negative rates across the four controller configurations.

## Limitations and Threats to Validity

- The Mininet topology is intentionally small and deterministic, so it may not represent production-scale traffic diversity.
- Controller-observed packet statistics are not identical to full wire-rate traffic telemetry, especially once forwarding flows are installed in the switches.
- False positives and false negatives are estimated from scenario labels rather than exhaustive packet-level ground truth.
- Throughput is reported as controller-observed byte deltas per second, which is a lightweight proxy rather than an end-to-end application throughput benchmark.
- If the ML runtime model is weak or poorly aligned with the live feature space, hybrid comparison results should be interpreted as a system-integration result rather than a definitive ML benchmark.
- Attack timing and packet-loss behavior can vary across runs due to container scheduling and Mininet timing noise.

