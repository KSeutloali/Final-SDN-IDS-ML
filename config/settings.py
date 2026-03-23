"""Configuration for the modular firewall, threshold IDS, and optional ML IDS."""

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Tuple

from core.ids_mode import normalize_ids_mode_internal


def _env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _env_float(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return float(value)


def _env_str(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value


def _env_tuple(name, default):
    value = os.getenv(name)
    if value is None or not value.strip():
        return tuple(default)
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _env_int_tuple(name, default):
    return tuple(int(item) for item in _env_tuple(name, default))


def _env_ids_mode(default):
    explicit_mode = os.getenv("SDN_IDS_MODE")
    if explicit_mode is not None:
        return normalize_ids_mode_internal(explicit_mode, default=default)
    legacy_mode = os.getenv("SDN_ML_MODE")
    if legacy_mode is not None:
        return normalize_ids_mode_internal(legacy_mode, default=default)
    return normalize_ids_mode_internal(default, default=default)


@dataclass(frozen=True)
class ControllerConfig:
    openflow_host: str = "0.0.0.0"
    openflow_port: int = 6633


@dataclass(frozen=True)
class FlowPriorityConfig:
    table_miss: int = 0
    forwarding: int = 10
    packet_block: int = 220
    restricted_service_block: int = 260
    static_source_block: int = 280
    temporary_source_block: int = 300


@dataclass(frozen=True)
class FlowTimeoutConfig:
    learned_idle_seconds: int = 60
    learned_hard_seconds: int = 0
    packet_block_seconds: int = 30


@dataclass(frozen=True)
class FirewallConfig:
    internal_subnet: str = "10.0.0.0/24"
    allow_arp: bool = True
    allow_internal_subnet: bool = True
    permit_icmp: bool = True
    permit_icmp_external: bool = False
    default_allow_ipv4: bool = True
    blocked_source_ips: Tuple[str, ...] = field(default_factory=tuple)
    restricted_tcp_ports: Tuple[int, ...] = (23,)
    restricted_udp_ports: Tuple[int, ...] = field(default_factory=tuple)
    dynamic_block_duration_seconds: int = 60

    @property
    def internal_network(self):
        return ipaddress.ip_network(self.internal_subnet, strict=False)


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file_path: str = "logs/controller.log"
    format_string: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    log_allowed_traffic: bool = False


@dataclass(frozen=True)
class DashboardConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    base_path: str = "/sdn-security"
    poll_interval_seconds: float = 1.0
    state_file_path: str = "runtime/dashboard_state.json"
    persist_interval_seconds: float = 0.25
    timeseries_points: int = 120


@dataclass(frozen=True)
class IDSConfig:
    enabled: bool = True
    inspect_tcp_udp_packets: bool = True
    packet_rate_window_seconds: int = 5
    packet_rate_threshold: int = 250
    syn_rate_window_seconds: int = 5
    syn_rate_threshold: int = 100
    scan_window_seconds: int = 10
    unique_destination_ports_threshold: int = 12
    unique_destination_hosts_threshold: int = 6
    failed_connection_window_seconds: int = 10
    failed_connection_threshold: int = 8
    connection_attempt_window_seconds: int = 15
    alert_suppression_seconds: int = 20


@dataclass(frozen=True)
class MitigationConfig:
    enabled: bool = True
    quarantine_enabled: bool = True
    auto_unblock_enabled: bool = False
    manual_unblock_enabled: bool = True


@dataclass(frozen=True)
class CaptureConfig:
    enabled: bool = True
    continuous_enabled: bool = True
    tool: str = "tcpdump"
    interfaces: Tuple[str, ...] = (
        "h1-eth0",
        "h3-eth0",
        "h2-eth0",
        "s2-eth3",
    )
    output_directory: str = "captures/output"
    snaplen: int = 160
    ring_file_seconds: int = 30
    ring_file_count: int = 12
    snapshot_files_per_interface: int = 2
    snapshot_settle_seconds: float = 1.0
    snapshot_cooldown_seconds: int = 10


@dataclass(frozen=True)
class MLConfig:
    enabled: bool = False
    mode: str = "threshold_only"
    mode_state_path: str = "runtime/ids_mode_state.json"
    hybrid_policy: str = "alert_only"
    model_path: str = "models/random_forest_ids.joblib"
    dataset_path: str = "datasets/cicids2018.parquet"
    dataset_recording_enabled: bool = False
    dataset_recording_path: str = "runtime/ml_dataset.jsonl"
    dataset_label_path: str = "runtime/dataset_label.json"
    dataset_label_refresh_seconds: float = 1.0
    dataset_record_unlabeled: bool = False
    dataset_disable_mitigation: bool = False
    feature_window_seconds: int = 10
    unanswered_syn_timeout_seconds: float = 1.5
    minimum_packets_before_inference: int = 12
    inference_packet_stride: int = 6
    inference_cooldown_seconds: float = 2.0
    confidence_threshold: float = 0.75
    mitigation_threshold: float = 0.92
    alert_suppression_seconds: int = 20
    hybrid_correlation_window_seconds: int = 10
    positive_labels: Tuple[str, ...] = (
        "attack",
        "malicious",
        "anomaly",
        "suspicious",
        "scan",
        "dos",
        "ddos",
        "portscan",
        "1",
        "true",
    )


@dataclass(frozen=True)
class AppConfig:
    controller: ControllerConfig = field(default_factory=ControllerConfig)
    flow_priorities: FlowPriorityConfig = field(default_factory=FlowPriorityConfig)
    flow_timeouts: FlowTimeoutConfig = field(default_factory=FlowTimeoutConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    ids: IDSConfig = field(default_factory=IDSConfig)
    mitigation: MitigationConfig = field(default_factory=MitigationConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    ml: MLConfig = field(default_factory=MLConfig)


def load_config():
    """Load controller configuration from environment variables."""

    return AppConfig(
        controller=ControllerConfig(
            openflow_host=_env_str("SDN_OPENFLOW_HOST", "0.0.0.0"),
            openflow_port=_env_int("SDN_OPENFLOW_PORT", 6633),
        ),
        flow_priorities=FlowPriorityConfig(
            table_miss=_env_int("SDN_FLOW_TABLE_MISS_PRIORITY", 0),
            forwarding=_env_int("SDN_FLOW_FORWARDING_PRIORITY", 10),
            packet_block=_env_int("SDN_FLOW_PACKET_BLOCK_PRIORITY", 220),
            restricted_service_block=_env_int(
                "SDN_FLOW_RESTRICTED_SERVICE_BLOCK_PRIORITY",
                260,
            ),
            static_source_block=_env_int(
                "SDN_FLOW_STATIC_SOURCE_BLOCK_PRIORITY",
                280,
            ),
            temporary_source_block=_env_int(
                "SDN_FLOW_TEMPORARY_SOURCE_BLOCK_PRIORITY",
                300,
            ),
        ),
        flow_timeouts=FlowTimeoutConfig(
            learned_idle_seconds=_env_int("SDN_FLOW_LEARNED_IDLE_SECONDS", 60),
            learned_hard_seconds=_env_int("SDN_FLOW_LEARNED_HARD_SECONDS", 0),
            packet_block_seconds=_env_int("SDN_FLOW_PACKET_BLOCK_SECONDS", 30),
        ),
        firewall=FirewallConfig(
            internal_subnet=_env_str("SDN_FIREWALL_INTERNAL_SUBNET", "10.0.0.0/24"),
            allow_arp=_env_bool("SDN_FIREWALL_ALLOW_ARP", True),
            allow_internal_subnet=_env_bool(
                "SDN_FIREWALL_ALLOW_INTERNAL_SUBNET",
                True,
            ),
            permit_icmp=_env_bool("SDN_FIREWALL_PERMIT_ICMP", True),
            permit_icmp_external=_env_bool(
                "SDN_FIREWALL_PERMIT_ICMP_EXTERNAL",
                False,
            ),
            default_allow_ipv4=_env_bool(
                "SDN_FIREWALL_DEFAULT_ALLOW_IPV4",
                True,
            ),
            blocked_source_ips=_env_tuple(
                "SDN_FIREWALL_BLOCKED_SOURCE_IPS",
                (),
            ),
            restricted_tcp_ports=_env_int_tuple(
                "SDN_FIREWALL_RESTRICTED_TCP_PORTS",
                (23,),
            ),
            restricted_udp_ports=_env_int_tuple(
                "SDN_FIREWALL_RESTRICTED_UDP_PORTS",
                (),
            ),
            dynamic_block_duration_seconds=_env_int(
                "SDN_FIREWALL_DYNAMIC_BLOCK_SECONDS",
                60,
            ),
        ),
        logging=LoggingConfig(
            level=_env_str("SDN_LOG_LEVEL", "INFO"),
            file_path=_env_str("SDN_LOG_FILE", "logs/controller.log"),
            format_string=_env_str(
                "SDN_LOG_FORMAT",
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            ),
            log_allowed_traffic=_env_bool(
                "SDN_LOG_ALLOWED_TRAFFIC",
                False,
            ),
        ),
        dashboard=DashboardConfig(
            host=_env_str("SDN_DASHBOARD_HOST", "0.0.0.0"),
            port=_env_int("SDN_DASHBOARD_PORT", 8080),
            base_path=_env_str("SDN_DASHBOARD_BASE_PATH", "/sdn-security"),
            poll_interval_seconds=_env_float(
                "SDN_DASHBOARD_POLL_INTERVAL_SECONDS",
                1.0,
            ),
            state_file_path=_env_str(
                "SDN_DASHBOARD_STATE_FILE",
                "runtime/dashboard_state.json",
            ),
            persist_interval_seconds=_env_float(
                "SDN_DASHBOARD_PERSIST_INTERVAL_SECONDS",
                0.25,
            ),
            timeseries_points=_env_int(
                "SDN_DASHBOARD_TIMESERIES_POINTS",
                120,
            ),
        ),
        ids=IDSConfig(
            enabled=_env_bool("SDN_IDS_ENABLED", True),
            inspect_tcp_udp_packets=_env_bool(
                "SDN_IDS_INSPECT_TCP_UDP_PACKETS",
                True,
            ),
            packet_rate_window_seconds=_env_int(
                "SDN_IDS_PACKET_RATE_WINDOW_SECONDS",
                5,
            ),
            packet_rate_threshold=_env_int(
                "SDN_IDS_PACKET_RATE_THRESHOLD",
                250,
            ),
            syn_rate_window_seconds=_env_int(
                "SDN_IDS_SYN_RATE_WINDOW_SECONDS",
                5,
            ),
            syn_rate_threshold=_env_int(
                "SDN_IDS_SYN_RATE_THRESHOLD",
                100,
            ),
            scan_window_seconds=_env_int(
                "SDN_IDS_SCAN_WINDOW_SECONDS",
                10,
            ),
            unique_destination_ports_threshold=_env_int(
                "SDN_IDS_UNIQUE_DESTINATION_PORTS_THRESHOLD",
                12,
            ),
            unique_destination_hosts_threshold=_env_int(
                "SDN_IDS_UNIQUE_DESTINATION_HOSTS_THRESHOLD",
                6,
            ),
            failed_connection_window_seconds=_env_int(
                "SDN_IDS_FAILED_CONNECTION_WINDOW_SECONDS",
                10,
            ),
            failed_connection_threshold=_env_int(
                "SDN_IDS_FAILED_CONNECTION_THRESHOLD",
                8,
            ),
            connection_attempt_window_seconds=_env_int(
                "SDN_IDS_CONNECTION_ATTEMPT_WINDOW_SECONDS",
                15,
            ),
            alert_suppression_seconds=_env_int(
                "SDN_IDS_ALERT_SUPPRESSION_SECONDS",
                20,
            ),
        ),
        mitigation=MitigationConfig(
            enabled=_env_bool("SDN_MITIGATION_ENABLED", True),
            quarantine_enabled=_env_bool("SDN_QUARANTINE_ENABLED", True),
            auto_unblock_enabled=_env_bool("SDN_AUTO_UNBLOCK_ENABLED", False),
            manual_unblock_enabled=_env_bool("SDN_MANUAL_UNBLOCK_ENABLED", True),
        ),
        capture=CaptureConfig(
            enabled=_env_bool("SDN_CAPTURE_ENABLED", True),
            continuous_enabled=_env_bool("SDN_CAPTURE_CONTINUOUS_ENABLED", True),
            tool=_env_str("SDN_CAPTURE_TOOL", "tcpdump"),
            interfaces=_env_tuple(
                "SDN_CAPTURE_INTERFACES",
                ("h1-eth0", "h3-eth0", "h2-eth0", "s2-eth3"),
            ),
            output_directory=_env_str("SDN_CAPTURE_OUTPUT_DIRECTORY", "captures/output"),
            snaplen=_env_int("SDN_CAPTURE_SNAPLEN", 160),
            ring_file_seconds=_env_int("SDN_CAPTURE_RING_FILE_SECONDS", 30),
            ring_file_count=_env_int("SDN_CAPTURE_RING_FILE_COUNT", 12),
            snapshot_files_per_interface=_env_int(
                "SDN_CAPTURE_SNAPSHOT_FILES_PER_INTERFACE",
                2,
            ),
            snapshot_settle_seconds=_env_float(
                "SDN_CAPTURE_SNAPSHOT_SETTLE_SECONDS",
                1.0,
            ),
            snapshot_cooldown_seconds=_env_int(
                "SDN_CAPTURE_SNAPSHOT_COOLDOWN_SECONDS",
                10,
            ),
        ),
        ml=MLConfig(
            enabled=_env_bool("SDN_ML_ENABLED", False),
            mode=_env_ids_mode("threshold"),
            mode_state_path=_env_str(
                "SDN_IDS_MODE_STATE_PATH",
                "runtime/ids_mode_state.json",
            ),
            hybrid_policy=_env_str(
                "SDN_ML_HYBRID_POLICY",
                "alert_only",
            ).strip().lower(),
            model_path=_env_str(
                "SDN_ML_MODEL_PATH",
                "models/random_forest_ids.joblib",
            ),
            dataset_path=_env_str(
                "SDN_ML_DATASET_PATH",
                "datasets/cicids2018.parquet",
            ),
            dataset_recording_enabled=_env_bool(
                "SDN_ML_DATASET_RECORDING_ENABLED",
                False,
            ),
            dataset_recording_path=_env_str(
                "SDN_ML_DATASET_RECORDING_PATH",
                "runtime/ml_dataset.jsonl",
            ),
            dataset_label_path=_env_str(
                "SDN_ML_DATASET_LABEL_PATH",
                "runtime/dataset_label.json",
            ),
            dataset_label_refresh_seconds=_env_float(
                "SDN_ML_DATASET_LABEL_REFRESH_SECONDS",
                1.0,
            ),
            dataset_record_unlabeled=_env_bool(
                "SDN_ML_DATASET_RECORD_UNLABELED",
                False,
            ),
            dataset_disable_mitigation=_env_bool(
                "SDN_ML_DATASET_DISABLE_MITIGATION",
                False,
            ),
            feature_window_seconds=_env_int(
                "SDN_ML_FEATURE_WINDOW_SECONDS",
                10,
            ),
            unanswered_syn_timeout_seconds=_env_float(
                "SDN_ML_UNANSWERED_SYN_TIMEOUT_SECONDS",
                1.5,
            ),
            minimum_packets_before_inference=_env_int(
                "SDN_ML_MINIMUM_PACKETS_BEFORE_INFERENCE",
                12,
            ),
            inference_packet_stride=_env_int(
                "SDN_ML_INFERENCE_PACKET_STRIDE",
                6,
            ),
            inference_cooldown_seconds=_env_float(
                "SDN_ML_INFERENCE_COOLDOWN_SECONDS",
                2.0,
            ),
            confidence_threshold=_env_float(
                "SDN_ML_CONFIDENCE_THRESHOLD",
                0.75,
            ),
            mitigation_threshold=_env_float(
                "SDN_ML_MITIGATION_THRESHOLD",
                0.92,
            ),
            alert_suppression_seconds=_env_int(
                "SDN_ML_ALERT_SUPPRESSION_SECONDS",
                20,
            ),
            hybrid_correlation_window_seconds=_env_int(
                "SDN_ML_HYBRID_CORRELATION_WINDOW_SECONDS",
                10,
            ),
            positive_labels=_env_tuple(
                "SDN_ML_POSITIVE_LABELS",
                (
                    "attack",
                    "malicious",
                    "anomaly",
                    "suspicious",
                    "scan",
                    "dos",
                    "ddos",
                    "portscan",
                    "1",
                    "true",
                ),
            ),
        ),
    )
