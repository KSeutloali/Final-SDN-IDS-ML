"""Main Ryu controller with modular firewall, threshold IDS, and optional ML IDS."""

import time

from captures.capture_manager import PacketCaptureManager
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from config.settings import load_config
from controller.events import (
    ControllerState,
    clear_runtime_topology_state,
    format_dpid,
    learn_host,
    lookup_output_port,
    register_datapath,
    unregister_datapath,
)
from controller.forwarding_policy import classify_visibility, should_install_forward_flow
from core.command_queue import ControllerCommandQueue
from core.flow_manager import FlowManager
from core.ids_mode import IDSModeStateStore, resolve_startup_ids_mode
from core.packet_parser import PacketParser
from monitoring.logger import StructuredLogger, configure_logger
from monitoring.metrics import MetricsStore
from monitoring.state import DashboardStateWriter
from ml.dataset_recorder import RuntimeDatasetRecorder
from ml.pipeline import MLIDSPipeline
from security.firewall import FirewallPolicy
from security.ids import ThresholdIDS
from security.mitigation import (
    MitigationService,
    clear_quarantines_for_topology_idle,
    should_auto_quarantine_threshold_alert,
)


class SecurityController(app_manager.RyuApp):
    """Modular OpenFlow 1.3 controller with firewall and threshold IDS."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)
        self.config = load_config()
        base_logger = configure_logger(self.config.logging)
        self.event_logger = StructuredLogger(
            base_logger,
            log_allowed_traffic=self.config.logging.log_allowed_traffic,
        )
        self.state = ControllerState()
        self.packet_parser = PacketParser()
        self.flow_manager = FlowManager(
            self.config.flow_priorities,
            self.config.flow_timeouts,
            flow_event_callback=self._handle_flow_event,
        )
        self.firewall = FirewallPolicy(
            self.config.firewall,
            self.config.flow_priorities,
            self.config.flow_timeouts,
            self.flow_manager,
        )
        self.metrics = MetricsStore()
        self.dashboard_state = DashboardStateWriter(self.config.dashboard)
        self.command_queue = ControllerCommandQueue()
        self.ids = ThresholdIDS(self.config.ids)
        self.ml_pipeline = MLIDSPipeline(self.config.ml)
        self.ids_mode_store = IDSModeStateStore(self.config.ml.mode_state_path)
        self.dataset_recorder = RuntimeDatasetRecorder(self.config.ml)
        self.capture_manager = PacketCaptureManager(
            self.config.capture,
            logger=base_logger,
            manage_workers=False,
        )
        self._last_reconnect_reset_at = 0.0
        self.mitigation = MitigationService(
            firewall=self.firewall,
            metrics=self.metrics,
            event_logger=self.event_logger,
            default_block_seconds=self.config.firewall.dynamic_block_duration_seconds,
        )
        restored_mode = resolve_startup_ids_mode(
            self.ml_pipeline.status().get("configured_mode_api", "threshold"),
            state_store=self.ids_mode_store,
        )
        restore_result = self.ml_pipeline.set_mode(restored_mode)
        self._persist_ids_mode_state(
            requested_by="controller_startup",
            previous_mode=restore_result.get("previous_mode_api"),
        )
        self.event_logger.controller_event(
            "controller_started",
            reason="firewall_ids_controller_ready",
        )
        self.event_logger.controller_event(
            "ids_mode_ready",
            reason="runtime_ids_mode_initialized",
            configured_mode=self.ml_pipeline.status().get("configured_mode_api"),
            selected_mode=self.ml_pipeline.status().get("selected_mode_api"),
            effective_mode=self.ml_pipeline.status().get("effective_mode_api"),
            model_available=self.ml_pipeline.status().get("model_available"),
        )
        self.event_logger.controller_event(
            "ml_pipeline_ready",
            reason=self.ml_pipeline.status().get("model_error") or "ml_runtime_initialized",
            configured_mode=self.ml_pipeline.status().get("configured_mode_api"),
            selected_mode=self.ml_pipeline.status().get("selected_mode_api"),
            effective_mode=self.ml_pipeline.status().get("effective_mode_api"),
            hybrid_policy=self.ml_pipeline.status().get("hybrid_policy"),
            model_available=self.ml_pipeline.status().get("model_available"),
            model_path=self.ml_pipeline.status().get("model_path"),
        )
        self.event_logger.controller_event(
            "dataset_recorder_ready",
            reason="runtime_dataset_recorder_initialized",
            enabled=self.dataset_recorder.status().get("enabled"),
            output_path=self.dataset_recorder.status().get("output_path"),
            label_path=self.dataset_recorder.status().get("label_path"),
            record_unlabeled=self.dataset_recorder.status().get("record_unlabeled"),
        )
        self.event_logger.controller_event(
            "capture_snapshot_manager_ready",
            reason="rolling_capture_snapshot_manager_initialized",
            capture_enabled=self.config.capture.enabled,
            continuous_capture_enabled=self.config.capture.continuous_enabled,
            capture_output_directory=self.config.capture.output_directory,
        )
        self._dashboard_heartbeat = hub.spawn(self._dashboard_heartbeat_loop)
        self._publish_dashboard_state(force=True)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, event):
        datapath = event.datapath
        if datapath.id is None:
            return

        dpid = format_dpid(datapath.id)
        if event.state == MAIN_DISPATCHER:
            register_datapath(self.state, datapath)
            self.metrics.record_controller_event("datapath_up", {"dpid": dpid})
            self.event_logger.controller_event(
                "datapath_up",
                dpid=dpid,
                reason="switch_connected",
            )
            self._publish_dashboard_state(force=True)
        elif event.state == DEAD_DISPATCHER:
            unregister_datapath(self.state, datapath.id)
            if self.state.datapaths:
                self.metrics.record_controller_event("datapath_down", {"dpid": dpid})
                self.event_logger.controller_event(
                    "datapath_down",
                    dpid=dpid,
                    reason="switch_disconnected",
                )
            else:
                self._reset_live_runtime_state(last_dpid=dpid)
            self._publish_dashboard_state(force=True)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        datapath = event.msg.datapath
        dpid = format_dpid(datapath.id)
        existing_datapath = self.state.datapaths.get(datapath.id)
        if existing_datapath is not None and existing_datapath is not datapath:
            self._reset_runtime_state_for_datapath_reconnect(dpid)
        dpid = register_datapath(self.state, datapath)
        self.flow_manager.install_table_miss(datapath)
        self.firewall.install_baseline_rules(datapath)
        self.metrics.record_controller_event("baseline_installed", {"dpid": dpid})
        self.event_logger.flow_event(
            "baseline_installed",
            dpid=dpid,
            priority=self.config.flow_priorities.table_miss,
            reason="table_miss_and_active_quarantines",
        )
        self._publish_dashboard_state(force=True)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        message = event.msg
        datapath = message.datapath
        dpid = format_dpid(datapath.id)
        in_port = message.match.get("in_port")

        packet_metadata = self.packet_parser.parse(message.data, dpid, in_port)
        if packet_metadata is None or packet_metadata.is_lldp:
            return

        self._drain_hybrid_correlation_events(packet_metadata.timestamp)
        learn_host(self.state, packet_metadata)
        self.metrics.record_packet(packet_metadata)
        threshold_alerts = self._run_threshold_ids_hook(packet_metadata)
        forwarding_visibility = classify_visibility(self.config.ids, packet_metadata)
        threshold_context = self.ids.describe_source(
            packet_metadata,
            alerts=threshold_alerts,
            forwarding_visibility=forwarding_visibility,
        )
        threshold_context.update(
            {
                "src_mac": getattr(packet_metadata, "eth_src", "") or "",
                "dst_mac": getattr(packet_metadata, "eth_dst", "") or "",
                "dst_ip": getattr(packet_metadata, "dst_ip", "") or "",
                "internal_subnet": getattr(self.config.firewall, "internal_subnet", ""),
                "protected_source_ips": list(
                    getattr(self.config.firewall, "protected_source_ips", ())
                ),
            }
        )
        ml_result = self.ml_pipeline.inspect(
            packet_metadata,
            threshold_alerts=threshold_alerts,
            threshold_context=threshold_context,
        )
        if ml_result.prediction is not None:
            self.metrics.record_ml_prediction(ml_result.prediction)
            self._handle_hybrid_correlation_events(
                self.ml_pipeline.note_prediction(ml_result.prediction)
            )
        self.dataset_recorder.record(
            packet_metadata,
            feature_snapshot=ml_result.feature_snapshot,
            threshold_context=threshold_context,
        )
        self._handle_threshold_ids_alerts(threshold_alerts)
        self._handle_ml_alert(ml_result.alert)

        decision = self.firewall.evaluate(packet_metadata)
        if decision.action == "block":
            self.firewall.enforce_block_decision(
                datapath=datapath,
                packet_metadata=packet_metadata,
                decision=decision,
                datapaths=self.state.iter_datapaths(),
            )
            self.event_logger.traffic_event(
                packet_metadata,
                action="block",
                reason=decision.reason,
                dpid=dpid,
            )
            self._publish_dashboard_state()
            return

        out_port = lookup_output_port(self.state, dpid, packet_metadata.eth_dst)
        if out_port is None:
            out_port = datapath.ofproto.OFPP_FLOOD
            self.event_logger.traffic_event(
                packet_metadata,
                action="allow",
                reason=decision.reason + "_unknown_destination",
                dpid=dpid,
                out_port="flood",
            )
            self.flow_manager.send_packet(
                datapath,
                message.buffer_id,
                in_port,
                out_port,
                message.data,
            )
            self._publish_dashboard_state()
            return

        handled_by_flow = False
        if self._should_install_forward_flow(packet_metadata):
            handled_by_flow = self.flow_manager.install_forward_flow(
                datapath,
                in_port,
                packet_metadata,
                out_port,
                buffer_id=message.buffer_id,
            )
        self.event_logger.traffic_event(
            packet_metadata,
            action="allow",
            reason=decision.reason,
            dpid=dpid,
            out_port=out_port,
        )
        if not handled_by_flow:
            self.flow_manager.send_packet(
                datapath,
                message.buffer_id,
                in_port,
                out_port,
                message.data,
            )
        self._publish_dashboard_state()

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, event):
        flow_event = self.flow_manager.build_flow_removed_event(event.msg)
        self._handle_flow_event(flow_event)

    def _handle_threshold_ids_alerts(self, alerts):
        for alert in alerts:
            snapshot = self._preserve_capture_snapshot(alert, detector="threshold")
            self._handle_hybrid_correlation_events(
                self.ml_pipeline.handle_threshold_alert(alert)
            )
            mitigation = None
            quarantine_status = "suppressed"

            if not self._is_mitigation_enabled():
                self.event_logger.security_event(
                    "mitigation_suppressed",
                    src_ip=alert.src_ip,
                    reason=self._mitigation_suppression_reason(),
                    alert_type=alert.alert_type,
                    detector="threshold",
                )
            elif not should_auto_quarantine_threshold_alert(alert):
                quarantine_status = "alert_only"
                self.event_logger.security_event(
                    "mitigation_suppressed",
                    src_ip=alert.src_ip,
                    reason="icmp_sweep_requires_excess_host_coverage_for_auto_quarantine",
                    alert_type=alert.alert_type,
                    detector="threshold",
                )
            else:
                mitigation = self.mitigation.handle_alert(
                    alert,
                    self.state.iter_datapaths(),
                    related_capture=snapshot,
                )
                quarantine_status = mitigation.status if mitigation is not None else "not_applied"

            self.metrics.record_alert(
                alert,
                related_capture=snapshot,
                quarantine_status=quarantine_status,
            )
            self.event_logger.security_event(
                "ids_alert",
                src_ip=alert.src_ip,
                reason=alert.reason,
                alert_type=alert.alert_type,
                severity=alert.severity,
                quarantine_status=quarantine_status,
                related_capture=(
                    snapshot.get("primary_file")
                    if snapshot is not None
                    else None
                ),
                **alert.details
            )

            if mitigation is not None and mitigation.status != "duplicate":
                self.event_logger.security_event(
                    "host_quarantined",
                    src_ip=mitigation.src_ip,
                    reason=mitigation.reason,
                    alert_type=mitigation.alert_type,
                    detector=mitigation.detector,
                    status=mitigation.status,
                    related_capture=(
                        mitigation.related_capture.get("primary_file")
                        if mitigation.related_capture
                        else None
                    ),
                )
            self._publish_dashboard_state(force=True)

    def _handle_ml_alert(self, alert):
        if alert is None:
            return

        correlation_status = alert.details.get("correlation_status")
        should_preserve_snapshot = True
        if correlation_status in (
            "threshold_plus_ml",
            "threshold_enriched_by_ml",
            "known_class_match",
        ):
            should_preserve_snapshot = False
        elif correlation_status in ("ml_only", "anomaly_only"):
            should_preserve_snapshot = bool(self.config.ml.capture_on_ml_only_alert)

        snapshot = None
        if should_preserve_snapshot:
            snapshot = self._preserve_capture_snapshot(alert, detector="ml")
        self._handle_hybrid_correlation_events(
            self.ml_pipeline.handle_ml_alert(alert)
        )
        mitigation = None
        quarantine_status = "alert_only" if not alert.should_mitigate else "suppressed"

        if not alert.should_mitigate:
            pass
        elif not self._is_mitigation_enabled():
            self.event_logger.ml_event(
                "ml_mitigation_suppressed",
                src_ip=alert.src_ip,
                reason=self._mitigation_suppression_reason(),
                alert_type=alert.alert_type,
                decision=alert.decision,
                confidence=round(float(alert.confidence), 6),
                suspicion_score=round(float(alert.suspicion_score), 6),
            )
        elif alert.should_mitigate:
            mitigation = self.mitigation.handle_alert(
                alert,
                self.state.iter_datapaths(),
                related_capture=snapshot,
            )
            quarantine_status = mitigation.status if mitigation is not None else "not_applied"

        self.metrics.record_alert(
            alert,
            source="ml",
            related_capture=snapshot,
            quarantine_status=quarantine_status,
        )
        self.event_logger.ml_event(
            "ml_alert",
            src_ip=alert.src_ip,
            reason=alert.reason,
            alert_type=alert.alert_type,
            severity=alert.severity,
            decision=alert.decision,
            quarantine_status=quarantine_status,
            confidence=round(float(alert.confidence), 6),
            suspicion_score=round(float(alert.suspicion_score), 6),
            model_name=alert.model_name,
            label=alert.label,
            agreement_with_threshold=alert.details.get("agreement_with_threshold"),
            correlation_status=alert.details.get("correlation_status"),
            predicted_family=alert.details.get("predicted_family"),
            classifier_confidence=alert.details.get("classifier_confidence"),
            anomaly_score=alert.details.get("anomaly_score"),
            threshold_reason=alert.details.get("threshold_reason"),
            repeated_window_count=alert.details.get("repeated_window_count"),
            block_decision_path=alert.details.get("block_decision_path"),
            final_block_reason=alert.details.get("final_block_reason"),
            final_action=alert.details.get("final_action"),
            detection_sources=",".join(alert.details.get("detection_sources", [])),
            block_suppressed=alert.details.get("block_suppressed"),
            block_suppression_reason=alert.details.get("block_suppression_reason"),
            related_capture=(
                snapshot.get("primary_file")
                if snapshot is not None
                else None
            ),
        )

        if mitigation is not None and mitigation.status != "duplicate":
            self.event_logger.security_event(
                "host_quarantined",
                src_ip=mitigation.src_ip,
                reason=mitigation.reason,
                alert_type=mitigation.alert_type,
                detector="ml",
                status=mitigation.status,
                related_capture=(
                    mitigation.related_capture.get("primary_file")
                    if mitigation.related_capture
                    else None
                ),
            )
        self._publish_dashboard_state(force=True)

    def _run_threshold_ids_hook(self, packet_metadata):
        """Run threshold IDS unless ML-only mode is actively selected."""

        if self.ml_pipeline.effective_mode() == "ml_only":
            return []
        return self.ids.inspect(packet_metadata)

    def _handle_flow_event(self, flow_event):
        action = "flow_rule_installed"
        if flow_event.get("operation") == "remove":
            action = "flow_rule_removed"

        self.metrics.record_flow_event(action, flow_event)
        self.event_logger.flow_event(
            action,
            dpid=flow_event.get("dpid"),
            priority=flow_event.get("priority"),
            reason=flow_event.get("reason"),
            match=flow_event.get("match"),
            actions=flow_event.get("actions"),
            idle_timeout=flow_event.get("idle_timeout"),
            hard_timeout=flow_event.get("hard_timeout"),
        )
        priority = flow_event.get("priority")
        try:
            is_security_flow = int(priority) >= self.config.flow_priorities.packet_block
        except (TypeError, ValueError):
            is_security_flow = False
        self._publish_dashboard_state(
            force=bool(
                is_security_flow or flow_event.get("operation") == "remove"
            )
        )

    def _handle_hybrid_correlation_events(self, events):
        for correlation_event in events or []:
            self.metrics.record_hybrid_correlation(correlation_event)
            self.event_logger.ml_event(
                "hybrid_correlation",
                src_ip=correlation_event.src_ip,
                reason=correlation_event.reason,
                status=correlation_event.status,
                correlation_window_seconds=correlation_event.correlation_window_seconds,
                threshold_timestamp=correlation_event.threshold_timestamp,
                ml_timestamp=correlation_event.ml_timestamp,
                confidence=correlation_event.confidence,
                suspicion_score=correlation_event.suspicion_score,
            )
            self._publish_dashboard_state(force=True)

    def _drain_hybrid_correlation_events(self, now):
        self._handle_hybrid_correlation_events(
            self.ml_pipeline.expire_correlations(now)
        )

    def _publish_dashboard_state(self, force=False):
        self.dashboard_state.publish(
            metrics=self.metrics,
            controller_state=self.state,
            firewall=self.firewall,
            force=force,
            ml_mode=self.ml_pipeline.effective_mode(),
            ml_status=self.ml_pipeline.status(),
            config_snapshot=self._dashboard_config_snapshot(),
        )

    def _dashboard_heartbeat_loop(self):
        heartbeat_interval = max(
            0.5,
            min(
                self.config.dashboard.poll_interval_seconds,
                1.0,
            ),
        )
        while True:
            self._drain_hybrid_correlation_events(time.time())
            self._process_dashboard_commands()
            self._publish_dashboard_state()
            hub.sleep(heartbeat_interval)

    def _reset_live_runtime_state(self, last_dpid):
        released_quarantines = []
        if self.config.mitigation.auto_unblock_enabled:
            released_quarantines = clear_quarantines_for_topology_idle(self.firewall)
            if released_quarantines:
                released_sources = sorted(
                    record.src_ip
                    for record in released_quarantines
                    if getattr(record, "src_ip", None)
                )
                self.metrics.record_controller_event(
                    "topology_idle_quarantine_reset",
                    {
                        "released_hosts_count": len(released_sources),
                        "released_hosts": released_sources,
                        "reason": "auto_unblock_enabled",
                    },
                )
                self.event_logger.security_event(
                    "topology_idle_quarantine_reset",
                    src_ip="controller",
                    released_hosts_count=len(released_sources),
                    released_hosts=",".join(released_sources),
                    reason="auto_unblock_enabled",
                )

        clear_runtime_topology_state(self.state)
        self.metrics.reset_runtime_session()
        self.ids.reset_runtime_session()
        self.ml_pipeline.reset_runtime_session()
        self.metrics.record_controller_event(
            "topology_idle",
            {
                "last_dpid": last_dpid,
                "reason": "all_switches_disconnected",
            },
        )
        self.event_logger.controller_event(
            "topology_idle",
            dpid=last_dpid,
            reason="all_switches_disconnected",
        )

    def _reset_runtime_state_for_datapath_reconnect(self, dpid):
        now = time.time()
        if (now - self._last_reconnect_reset_at) < 2.0:
            return
        self._last_reconnect_reset_at = now

        released_sources = []
        if self.config.mitigation.auto_unblock_enabled:
            released = clear_quarantines_for_topology_idle(self.firewall)
            released_sources = sorted(
                record.src_ip
                for record in released
                if getattr(record, "src_ip", None)
            )

        clear_runtime_topology_state(self.state)
        self.metrics.reset_runtime_session()
        self.ids.reset_runtime_session()
        self.ml_pipeline.reset_runtime_session()

        self.metrics.record_controller_event(
            "datapath_reconnect_runtime_reset",
            {
                "dpid": dpid,
                "released_hosts_count": len(released_sources),
                "released_hosts": released_sources,
                "reason": "replacement_datapath_detected",
            },
        )
        self.event_logger.controller_event(
            "datapath_reconnect_runtime_reset",
            dpid=dpid,
            released_hosts_count=len(released_sources),
            released_hosts=",".join(released_sources),
            reason="replacement_datapath_detected",
        )

    def _should_suppress_dataset_collection_mitigation(self):
        if not self.config.ml.dataset_disable_mitigation:
            return False
        if not self.dataset_recorder.enabled:
            return False
        return self.dataset_recorder.current_label() is not None

    def _is_mitigation_enabled(self):
        if not self.config.mitigation.enabled:
            return False
        return not self._should_suppress_dataset_collection_mitigation()

    def _mitigation_suppression_reason(self):
        if not self.config.mitigation.enabled:
            return "mitigation_disabled"
        return "dataset_collection_mode"

    def _process_dashboard_commands(self):
        for command in self.command_queue.pending_commands():
            action = command.get("action")
            payload = dict(command.get("payload") or {})
            if action == "unblock_host":
                self._process_unblock_host_command(command, payload)
                continue
            if action == "set_ids_mode":
                self._process_ids_mode_command(command, payload)
                continue
            self.command_queue.mark_processed(
                command,
                status="ignored",
                result={"reason": "unsupported_action"},
            )

    def _process_unblock_host_command(self, command, payload):
        src_ip = payload.get("src_ip")
        if not src_ip:
            self.command_queue.mark_processed(
                command,
                status="invalid",
                result={"reason": "missing_src_ip"},
            )
            return
        mitigation = self.mitigation.manual_unblock(
            src_ip,
            self.state.iter_datapaths(),
            released_by=payload.get("requested_by", "dashboard"),
        )
        if mitigation is None:
            self.event_logger.security_event(
                "manual_unblock_ignored",
                src_ip=src_ip,
                reason="host_not_quarantined",
            )
            self.command_queue.mark_processed(
                command,
                status="noop",
                result={"reason": "host_not_quarantined", "src_ip": src_ip},
            )
            return
        self.event_logger.security_event(
            "host_manually_unblocked",
            src_ip=mitigation.src_ip,
            reason=mitigation.reason,
            released_by=payload.get("requested_by", "dashboard"),
            related_capture=(
                mitigation.related_capture.get("primary_file")
                if mitigation.related_capture
                else None
            ),
        )
        self.command_queue.mark_processed(
            command,
            status="completed",
            result={"src_ip": mitigation.src_ip},
        )
        self._publish_dashboard_state(force=True)

    def _process_ids_mode_command(self, command, payload):
        requested_mode = payload.get("mode")
        if not requested_mode:
            self.command_queue.mark_processed(
                command,
                status="invalid",
                result={"reason": "missing_mode"},
            )
            return

        selection_error = self.ml_pipeline.selection_error(requested_mode)
        if selection_error is not None:
            self.event_logger.controller_event(
                "ids_mode_change_rejected",
                reason=selection_error,
                requested_mode=requested_mode,
                current_mode=self.ml_pipeline.status().get("selected_mode_api"),
            )
            self.command_queue.mark_processed(
                command,
                status="rejected",
                result={
                    "reason": selection_error,
                    "requested_mode": requested_mode,
                    "current_mode": self.ml_pipeline.status().get("selected_mode_api"),
                },
            )
            self._publish_dashboard_state(force=True)
            return

        change = self.ml_pipeline.set_mode(requested_mode)
        self._persist_ids_mode_state(
            requested_by=payload.get("requested_by", "dashboard"),
            previous_mode=change.get("previous_mode_api"),
        )

        if change.get("changed"):
            self.event_logger.controller_event(
                "ids_mode_changed",
                reason="runtime_mode_selector_update",
                requested_by=payload.get("requested_by", "dashboard"),
                previous_mode=change.get("previous_mode_api"),
                selected_mode=change.get("selected_mode_api"),
                effective_mode=change.get("effective_mode_api"),
            )
            status = "completed"
        else:
            status = "noop"

        self.command_queue.mark_processed(
            command,
            status=status,
            result={
                "selected_mode": change.get("selected_mode_api"),
                "effective_mode": change.get("effective_mode_api"),
                "changed": bool(change.get("changed")),
            },
        )
        self._publish_dashboard_state(force=True)

    def _preserve_capture_snapshot(self, alert, detector):
        snapshot = self.capture_manager.preserve_snapshot(
            src_ip=getattr(alert, "src_ip", None),
            alert_type=getattr(alert, "alert_type", None),
            detector=detector,
            reason=getattr(alert, "reason", None),
            timestamp=getattr(alert, "timestamp", time.time()),
        )
        if snapshot:
            self.metrics.record_capture_snapshot(snapshot)
            self.event_logger.controller_event(
                "capture_snapshot_preserved",
                reason=getattr(alert, "reason", None),
                src_ip=getattr(alert, "src_ip", None),
                alert_type=getattr(alert, "alert_type", None),
                detector=detector,
                snapshot=snapshot.get("primary_file"),
                file_count=snapshot.get("file_count"),
            )
        return snapshot

    def _persist_ids_mode_state(self, requested_by, previous_mode=None):
        return self.ids_mode_store.persist(
            mode=self.ml_pipeline.status().get("selected_mode_api", "threshold"),
            effective_mode=self.ml_pipeline.status().get("effective_mode_api", "threshold"),
            requested_by=requested_by,
            previous_mode=previous_mode,
        )

    def _should_install_forward_flow(self, packet_metadata):
        """Install forwarding flows while keeping probe traffic controller-visible."""

        return should_install_forward_flow(self.config.ids, packet_metadata)

    def _dashboard_config_snapshot(self):
        return {
            "controller": {
                "openflow_host": self.config.controller.openflow_host,
                "openflow_port": self.config.controller.openflow_port,
            },
            "dashboard": {
                "host": self.config.dashboard.host,
                "port": self.config.dashboard.port,
                "base_path": self.config.dashboard.base_path,
                "poll_interval_seconds": self.config.dashboard.poll_interval_seconds,
                "persist_interval_seconds": self.config.dashboard.persist_interval_seconds,
                "timeseries_points": self.config.dashboard.timeseries_points,
            },
            "firewall": {
                "internal_subnet": self.config.firewall.internal_subnet,
                "permit_icmp": self.config.firewall.permit_icmp,
                "permit_icmp_external": self.config.firewall.permit_icmp_external,
                "default_allow_ipv4": self.config.firewall.default_allow_ipv4,
                "blocked_source_ips": list(self.config.firewall.blocked_source_ips),
                "protected_source_ips": list(self.config.firewall.protected_source_ips),
                "restricted_tcp_ports": list(self.config.firewall.restricted_tcp_ports),
                "restricted_udp_ports": list(self.config.firewall.restricted_udp_ports),
                "dynamic_block_duration_seconds": self.config.firewall.dynamic_block_duration_seconds,
            },
            "ids": {
                "enabled": self.config.ids.enabled,
                "inspect_tcp_udp_packets": self.config.ids.inspect_tcp_udp_packets,
                "keep_tcp_syn_packets_visible": self.config.ids.keep_tcp_syn_packets_visible,
                "keep_udp_probe_packets_visible": self.config.ids.keep_udp_probe_packets_visible,
                "keep_icmp_echo_requests_visible": self.config.ids.keep_icmp_echo_requests_visible,
                "udp_fastpath_ports": list(self.config.ids.udp_fastpath_ports),
                "packet_rate_window_seconds": self.config.ids.packet_rate_window_seconds,
                "packet_rate_threshold": self.config.ids.packet_rate_threshold,
                "syn_rate_window_seconds": self.config.ids.syn_rate_window_seconds,
                "syn_rate_threshold": self.config.ids.syn_rate_threshold,
                "scan_window_seconds": self.config.ids.scan_window_seconds,
                "unique_destination_ports_threshold": self.config.ids.unique_destination_ports_threshold,
                "unique_destination_hosts_threshold": self.config.ids.unique_destination_hosts_threshold,
                "tcp_scan_unique_destination_ports_threshold": self.config.ids.tcp_scan_unique_destination_ports_threshold,
                "tcp_scan_probe_threshold": self.config.ids.tcp_scan_probe_threshold,
                "udp_scan_unique_destination_ports_threshold": self.config.ids.udp_scan_unique_destination_ports_threshold,
                "udp_scan_probe_threshold": self.config.ids.udp_scan_probe_threshold,
                "icmp_sweep_unique_destination_hosts_threshold": self.config.ids.icmp_sweep_unique_destination_hosts_threshold,
                "icmp_sweep_probe_threshold": self.config.ids.icmp_sweep_probe_threshold,
                "combined_recon_unique_destination_hosts_threshold": self.config.ids.combined_recon_unique_destination_hosts_threshold,
                "combined_recon_unique_destination_ports_threshold": self.config.ids.combined_recon_unique_destination_ports_threshold,
                "combined_recon_probe_threshold": self.config.ids.combined_recon_probe_threshold,
                "failed_connection_window_seconds": self.config.ids.failed_connection_window_seconds,
                "failed_connection_threshold": self.config.ids.failed_connection_threshold,
                "connection_attempt_window_seconds": self.config.ids.connection_attempt_window_seconds,
                "unanswered_syn_window_seconds": self.config.ids.unanswered_syn_window_seconds,
                "unanswered_syn_threshold": self.config.ids.unanswered_syn_threshold,
                "unanswered_syn_timeout_seconds": self.config.ids.unanswered_syn_timeout_seconds,
                "alert_suppression_seconds": self.config.ids.alert_suppression_seconds,
            },
            "ids_runtime": {
                "configured_mode": self.ml_pipeline.status().get("configured_mode_api"),
                "configured_mode_label": self.ml_pipeline.status().get("configured_mode_label"),
                "selected_mode": self.ml_pipeline.status().get("selected_mode_api"),
                "selected_mode_label": self.ml_pipeline.status().get("selected_mode_label"),
                "effective_mode": self.ml_pipeline.status().get("effective_mode_api"),
                "effective_mode_label": self.ml_pipeline.status().get("effective_mode_label"),
                "available_modes": self.ml_pipeline.status().get("available_modes", []),
                "hybrid_policy": self.ml_pipeline.status().get("hybrid_policy"),
                "model_available": self.ml_pipeline.status().get("model_available"),
            },
            "mitigation": {
                "enabled": self.config.mitigation.enabled,
                "quarantine_enabled": self.config.mitigation.quarantine_enabled,
                "auto_unblock_enabled": self.config.mitigation.auto_unblock_enabled,
                "manual_unblock_enabled": self.config.mitigation.manual_unblock_enabled,
            },
            "capture": {
                "enabled": self.config.capture.enabled,
                "continuous_enabled": self.config.capture.continuous_enabled,
                "tool": self.config.capture.tool,
                "interfaces": list(self.config.capture.interfaces),
                "output_directory": self.config.capture.output_directory,
                "ring_file_seconds": self.config.capture.ring_file_seconds,
                "ring_file_count": self.config.capture.ring_file_count,
                "snapshot_files_per_interface": (
                    self.config.capture.snapshot_files_per_interface
                ),
                "snapshot_cooldown_seconds": (
                    self.config.capture.snapshot_cooldown_seconds
                ),
            },
            "ml": {
                "enabled": self.config.ml.enabled,
                "mode": self.config.ml.mode,
                "mode_state_path": self.config.ml.mode_state_path,
                "hybrid_policy": self.config.ml.hybrid_policy,
                "enable_random_forest": self.config.ml.enable_random_forest,
                "enable_isolation_forest": self.config.ml.enable_isolation_forest,
                "hybrid_block_enabled": self.config.ml.hybrid_block_enabled,
                "hybrid_anomaly_block_enabled": self.config.ml.hybrid_anomaly_block_enabled,
                "require_threshold_for_ml_block": self.config.ml.require_threshold_for_ml_block,
                "model_path": self.config.ml.model_path,
                "anomaly_model_path": self.config.ml.anomaly_model_path,
                "inference_mode": self.config.ml.inference_mode,
                "dataset_path": self.config.ml.dataset_path,
                "feature_window_seconds": self.config.ml.feature_window_seconds,
                "minimum_packets_before_inference": self.config.ml.minimum_packets_before_inference,
                "inference_packet_stride": self.config.ml.inference_packet_stride,
                "inference_cooldown_seconds": self.config.ml.inference_cooldown_seconds,
                "confidence_threshold": self.config.ml.confidence_threshold,
                "mitigation_threshold": self.config.ml.mitigation_threshold,
                "alert_only_threshold": self.config.ml.alert_only_threshold,
                "anomaly_score_threshold": self.config.ml.anomaly_score_threshold,
                "hybrid_classifier_block_threshold": (
                    self.config.ml.hybrid_classifier_block_threshold
                ),
                "hybrid_anomaly_support_threshold": (
                    self.config.ml.hybrid_anomaly_support_threshold
                ),
                "hybrid_block_repeat_count": self.config.ml.hybrid_block_repeat_count,
                "hybrid_threshold_near_miss_repeat_count": (
                    self.config.ml.hybrid_threshold_near_miss_repeat_count
                ),
                "hybrid_known_family_block_enabled": (
                    self.config.ml.hybrid_known_family_block_enabled
                ),
                "hybrid_block_eligible_families": list(
                    self.config.ml.hybrid_block_eligible_families
                ),
                "hybrid_anomaly_trend_threshold": (
                    self.config.ml.hybrid_anomaly_trend_threshold
                ),
                "hybrid_anomaly_only_block_enabled": (
                    self.config.ml.hybrid_anomaly_only_block_enabled
                ),
                "hybrid_anomaly_only_block_threshold": (
                    self.config.ml.hybrid_anomaly_only_block_threshold
                ),
                "alert_suppression_seconds": self.config.ml.alert_suppression_seconds,
                "hybrid_correlation_window_seconds": (
                    self.config.ml.hybrid_correlation_window_seconds
                ),
                "ml_only_escalation_count": self.config.ml.ml_only_escalation_count,
                "anomaly_only_escalation_count": (
                    self.config.ml.anomaly_only_escalation_count
                ),
                "ml_only_escalation_enabled": self.config.ml.ml_only_escalation_enabled,
                "capture_on_ml_only_alert": self.config.ml.capture_on_ml_only_alert,
            },
            "logging": {
                "level": self.config.logging.level,
                "log_allowed_traffic": self.config.logging.log_allowed_traffic,
            },
        }
