(function () {
  "use strict";

  const SIDEBAR_STORAGE_KEY = "sdn-dashboard-sidebar-collapsed";
  const SIDEBAR_MOBILE_MEDIA_QUERY = "(max-width: 960px)";
  const CAPTURE_PAGE_SIZE = 5;
  const ALERT_TABLE_WIDTHS_STORAGE_KEY = "sdn-dashboard-alert-table-widths";
  const ALERT_SNAPSHOTS_TABLE_WIDTHS_STORAGE_KEY = "alertSnapshotsTableColumnWidths";
  const RING_BUFFER_TABLE_WIDTHS_STORAGE_KEY = "ringBufferTableColumnWidths";
  const ALERT_TABLE_MIN_WIDTHS = [120, 110, 130, 120, 130, 220, 120, 120];
  const ALERT_TABLE_DEFAULT_WIDTHS = [140, 120, 170, 150, 170, 420, 150, 140];
  const ALERT_SNAPSHOTS_TABLE_MIN_WIDTHS = [44, 260, 200, 140, 130, 220, 76, 110, 150, 130];
  const ALERT_SNAPSHOTS_TABLE_DEFAULT_WIDTHS = [44, 360, 230, 160, 150, 280, 90, 120, 170, 150];
  const RING_BUFFER_TABLE_MIN_WIDTHS = [44, 150, 180, 130, 320, 130, 100, 130, 130];
  const RING_BUFFER_TABLE_DEFAULT_WIDTHS = [44, 180, 220, 140, 420, 150, 120, 160, 150];
  const TOKEN_ACRONYMS = {
    ids: "IDS",
    ip: "IP",
    ml: "ML",
    icmp: "ICMP",
    tcp: "TCP",
    udp: "UDP",
    dpid: "DPID",
    pcap: "PCAP",
  };

  const state = {
    charts: {},
    lastPayload: null,
    pollTimer: null,
    isFetching: false,
    hasHydrated: false,
    idsModePendingValue: null,
    idsModeRequestInFlight: false,
    idsModeStatusMessage: "Loading runtime mode...",
    idsModeStatusTone: "warning",
    sidebarMediaQuery: null,
    tableRenderSignatures: {},
    captureVisibleRows: {
      snapshots: CAPTURE_PAGE_SIZE,
      files: CAPTURE_PAGE_SIZE,
    },
    captureSelection: {
      snapshotKeys: new Set(),
      filePaths: new Set(),
    },
    captureDeleteInFlight: false,
    captureScrollbarDrag: null,
    captureScrollbarReady: false,
  };

  document.addEventListener("DOMContentLoaded", function () {
    const body = document.body;
    if (!body) {
      return;
    }

    body.setAttribute("data-dashboard-hydrated", "false");
    ensureSidebarToggle();
    initializeSidebar();
    initializeCaptureScrollbars();
    initializeResizableTables();
    markSidebarReady();
    document.addEventListener("click", handleActionClick);
    document.addEventListener("change", handleActionChange);
    document.addEventListener("pointermove", handleCaptureScrollbarPointerMove);
    document.addEventListener("pointerup", handleCaptureScrollbarPointerUp);
    startPolling();
  });

  function startPolling() {
    scheduleNextTick(0);
  }

  function scheduleNextTick(delayMs) {
    if (state.pollTimer) {
      window.clearTimeout(state.pollTimer);
    }
    state.pollTimer = window.setTimeout(tick, delayMs);
  }

  async function tick() {
    if (state.isFetching) {
      scheduleNextTick(pollIntervalMs());
      return;
    }

    state.isFetching = true;
    try {
      const payload = await fetchPayload(apiEndpoint());
      state.lastPayload = payload;
      markDashboardHydrated();
      updateConnectionStatus(payload, true);
      updateChrome(payload);
      updatePage(payload);
    } catch (error) {
      updateConnectionStatus(state.lastPayload, false, error);
    } finally {
      state.isFetching = false;
      scheduleNextTick(pollIntervalMs());
    }
  }

  function markDashboardHydrated() {
    if (state.hasHydrated) {
      return;
    }
    state.hasHydrated = true;
    if (document.body) {
      document.body.setAttribute("data-dashboard-hydrated", "true");
    }
  }

  async function fetchPayload(endpoint) {
    const response = await fetch(endpoint, {
      cache: "no-store",
      headers: {
        "Accept": "application/json",
      },
    });
    if (!response.ok) {
      throw new Error("dashboard_fetch_failed_" + response.status);
    }
    return response.json();
  }

  function updateConnectionStatus(payload, connected, error) {
    const connectionBadge = document.getElementById("chrome-live-status");
    const sidebarChip = document.getElementById("sidebar-live-chip");
    const freshness = calculateFreshness(payload);

    let text = "Live";
    let className = "badge badge--success";
    let chipClassName = "status-chip status-chip--success";

    if (!connected) {
      text = "Disconnected";
      className = "badge badge--danger";
      chipClassName = "status-chip status-chip--danger";
    } else if (freshness.isStale) {
      text = "Delayed";
      className = "badge badge--warning";
      chipClassName = "status-chip status-chip--warning";
    }

    if (connectionBadge) {
      connectionBadge.className = className;
      connectionBadge.textContent = text;
    }
    if (sidebarChip) {
      sidebarChip.className = chipClassName;
      sidebarChip.textContent = connected
        ? "Live"
        : "Waiting";
    }

    if (error) {
      console.error(error);
    }
  }

  function updateChrome(payload) {
    const summary = payload.summary || {};
    const ml = payload.ml || {};
    const modeLabel = ml.effective_mode_label || formatIdsModeLabel(ml.effective_mode || summary.ml_mode || "threshold");

    const modeBadge = document.getElementById("chrome-ml-mode");
    if (modeBadge) {
      modeBadge.className = "badge " + idsModeBadgeClass(ml.effective_mode_api || ml.effective_mode || "threshold");
      modeBadge.textContent = modeLabel;
    }
    setText("chrome-last-updated", formatTimestamp(payload.generated_at));
    setText("footer-total-packets", formatNumber(summary.total_packets));
    setText("footer-switches", formatNumber(summary.active_switches));
    setText("footer-alerts", formatNumber(summary.alerts_total));
    setText("footer-blocks", formatNumber(summary.active_blocks));
    syncIdsModeControls(payload);
  }

  function updatePage(payload) {
    const pageName = currentPage();
    const handlers = {
      dashboard: updateDashboardPage,
      traffic: updateTrafficPage,
      alerts: updateAlertsPage,
      blocked_hosts: updateBlockedHostsPage,
      performance: updatePerformancePage,
      captures: updateCapturesPage,
      ml_ids: updateMlPage,
      settings: updateSettingsPage,
    };

    const handler = handlers[pageName];
    if (handler) {
      handler(payload);
    }
  }

  function updateDashboardPage(payload) {
    const summary = payload.summary || {};
    const performance = payload.performance || {};
    const ml = payload.ml || {};

    setText("stat-total-packets", formatNumber(summary.total_packets));
    setText("stat-packet-rate", performance.packet_in_rate_display || "0 pkt/s");
    setText("stat-active-switches", formatNumber(summary.active_switches));
    setText("stat-active-hosts", formatNumber(summary.active_hosts));
    setText("stat-active-blocks", formatNumber(summary.active_blocks));
    setText("stat-alert-total", formatNumber(summary.alerts_total) + " alerts total");
    setText("overview-ids-mode", ml.effective_mode_label || formatIdsModeLabel(ml.effective_mode || "threshold"));
    setText("overview-ids-mode-detail", idsModeDescription(ml));

    renderLineChart("chart-overview-packets", {
      labels: labelsFromTimeseries(payload.timeseries),
      datasets: [
        datasetLine("Packets", valuesFromTimeseries(payload.timeseries, "total_packets"), "#5bb78c"),
      ],
    });

    renderLineChart("chart-overview-alerts", {
      labels: labelsFromTimeseries(payload.timeseries),
      datasets: [
        datasetLine("Threshold Alerts", valuesFromTimeseries(payload.timeseries, "threshold_alerts_total"), "#f0a639"),
        datasetLine("ML Alerts", valuesFromTimeseries(payload.timeseries, "ml_alerts_total"), "#42c2ff"),
        datasetLine("Active Blocks", valuesFromTimeseries(payload.timeseries, "active_blocks"), "#ef5d4d"),
      ],
    });

    renderDoughnutChart("chart-overview-protocols", payload.traffic ? payload.traffic.protocols : []);
    renderAlertsTable("overview-alerts-table", (payload.alerts && payload.alerts.rows) || [], 8);
    renderBlockedHostsTable("overview-blocked-table", payload.blocked_hosts || [], 6);
    renderInventory("overview-inventory", payload.switches || [], payload.learned_hosts || []);
  }

  function updateTrafficPage(payload) {
    const traffic = payload.traffic || {};
    const topTalkers = traffic.top_talkers || [];
    const protocols = traffic.protocols || [];

    setText("traffic-packet-rate", traffic.packet_rate_display || "0 pkt/s");
    setText("traffic-byte-rate", traffic.byte_rate_display || "0 B/s");
    setText("traffic-protocol-count", formatNumber(protocols.length));
    setText("traffic-top-talker", topTalkers.length ? topTalkers[0].src_ip : "-");

    renderLineChart("chart-traffic-trend", {
      labels: labelsFromTimeseries(payload.timeseries),
      datasets: [
        datasetLine("Packets", valuesFromTimeseries(payload.timeseries, "total_packets"), "#70c1b3"),
        datasetLine("Bytes", valuesFromTimeseries(payload.timeseries, "total_bytes"), "#3d7ea6"),
      ],
    });
    renderDoughnutChart("chart-traffic-protocols", protocols);
    renderTrafficTalkersTable("traffic-top-talkers-table", topTalkers);
    renderProtocolTable("traffic-protocol-table", protocols);
  }

  function updateAlertsPage(payload) {
    const alerts = payload.alerts || {};
    const summary = payload.summary || {};
    const severityCounts = alerts.counts_by_severity || {};
    const ml = payload.ml || {};

    setText("alerts-total", formatNumber(summary.alerts_total));
    setText("alerts-threshold", formatNumber(summary.threshold_alerts_total));
    setText("alerts-ml", formatNumber(summary.ml_alerts_total));
    setText("alerts-critical", formatNumber((severityCounts.critical || 0)));
    setText("alerts-active-mode", ml.effective_mode_label || formatIdsModeLabel(ml.effective_mode || "threshold"));
    setText("alerts-mode-detail", idsModeAlertDescription(ml));
    renderFullAlertsTable("alerts-table", alerts.rows || []);
  }

  function updateBlockedHostsPage(payload) {
    const summary = payload.summary || {};
    const blockedHosts = payload.blocked_hosts || [];
    const activeThresholdBlocks = Number(summary.active_threshold_blocks || 0);
    const activeMlBlocks = Number(summary.active_ml_blocks || 0);

    setText("blocked-total", formatNumber(summary.active_blocks));
    setText("blocked-threshold", formatNumber(activeThresholdBlocks));
    setText("blocked-ml", formatNumber(activeMlBlocks));
    setText("blocked-manual-unblocks", formatNumber(summary.manual_unblocks_total || 0));
    renderBlockedHostsFullTable("blocked-hosts-table", blockedHosts);
  }

  function updatePerformancePage(payload) {
    const performance = payload.performance || {};

    setText("perf-packet-rate", performance.packet_in_rate_display || "0 pkt/s");
    setText("perf-flow-rate", performance.flow_install_rate_display || "0 flow/s");
    setText("perf-event-rate", performance.event_processing_rate_display || "0 evt/s");
    setText("perf-flow-removals", formatNumber(performance.flow_removals_total || 0));
    setText("perf-active-security-flows", formatNumber(performance.active_security_flows_total || 0));
    setText("perf-active-flows", formatNumber(performance.active_flows_total || 0));
    setText("perf-active-blocks", formatNumber(performance.active_blocks || 0));

    renderLineChart("chart-performance-rates", {
      labels: labelsFromTimeseries(payload.timeseries),
      datasets: [
        datasetLine("Packets", rateSeries(payload.timeseries, "total_packets"), "#65c18c"),
        datasetLine("Controller Events", rateSeries(payload.timeseries, "controller_events_total"), "#f4a259"),
      ],
    });

    renderLineChart("chart-performance-flows", {
      labels: labelsFromTimeseries(payload.timeseries),
      datasets: [
        datasetLine("Flow Installs", valuesFromTimeseries(payload.timeseries, "flow_installs_total"), "#3d7ea6"),
        datasetLine("Flow Removals", valuesFromTimeseries(payload.timeseries, "flow_removals_total"), "#a855f7"),
        datasetLine("Active Security Flows", valuesFromTimeseries(payload.timeseries, "active_security_flows_total"), "#ef5d4d"),
        datasetLine("Active Blocks", valuesFromTimeseries(payload.timeseries, "active_blocks"), "#f0a639"),
        datasetLine("Active Flows", valuesFromTimeseries(payload.timeseries, "active_flows_total"), "#5bb78c"),
      ],
    });

    renderControllerActivityTable("performance-activity-table", payload.controller_activity || []);
  }

  function updateCapturesPage(payload) {
    const captures = payload.captures || {};
    const continuous = captures.continuous || {};
    const snapshotRows = captures.snapshots || [];
    const fileRows = captures.continuous_files || [];
    syncCaptureSelections(snapshotRows, fileRows);

    const sessions = snapshotRows;
    const files = fileRows;
    const totalBytes = files.reduce(function (total, row) {
      return total + (row.size_bytes || 0);
    }, 0) + sessions.reduce(function (total, row) {
      return total + (row.size_bytes || 0);
    }, 0);

    setText("captures-session-count", formatNumber(files.length));
    setText("captures-file-count", formatNumber(sessions.length));
    setText(
      "captures-active-session",
      (continuous.interfaces || []).length
        ? "Interfaces: " + (continuous.interfaces || []).map(function (row) { return row.interface; }).join(", ")
        : "None"
    );
    setText("captures-status", continuous.active ? "Active" : "Inactive");
    setText("captures-last-scan", formatTimestamp(captures.last_scan_at));
    setText("captures-total-size", formatBytes(totalBytes));

    const visibleSnapshots = renderCaptureSessionsTable("captures-session-table", sessions);
    const visibleFiles = renderCaptureFilesTable("captures-file-table", files);
    syncCaptureSelectionControls(visibleSnapshots, visibleFiles, sessions, files);
    window.requestAnimationFrame(syncCaptureScrollbars);
  }

  function initializeCaptureScrollbars() {
    const shells = document.querySelectorAll(".js-scroll-shell");
    if (!shells.length) {
      return;
    }

    shells.forEach(function (shell) {
      if (shell.dataset.scrollbarBound === "true") {
        return;
      }

      const layout = shell.closest(".js-scroll-layout");
      const rail = layout ? layout.querySelector(".js-scroll-rail") : null;
      const thumb = layout ? layout.querySelector(".js-scroll-thumb") : null;
      if (!rail || !thumb) {
        return;
      }

      shell.addEventListener("scroll", function () {
        syncCaptureScrollbar(shell);
      }, { passive: true });

      rail.addEventListener("pointerdown", function (event) {
        if (event.button !== 0) {
          return;
        }

        const targetThumb = event.target.closest(".js-scroll-thumb");
        if (!targetThumb) {
          event.preventDefault();
          jumpCaptureScrollbar(shell, rail, event.clientY);
        }

        startCaptureScrollbarDrag(event, shell, rail, thumb);
      });

      shell.dataset.scrollbarBound = "true";
    });

    if (!state.captureScrollbarReady) {
      window.addEventListener("resize", syncCaptureScrollbars);
      state.captureScrollbarReady = true;
    }

    syncCaptureScrollbars();
  }

  function syncCaptureScrollbars() {
    document.querySelectorAll(".js-scroll-shell").forEach(function (shell) {
      syncCaptureScrollbar(shell);
    });
  }

  function syncCaptureScrollbar(shell) {
    const layout = shell.closest(".js-scroll-layout");
    const rail = layout ? layout.querySelector(".js-scroll-rail") : null;
    const thumb = layout ? layout.querySelector(".js-scroll-thumb") : null;
    if (!rail || !thumb) {
      return;
    }

    const viewportHeight = shell.clientHeight;
    const scrollHeight = shell.scrollHeight;
    const maxScroll = Math.max(scrollHeight - viewportHeight, 0);
    const trackHeight = rail.clientHeight;

    if (!trackHeight) {
      return;
    }

    const thumbHeight = maxScroll > 0
      ? Math.min(trackHeight, Math.max(Math.round((viewportHeight / scrollHeight) * trackHeight), 44))
      : trackHeight;
    const maxThumbTravel = Math.max(trackHeight - thumbHeight, 0);
    const thumbTop = maxScroll > 0
      ? (shell.scrollTop / maxScroll) * maxThumbTravel
      : 0;

    thumb.style.height = thumbHeight + "px";
    thumb.style.transform = "translateY(" + Math.round(thumbTop) + "px)";
    rail.classList.toggle("scroll-rail--static", maxScroll <= 0);
  }

  function startCaptureScrollbarDrag(event, shell, rail, thumb) {
    event.preventDefault();
    state.captureScrollbarDrag = {
      shell: shell,
      rail: rail,
      thumb: thumb,
      startY: event.clientY,
      startTop: currentCaptureThumbTop(thumb),
    };
  }

  function jumpCaptureScrollbar(shell, rail, clientY) {
    const thumb = rail.querySelector(".js-scroll-thumb");
    if (!thumb) {
      return;
    }

    const trackRect = rail.getBoundingClientRect();
    const thumbHeight = thumb.offsetHeight || 44;
    const targetTop = clampValue(clientY - trackRect.top - (thumbHeight / 2), 0, Math.max(trackRect.height - thumbHeight, 0));
    applyCaptureThumbPosition(shell, rail, thumb, targetTop);
  }

  function handleCaptureScrollbarPointerMove(event) {
    if (!state.captureScrollbarDrag) {
      return;
    }

    const drag = state.captureScrollbarDrag;
    const nextTop = drag.startTop + (event.clientY - drag.startY);
    applyCaptureThumbPosition(drag.shell, drag.rail, drag.thumb, nextTop);
  }

  function handleCaptureScrollbarPointerUp() {
    if (!state.captureScrollbarDrag) {
      return;
    }

    state.captureScrollbarDrag = null;
  }

  function applyCaptureThumbPosition(shell, rail, thumb, requestedTop) {
    const trackHeight = rail.clientHeight;
    const thumbHeight = thumb.offsetHeight || 44;
    const maxThumbTravel = Math.max(trackHeight - thumbHeight, 0);
    const boundedTop = clampValue(requestedTop, 0, maxThumbTravel);
    const maxScroll = Math.max(shell.scrollHeight - shell.clientHeight, 0);

    thumb.style.transform = "translateY(" + Math.round(boundedTop) + "px)";
    shell.scrollTop = maxThumbTravel > 0
      ? (boundedTop / maxThumbTravel) * maxScroll
      : 0;
  }

  function currentCaptureThumbTop(thumb) {
    const transform = thumb.style.transform || "";
    const match = transform.match(/translateY\(([-\d.]+)px\)/);
    return match ? Number(match[1]) : 0;
  }

  function updateMlPage(payload) {
    const ml = payload.ml || {};
    const predictionCounts = ml.prediction_counts || {};
    const alertCounts = ml.alert_counts || {};

    setText("ml-effective-mode", ml.effective_mode_label || formatDisplayValue(ml.effective_mode || "threshold"));
    setText(
      "ml-hybrid-policy",
      "Selected: " +
        (ml.selected_mode_label || formatIdsModeLabel(ml.selected_mode || "threshold")) +
        " · Policy: " +
        formatDisplayValue(ml.hybrid_policy || "layered_consensus")
    );
    setText("ml-model-status", ml.model_available ? "Available" : "Unavailable");
    setText("ml-model-path", ml.model_path || "-");
    setText("ml-predictions-total", formatNumber(predictionCounts.total || 0));
    setText(
      "ml-prediction-split",
      formatNumber(predictionCounts.malicious || 0) +
        " malicious / " +
        formatNumber(predictionCounts.benign || 0) +
        " benign"
    );
    setText("ml-alert-count", formatNumber(alertCounts.total || 0));
    setText(
      "ml-agreement-count",
      formatNumber(alertCounts.agreements || 0) + " hybrid agreements"
    );
    setText("ml-disagreement-count", formatNumber(alertCounts.disagreements || 0));
    setText("ml-threshold-only-count", formatNumber(alertCounts.threshold_only || 0));
    setText("ml-only-count", formatNumber(alertCounts.ml_only || 0));
    setText(
      "ml-agreement-rate",
      formatPercent((ml.agreement_rate || 0) * 100.0)
    );

    renderLineChart("chart-ml-confidence", {
      labels: recentPredictionLabels(ml.recent_predictions || []),
      datasets: [
        datasetLine("Confidence", recentPredictionValues(ml.recent_predictions || [], "confidence"), "#42c2ff"),
        datasetLine("Suspicion Score", recentPredictionValues(ml.recent_predictions || [], "suspicion_score"), "#ef5d4d"),
      ],
    });

    renderLineChart("chart-ml-alerts", {
      labels: labelsFromTimeseries(payload.timeseries),
      datasets: [
        datasetLine("ML Alerts", valuesFromTimeseries(payload.timeseries, "ml_alerts_total"), "#42c2ff"),
        datasetLine("ML Predictions", valuesFromTimeseries(payload.timeseries, "ml_predictions_total"), "#7dd3fc"),
        datasetLine("Hybrid Agreements", valuesFromTimeseries(payload.timeseries, "hybrid_agreements_total"), "#ef5d4d"),
        datasetLine("Hybrid Disagreements", valuesFromTimeseries(payload.timeseries, "hybrid_disagreements_total"), "#f0a639"),
      ],
    });

    renderMlAlertsTable("ml-alerts-table", ml.recent_alerts || []);
    renderMlHybridTable("ml-hybrid-table", ml.recent_hybrid_events || []);
    renderMlPredictionsTable("ml-predictions-table", ml.recent_predictions || []);
  }

  function updateSettingsPage(payload) {
    const settings = payload.settings || {};
    renderKeyValueGrid("settings-runtime-grid", settings.ids_runtime || {});
    renderKeyValueGrid("settings-ids-grid", settings.ids || {});
    renderKeyValueGrid("settings-firewall-grid", settings.firewall || {});
    renderKeyValueGrid("settings-ml-grid", settings.ml || {});
    renderKeyValueGrid("settings-dashboard-grid", mergeSettingsSections(settings.controller || {}, settings.dashboard || {}, settings.logging || {}));
  }

  function renderInventory(elementId, switches, hosts) {
    const container = document.getElementById(elementId);
    if (!container) {
      return;
    }

    const switchLines = switches.slice(0, 6).map(function (item) {
      return "<div class=\"stacked-list__item\"><span class=\"stacked-list__title\">Switch</span><span class=\"stacked-list__value\">" +
        escapeHtml(item.dpid || "-") + "</span></div>";
    });
    const hostLines = hosts.slice(0, 6).map(function (item) {
      return "<div class=\"stacked-list__item\"><span class=\"stacked-list__title\">" +
        escapeHtml(item.ip_address || item.mac_address || "-") +
        "</span><span class=\"stacked-list__value\">dpid " +
        escapeHtml(item.switch_id || "-") +
        " · port " +
        escapeHtml(item.port_no) +
        "</span></div>";
    });

    const html = [
      "<h3 class=\"stacked-list__heading\">Switches</h3>",
      switchLines.length ? switchLines.join("") : emptyState("No active switches yet."),
      "<h3 class=\"stacked-list__heading\">Learned Hosts</h3>",
      hostLines.length ? hostLines.join("") : emptyState("No learned hosts yet."),
    ].join("");

    container.innerHTML = html;
  }

  function renderAlertsTable(elementId, rows, limit) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    const subset = rows.slice(0, limit);
    tbody.innerHTML = subset.length
      ? subset.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(shortTimestamp(row.timestamp)) + "</td>" +
            "<td><span class=\"badge " + severityBadgeClass(row.severity) + "\">" + escapeHtml(formatDisplayValue(row.alert_type || "-")) + "</span></td>" +
            "<td>" + escapeHtml(formatDisplayValue(row.detector || "-")) + "</td>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(5, "No security activity yet.");
  }

  function renderFullAlertsTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    const tableSignature = rows.length
      ? rows.map(function (row) {
          return String(row.row_id || [
            row.timestamp || "",
            row.alert_type || "",
            row.detector || "",
            row.src_ip || "",
            row.status || "",
            row.reason || "",
          ].join("|"));
        }).join("::")
      : "__empty__";
    if (state.tableRenderSignatures[elementId] === tableSignature) {
      return;
    }
    state.tableRenderSignatures[elementId] = tableSignature;

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + renderEllipsisText(shortTimestamp(row.timestamp), 16, row.timestamp || "-") + "</td>" +
            "<td><span class=\"badge " + severityBadgeClass(row.severity) + "\">" + escapeHtml(row.severity || "-") + "</span></td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.alert_type), 22, row.alert_type || "-") + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.detector), 16, row.detector || "-") + "</td>" +
            "<td>" + renderEllipsisText(row.src_ip || "-", 18, row.src_ip || "-") + "</td>" +
            "<td class=\"table-reason-cell\">" + renderEllipsisText(row.reason || "-", 58) + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.quarantine_status || row.status || "-"), 18, row.quarantine_status || row.status || "-") + "</td>" +
            "<td>" + renderCaptureLink(row.related_capture) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(8, "No alerts available.");
  }

  function renderBlockedHostsTable(elementId, rows, limit) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    const subset = rows.slice(0, limit);
    tbody.innerHTML = subset.length
      ? subset.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td>" + escapeHtml(formatDisplayValue(row.detector || "-")) + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
            "<td>" + escapeHtml(shortTimestamp(row.created_at || row.created_at_epoch || "-")) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(4, "No active quarantines.");
  }

  function renderBlockedHostsFullTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td>" + escapeHtml(formatDisplayValue(row.detector || "-")) + "</td>" +
            "<td>" + escapeHtml(formatDisplayValue(row.alert_type || "-")) + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
            "<td>" + escapeHtml(shortTimestamp(row.created_at || row.created_at_epoch || "-")) + "</td>" +
            "<td>" + renderCaptureLink(row.related_capture) + "</td>" +
            "<td><button class=\"table-button js-unblock-host\" data-src-ip=\"" +
              escapeAttribute(row.src_ip || "") +
              "\">Unblock</button></td>" +
          "</tr>";
        }).join("")
      : emptyRow(7, "No quarantined hosts.");
  }

  function renderTrafficTalkersTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td>" + formatNumber(row.packet_count || 0) + "</td>" +
            "<td>" + formatBytes(row.byte_count || 0) + "</td>" +
            "<td>" + formatNumber(row.alert_count || 0) + "</td>" +
            "<td>" + formatNumber(row.block_count || 0) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(5, "No top talker data yet.");
  }

  function renderProtocolTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(row.protocol || "-") + "</td>" +
            "<td>" + formatNumber(row.packet_count || 0) + "</td>" +
            "<td>" + formatPercent(row.share_percent || 0) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(3, "No protocol counters yet.");
  }

  function renderControllerActivityTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(shortTimestamp(row.timestamp)) + "</td>" +
            "<td>" + escapeHtml(row.category || "-") + "</td>" +
            "<td>" + escapeHtml(row.event_type || "-") + "</td>" +
            "<td>" + escapeHtml(row.dpid || "-") + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
            "<td>" + escapeHtml(String(row.priority || "-")) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(6, "No controller activity recorded yet.");
  }

  function renderCaptureSessionsTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return [];
    }

    const visibleRows = limitedCaptureRows("snapshots", rows);
    tbody.innerHTML = visibleRows.length
      ? visibleRows.map(function (row) {
          const statusBadge = row.status === "preserved"
            ? "<span class=\"badge badge--danger\">Preserved</span>"
            : "<span class=\"badge badge--neutral\">" + escapeHtml(row.status || "stored") + "</span>";
          return "<tr>" +
            "<td class=\"table-select-cell\">" + renderCaptureSelectionCell("snapshot", row.snapshot_key || row.snapshot_name, row.snapshot_name) + "</td>" +
            "<td>" + renderEllipsisText(row.snapshot_name || "-", 120) + "</td>" +
            "<td>" + renderEllipsisText(formatCaptureTimestamp(row.timestamp), 32, row.timestamp || "-") + "</td>" +
            "<td>" + renderEllipsisText(row.source_ip || "-", 28) + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.detector), 28, row.detector || "-") + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.alert_type), 90, row.alert_type || "-") + "</td>" +
            "<td>" + formatNumber(row.file_count || 0) + "</td>" +
            "<td>" + escapeHtml(row.size_human || "0 B") + "</td>" +
            "<td>" + statusBadge + "</td>" +
            "<td>" + renderPrimaryDownloadLink(row) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(10, "No preserved alert snapshots yet.");
    syncCaptureMoreButton("snapshots", rows.length);
    return visibleRows;
  }

  function renderCaptureFilesTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return [];
    }

    const visibleRows = limitedCaptureRows("files", rows);
    tbody.innerHTML = visibleRows.length
      ? visibleRows.map(function (row) {
          const downloadCell = row.download_path
            ? "<a class=\"table-link\" href=\"" + escapeAttribute(row.download_path) + "\">Download</a>"
            : "-";
          return "<tr>" +
            "<td class=\"table-select-cell\">" + renderCaptureSelectionCell("file", row.relative_path, row.file_name) + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.session_name), 28, row.session_name || "-") + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.scenario), 44, row.scenario || "-") + "</td>" +
            "<td>" + renderEllipsisText(row.interface || "-", 24, row.interface || "-") + "</td>" +
            "<td>" + renderEllipsisText(row.file_name || "-", 140) + "</td>" +
            "<td>" + renderEllipsisText(formatDisplayValue(row.status), 28, row.status || "-") + "</td>" +
            "<td>" + escapeHtml(row.size_human || "0 B") + "</td>" +
            "<td>" + escapeHtml(shortTimestamp(row.modified_at || row.timestamp || "-")) + "</td>" +
            "<td>" + downloadCell + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(9, "No capture files available.");
    syncCaptureMoreButton("files", rows.length);
    return visibleRows;
  }

  function limitedCaptureRows(section, rows) {
    const visibleCount = captureVisibleCount(section, rows.length);
    return rows.slice(0, visibleCount);
  }

  function captureVisibleCount(section, totalRows) {
    const current = state.captureVisibleRows[section] || CAPTURE_PAGE_SIZE;
    return Math.min(Math.max(current, CAPTURE_PAGE_SIZE), Math.max(totalRows, 0));
  }

  function revealMoreCaptureRows(button) {
    const section = button.getAttribute("data-capture-section");
    if (!section || !Object.prototype.hasOwnProperty.call(state.captureVisibleRows, section)) {
      return;
    }
    state.captureVisibleRows[section] = (state.captureVisibleRows[section] || CAPTURE_PAGE_SIZE) + CAPTURE_PAGE_SIZE;
    if (state.lastPayload) {
      updateCapturesPage(state.lastPayload);
    }
  }

  function syncCaptureMoreButton(section, totalRows) {
    const button = document.getElementById(
      section === "snapshots" ? "captures-snapshots-more" : "captures-files-more"
    );
    if (!button) {
      return;
    }

    const visibleCount = captureVisibleCount(section, totalRows);
    const remaining = Math.max(totalRows - visibleCount, 0);
    if (remaining <= 0 || totalRows <= CAPTURE_PAGE_SIZE) {
      button.hidden = true;
      return;
    }

    button.hidden = false;
    button.textContent = "Show " + Math.min(CAPTURE_PAGE_SIZE, remaining) + " more";
  }

  function captureSnapshotKey(row) {
    if (!row) {
      return "";
    }
    return String(row.snapshot_key || row.snapshot_name || "").trim();
  }

  function syncCaptureSelections(snapshotRows, fileRows) {
    const validSnapshotKeys = new Set(
      (snapshotRows || []).map(function (row) {
        return captureSnapshotKey(row);
      }).filter(Boolean)
    );
    const validFilePaths = new Set(
      (fileRows || []).map(function (row) {
        return String(row.relative_path || "").trim();
      }).filter(Boolean)
    );

    state.captureSelection.snapshotKeys.forEach(function (key) {
      if (!validSnapshotKeys.has(key)) {
        state.captureSelection.snapshotKeys.delete(key);
      }
    });
    state.captureSelection.filePaths.forEach(function (path) {
      if (!validFilePaths.has(path)) {
        state.captureSelection.filePaths.delete(path);
      }
    });
  }

  function renderCaptureSelectionCell(kind, key, label) {
    const normalizedKey = String(key || "").trim();
    if (!normalizedKey) {
      return "-";
    }
    const selected = kind === "snapshot"
      ? state.captureSelection.snapshotKeys.has(normalizedKey)
      : state.captureSelection.filePaths.has(normalizedKey);
    const safeLabel = label ? String(label) : normalizedKey;
    return "<input class=\"table-checkbox js-capture-select\" type=\"checkbox\" " +
      "data-capture-kind=\"" + escapeAttribute(kind) + "\" " +
      "data-capture-key=\"" + escapeAttribute(normalizedKey) + "\" " +
      "aria-label=\"Select " + escapeAttribute(safeLabel) + "\" " +
      (selected ? "checked " : "") +
      (state.captureDeleteInFlight ? "disabled" : "") +
      "/>";
  }

  function syncCaptureSelectionControls(visibleSnapshots, visibleFiles, allSnapshots, allFiles) {
    syncCaptureSelectAllCheckbox(
      "snapshot",
      (visibleSnapshots || []).map(function (row) { return captureSnapshotKey(row); }).filter(Boolean)
    );
    syncCaptureSelectAllCheckbox(
      "file",
      (visibleFiles || []).map(function (row) { return String(row.relative_path || "").trim(); }).filter(Boolean)
    );
    const totalRows = (allSnapshots || []).length + (allFiles || []).length;
    setCaptureSelectionSummary(totalRows);
    updateCaptureActionButtons(totalRows);
  }

  function syncCaptureSelectAllCheckbox(kind, keys) {
    const selector = document.querySelector(
      ".js-capture-select-all[data-capture-kind=\"" + kind + "\"]"
    );
    if (!selector) {
      return;
    }
    const rows = (keys || []).filter(Boolean);
    if (!rows.length) {
      selector.checked = false;
      selector.indeterminate = false;
      selector.disabled = true;
      return;
    }
    selector.disabled = state.captureDeleteInFlight;
    const selectedCount = rows.filter(function (key) {
      return kind === "snapshot"
        ? state.captureSelection.snapshotKeys.has(key)
        : state.captureSelection.filePaths.has(key);
    }).length;
    selector.checked = selectedCount > 0 && selectedCount === rows.length;
    selector.indeterminate = selectedCount > 0 && selectedCount < rows.length;
  }

  function setCaptureSelectionSummary(totalRows) {
    const element = document.getElementById("captures-selection-summary");
    if (!element) {
      return;
    }
    const selected = selectedCaptureCount();
    if (!selected) {
      element.textContent = totalRows
        ? "No captures selected."
        : "No captures available.";
      return;
    }
    element.textContent = String(selected) + " capture" + (selected === 1 ? "" : "s") + " selected.";
  }

  function selectedCaptureCount() {
    return state.captureSelection.snapshotKeys.size + state.captureSelection.filePaths.size;
  }

  function setCaptureActionFeedback(message, tone) {
    const element = document.getElementById("captures-action-feedback");
    if (!element) {
      return;
    }
    element.textContent = message;
    element.className = "capture-toolbar__feedback capture-toolbar__feedback--" + (tone || "neutral");
  }

  function updateCaptureActionButtons(totalRows) {
    const deleteSelectedButton = document.getElementById("captures-delete-selected");
    const deleteAllButton = document.getElementById("captures-delete-all");
    const hasAnyRows = Number(totalRows || 0) > 0;
    const hasSelection = selectedCaptureCount() > 0;

    if (deleteSelectedButton) {
      deleteSelectedButton.disabled = !hasSelection || state.captureDeleteInFlight;
    }
    if (deleteAllButton) {
      deleteAllButton.disabled = !hasAnyRows || state.captureDeleteInFlight;
    }
  }

  function toggleCaptureSelection(kind, key, selected) {
    const normalizedKey = String(key || "").trim();
    if (!normalizedKey) {
      return;
    }
    const selectionSet = kind === "snapshot"
      ? state.captureSelection.snapshotKeys
      : state.captureSelection.filePaths;
    if (selected) {
      selectionSet.add(normalizedKey);
      return;
    }
    selectionSet.delete(normalizedKey);
  }

  function toggleCaptureSelectAll(kind, selected) {
    const selector = ".js-capture-select[data-capture-kind=\"" + kind + "\"]";
    document.querySelectorAll(selector).forEach(function (checkbox) {
      const key = checkbox.getAttribute("data-capture-key");
      checkbox.checked = selected;
      toggleCaptureSelection(kind, key, selected);
    });
  }

  async function deleteSelectedCaptures() {
    const snapshotNames = Array.from(state.captureSelection.snapshotKeys);
    const filePaths = Array.from(state.captureSelection.filePaths);
    const selectedCount = snapshotNames.length + filePaths.length;
    if (!selectedCount) {
      setCaptureActionFeedback("Select at least one capture before deleting.", "warning");
      return;
    }

    const confirmationMessage = "Delete " + selectedCount + " selected capture item(s)? This action cannot be undone.";
    if (!window.confirm(confirmationMessage)) {
      return;
    }

    await performCaptureDelete(
      basePath() + "/api/captures/delete-selected",
      {
        snapshot_names: snapshotNames,
        file_paths: filePaths,
      },
      "Selected captures deleted."
    );
  }

  async function deleteAllCaptures() {
    if (!window.confirm("Delete all stored captures and snapshots? This action cannot be undone.")) {
      return;
    }

    await performCaptureDelete(
      basePath() + "/api/captures/delete-all",
      {
        confirm: true,
      },
      "All captures deleted."
    );
  }

  async function performCaptureDelete(endpoint, requestBody, successMessage) {
    state.captureDeleteInFlight = true;
    setCaptureActionFeedback("Deleting capture artifacts...", "warning");
    updateCaptureActionButtons(state.lastPayload && state.lastPayload.captures
      ? ((state.lastPayload.captures.snapshots || []).length + (state.lastPayload.captures.continuous_files || []).length)
      : 0);

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestBody || {}),
      });
      const result = await response.json().catch(function () {
        return {};
      });
      if (!response.ok || !result.accepted) {
        throw new Error((result && (result.reason || result.status)) || ("capture_delete_failed_" + response.status));
      }

      state.captureSelection.snapshotKeys.clear();
      state.captureSelection.filePaths.clear();
      setCaptureActionFeedback(successMessage, "success");
      scheduleNextTick(120);
    } catch (error) {
      console.error(error);
      setCaptureActionFeedback("Capture deletion failed. Check dashboard logs and try again.", "danger");
    } finally {
      state.captureDeleteInFlight = false;
      if (state.lastPayload) {
        updateCapturesPage(state.lastPayload);
      } else {
        updateCaptureActionButtons(0);
      }
    }
  }

  async function handleActionChange(event) {
    const selectAllCapture = event.target.closest(".js-capture-select-all");
    if (selectAllCapture) {
      const captureKind = selectAllCapture.getAttribute("data-capture-kind");
      if (captureKind === "snapshot" || captureKind === "file") {
        toggleCaptureSelectAll(captureKind, !!selectAllCapture.checked);
        if (state.lastPayload) {
          updateCapturesPage(state.lastPayload);
        }
      }
      return;
    }

    const captureSelector = event.target.closest(".js-capture-select");
    if (captureSelector) {
      const captureKind = captureSelector.getAttribute("data-capture-kind");
      const captureKey = captureSelector.getAttribute("data-capture-key");
      if ((captureKind === "snapshot" || captureKind === "file") && captureKey) {
        toggleCaptureSelection(captureKind, captureKey, !!captureSelector.checked);
        if (state.lastPayload) {
          updateCapturesPage(state.lastPayload);
        }
      }
      return;
    }

    const selector = event.target.closest(".js-ids-mode-selector");
    if (!selector) {
      return;
    }

    const requestedMode = normalizeIdsMode(selector.value);
    const currentMode = currentSelectedIdsMode();
    if (!requestedMode || requestedMode === currentMode) {
      selector.value = currentMode;
      return;
    }

    state.idsModePendingValue = requestedMode;
    state.idsModeRequestInFlight = true;
    setIdsModeStatus("Applying " + formatIdsModeLabel(requestedMode) + "...", "warning");
    syncIdsModeControls(state.lastPayload);

    try {
      const response = await fetch(basePath() + "/api/set-ids-mode", {
        method: "POST",
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ mode: requestedMode }),
      });
      const result = await response.json().catch(function () {
        return {};
      });

      if (!response.ok || !result.accepted) {
        throw new Error(result.reason || result.status || ("ids_mode_change_failed_" + response.status));
      }

      setIdsModeStatus("Queued " + formatIdsModeLabel(requestedMode) + ". Waiting for controller update...", "warning");
      if (result.command_id) {
        const command = await waitForCommandResult(result.command_id, 8000);
        state.idsModePendingValue = null;
        state.idsModeRequestInFlight = false;
        if (command.status === "completed") {
          setIdsModeStatus("Controller mode updated to " + formatIdsModeLabel(requestedMode) + ".", "success");
        } else if (command.status === "noop") {
          setIdsModeStatus(formatIdsModeLabel(requestedMode) + " is already active.", "success");
        } else {
          throw new Error((command.result && command.result.reason) || command.status || "ids_mode_change_failed");
        }
      } else {
        state.idsModePendingValue = null;
        state.idsModeRequestInFlight = false;
      }
      scheduleNextTick(150);
    } catch (error) {
      console.error(error);
      state.idsModePendingValue = null;
      state.idsModeRequestInFlight = false;
      setIdsModeStatus(idsModeErrorMessage(error), "danger");
      syncIdsModeControls(state.lastPayload);
    }
  }

  async function handleActionClick(event) {
    const sidebarToggle = event.target.closest(".js-sidebar-toggle");
    if (sidebarToggle) {
      toggleSidebar();
      return;
    }

    const captureMoreButton = event.target.closest(".js-capture-more");
    if (captureMoreButton) {
      revealMoreCaptureRows(captureMoreButton);
      return;
    }

    const deleteSelectedButton = event.target.closest(".js-capture-delete-selected");
    if (deleteSelectedButton) {
      await deleteSelectedCaptures();
      return;
    }

    const deleteAllButton = event.target.closest(".js-capture-delete-all");
    if (deleteAllButton) {
      await deleteAllCaptures();
      return;
    }

    const button = event.target.closest(".js-unblock-host");
    if (!button) {
      return;
    }
    const srcIp = button.getAttribute("data-src-ip");
    if (!srcIp) {
      return;
    }
    button.disabled = true;
    button.textContent = "Queued...";
    try {
      const response = await fetch(
        basePath() + "/api/blocked-hosts/" + encodeURIComponent(srcIp) + "/unblock",
        {
          method: "POST",
          headers: {
            "Accept": "application/json",
          },
        }
      );
      if (!response.ok) {
        throw new Error("unblock_failed_" + response.status);
      }
      const result = await response.json().catch(function () {
        return {};
      });
      if (result.command_id) {
        const command = await waitForCommandResult(result.command_id, 8000);
        if (!(command.status === "completed" || command.status === "noop")) {
          throw new Error((command.result && command.result.reason) || command.status || "unblock_failed");
        }
      }
      scheduleNextTick(150);
    } catch (error) {
      console.error(error);
      button.disabled = false;
      button.textContent = "Unblock";
    }
  }

  async function waitForCommandResult(commandId, timeoutMs) {
    const deadline = Date.now() + Number(timeoutMs || 8000);
    while (Date.now() < deadline) {
      const response = await fetch(basePath() + "/api/commands/" + encodeURIComponent(commandId), {
        cache: "no-store",
        headers: {
          "Accept": "application/json",
        },
      });
      if (response.status === 404) {
        await sleep(150);
        continue;
      }
      if (!response.ok) {
        throw new Error("command_status_failed_" + response.status);
      }
      const command = await response.json();
      if (command.status && command.status !== "pending") {
        return command;
      }
      await sleep(150);
    }
    throw new Error("command_timeout");
  }

  function sleep(delayMs) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, delayMs);
    });
  }

  function initializeSidebar() {
    if (typeof window.matchMedia === "function") {
      state.sidebarMediaQuery = window.matchMedia(SIDEBAR_MOBILE_MEDIA_QUERY);
      syncSidebarForViewport();
      if (typeof state.sidebarMediaQuery.addEventListener === "function") {
        state.sidebarMediaQuery.addEventListener("change", syncSidebarForViewport);
      } else if (typeof state.sidebarMediaQuery.addListener === "function") {
        state.sidebarMediaQuery.addListener(syncSidebarForViewport);
      }
      return;
    }
    applySidebarState(readSidebarPreference(), false);
  }

  function markSidebarReady() {
    const root = document.documentElement;
    if (!root) {
      return;
    }
    window.requestAnimationFrame(function () {
      root.classList.add("sidebar-ready");
    });
  }

  function ensureSidebarToggle() {
    const sidebar = document.getElementById("sidebar");
    const header = sidebar ? sidebar.querySelector(".sidebar__header") : null;
    if (!header) {
      return;
    }

    let toggle = document.getElementById("sidebar-toggle");
    if (!toggle) {
      toggle = document.createElement("button");
      toggle.className = "sidebar__toggle js-sidebar-toggle";
      toggle.id = "sidebar-toggle";
      toggle.type = "button";
      toggle.setAttribute("aria-controls", "sidebar");
      header.appendChild(toggle);
    }

    if (!document.getElementById("sidebar-toggle-glyph")) {
      const glyph = document.createElement("span");
      glyph.className = "sidebar__toggle-glyph";
      glyph.id = "sidebar-toggle-glyph";
      glyph.setAttribute("aria-hidden", "true");
      glyph.textContent = "‹";
      toggle.appendChild(glyph);
    }

    if (!toggle.querySelector(".sr-only")) {
      const srOnly = document.createElement("span");
      srOnly.className = "sr-only";
      srOnly.textContent = "Toggle sidebar";
      toggle.appendChild(srOnly);
    }
  }

  function syncSidebarForViewport() {
    applySidebarState(readSidebarPreference(), false);
  }

  function toggleSidebar() {
    const shouldCollapse = !document.documentElement.classList.contains("sidebar-collapsed");
    applySidebarState(shouldCollapse, true);
  }

  function applySidebarState(collapsed, persist) {
    const root = document.documentElement;
    const body = document.body;
    const toggle = document.getElementById("sidebar-toggle");
    const isCollapsed = Boolean(collapsed);
    const label = isCollapsed ? "Expand sidebar" : "Collapse sidebar";

    root.classList.toggle("sidebar-collapsed", isCollapsed);
    if (body) {
      body.classList.toggle("sidebar-collapsed", isCollapsed);
    }

    if (toggle) {
      toggle.setAttribute("aria-expanded", String(!isCollapsed));
      toggle.setAttribute("aria-label", label);
      toggle.setAttribute("title", label);
    }

    if (persist) {
      writeSidebarPreference(isCollapsed);
    }
  }

  function readSidebarPreference() {
    try {
      return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === "true";
    } catch (error) {
      return false;
    }
  }

  function writeSidebarPreference(collapsed) {
    try {
      window.localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "true" : "false");
    } catch (error) {
      // Ignore localStorage failures and keep the current in-memory UI state.
    }
  }

  function syncIdsModeControls(payload) {
    const ml = (payload && payload.ml) || {};
    const selectedMode = ml.selected_mode_api || normalizeIdsMode(ml.selected_mode || "threshold");
    const effectiveMode = ml.effective_mode_api || normalizeIdsMode(ml.effective_mode || selectedMode);
    const selectedLabel = ml.selected_mode_label || formatIdsModeLabel(selectedMode);
    const effectiveLabel = ml.effective_mode_label || formatIdsModeLabel(effectiveMode);
    const selector = document.getElementById("ids-mode-selector");

    if (state.idsModePendingValue && selectedMode === state.idsModePendingValue) {
      state.idsModePendingValue = null;
      state.idsModeRequestInFlight = false;
      setIdsModeStatus("Controller mode updated to " + selectedLabel + ".", "success");
    }

    if (selector && !state.idsModePendingValue) {
      selector.value = selectedMode;
    }
    if (selector) {
      selector.disabled = state.idsModeRequestInFlight;
    }

    setText("ids-mode-selected", selectedLabel);
    setText("ids-mode-effective", effectiveLabel);
    setText("ids-mode-help", idsModeHelpText(ml));
    if (!state.idsModePendingValue && state.idsModeStatusMessage === "Loading runtime mode...") {
      state.idsModeStatusMessage = "Ready";
      state.idsModeStatusTone = "success";
    }
    updateIdsModeStatusElement();
  }

  function setIdsModeStatus(message, tone) {
    state.idsModeStatusMessage = message;
    state.idsModeStatusTone = tone || "success";
    updateIdsModeStatusElement();
  }

  function updateIdsModeStatusElement() {
    const element = document.getElementById("ids-mode-status");
    if (!element) {
      return;
    }
    element.textContent = state.idsModeStatusMessage || "Ready";
    element.className = "mode-feedback mode-feedback--" + (state.idsModeStatusTone || "success");
  }

  function renderCaptureLink(relatedCapture) {
    if (!relatedCapture || !relatedCapture.download_path) {
      return "-";
    }
    const label = relatedCapture.primary_file
      ? relatedCapture.primary_file.split("/").pop()
      : "Capture";
    return "<a class=\"table-link\" href=\"" + escapeAttribute(relatedCapture.download_path) + "\">" +
      escapeHtml(label) +
      "</a>";
  }

  function renderPrimaryDownloadLink(row) {
    if (!row || !row.primary_download_path) {
      return "-";
    }
    return "<a class=\"table-link\" href=\"" + escapeAttribute(row.primary_download_path) + "\">Download</a>";
  }

  function renderMlAlertsTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(shortTimestamp(row.timestamp)) + "</td>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td>" + formatDecimal(row.confidence) + "</td>" +
            "<td>" + escapeHtml(formatDisplayValue(row.status || row.action || row.alert_type || "-")) + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(5, "No ML alerts observed.");
  }

  function renderMlPredictionsTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          const classification = row.is_malicious
            ? "<span class=\"badge badge--danger\">Malicious</span>"
            : "<span class=\"badge badge--success\">Benign</span>";
          return "<tr>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td>" + escapeHtml(row.label || "-") + "</td>" +
            "<td>" + formatDecimal(row.confidence) + "</td>" +
            "<td>" + formatDecimal(row.suspicion_score) + "</td>" +
            "<td>" + classification + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(5, "No ML prediction samples recorded yet.");
  }

  function renderMlHybridTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(shortTimestamp(row.timestamp)) + "</td>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td><span class=\"badge " + severityBadgeClass(row.status) + "\">" + escapeHtml(formatDisplayValue(row.status || "-")) + "</span></td>" +
            "<td>" + formatDecimal(row.confidence) + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(5, "No hybrid correlation events recorded yet.");
  }

  function renderKeyValueGrid(elementId, values) {
    const container = document.getElementById(elementId);
    if (!container) {
      return;
    }

    const entries = Object.keys(values).sort().map(function (key) {
      return "<div class=\"kv-item\">" +
        "<span class=\"kv-item__key\">" + escapeHtml(prettyKey(key)) + "</span>" +
        "<span class=\"kv-item__value\">" + escapeHtml(formatSettingValue(values[key])) + "</span>" +
      "</div>";
    });
    container.innerHTML = entries.length ? entries.join("") : emptyState("No settings available.");
  }

  function renderLineChart(elementId, data) {
    const canvas = document.getElementById(elementId);
    if (!canvas) {
      return;
    }
    if (typeof Chart === "undefined") {
      markChartUnavailable(canvas, "Chart rendering unavailable.");
      return;
    }
    clearChartUnavailable(canvas);

    upsertChart(elementId, "line", {
      labels: data.labels,
      datasets: data.datasets,
    }, {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: {
        mode: "index",
        intersect: false,
      },
      plugins: {
        legend: {
          labels: {
            color: themeColor("--chart-text", "#5d7087"),
          },
        },
      },
      scales: {
        x: {
          ticks: { color: themeColor("--chart-text", "#5d7087") },
          grid: { color: themeColor("--chart-grid", "rgba(148, 163, 184, 0.2)") },
        },
        y: {
          ticks: { color: themeColor("--chart-text", "#5d7087") },
          grid: { color: themeColor("--chart-grid", "rgba(148, 163, 184, 0.2)") },
        },
      },
    });
  }

  function renderDoughnutChart(elementId, protocolRows) {
    const canvas = document.getElementById(elementId);
    if (!canvas) {
      return;
    }
    if (typeof Chart === "undefined") {
      markChartUnavailable(canvas, "Chart rendering unavailable.");
      return;
    }
    clearChartUnavailable(canvas);

    const labels = protocolRows.map(function (row) { return row.protocol; });
    const values = protocolRows.map(function (row) { return row.packet_count; });
    upsertChart(elementId, "doughnut", {
      labels: labels,
      datasets: [
        {
          data: values,
          backgroundColor: ["#5bb78c", "#42c2ff", "#f0a639", "#ef5d4d", "#a855f7", "#8b8f97"],
          borderWidth: 0,
        },
      ],
    }, {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: themeColor("--chart-text", "#5d7087"),
          },
        },
      },
    });
  }

  function upsertChart(key, type, data, options) {
    const nextDataSignature = chartSignature(data);
    const nextOptionsSignature = chartSignature(options);
    const existing = state.charts[key];
    if (existing) {
      if (existing.$dataSignature === nextDataSignature &&
          existing.$optionsSignature === nextOptionsSignature) {
        return existing;
      }

      if (existing.$dataSignature !== nextDataSignature) {
        existing.data.labels = data.labels.slice();
        existing.data.datasets = cloneDatasets(data.datasets);
        existing.$dataSignature = nextDataSignature;
      }

      if (existing.$optionsSignature !== nextOptionsSignature) {
        existing.options = options;
        existing.$optionsSignature = nextOptionsSignature;
      }

      existing.update("none");
      return existing;
    }

    const canvas = document.getElementById(key);
    if (!canvas) {
      return null;
    }

    state.charts[key] = new Chart(canvas.getContext("2d"), {
      type: type,
      data: data,
      options: options,
    });
    state.charts[key].$dataSignature = nextDataSignature;
    state.charts[key].$optionsSignature = nextOptionsSignature;
    return state.charts[key];
  }

  function markChartUnavailable(canvas, message) {
    const shell = canvas.parentElement;
    if (!shell) {
      return;
    }
    canvas.style.display = "none";
    let placeholder = shell.querySelector(".chart-fallback");
    if (!placeholder) {
      placeholder = document.createElement("p");
      placeholder.className = "chart-fallback";
      shell.appendChild(placeholder);
    }
    placeholder.textContent = message;
  }

  function clearChartUnavailable(canvas) {
    const shell = canvas.parentElement;
    if (!shell) {
      return;
    }
    canvas.style.display = "";
    const placeholder = shell.querySelector(".chart-fallback");
    if (placeholder) {
      placeholder.remove();
    }
  }

  function cloneDatasets(datasets) {
    return (datasets || []).map(function (dataset) {
      return Object.assign({}, dataset, {
        data: Array.isArray(dataset.data) ? dataset.data.slice() : dataset.data,
      });
    });
  }

  function chartSignature(value) {
    return JSON.stringify(value || null);
  }

  function themeColor(variableName, fallback) {
    if (!window.getComputedStyle) {
      return fallback;
    }
    const value = window.getComputedStyle(document.documentElement).getPropertyValue(variableName);
    return value ? (value.trim() || fallback) : fallback;
  }

  function datasetLine(label, values, color) {
    return {
      label: label,
      data: values,
      borderColor: color,
      backgroundColor: color,
      borderWidth: 2,
      fill: false,
      tension: 0.25,
      pointRadius: 0,
      pointHoverRadius: 3,
    };
  }

  function labelsFromTimeseries(timeseries) {
    return (timeseries || []).map(function (point) {
      return point.label || "-";
    });
  }

  function valuesFromTimeseries(timeseries, key) {
    return (timeseries || []).map(function (point) {
      return point[key] || 0;
    });
  }

  function rateSeries(timeseries, key) {
    return (timeseries || []).map(function (point, index) {
      if (index === 0) {
        return 0;
      }
      const previous = timeseries[index - 1];
      const elapsed = (point.timestamp_epoch || 0) - (previous.timestamp_epoch || 0);
      if (elapsed <= 0) {
        return 0;
      }
      const delta = (point[key] || 0) - (previous[key] || 0);
      return delta > 0 ? Number((delta / elapsed).toFixed(2)) : 0;
    });
  }

  function recentPredictionLabels(rows) {
    return rows.map(function (row, index) {
      return row.src_ip ? row.src_ip + " #" + (rows.length - index) : "sample";
    }).reverse();
  }

  function recentPredictionValues(rows, key) {
    return rows.map(function (row) {
      return row[key] || 0;
    }).reverse();
  }

  function mergeSettingsSections() {
    const merged = {};
    Array.prototype.slice.call(arguments).forEach(function (section) {
      Object.keys(section).forEach(function (key) {
        merged[key] = section[key];
      });
    });
    return merged;
  }

  function normalizeIdsMode(mode) {
    const value = String(mode || "").trim().toLowerCase();
    if (value === "threshold" || value === "threshold_only") {
      return "threshold";
    }
    if (value === "ml" || value === "ml_only") {
      return "ml";
    }
    if (value === "hybrid") {
      return "hybrid";
    }
    return "threshold";
  }

  function formatIdsModeLabel(mode) {
    const value = normalizeIdsMode(mode);
    if (value === "ml") {
      return "ML IDS";
    }
    if (value === "hybrid") {
      return "Hybrid";
    }
    return "Threshold IDS";
  }

  function currentSelectedIdsMode() {
    const ml = (state.lastPayload && state.lastPayload.ml) || {};
    return ml.selected_mode_api || normalizeIdsMode(ml.selected_mode || ml.effective_mode || "threshold");
  }

  function idsModeDescription(ml) {
    const selectedMode = ml.selected_mode_api || normalizeIdsMode(ml.selected_mode || "threshold");
    const effectiveMode = ml.effective_mode_api || normalizeIdsMode(ml.effective_mode || selectedMode);
    if (selectedMode !== effectiveMode) {
      return (
        "Selected " +
        formatIdsModeLabel(selectedMode) +
        ", running " +
        formatIdsModeLabel(effectiveMode) +
        " because ML is unavailable."
      );
    }
    if (effectiveMode === "ml") {
      return "ML-only inference is active.";
    }
    if (effectiveMode === "hybrid") {
      return "Threshold and ML run together with live correlation.";
    }
    return "Threshold-only inspection is active.";
  }

  function idsModeAlertDescription(ml) {
    const effectiveMode = ml.effective_mode_api || normalizeIdsMode(ml.effective_mode || "threshold");
    if (effectiveMode === "ml") {
      return "Feed shows ML detections only.";
    }
    if (effectiveMode === "hybrid") {
      return "Feed includes threshold, ML, and correlation events.";
    }
    return "Feed shows threshold detections only.";
  }

  function idsModeHelpText(ml) {
    const modelAvailable = !!ml.model_available;
    const selectedMode = ml.selected_mode_api || normalizeIdsMode(ml.selected_mode || "threshold");
    if (!modelAvailable) {
      return "No runtime model is loaded. Threshold mode stays available.";
    }
    if (selectedMode === "hybrid") {
      return "Hybrid keeps the baseline detector and layers in ML correlation.";
    }
    if (selectedMode === "ml") {
      return "ML mode relies on live features and runtime inference only.";
    }
    return "Threshold mode keeps the baseline detector active.";
  }

  function idsModeErrorMessage(error) {
    const message = String((error && error.message) || "ids_mode_change_failed");
    if (message.indexOf("model_unavailable") !== -1) {
      return "ML mode is unavailable because no runtime model is loaded.";
    }
    if (message.indexOf("command_timeout") !== -1) {
      return "The controller did not confirm the IDS mode change in time.";
    }
    if (message.indexOf("unsupported_mode") !== -1) {
      return "That IDS mode is not supported.";
    }
    return "Could not change IDS mode. The controller kept the previous selection.";
  }

  function calculateFreshness(payload) {
    const generatedAt = payload && payload.generated_at_epoch ? payload.generated_at_epoch * 1000 : 0;
    const staleAfter = payload && payload.stale_after_seconds
      ? payload.stale_after_seconds * 1000
      : Math.max(4000, pollIntervalMs() * 2.5);
    const ageMs = generatedAt ? (Date.now() - generatedAt) : Infinity;
    return {
      ageMs: ageMs,
      isStale: ageMs > staleAfter,
    };
  }

  function pollIntervalMs() {
    return Number(document.body.getAttribute("data-poll-interval-ms") || "2000");
  }

  function basePath() {
    return document.body.getAttribute("data-base-path") || "/sdn-security";
  }

  function apiEndpoint() {
    return document.body.getAttribute("data-api-endpoint") || "/sdn-security/api/dashboard";
  }

  function currentPage() {
    return document.body.getAttribute("data-page") || "dashboard";
  }

  function setText(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = value;
    }
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function formatBytes(value) {
    const size = Number(value || 0);
    if (!size) {
      return "0 B";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    let unitIndex = 0;
    let current = size;
    while (current >= 1024 && unitIndex < units.length - 1) {
      current /= 1024;
      unitIndex += 1;
    }
    if (unitIndex === 0) {
      return String(Math.round(current)) + " " + units[unitIndex];
    }
    return current.toFixed(1) + " " + units[unitIndex];
  }

  function formatPercent(value) {
    return Number(value || 0).toFixed(2) + "%";
  }

  function formatDecimal(value) {
    if (value === null || value === undefined || value === "") {
      return "-";
    }
    return Number(value).toFixed(3);
  }

  function formatTimestamp(value) {
    if (!value) {
      return "Waiting";
    }
    return shortTimestamp(value);
  }

  function formatCaptureTimestamp(value) {
    if (!value) {
      return "-";
    }

    try {
      const date = parseTimestampValue(value);
      if (!date) {
        return String(value);
      }
      return [
        date.getFullYear(),
        padNumber(date.getMonth() + 1),
        padNumber(date.getDate()),
      ].join("-") + " " + [
        padNumber(date.getHours()),
        padNumber(date.getMinutes()),
        padNumber(date.getSeconds()),
      ].join(":");
    } catch (error) {
      return String(value);
    }
  }

  function shortTimestamp(value) {
    try {
      const date = parseTimestampValue(value);
      if (!date) {
        return value;
      }
      return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch (error) {
      return value;
    }
  }

  function parseTimestampValue(value) {
    if (value === null || value === undefined || value === "") {
      return null;
    }

    if (typeof value === "number" && Number.isFinite(value)) {
      const epochMs = value >= 1e12 ? value : value * 1000;
      const fromNumber = new Date(epochMs);
      return Number.isNaN(fromNumber.getTime()) ? null : fromNumber;
    }

    const textValue = String(value).trim();
    if (!textValue) {
      return null;
    }

    if (/^-?\d+(\.\d+)?$/.test(textValue)) {
      const numericValue = Number(textValue);
      if (Number.isFinite(numericValue)) {
        const epochMs = numericValue >= 1e12 ? numericValue : numericValue * 1000;
        const fromNumericText = new Date(epochMs);
        return Number.isNaN(fromNumericText.getTime()) ? null : fromNumericText;
      }
    }

    const fromText = new Date(textValue);
    return Number.isNaN(fromText.getTime()) ? null : fromText;
  }

  function initializeResizableTables() {
    [
      {
        selector: ".js-resizable-alerts-table",
        storageKey: ALERT_TABLE_WIDTHS_STORAGE_KEY,
        minWidths: ALERT_TABLE_MIN_WIDTHS,
        defaultWidths: ALERT_TABLE_DEFAULT_WIDTHS,
      },
      {
        selector: ".js-resizable-snapshots-table",
        storageKey: ALERT_SNAPSHOTS_TABLE_WIDTHS_STORAGE_KEY,
        minWidths: ALERT_SNAPSHOTS_TABLE_MIN_WIDTHS,
        defaultWidths: ALERT_SNAPSHOTS_TABLE_DEFAULT_WIDTHS,
        lockedColumns: [0],
      },
      {
        selector: ".js-resizable-ring-buffer-table",
        storageKey: RING_BUFFER_TABLE_WIDTHS_STORAGE_KEY,
        minWidths: RING_BUFFER_TABLE_MIN_WIDTHS,
        defaultWidths: RING_BUFFER_TABLE_DEFAULT_WIDTHS,
        lockedColumns: [0],
      },
    ].forEach(function (config) {
      initializeResizableTable(config);
    });
  }

  function initializeResizableTable(config) {
    const table = document.querySelector(config.selector);
    if (!table || table.dataset.resizableInitialized === "true") {
      return;
    }

    const columnGroup = table.querySelector("colgroup");
    const tableHead = table.tHead;
    if (!columnGroup || !tableHead || !tableHead.rows.length) {
      return;
    }

    const columns = Array.from(columnGroup.querySelectorAll("col"));
    const headerCells = Array.from(tableHead.rows[0].cells);
    if (!columns.length || columns.length !== headerCells.length) {
      return;
    }

    applyStoredColumnWidths(columns, config);
    table.dataset.resizableInitialized = "true";

    headerCells.forEach(function (headerCell, index) {
      if ((config.lockedColumns || []).indexOf(index) >= 0) {
        headerCell.classList.add("is-resize-locked");
        return;
      }
      if (headerCell.querySelector(".table-column-resizer")) {
        return;
      }

      headerCell.classList.add("is-resizable");
      const handle = document.createElement("span");
      handle.className = "table-column-resizer";
      handle.setAttribute("role", "separator");
      handle.setAttribute("aria-orientation", "vertical");
      handle.setAttribute("tabindex", "0");
      handle.setAttribute("title", "Drag to resize column");
      handle.addEventListener("pointerdown", function (event) {
        if (event.button !== 0) {
          return;
        }
        event.preventDefault();
        beginColumnResize(event, table, columns, index, config);
      });
      handle.addEventListener("keydown", function (event) {
        if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {
          return;
        }
        event.preventDefault();
        const delta = event.key === "ArrowRight" ? 16 : -16;
        nudgeColumnWidth(columns, index, delta, config);
      });
      headerCell.appendChild(handle);
    });
  }

  function applyStoredColumnWidths(columns, config) {
    let storedWidths = null;
    try {
      storedWidths = JSON.parse(window.localStorage.getItem(config.storageKey) || "null");
    } catch (error) {
      storedWidths = null;
    }

    columns.forEach(function (column, index) {
      const minimumWidth = (config.minWidths && config.minWidths[index]) || 110;
      const fallbackWidth = (config.defaultWidths && config.defaultWidths[index]) || minimumWidth;
      const widthValue = Array.isArray(storedWidths)
        ? Number(storedWidths[index])
        : NaN;
      const resolvedWidth = Number.isFinite(widthValue)
        ? Math.max(minimumWidth, widthValue)
        : fallbackWidth;
      column.style.width = resolvedWidth + "px";
      column.style.minWidth = minimumWidth + "px";
    });
  }

  function beginColumnResize(pointerEvent, table, columns, columnIndex, config) {
    const column = columns[columnIndex];
    if (!column) {
      return;
    }

    const startingWidth = column.getBoundingClientRect().width;
    const minimumWidth = (config.minWidths && config.minWidths[columnIndex]) || 110;
    const startX = pointerEvent.clientX;
    table.classList.add("is-resizing-columns");

    const onPointerMove = function (moveEvent) {
      const delta = moveEvent.clientX - startX;
      const nextWidth = Math.max(minimumWidth, Math.round(startingWidth + delta));
      column.style.width = nextWidth + "px";
    };

    const onPointerUp = function () {
      table.classList.remove("is-resizing-columns");
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      persistColumnWidths(columns, config);
    };

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
  }

  function nudgeColumnWidth(columns, columnIndex, delta, config) {
    const column = columns[columnIndex];
    if (!column) {
      return;
    }

    const minimumWidth = (config.minWidths && config.minWidths[columnIndex]) || 110;
    const currentWidth = column.getBoundingClientRect().width;
    const nextWidth = Math.max(minimumWidth, Math.round(currentWidth + delta));
    column.style.width = nextWidth + "px";
    persistColumnWidths(columns, config);
  }

  function persistColumnWidths(columns, config) {
    const widths = columns.map(function (column, index) {
      const minimumWidth = (config.minWidths && config.minWidths[index]) || 110;
      return Math.max(minimumWidth, Math.round(column.getBoundingClientRect().width));
    });

    try {
      window.localStorage.setItem(
        config.storageKey,
        JSON.stringify(widths)
      );
    } catch (error) {
      // Ignore storage failures and keep runtime widths only.
    }
  }

  function truncateText(value, maxLength) {
    const text = value === null || value === undefined || value === ""
      ? "-"
      : String(value);
    if (!maxLength || text.length <= maxLength) {
      return text;
    }
    return text.slice(0, Math.max(0, maxLength - 3)).trimEnd() + "...";
  }

  function renderEllipsisText(value, maxLength, titleValue) {
    const rawValue = value === null || value === undefined || value === ""
      ? "-"
      : String(value);
    const title = titleValue === null || titleValue === undefined || titleValue === ""
      ? rawValue
      : String(titleValue);
    return "<span class=\"table-ellipsis\" title=\"" +
      escapeAttribute(title) +
      "\">" +
      escapeHtml(truncateText(rawValue, maxLength)) +
      "</span>";
  }

  function padNumber(value) {
    return String(value).padStart(2, "0");
  }

  function formatSettingValue(value) {
    if (Array.isArray(value)) {
      return value.length
        ? value.map(function (item) { return formatDisplayValue(item); }).join(", ")
        : "(none)";
    }
    if (typeof value === "boolean") {
      return value ? "Enabled" : "Disabled";
    }
    if (value === null || value === undefined || value === "") {
      return "-";
    }
    return formatDisplayValue(value);
  }

  function formatDisplayValue(value) {
    if (value === null || value === undefined || value === "") {
      return "-";
    }
    const text = String(value).trim();
    if (!text) {
      return "-";
    }
    if (text.indexOf("/") !== -1 || text.indexOf("\\") !== -1 || text.indexOf(".") !== -1 || text.indexOf(":") !== -1) {
      return text;
    }
    if (text.indexOf("_") !== -1 || text.indexOf("-") !== -1) {
      return text
        .split(/[_-]+/)
        .filter(Boolean)
        .map(titleCaseToken)
        .join(" ");
    }
    if (/^[a-z]+(?:[A-Z][a-z0-9]+)+$/.test(text)) {
      return text
        .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
        .split(" ")
        .map(titleCaseToken)
        .join(" ");
    }
    if (/^[a-z0-9]+$/.test(text)) {
      return titleCaseToken(text);
    }
    return text;
  }

  function titleCaseToken(value) {
    const token = String(value || "").trim();
    if (!token) {
      return "";
    }
    const lower = token.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(TOKEN_ACRONYMS, lower)) {
      return TOKEN_ACRONYMS[lower];
    }
    return lower.charAt(0).toUpperCase() + lower.slice(1);
  }

  function prettyKey(value) {
    return String(value)
      .replace(/_/g, " ")
      .replace(/\b\w/g, function (match) { return match.toUpperCase(); });
  }

  function clampValue(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function emptyRow(colspan, message) {
    return "<tr><td colspan=\"" + colspan + "\" class=\"data-table__empty\">" + escapeHtml(message) + "</td></tr>";
  }

  function emptyState(message) {
    return "<div class=\"empty-state\">" + escapeHtml(message) + "</div>";
  }

  function severityBadgeClass(severity) {
    const value = (severity || "").toLowerCase();
    if (
      value === "critical" ||
      value === "high" ||
      value === "agreement"
    ) {
      return "badge--danger";
    }
    if (
      value === "medium" ||
      value === "warning" ||
      value === "disagreement"
    ) {
      return "badge--warning";
    }
    if (
      value === "low" ||
      value === "info" ||
      value === "threshold_only" ||
      value === "ml_only"
    ) {
      return "badge--info";
    }
    return "badge--neutral";
  }

  function idsModeBadgeClass(mode) {
    const normalized = normalizeIdsMode(mode);
    if (normalized === "hybrid") {
      return "badge--warning";
    }
    if (normalized === "ml") {
      return "badge--info";
    }
    return "badge--success";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function escapeAttribute(value) {
    return escapeHtml(value);
  }
})();
