(function () {
  "use strict";

  const state = {
    charts: {},
    lastPayload: null,
    pollTimer: null,
    isFetching: false,
  };

  document.addEventListener("DOMContentLoaded", function () {
    const body = document.body;
    if (!body) {
      return;
    }

    document.addEventListener("click", handleActionClick);
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
        ? "Live data stream"
        : "Waiting for controller state";
    }

    if (error) {
      console.error(error);
    }
  }

  function updateChrome(payload) {
    const summary = payload.summary || {};
    const ml = payload.ml || {};

    setText("chrome-ml-mode", ml.effective_mode || summary.ml_mode || "threshold_only");
    setText("chrome-last-updated", formatTimestamp(payload.generated_at));
    setText("footer-total-packets", formatNumber(summary.total_packets));
    setText("footer-switches", formatNumber(summary.active_switches));
    setText("footer-alerts", formatNumber(summary.alerts_total));
    setText("footer-blocks", formatNumber(summary.active_blocks));
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

    setText("stat-total-packets", formatNumber(summary.total_packets));
    setText("stat-packet-rate", performance.packet_in_rate_display || "0 pkt/s");
    setText("stat-active-switches", formatNumber(summary.active_switches));
    setText("stat-active-hosts", formatNumber(summary.active_hosts));
    setText("stat-active-blocks", formatNumber(summary.active_blocks));
    setText("stat-alert-total", formatNumber(summary.alerts_total) + " alerts total");

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

    setText("alerts-total", formatNumber(summary.alerts_total));
    setText("alerts-threshold", formatNumber(summary.threshold_alerts_total));
    setText("alerts-ml", formatNumber(summary.ml_alerts_total));
    setText("alerts-critical", formatNumber((severityCounts.critical || 0)));
    renderFullAlertsTable("alerts-table", alerts.rows || []);
  }

  function updateBlockedHostsPage(payload) {
    const summary = payload.summary || {};
    const blockedHosts = payload.blocked_hosts || [];

    setText("blocked-total", formatNumber(summary.active_blocks));
    setText("blocked-threshold", formatNumber(summary.threshold_blocks_total));
    setText("blocked-ml", formatNumber(summary.ml_blocks_total));
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
    const sessions = captures.snapshots || [];
    const files = captures.continuous_files || [];
    const totalBytes = files.reduce(function (total, row) {
      return total + (row.size_bytes || 0);
    }, 0) + sessions.reduce(function (total, row) {
      return total + (row.size_bytes || 0);
    }, 0);

    setText("captures-session-count", formatNumber(files.length));
    setText("captures-file-count", formatNumber(sessions.length));
    setText(
      "captures-active-session",
      (continuous.interfaces || []).map(function (row) { return row.interface; }).join(", ") || "None"
    );
    setText("captures-status", continuous.active ? "active" : "inactive");
    setText("captures-last-scan", formatTimestamp(captures.last_scan_at));
    setText("captures-total-size", formatBytes(totalBytes));

    renderCaptureSessionsTable("captures-session-table", sessions);
    renderCaptureFilesTable("captures-file-table", files);
  }

  function updateMlPage(payload) {
    const ml = payload.ml || {};
    const predictionCounts = ml.prediction_counts || {};
    const alertCounts = ml.alert_counts || {};

    setText("ml-effective-mode", ml.effective_mode || "threshold_only");
    setText("ml-hybrid-policy", ml.hybrid_policy || "alert_only");
    setText("ml-model-status", ml.model_available ? "Yes" : "No");
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
            "<td><span class=\"badge " + severityBadgeClass(row.severity) + "\">" + escapeHtml(row.alert_type || "-") + "</span></td>" +
            "<td>" + escapeHtml(row.detector || "-") + "</td>" +
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

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(shortTimestamp(row.timestamp)) + "</td>" +
            "<td><span class=\"badge " + severityBadgeClass(row.severity) + "\">" + escapeHtml(row.severity || "-") + "</span></td>" +
            "<td>" + escapeHtml(row.alert_type || "-") + "</td>" +
            "<td>" + escapeHtml(row.detector || "-") + "</td>" +
            "<td>" + escapeHtml(row.src_ip || "-") + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
            "<td>" + escapeHtml(row.quarantine_status || row.status || "-") + "</td>" +
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
            "<td>" + escapeHtml(row.detector || "-") + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
            "<td>" + renderCaptureLink(row.related_capture) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(4, "No active blocks.");
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
            "<td>" + escapeHtml(row.detector || "-") + "</td>" +
            "<td>" + escapeHtml(row.alert_type || "-") + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.reason || "-") + "</td>" +
            "<td>" + escapeHtml(row.created_at || "-") + "</td>" +
            "<td>" + renderCaptureLink(row.related_capture) + "</td>" +
            "<td><button class=\"table-button js-unblock-host\" data-src-ip=\"" +
              escapeAttribute(row.src_ip || "") +
              "\">Unblock</button></td>" +
          "</tr>";
        }).join("")
      : emptyRow(7, "No blocked hosts.");
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
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          const statusBadge = row.status === "preserved"
            ? "<span class=\"badge badge--danger\">Preserved</span>"
            : "<span class=\"badge badge--neutral\">" + escapeHtml(row.status || "stored") + "</span>";
          return "<tr>" +
            "<td>" + escapeHtml(row.snapshot_name || "-") + "</td>" +
            "<td>" + escapeHtml(row.timestamp || "-") + "</td>" +
            "<td>" + escapeHtml(row.source_ip || "-") + "</td>" +
            "<td>" + escapeHtml(row.detector || "-") + "</td>" +
            "<td>" + escapeHtml(row.alert_type || "-") + "</td>" +
            "<td>" + formatNumber(row.file_count || 0) + "</td>" +
            "<td>" + escapeHtml(row.size_human || "0 B") + "</td>" +
            "<td>" + statusBadge + "</td>" +
            "<td>" + renderPrimaryDownloadLink(row) + "</td>" +
          "</tr>";
        }).join("")
      : emptyRow(9, "No preserved alert snapshots yet.");
  }

  function renderCaptureFilesTable(elementId, rows) {
    const tbody = document.getElementById(elementId);
    if (!tbody) {
      return;
    }

    tbody.innerHTML = rows.length
      ? rows.map(function (row) {
          return "<tr>" +
            "<td>" + escapeHtml(row.session_name || "-") + "</td>" +
            "<td>" + escapeHtml(row.scenario || "-") + "</td>" +
            "<td>" + escapeHtml(row.interface || "-") + "</td>" +
            "<td class=\"table-wrap\">" + escapeHtml(row.file_name || "-") + "</td>" +
            "<td>" + escapeHtml(row.status || "-") + "</td>" +
            "<td>" + escapeHtml(row.size_human || "0 B") + "</td>" +
            "<td>" + escapeHtml(shortTimestamp(row.modified_at || row.timestamp || "-")) + "</td>" +
            "<td><a class=\"table-link\" href=\"" + escapeAttribute(row.download_path || "#") + "\">Download</a></td>" +
          "</tr>";
        }).join("")
      : emptyRow(8, "No capture files available.");
  }

  async function handleActionClick(event) {
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
      scheduleNextTick(150);
    } catch (error) {
      console.error(error);
      button.disabled = false;
      button.textContent = "Unblock";
    }
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
            "<td>" + escapeHtml(row.status || row.action || row.alert_type || "-") + "</td>" +
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
            ? "<span class=\"badge badge--danger\">malicious</span>"
            : "<span class=\"badge badge--success\">benign</span>";
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
            "<td><span class=\"badge " + severityBadgeClass(row.status) + "\">" + escapeHtml(row.status || "-") + "</span></td>" +
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
    if (!canvas || typeof Chart === "undefined") {
      return;
    }

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
            color: "#d8e1eb",
          },
        },
      },
      scales: {
        x: {
          ticks: { color: "#94a7bc" },
          grid: { color: "rgba(148, 167, 188, 0.12)" },
        },
        y: {
          ticks: { color: "#94a7bc" },
          grid: { color: "rgba(148, 167, 188, 0.12)" },
        },
      },
    });
  }

  function renderDoughnutChart(elementId, protocolRows) {
    const canvas = document.getElementById(elementId);
    if (!canvas || typeof Chart === "undefined") {
      return;
    }

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
            color: "#d8e1eb",
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

  function shortTimestamp(value) {
    try {
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return value;
      }
      return date.toLocaleTimeString();
    } catch (error) {
      return value;
    }
  }

  function formatSettingValue(value) {
    if (Array.isArray(value)) {
      return value.length ? value.join(", ") : "(none)";
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    if (value === null || value === undefined || value === "") {
      return "-";
    }
    return String(value);
  }

  function prettyKey(value) {
    return String(value)
      .replace(/_/g, " ")
      .replace(/\b\w/g, function (match) { return match.toUpperCase(); });
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
