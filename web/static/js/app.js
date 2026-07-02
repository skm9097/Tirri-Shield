document.addEventListener("DOMContentLoaded", function () {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");
  const statusDot = document.getElementById("connection-status");

  let ws = null;

  // Tab switching
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      const target = tab.dataset.panel;
      tabs.forEach(function (t) { t.classList.remove("active"); });
      panels.forEach(function (p) { p.classList.remove("active"); });
      tab.classList.add("active");
      document.getElementById("panel-" + target).classList.add("active");
    });
  });

  // WebSocket connection
  function connectWS() {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(protocol + "//" + location.host + "/ws");

    ws.onopen = function () {
      statusDot.className = "status-indicator connected";
      statusDot.querySelector(".label").textContent = "Connected";
    };

    ws.onclose = function () {
      statusDot.className = "status-indicator disconnected";
      statusDot.querySelector(".label").textContent = "Disconnected";
      setTimeout(connectWS, 3000);
    };

    ws.onerror = function () {
      statusDot.className = "status-indicator disconnected";
      statusDot.querySelector(".label").textContent = "Error";
    };

    ws.onmessage = function (event) {
      var data = JSON.parse(event.data);
      handleWSMessage(data);
    };
  }

  function handleWSMessage(data) {
    if (data.type === "alert") {
      addAlert(data.data);
    } else if (data.type === "scan_started") {
      showScanStatus("Scanning for BMS devices...", "scanning");
    } else if (data.type === "scan_complete") {
      hideScanStatus();
      displayScanResults(data.data);
    }
  }

  // Scanner
  var btnScan = document.getElementById("btn-scan");
  var scanStatus = document.getElementById("scan-status");
  var scanResults = document.getElementById("scan-results");

  btnScan.addEventListener("click", function () {
    var duration = parseFloat(document.getElementById("scan-duration").value) || 10;
    var deep = document.getElementById("deep-scan").checked;

    btnScan.disabled = true;
    btnScan.textContent = "Scanning...";
    showScanStatus("Scanning for BMS devices... (" + duration + "s)", "scanning");

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ duration: duration, deep: deep }),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        btnScan.disabled = false;
        btnScan.textContent = "Scan for BMS Devices";
        hideScanStatus();

        if (data.error) {
          showScanStatus("Scan failed: " + data.error, "error");
          return;
        }
        displayScanResults(data.results);
      })
      .catch(function (err) {
        btnScan.disabled = false;
        btnScan.textContent = "Scan for BMS Devices";
        showScanStatus("Scan failed: " + err.message, "error");
      });
  });

  function showScanStatus(message, type) {
    scanStatus.textContent = message;
    scanStatus.className = "status-box " + type;
    scanStatus.classList.remove("hidden");
  }

  function hideScanStatus() {
    scanStatus.classList.add("hidden");
  }

  function displayScanResults(results) {
    if (!results || results.length === 0) {
      scanResults.innerHTML =
        '<p class="placeholder">No BMS devices found. Try moving closer to the vehicle or increasing scan duration.</p>';
      return;
    }

    var html = "";
    results.forEach(function (report) {
      var device = report.device;
      var level = report.overall_level;

      html += '<div class="device-card ' + level + '">';
      html += '<div class="device-header">';
      html += '<span class="device-name">' + escapeHtml(device.name || "Unknown Device") + "</span>";
      html += '<span class="severity-badge ' + level + '">' + level.toUpperCase() + "</span>";
      html += "</div>";

      html += '<div class="device-meta">';
      html += "<span>Address: " + escapeHtml(device.address) + "</span>";
      html += "<span>Type: " + escapeHtml(device.type) + "</span>";
      html += "<span>RSSI: " + device.rssi + " dBm</span>";
      html += "<span>Signal: " + escapeHtml(device.signal_strength) + "</span>";
      if (device.estimated_distance_m >= 0) {
        html += "<span>Distance: ~" + device.estimated_distance_m + "m</span>";
      }
      html += "</div>";

      if (report.findings && report.findings.length > 0) {
        html += '<div class="findings-list">';
        report.findings.forEach(function (finding) {
          html += '<div class="finding">';
          html += '<div class="finding-title">[' + finding.severity.toUpperCase() + "] " + escapeHtml(finding.title) + "</div>";
          html += '<div class="finding-desc">' + escapeHtml(finding.description) + "</div>";
          html += '<div class="finding-rec">' + escapeHtml(finding.recommendation) + "</div>";
          html += "</div>";
        });
        html += "</div>";
      }

      html += "</div>";
    });

    scanResults.innerHTML = html;
  }

  // Monitor
  var btnStart = document.getElementById("btn-monitor-start");
  var btnStop = document.getElementById("btn-monitor-stop");
  var alertFeed = document.getElementById("alert-feed");

  btnStart.addEventListener("click", function () {
    var target = document.getElementById("monitor-target").value || null;
    var interval = parseFloat(document.getElementById("monitor-interval").value) || 5;

    fetch("/api/monitor/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target, interval: interval }),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.status === "started" || data.status === "already_running") {
          btnStart.disabled = true;
          btnStop.disabled = false;
          alertFeed.innerHTML = '<p class="placeholder">Monitoring active. Alerts will appear here.</p>';
        }
      })
      .catch(function (err) {
        console.error("Failed to start monitor:", err);
      });
  });

  btnStop.addEventListener("click", function () {
    fetch("/api/monitor/stop", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function () {
        btnStart.disabled = false;
        btnStop.disabled = true;
      })
      .catch(function (err) {
        console.error("Failed to stop monitor:", err);
      });
  });

  function addAlert(alertData) {
    var placeholder = alertFeed.querySelector(".placeholder");
    if (placeholder) placeholder.remove();

    var item = document.createElement("div");
    item.className = "alert-item " + alertData.severity;

    var time = new Date(alertData.timestamp * 1000);
    var timeStr = time.toLocaleTimeString();

    item.innerHTML =
      '<span class="alert-time">' + timeStr + "</span>" +
      '<span class="alert-message">' + escapeHtml(alertData.message) + "</span>";

    alertFeed.insertBefore(item, alertFeed.firstChild);

    if (alertFeed.children.length > 100) {
      alertFeed.removeChild(alertFeed.lastChild);
    }
  }

  function escapeHtml(text) {
    if (!text) return "";
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
  }

  connectWS();
});
