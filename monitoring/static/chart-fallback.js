(function () {
  "use strict";

  if (typeof window.Chart !== "undefined") {
    return;
  }

  function SimpleChart(context, config) {
    this.context = context;
    this.canvas = context.canvas;
    this.type = config.type || "line";
    this.data = config.data || { labels: [], datasets: [] };
    this.options = config.options || {};
    this._resizeHandler = this.update.bind(this);
    window.addEventListener("resize", this._resizeHandler);
    this.update();
  }

  SimpleChart.prototype.destroy = function () {
    window.removeEventListener("resize", this._resizeHandler);
    this._clear();
  };

  SimpleChart.prototype.update = function () {
    this._resizeCanvas();
    this._clear();
    if (this.type === "doughnut") {
      this._drawDoughnut();
      return;
    }
    this._drawLine();
  };

  SimpleChart.prototype._resizeCanvas = function () {
    var canvas = this.canvas;
    var ratio = window.devicePixelRatio || 1;
    var width = Math.max(canvas.clientWidth || canvas.parentElement.clientWidth || 320, 160);
    var height = Math.max(canvas.clientHeight || canvas.parentElement.clientHeight || 220, 160);
    if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
    }
    this.context.setTransform(ratio, 0, 0, ratio, 0, 0);
  };

  SimpleChart.prototype._clear = function () {
    this.context.clearRect(0, 0, this.canvas.width, this.canvas.height);
  };

  SimpleChart.prototype._drawLine = function () {
    var ctx = this.context;
    var width = this.canvas.clientWidth || 320;
    var height = this.canvas.clientHeight || 220;
    var labels = (this.data && this.data.labels) || [];
    var datasets = (this.data && this.data.datasets) || [];
    var padding = { top: 20, right: 18, bottom: 28, left: 36 };
    var plotWidth = Math.max(width - padding.left - padding.right, 16);
    var plotHeight = Math.max(height - padding.top - padding.bottom, 16);
    var allValues = [];
    var datasetIndex;
    var pointIndex;

    for (datasetIndex = 0; datasetIndex < datasets.length; datasetIndex += 1) {
      var series = datasets[datasetIndex].data || [];
      for (pointIndex = 0; pointIndex < series.length; pointIndex += 1) {
        if (typeof series[pointIndex] === "number" && !isNaN(series[pointIndex])) {
          allValues.push(series[pointIndex]);
        }
      }
    }

    var maxValue = allValues.length ? Math.max.apply(null, allValues) : 1;
    var minValue = allValues.length ? Math.min.apply(null, allValues) : 0;
    if (maxValue === minValue) {
      maxValue += 1;
      minValue = Math.min(0, minValue);
    }

    ctx.strokeStyle = "rgba(148, 167, 188, 0.16)";
    ctx.lineWidth = 1;
    for (var grid = 0; grid <= 4; grid += 1) {
      var y = padding.top + (plotHeight * grid / 4);
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();
    }

    for (datasetIndex = 0; datasetIndex < datasets.length; datasetIndex += 1) {
      var dataset = datasets[datasetIndex];
      var data = dataset.data || [];
      ctx.beginPath();
      ctx.strokeStyle = dataset.borderColor || dataset.backgroundColor || "#42c2ff";
      ctx.lineWidth = dataset.borderWidth || 2;
      for (pointIndex = 0; pointIndex < data.length; pointIndex += 1) {
        var value = typeof data[pointIndex] === "number" ? data[pointIndex] : 0;
        var x = padding.left + (plotWidth * (labels.length <= 1 ? 0 : pointIndex / (labels.length - 1)));
        var yValue = (value - minValue) / (maxValue - minValue);
        var yPos = padding.top + plotHeight - (plotHeight * yValue);
        if (pointIndex === 0) {
          ctx.moveTo(x, yPos);
        } else {
          ctx.lineTo(x, yPos);
        }
      }
      ctx.stroke();
    }

    ctx.fillStyle = "#94a7bc";
    ctx.font = "12px IBM Plex Sans, Segoe UI, sans-serif";
    ctx.textBaseline = "middle";
    ctx.fillText(String(Math.round(maxValue)), 4, padding.top + 4);
    ctx.fillText(String(Math.round(minValue)), 4, padding.top + plotHeight - 2);

    if (labels.length) {
      ctx.textBaseline = "alphabetic";
      ctx.fillText(String(labels[0] || ""), padding.left, height - 8);
      ctx.textAlign = "right";
      ctx.fillText(String(labels[labels.length - 1] || ""), width - padding.right, height - 8);
      ctx.textAlign = "left";
    }
  };

  SimpleChart.prototype._drawDoughnut = function () {
    var ctx = this.context;
    var width = this.canvas.clientWidth || 260;
    var height = this.canvas.clientHeight || 260;
    var dataset = ((this.data && this.data.datasets) || [])[0] || { data: [] };
    var values = dataset.data || [];
    var labels = (this.data && this.data.labels) || [];
    var colors = dataset.backgroundColor || [];
    var total = values.reduce(function (sum, value) {
      return sum + (typeof value === "number" ? value : 0);
    }, 0);
    var centerX = width / 2;
    var centerY = height / 2;
    var radius = Math.max(Math.min(width, height) * 0.28, 24);
    var ringWidth = Math.max(radius * 0.45, 12);
    var angle = -Math.PI / 2;

    if (!total) {
      ctx.fillStyle = "#94a7bc";
      ctx.font = "13px IBM Plex Sans, Segoe UI, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No protocol data", centerX, centerY);
      ctx.textAlign = "left";
      return;
    }

    for (var index = 0; index < values.length; index += 1) {
      var value = typeof values[index] === "number" ? values[index] : 0;
      var slice = (value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.strokeStyle = colors[index % colors.length] || "#42c2ff";
      ctx.lineWidth = ringWidth;
      ctx.arc(centerX, centerY, radius, angle, angle + slice);
      ctx.stroke();
      angle += slice;
    }

    ctx.fillStyle = "#e6edf5";
    ctx.font = "700 16px IBM Plex Sans, Segoe UI, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(String(total), centerX, centerY + 4);
    ctx.font = "12px IBM Plex Sans, Segoe UI, sans-serif";
    ctx.fillStyle = "#94a7bc";
    ctx.fillText("packets", centerX, centerY + 22);
    ctx.textAlign = "left";

    var legendX = 16;
    var legendY = 18;
    for (var legendIndex = 0; legendIndex < Math.min(labels.length, 4); legendIndex += 1) {
      ctx.fillStyle = colors[legendIndex % colors.length] || "#42c2ff";
      ctx.fillRect(legendX, legendY + (legendIndex * 18), 10, 10);
      ctx.fillStyle = "#94a7bc";
      ctx.font = "11px IBM Plex Sans, Segoe UI, sans-serif";
      ctx.fillText(String(labels[legendIndex] || "-"), legendX + 16, legendY + 9 + (legendIndex * 18));
    }
  };

  window.Chart = SimpleChart;
}());
