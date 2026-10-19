(function () {
  "use strict";

  const DATA = JSON.parse(document.getElementById("dashboard-data").textContent);
  const CATEGORIES = DATA.categories;

  const CAT_COLOR = {
    "Human": "var(--cat-human)",
    "Undeclared bot": "var(--cat-undeclared)",
    "Verified AI crawler": "var(--cat-verified)",
    "Spoofed crawler": "var(--cat-spoofed)",
    "Search engine": "var(--cat-search)",
    "Block evader": "var(--cat-evader)",
  };
  const METHOD_COLOR = {
    "Rules": "var(--cat-human)",
    "ML": "var(--cat-search)",
    "Anomaly": "var(--cat-spoofed)",
    "Hybrid": "var(--cat-verified)",
  };

  const fmtInt = d3.format(",");
  const fmtPct1 = (x) => (x * 100).toFixed(1) + "%";
  const fmtPct0 = (x) => Math.round(x * 100) + "%";
  function fmtBytes(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
    return n + " B";
  }

  const tooltipEl = document.getElementById("tooltip");
  function showTip(evt, html) {
    tooltipEl.innerHTML = html;
    tooltipEl.style.display = "block";
    const pad = 14;
    let x = evt.clientX + pad;
    let y = evt.clientY + pad;
    const rect = tooltipEl.getBoundingClientRect();
    if (x + rect.width > window.innerWidth - 8) x = evt.clientX - rect.width - pad;
    if (y + rect.height > window.innerHeight - 8) y = evt.clientY - rect.height - pad;
    tooltipEl.style.left = x + "px";
    tooltipEl.style.top = y + "px";
  }
  function hideTip() {
    tooltipEl.style.display = "none";
  }

  document.getElementById("tabs").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-tab]");
    if (!btn) return;
    document.querySelectorAll("nav.tabs button").forEach((b) => b.classList.toggle("active", b === btn));
    const id = btn.dataset.tab;
    document.querySelectorAll("section.tabpanel").forEach((s) => s.classList.toggle("active", s.id === "tab-" + id));
  });

  function statTile(label, value, sub) {
    return `<div class="stat-tile"><div class="label">${label}</div><div class="value">${value}${sub ? ` <small>${sub}</small>` : ""}</div></div>`;
  }

  const hs = DATA.headline_stats;
  document.getElementById("stat-grid").innerHTML = [
    statTile("Total requests", fmtInt(hs.total_requests)),
    statTile("Total clients", fmtInt(hs.total_clients)),
    statTile("Traffic from claimed AI crawlers", hs.pct_ai_crawler_traffic + "%"),
    statTile("Of those claims, spoofed", hs.pct_ai_crawler_claims_spoofed + "%"),
    statTile("Bandwidth from bot categories", hs.bot_bandwidth_pct + "%", fmtBytes(hs.bot_bandwidth_bytes)),
  ].join("");

  const le = DATA.block_evasion.linking_eval;
  document.getElementById("evasion-stats").innerHTML = [
    statTile("True block evaders", fmtInt(le.total_true_block_evaders)),
    statTile("Linked by the detector", fmtInt(le.flagged_as_linked)),
    statTile("Linked to the correct origin", fmtInt(le.correctly_linked_to_origin)),
    statTile("Linking recall", fmtPct0(le.linking_recall)),
    statTile("Linking precision", fmtPct0(le.linking_precision)),
    statTile("False-positive links", fmtInt(le.false_positive_links)),
  ].join("");

  function horizontalBarChart(svgEl, data, opts) {
    const { valueKey, labelKey, colorFn, valueFormat = fmtInt, width = 600, labelWidth = 150 } = opts;
    const barHeight = 20, gap = 10;
    const svg = d3.select(svgEl);
    svg.selectAll("*").remove();
    const margin = { top: 4, right: 56, bottom: 4, left: labelWidth };
    const innerW = Math.max(120, width - margin.left - margin.right);
    const height = data.length * (barHeight + gap) - gap + margin.top + margin.bottom;
    svg.attr("viewBox", `0 0 ${width} ${height}`);
    const maxVal = d3.max(data, (d) => d[valueKey]) || 1;
    const x = d3.scaleLinear().domain([0, maxVal]).nice().range([0, innerW]);
    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

    const rows = g
      .selectAll("g.row")
      .data(data)
      .join("g")
      .attr("class", "row")
      .attr("transform", (d, i) => `translate(0,${i * (barHeight + gap)})`);

    rows
      .append("text")
      .attr("x", -8)
      .attr("y", barHeight / 2)
      .attr("dy", "0.32em")
      .attr("text-anchor", "end")
      .text((d) => d[labelKey]);

    rows
      .append("rect")
      .attr("x", 0)
      .attr("y", 0)
      .attr("height", barHeight)
      .attr("rx", 4)
      .attr("width", (d) => Math.max(2, x(d[valueKey])))
      .attr("fill", (d) => (colorFn ? colorFn(d) : "var(--accent)"))
      .style("cursor", "default")
      .on("mousemove", (e, d) => showTip(e, `<b>${d[labelKey]}</b><br>${valueFormat(d[valueKey])}`))
      .on("mouseleave", hideTip);

    rows
      .append("text")
      .attr("x", (d) => x(d[valueKey]) + 6)
      .attr("y", barHeight / 2)
      .attr("dy", "0.32em")
      .attr("fill", "var(--text-secondary)")
      .text((d) => valueFormat(d[valueKey]));
  }

  function groupedBarChart(svgEl, groups, seriesNames, opts) {
    const { colorOf, valueFormat = fmtPct0, width = 600, height = 260, yDomain = [0, 1], legendEl } = opts;
    const svg = d3.select(svgEl);
    svg.selectAll("*").remove();
    const margin = { top: 10, right: 10, bottom: 34, left: 38 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const x0 = d3.scaleBand().domain(groups.map((g) => g.label)).range([0, innerW]).paddingInner(0.3).paddingOuter(0.1);
    const x1 = d3.scaleBand().domain(seriesNames).range([0, x0.bandwidth()]).padding(0.08);
    const y = d3.scaleLinear().domain(yDomain).nice().range([innerH, 0]);

    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

    g.append("g")
      .selectAll("line")
      .data(y.ticks(5))
      .join("line")
      .attr("class", "gridline")
      .attr("x1", 0).attr("x2", innerW)
      .attr("y1", (d) => y(d)).attr("y2", (d) => y(d));

    g.append("g")
      .selectAll("text")
      .data(y.ticks(5))
      .join("text")
      .attr("x", -8).attr("y", (d) => y(d)).attr("dy", "0.32em")
      .attr("text-anchor", "end")
      .text((d) => valueFormat(d));

    g.append("line").attr("class", "axis-line").attr("x1", 0).attr("x2", innerW).attr("y1", innerH).attr("y2", innerH);

    const groupG = g
      .selectAll("g.group")
      .data(groups)
      .join("g")
      .attr("class", "group")
      .attr("transform", (d) => `translate(${x0(d.label)},0)`);

    groupG
      .selectAll("rect")
      .data((d) => seriesNames.map((s) => ({ series: s, label: d.label, value: d.values[s] ?? 0 })))
      .join("rect")
      .attr("x", (d) => x1(d.series))
      .attr("y", (d) => y(Math.max(0, d.value)))
      .attr("width", Math.max(2, x1.bandwidth()))
      .attr("height", (d) => Math.max(0, innerH - y(Math.max(0, d.value))))
      .attr("rx", 3)
      .attr("fill", (d) => colorOf(d.series))
      .on("mousemove", (e, d) => showTip(e, `<b>${d.label}</b><br>${d.series}: ${valueFormat(d.value)}`))
      .on("mouseleave", hideTip);

    g.append("g")
      .selectAll("text")
      .data(groups)
      .join("text")
      .attr("x", (d) => x0(d.label) + x0.bandwidth() / 2)
      .attr("y", innerH + 18)
      .attr("text-anchor", "middle")
      .text((d) => d.label);

    if (legendEl) {
      legendEl.innerHTML = seriesNames
        .map((s) => `<div class="item"><span class="swatch" style="background:${colorOf(s)}"></span>${s}</div>`)
        .join("");
    }
  }

  {
    const data = CATEGORIES.map((c) => ({ category: c, requests: DATA.traffic_share_by_category[c] || 0 })).sort(
      (a, b) => b.requests - a.requests
    );
    horizontalBarChart(document.getElementById("chart-traffic-share"), data, {
      valueKey: "requests",
      labelKey: "category",
      colorFn: (d) => CAT_COLOR[d.category],
      width: 560,
      labelWidth: 150,
    });
  }

  {
    const ids = DATA.top_claimed_identities.filter((d) => d.is_ai_crawler);
    const groups = ids.map((d) => ({ label: d.identity, values: { Verified: d.verified_count, Spoofed: d.spoofed_count } }));
    const maxV = d3.max(groups, (g) => Math.max(g.values.Verified, g.values.Spoofed)) || 1;
    groupedBarChart(document.getElementById("chart-identities"), groups, ["Verified", "Spoofed"], {
      colorOf: (s) => (s === "Verified" ? "var(--cat-verified)" : "var(--cat-spoofed)"),
      valueFormat: (v) => fmtInt(Math.round(v)),
      yDomain: [0, maxV],
      width: 560,
      height: 240,
      legendEl: document.getElementById("chart-identities").parentElement.querySelector(".legend") || (() => {
        const el = document.createElement("div");
        el.className = "legend";
        document.getElementById("chart-identities").after(el);
        return el;
      })(),
    });
  }

  {
    const rows = DATA.robots_violations.slice(0, 25);
    const tbl = document.getElementById("table-violations");
    tbl.innerHTML =
      "<thead><tr><th>Client</th><th>True category</th><th>Claimed identity</th><th class='num'>Disallowed hits</th></tr></thead><tbody>" +
      rows
        .map(
          (r) =>
            `<tr><td class="mono">${shortKey(r.client_key_str)}</td><td>${badge(r.category)}</td><td>${r.claimed_identity ?? "—"}</td><td class="num">${r.disallowed_hits}</td></tr>`
        )
        .join("") +
      "</tbody>";
    if (!rows.length) tbl.innerHTML = "<tbody><tr><td>No robots.txt violations recorded.</td></tr></tbody>";
  }

  function shortKey(k) {
    const parts = k.split("||");
    return parts[0];
  }
  function badge(cat) {
    return `<span class="badge" style="background:${CAT_COLOR[cat] || "var(--text-muted)"}">${cat}</span>`;
  }

  {
    const mc = DATA.method_comparison;
    const groups = CATEGORIES.map((cat) => ({
      label: cat,
      values: {
        Rules: mc.rules.report[cat] ? mc.rules.report[cat].recall : 0,
        ML: mc.ml.report[cat] ? mc.ml.report[cat].recall : 0,
        Anomaly: mc.anomaly.flag_rate_by_category[cat] ?? 0,
        Hybrid: mc.hybrid.report[cat] ? mc.hybrid.report[cat].recall : 0,
      },
    }));
    const legendEl = document.createElement("div");
    legendEl.className = "legend";
    document.getElementById("chart-method-recall").after(legendEl);
    groupedBarChart(document.getElementById("chart-method-recall"), groups, ["Rules", "ML", "Anomaly", "Hybrid"], {
      colorOf: (s) => METHOD_COLOR[s],
      valueFormat: fmtPct0,
      yDomain: [0, 1],
      width: 1000,
      height: 280,
      legendEl,
    });
  }

  {
    const items = Object.entries(DATA.feature_importance)
      .slice(0, 12)
      .map(([feature, importance]) => ({ feature: niceFeatureName(feature), importance }));
    horizontalBarChart(document.getElementById("chart-feature-importance"), items, {
      valueKey: "importance",
      labelKey: "feature",
      colorFn: () => "var(--accent)",
      valueFormat: (v) => v.toFixed(3),
      width: 560,
      labelWidth: 170,
    });
  }
  function niceFeatureName(f) {
    return f
      .replace(/_num$/, "")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  {
    const anomaly = DATA.method_comparison.anomaly;
    document.getElementById("anomaly-auc-hint").textContent =
      `ROC-AUC (any-bot vs. human): ${anomaly.roc_auc}. Flag rate per true category at risk ≥ 50 — ~half this traffic is bot traffic, so a single hard threshold is less meaningful than the ranking itself.`;
    const data = CATEGORIES.map((c) => ({ category: c, rate: anomaly.flag_rate_by_category[c] ?? 0 })).sort(
      (a, b) => b.rate - a.rate
    );
    horizontalBarChart(document.getElementById("chart-anomaly-flagrate"), data, {
      valueKey: "rate",
      labelKey: "category",
      colorFn: (d) => CAT_COLOR[d.category],
      valueFormat: fmtPct0,
      width: 560,
      labelWidth: 150,
    });
  }

  function renderConfusionMatrix(container, title, matrix, labels) {
    const cell = 50, labelW = 150, labelH = 70;
    const width = labelW + labels.length * cell + 10;
    const height = labelH + labels.length * cell + 10;
    const wrap = document.createElement("div");
    wrap.style.marginBottom = "22px";
    wrap.innerHTML = `<div style="font-weight:600;font-size:0.86rem;margin-bottom:8px;">${title}</div>`;
    const svgWrap = document.createElement("div");
    svgWrap.style.overflowX = "auto";
    wrap.appendChild(svgWrap);
    container.appendChild(wrap);

    const svg = d3.select(svgWrap).append("svg").attr("class", "chart").attr("viewBox", `0 0 ${width} ${height}`).style("width", Math.min(width, 760) + "px");
    const maxCell = d3.max(matrix.flat()) || 1;
    const seq = d3.scaleLinear().domain([0, maxCell]).range([0, 1]);
    const colorSteps = ["var(--surface-raised)", "var(--seq-100)", "var(--seq-200)", "var(--seq-300)", "var(--seq-400)", "var(--seq-500)", "var(--seq-600)", "var(--seq-700)"];
    function cellColor(v) {
      if (v === 0) return "var(--surface-raised)";
      const t = seq(v);
      const idx = Math.min(colorSteps.length - 1, 1 + Math.floor(t * (colorSteps.length - 2)));
      return colorSteps[idx];
    }
    const rowMax = matrix.map((row) => d3.max(row) || 1);

    const g = svg.append("g").attr("transform", `translate(${labelW},${labelH})`);

    g.selectAll("text.collabel")
      .data(labels)
      .join("text")
      .attr("class", "collabel")
      .attr("x", (d, i) => i * cell + cell / 2)
      .attr("y", -10)
      .attr("text-anchor", "start")
      .attr("transform", (d, i) => `rotate(-35, ${i * cell + cell / 2}, -10)`)
      .text((d) => d);

    g.selectAll("text.rowlabel")
      .data(labels)
      .join("text")
      .attr("class", "rowlabel")
      .attr("x", -8)
      .attr("y", (d, i) => i * cell + cell / 2)
      .attr("dy", "0.32em")
      .attr("text-anchor", "end")
      .text((d) => d);

    labels.forEach((rowLabel, i) => {
      labels.forEach((colLabel, j) => {
        const v = matrix[i][j];
        const rowTotal = d3.sum(matrix[i]) || 1;
        g.append("rect")
          .attr("x", j * cell)
          .attr("y", i * cell)
          .attr("width", cell - 2)
          .attr("height", cell - 2)
          .attr("rx", 3)
          .attr("fill", cellColor(v))
          .on("mousemove", (e) =>
            showTip(e, `True: <b>${rowLabel}</b><br>Predicted: <b>${colLabel}</b><br>${v} client(s) (${fmtPct0(v / rowTotal)} of true ${rowLabel})`)
          )
          .on("mouseleave", hideTip);
        g.append("text")
          .attr("x", j * cell + (cell - 2) / 2)
          .attr("y", i * cell + (cell - 2) / 2)
          .attr("dy", "0.32em")
          .attr("text-anchor", "middle")
          .attr("fill", v / rowMax[i] > 0.55 ? "#0b0b0b" : "var(--text-secondary)")
          .text(v || "");
      });
    });
  }

  {
    const el = document.getElementById("confusion-matrices");
    el.innerHTML = "";
    renderConfusionMatrix(el, "Rules", DATA.method_comparison.rules.confusion_matrix, CATEGORIES);
    renderConfusionMatrix(el, "ML (5-fold out-of-fold)", DATA.method_comparison.ml.confusion_matrix, CATEGORIES);
    renderConfusionMatrix(el, "Hybrid", DATA.method_comparison.hybrid.confusion_matrix, CATEGORIES);
    renderConfusionMatrix(el, "Anomaly detection (binary flag, risk ≥ 50)", DATA.method_comparison.anomaly.binary_confusion_matrix, ["Human", "Any bot/crawler"]);
  }

  {
    const mc = DATA.method_comparison;
    const data = [
      { method: "Rules", value: mc.rules.report.accuracy },
      { method: "ML (OOF)", value: mc.ml.report.accuracy },
      { method: "Anomaly (ROC-AUC)", value: mc.anomaly.roc_auc },
      { method: "Hybrid", value: mc.hybrid.report.accuracy },
    ];
    horizontalBarChart(document.getElementById("chart-overall-accuracy"), data, {
      valueKey: "value",
      labelKey: "method",
      colorFn: (d) => METHOD_COLOR[d.method.split(" ")[0]] || "var(--accent)",
      valueFormat: (v) => v.toFixed(3),
      width: 560,
      labelWidth: 150,
    });
  }

  {
    const clusters = DATA.block_evasion.clusters;
    const list = document.getElementById("cluster-list");
    if (!clusters.length) {
      list.innerHTML = "<li>No operator clusters detected.</li>";
    } else {
      list.innerHTML = clusters
        .map((c) => {
          const blockedShort = shortKey(c.blocked_client_key);
          const disguised = c.disguised_client_keys.map(shortKey).join(", ");
          return `<li class="cluster-card">
            <div class="title">Blocked identity <span class="mono">${blockedShort}</span> &rarr; ${c.n_disguised_clients} disguised client(s)</div>
            <div class="meta">
              Disguised IPs: <span class="mono">${disguised}</span><br>
              Distinct ASNs among disguised clients: ${c.distinct_asns}<br>
              Average link confidence: ${fmtPct0(c.avg_link_confidence)}
            </div>
          </li>`;
        })
        .join("");
    }
  }

  {
    const catSel = document.getElementById("filter-category");
    CATEGORIES.forEach((c) => catSel.insertAdjacentHTML("beforeend", `<option value="${c}">${c}</option>`));
    const verdictSel = document.getElementById("filter-verdict");
    CATEGORIES.forEach((c) => verdictSel.insertAdjacentHTML("beforeend", `<option value="${c}">${c}</option>`));

    const columns = [
      { key: "client", label: "Client", sort: (d) => d.ip },
      { key: "true_category", label: "True category", sort: (d) => d.true_category },
      { key: "claimed_identity", label: "Claims", sort: (d) => d.claimed_identity || "" },
      { key: "n_requests", label: "Reqs", num: true, sort: (d) => d.n_requests },
      { key: "rules_score", label: "Rules", num: true, sort: (d) => d.rules_score },
      { key: "ml_pred", label: "ML", sort: (d) => d.ml_pred },
      { key: "anomaly_risk", label: "Anomaly", num: true, sort: (d) => d.anomaly_risk },
      { key: "hybrid_label", label: "Hybrid verdict", sort: (d) => d.hybrid_label },
      { key: "hybrid_score", label: "Risk", num: true, sort: (d) => d.hybrid_score },
    ];

    const thead = document.querySelector("#table-clients thead");
    thead.innerHTML =
      "<tr>" + columns.map((c) => `<th class="sortable${c.num ? " num" : ""}" data-key="${c.key}">${c.label} <span class="arrow"></span></th>`).join("") + "</tr>";

    let sortKey = "hybrid_score";
    let sortDir = -1;

    thead.addEventListener("click", (e) => {
      const th = e.target.closest("th.sortable");
      if (!th) return;
      const key = th.dataset.key;
      if (sortKey === key) sortDir *= -1;
      else {
        sortKey = key;
        sortDir = 1;
      }
      render();
    });

    function riskColor(score) {
      if (score >= 75) return "var(--critical)";
      if (score >= 55) return "var(--serious)";
      if (score >= 35) return "var(--warning)";
      return "var(--good)";
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }

    function render() {
      const q = document.getElementById("filter-search").value.trim().toLowerCase();
      const catFilter = catSel.value;
      const verdictFilter = verdictSel.value;

      let rows = DATA.clients.filter((d) => {
        if (catFilter && d.true_category !== catFilter) return false;
        if (verdictFilter && d.hybrid_label !== verdictFilter) return false;
        if (q) {
          const hay = (d.ip + " " + d.asn + " " + d.user_agent + " " + (d.claimed_identity || "")).toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const col = columns.find((c) => c.key === sortKey);
      rows = rows.slice().sort((a, b) => {
        const av = col.sort(a), bv = col.sort(b);
        if (av < bv) return -1 * sortDir;
        if (av > bv) return 1 * sortDir;
        return 0;
      });

      thead.querySelectorAll("th.sortable .arrow").forEach((a) => (a.textContent = ""));
      const activeTh = thead.querySelector(`th[data-key="${sortKey}"] .arrow`);
      if (activeTh) activeTh.textContent = sortDir === 1 ? "▲" : "▼";

      const tbody = document.querySelector("#table-clients tbody");
      tbody.innerHTML = "";
      rows.forEach((d) => {
        const tr = document.createElement("tr");
        tr.className = "client-row";
        tr.innerHTML = `
          <td class="mono">${d.ip}<br><span style="color:var(--text-muted)">${d.asn}</span></td>
          <td>${badge(d.true_category)}</td>
          <td>${d.claimed_identity ?? "—"}</td>
          <td class="num">${fmtInt(d.n_requests)}</td>
          <td class="num">${d.rules_score.toFixed(0)}</td>
          <td>${d.ml_pred}</td>
          <td class="num">${d.anomaly_risk.toFixed(0)}${d.anomaly_flag ? " ⚑" : ""}</td>
          <td>${badge(d.hybrid_label)}</td>
          <td class="num"><span class="risk-pill"><span class="risk-dot" style="background:${riskColor(d.hybrid_score)}"></span>${d.hybrid_score.toFixed(0)}</span></td>
        `;
        const detailTr = document.createElement("tr");
        detailTr.className = "detail-row";
        detailTr.hidden = true;
        const td = document.createElement("td");
        td.colSpan = columns.length;
        const rulesReasons = (d.rules_reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
        const hybridReasons = (d.hybrid_reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
        td.innerHTML = `
          <div class="detail-grid">
            <div>
              <h4>User agent</h4>
              <div class="mono" style="margin-bottom:10px;">${escapeHtml(d.user_agent)}</div>
              <h4>Rule-based reasons (score ${d.rules_score.toFixed(0)}, verdict ${d.rules_label})</h4>
              <ul>${rulesReasons || "<li>No notable signals.</li>"}</ul>
            </div>
            <div>
              <h4>Hybrid verdict reasoning</h4>
              <ul>${hybridReasons || "<li>&mdash;</li>"}</ul>
              <h4>Behavior</h4>
              <ul>
                <li>Request rate: ${d.request_rate_per_min} / min, timing CV ${d.timing_cv}</li>
                <li>Asset ratio ${d.asset_ratio}, sequential score ${d.sequential_score}</li>
                <li>Disallowed-path hits: ${d.disallowed_hits}, fetched robots.txt: ${d.robots_txt_fetched ? "yes" : "no"}</li>
                ${d.linked_to_blocked_client ? `<li>Linked to blocked client <span class="mono">${shortKey(d.suspected_operator_cluster)}</span></li>` : ""}
              </ul>
            </div>
          </div>
          ${d.analyst_note ? `<h4 style="margin-top:12px;">Analyst note</h4><div class="analyst-note">${escapeHtml(d.analyst_note)}</div>` : ""}
        `;
        detailTr.appendChild(td);

        tr.addEventListener("click", () => {
          detailTr.hidden = !detailTr.hidden;
        });

        tbody.appendChild(tr);
        tbody.appendChild(detailTr);
      });
    }

    document.getElementById("filter-search").addEventListener("input", render);
    catSel.addEventListener("change", render);
    verdictSel.addEventListener("change", render);
    render();
  }
})();
