(function () {
  "use strict";

  const data = window.KEV_DATA || { vulnerabilities: [] };
  const elements = {
    catalogCount: document.querySelector("#catalog-count"),
    catalogVersion: document.querySelector("#catalog-version"),
    dataRelease: document.querySelector("#data-release"),
    input: document.querySelector("#cve-input"),
    dueWindow: document.querySelector("#due-window"),
    queueLabel: document.querySelector("#queue-label"),
    summaryGrid: document.querySelector("#summary-grid"),
    memoOutput: document.querySelector("#memo-output"),
    resultsBody: document.querySelector("#results-body"),
    notFound: document.querySelector("#not-found"),
    tableFilter: document.querySelector("#table-filter"),
    loadExample: document.querySelector("#load-example"),
    clearInput: document.querySelector("#clear-input"),
    copyMarkdown: document.querySelector("#copy-markdown"),
    copyCsv: document.querySelector("#copy-csv"),
    downloadCsv: document.querySelector("#download-csv"),
    downloadIcs: document.querySelector("#download-ics")
  };

  const catalog = data.vulnerabilities || [];
  const byCve = new Map(catalog.map((item) => [item.cveID.toUpperCase(), item]));
  const today = startOfDay(new Date());
  let current = computeQueue();

  elements.catalogCount.textContent = catalog.length.toLocaleString("en-US");
  elements.catalogVersion.textContent = `Catalog ${data.catalogVersion || "snapshot"}`;
  elements.dataRelease.textContent = `${data.catalogVersion || "unknown"} released ${formatDate(data.dateReleased)}`;

  elements.input.value = catalog.slice(0, 8).map((item) => item.cveID).join("\n");
  render();

  elements.input.addEventListener("input", render);
  elements.dueWindow.addEventListener("change", render);
  elements.queueLabel.addEventListener("input", render);
  elements.tableFilter.addEventListener("input", renderTable);
  elements.loadExample.addEventListener("click", () => {
    elements.input.value = catalog.slice(0, 10).map((item) => `${item.cveID}, ${item.vendorProject}, ${item.product}`).join("\n");
    render();
  });
  elements.clearInput.addEventListener("click", () => {
    elements.input.value = "";
    render();
  });
  elements.copyMarkdown.addEventListener("click", () => copyText(current.markdown));
  elements.copyCsv.addEventListener("click", () => copyText(current.csv));
  elements.downloadCsv.addEventListener("click", () => downloadFile("kev-deadline-queue.csv", current.csv, "text/csv"));
  elements.downloadIcs.addEventListener("click", () => downloadFile("kev-deadline-queue.ics", current.ics, "text/calendar"));

  function startOfDay(date) {
    return new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate(), 12));
  }

  function parseDate(value) {
    if (!value) return null;
    const date = new Date(`${String(value).slice(0, 10)}T12:00:00Z`);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value) {
    if (!value) return "unknown";
    const date = typeof value === "string" ? parseDate(value) || new Date(value) : value;
    return Number.isNaN(date.getTime()) ? "unknown" : date.toISOString().slice(0, 10);
  }

  function daysUntil(value) {
    const date = parseDate(value);
    if (!date) return null;
    return Math.round((date.getTime() - today.getTime()) / 86400000);
  }

  function csvEscape(value) {
    const text = String(value ?? "");
    return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  }

  function extractCves(text) {
    const matches = String(text || "").toUpperCase().match(/CVE-\d{4}-\d{4,7}/g) || [];
    return [...new Set(matches)];
  }

  function classify(item, windowDays) {
    const days = daysUntil(item.dueDate);
    if (days === null) return { label: "No due date", kind: "", days };
    if (days < 0) return { label: `${Math.abs(days)} days overdue`, kind: "danger", days };
    if (days === 0) return { label: "Due today", kind: "danger", days };
    if (days <= windowDays) return { label: `Due in ${days} days`, kind: "warn", days };
    return { label: `Due in ${days} days`, kind: "", days };
  }

  function computeQueue() {
    const windowDays = Number(elements.dueWindow.value || 30);
    const cves = extractCves(elements.input.value);
    const matched = [];
    const notFound = [];
    for (const cve of cves) {
      const item = byCve.get(cve);
      if (!item) {
        notFound.push(cve);
        continue;
      }
      const status = classify(item, windowDays);
      matched.push({
        ...item,
        status,
        knownRansomware: String(item.knownRansomwareCampaignUse || "").toLowerCase() === "known"
      });
    }
    matched.sort((a, b) => {
      const aDays = a.status.days ?? 99999;
      const bDays = b.status.days ?? 99999;
      if (aDays !== bDays) return aDays - bDays;
      if (a.knownRansomware !== b.knownRansomware) return a.knownRansomware ? -1 : 1;
      return a.cveID.localeCompare(b.cveID);
    });
    const overdue = matched.filter((item) => (item.status.days ?? 0) < 0).length;
    const dueSoon = matched.filter((item) => (item.status.days ?? 99999) >= 0 && (item.status.days ?? 99999) <= windowDays).length;
    const ransomware = matched.filter((item) => item.knownRansomware).length;
    const markdown = buildMarkdown(matched, notFound, windowDays);
    const csv = buildCsv(matched, notFound);
    const ics = buildIcs(matched);
    return { cves, matched, notFound, overdue, dueSoon, ransomware, windowDays, markdown, csv, ics };
  }

  function buildMarkdown(matched, notFound, windowDays) {
    const label = elements.queueLabel.value.trim() || "KEV remediation queue";
    const lines = [
      `# ${label}`,
      "",
      `Generated: ${formatDate(today)}`,
      `CISA KEV catalog snapshot: ${data.catalogVersion || "unknown"} (${formatDate(data.dateReleased)})`,
      `Due-soon window: ${windowDays} days`,
      "",
      `Matched KEVs: ${matched.length}`,
      `Not in bundled KEV snapshot: ${notFound.length}`,
      "",
      "## Prioritized Items"
    ];
    if (!matched.length) {
      lines.push("", "No pasted CVEs matched the bundled CISA KEV snapshot.");
    }
    matched.forEach((item, index) => {
      lines.push(
        "",
        `${index + 1}. ${item.cveID} - ${item.vendorProject} ${item.product}`,
        `   - Due date: ${item.dueDate} (${item.status.label})`,
        `   - Known ransomware campaign use: ${item.knownRansomwareCampaignUse || "Unknown"}`,
        `   - Required action: ${item.requiredAction || "Verify with CISA and vendor guidance."}`,
        `   - Notes: ${item.notes || "No notes in snapshot."}`
      );
    });
    if (notFound.length) {
      lines.push("", "## Not Found In Bundled Snapshot", "", notFound.join(", "));
    }
    lines.push(
      "",
      "Unofficial informational worksheet. Verify current CISA catalog status, product applicability, asset exposure, and vendor remediation guidance before acting."
    );
    return lines.join("\n");
  }

  function buildCsv(matched, notFound) {
    const rows = [[
      "cve",
      "match_status",
      "vendor_project",
      "product",
      "vulnerability_name",
      "date_added",
      "due_date",
      "days_until_due",
      "queue_status",
      "known_ransomware_campaign_use",
      "required_action",
      "notes"
    ]];
    matched.forEach((item) => {
      rows.push([
        item.cveID,
        "matched_kev",
        item.vendorProject,
        item.product,
        item.vulnerabilityName,
        item.dateAdded,
        item.dueDate,
        item.status.days ?? "",
        item.status.label,
        item.knownRansomwareCampaignUse || "Unknown",
        item.requiredAction || "",
        item.notes || ""
      ]);
    });
    notFound.forEach((cve) => {
      rows.push([cve, "not_in_bundled_snapshot", "", "", "", "", "", "", "", "", "", ""]);
    });
    return rows.map((row) => row.map(csvEscape).join(",")).join("\n");
  }

  function icsDate(value) {
    return formatDate(value).replaceAll("-", "");
  }

  function icsEscape(value) {
    return String(value ?? "")
      .replaceAll("\\", "\\\\")
      .replaceAll("\n", "\\n")
      .replaceAll(";", "\\;")
      .replaceAll(",", "\\,");
  }

  function buildIcs(matched) {
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
    const events = matched
      .filter((item) => item.dueDate)
      .slice(0, 100)
      .map((item) => [
        "BEGIN:VEVENT",
        `UID:${item.cveID.toLowerCase()}-${item.dueDate}@kev-deadline-planner.vercel.app`,
        `DTSTAMP:${stamp}`,
        `DTSTART;VALUE=DATE:${icsDate(item.dueDate)}`,
        `SUMMARY:${icsEscape(`${item.cveID} KEV due date`)}`,
        `DESCRIPTION:${icsEscape(`${item.vendorProject} ${item.product}. ${item.status.label}. ${item.requiredAction || "Verify current CISA and vendor guidance."}`)}`,
        "END:VEVENT"
      ].join("\r\n"));
    return ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//KEV Deadline Planner//EN", ...events, "END:VCALENDAR"].join("\r\n");
  }

  function render() {
    current = computeQueue();
    elements.summaryGrid.innerHTML = [
      metric("Matched KEVs", current.matched.length, "Catalog hits"),
      metric("Overdue", current.overdue, "Due date before today", current.overdue ? "danger" : ""),
      metric(`Due in ${current.windowDays} days`, current.dueSoon, "Within selected window", current.dueSoon ? "warn" : ""),
      metric("Not in snapshot", current.notFound.length, "Pasted CVEs not matched")
    ].join("");
    elements.memoOutput.value = current.markdown;
    renderTable();
  }

  function metric(label, value, note, kind = "") {
    return `<div class="metric ${kind}"><small>${label}</small><strong>${value}</strong><small>${note}</small></div>`;
  }

  function renderTable() {
    const filter = elements.tableFilter.value.trim().toLowerCase();
    const rows = current.matched.filter((item) => !filter || JSON.stringify(item).toLowerCase().includes(filter));
    elements.resultsBody.innerHTML = rows.map((item) => {
      const statusClass = item.status.kind ? ` ${item.status.kind}` : "";
      const ransomwareClass = item.knownRansomware ? " danger" : "";
      return `<tr>
        <td><strong>${item.cveID}</strong></td>
        <td>${escapeHtml(item.vendorProject)}<br><small>${escapeHtml(item.product)}</small></td>
        <td>${item.dueDate}</td>
        <td><span class="pill${statusClass}">${escapeHtml(item.status.label)}</span></td>
        <td><span class="pill${ransomwareClass}">${escapeHtml(item.knownRansomwareCampaignUse || "Unknown")}</span></td>
        <td>${escapeHtml(item.requiredAction || "Verify current CISA and vendor guidance.")}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="6">No KEV matches for the current input and filter.</td></tr>`;
    elements.notFound.textContent = current.notFound.length
      ? `Not found in bundled CISA KEV snapshot: ${current.notFound.join(", ")}`
      : "";
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
  }

  function downloadFile(filename, text, type) {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }
})();
