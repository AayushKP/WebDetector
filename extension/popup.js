const API_BASE = "http://localhost:8000";
const $ = (sel) => document.querySelector(sel);

const dom = {
  currentUrl: $("#currentUrl"), scanStatus: $("#scanStatus"),
  scanningState: $("#scanningState"), verdictCard: $("#verdictCard"),
  verdictBadge: $("#verdictBadge"), verdictLabel: $("#verdictLabel"),
  verdictConfidence: $("#verdictConfidence"), confidenceBar: $("#confidenceBar"),
  analysisTime: $("#analysisTime"), probSection: $("#probSection"),
  probBars: $("#probBars"), featuresSection: $("#featuresSection"),
  featuresToggle: $("#featuresToggle"), featuresContent: $("#featuresContent"),
  lexicalItems: $("#lexicalItems"), contentItems: $("#contentItems"),
  domainItems: $("#domainItems"), historySection: $("#historySection"),
  historyToggle: $("#historyToggle"), historyContent: $("#historyContent"),
  errorCard: $("#errorCard"), errorMsg: $("#errorMsg"),
  rescanBtn: $("#rescanBtn"), backendStatus: $("#backendStatus"),
};

const RISK_STYLES = {
  safe:     { label: "SAFE",       color: "#22c55e", bg: "rgba(34,197,94,0.08)"  },
  low:      { label: "LOW RISK",   color: "#eab308", bg: "rgba(234,179,8,0.08)"  },
  medium:   { label: "SUSPICIOUS", color: "#f97316", bg: "rgba(249,115,22,0.08)" },
  high:     { label: "DANGEROUS",  color: "#ef4444", bg: "rgba(239,68,68,0.08)"  },
  critical: { label: "CRITICAL",   color: "#dc2626", bg: "rgba(220,38,38,0.10)"  },
};

const PROB_COLORS = { benign: "#22c55e", phishing: "#ef4444", defacement: "#f97316", malware: "#dc2626" };

const FEATURE_LABELS = {
  url_length: "URL Length", num_dots: "Dots", num_slashes: "Slashes",
  num_digits: "Digits", num_special_chars: "Special Chars", has_https: "HTTPS",
  has_ip: "IP Address", has_at_symbol: "@ Symbol", has_dash: "Dashes",
  subdomain_count: "Subdomains", entropy: "Entropy", suspicious_keywords: "Susp. Keywords",
  brand_similarity: "Brand Distance", tld_risk_score: "TLD Risk", path_length: "Path Depth",
  num_forms: "Forms", num_iframes: "Iframes", num_anchors: "Links",
  num_scripts: "Scripts", has_login_form: "Login Form", external_link_ratio: "Ext. Link Ratio",
  has_redirect: "Meta Redirect", input_fields: "Input Fields", password_fields: "Password Fields",
  js_obfuscation_score: "JS Obfuscation", domain_age: "Domain Age", time_to_expiry: "Expiry (days)",
  has_whois: "WHOIS Record", has_dns_record: "DNS Record", ssl_valid: "SSL Valid",
  cert_validity_days: "Cert Duration", domain_reputation: "Reputation", hosting_country_risk: "Geo Risk",
};

function getFeatureClass(key, value) {
  const danger = {
    has_ip: (v) => v === 1, has_at_symbol: (v) => v === 1, has_login_form: (v) => v === 1,
    has_redirect: (v) => v === 1, tld_risk_score: (v) => v >= 1, suspicious_keywords: (v) => v >= 2,
    js_obfuscation_score: (v) => v >= 3, domain_reputation: (v) => v >= 1,
    hosting_country_risk: (v) => v >= 1, ssl_valid: (v) => v === 0,
    has_whois: (v) => v === 0, has_dns_record: (v) => v === 0,
    domain_age: (v) => v >= 0 && v < 90, password_fields: (v) => v >= 1,
  };
  const safe = {
    has_https: (v) => v === 1, ssl_valid: (v) => v === 1, has_whois: (v) => v === 1,
    has_dns_record: (v) => v === 1, domain_age: (v) => v > 365,
  };
  if (danger[key] && danger[key](value)) return "danger";
  if (safe[key] && safe[key](value)) return "safe";
  return "neutral";
}

function formatFeatureValue(key, value) {
  if (typeof value !== "number") return String(value);
  if (key === "entropy" || key === "external_link_ratio") return value.toFixed(2);
  if (["domain_age","time_to_expiry","cert_validity_days"].includes(key)) return value === -1 ? "N/A" : `${value}d`;
  if (["has_https","has_ip","has_at_symbol","has_dash","has_login_form","has_redirect",
       "has_whois","has_dns_record","ssl_valid","domain_reputation","hosting_country_risk","tld_risk_score"].includes(key))
    return value === 1 ? "Yes" : "No";
  return String(value);
}

function renderVerdict(result) {
  const style = RISK_STYLES[result.risk_level] || RISK_STYLES.safe;
  dom.verdictCard.style.setProperty("--verdict-color", style.color);
  dom.verdictCard.style.setProperty("--verdict-bg", style.bg);
  dom.verdictBadge.textContent = style.label;
  dom.verdictLabel.textContent = result.prediction;
  dom.verdictConfidence.textContent = `${(result.confidence * 100).toFixed(1)}%`;
  dom.analysisTime.textContent = `Analysed in ${result.analysis_time}s`;
  setTimeout(() => {
    dom.confidenceBar.style.width = `${(result.confidence * 100).toFixed(1)}%`;
    dom.confidenceBar.style.background = style.color;
  }, 100);
  dom.scanStatus.classList.add("hidden");
  dom.verdictCard.classList.remove("hidden");
}

function renderProbabilities(probabilities) {
  dom.probBars.innerHTML = "";
  const sorted = Object.entries(probabilities).sort((a, b) => b[1] - a[1]);
  for (const [label, prob] of sorted) {
    const pct = (prob * 100).toFixed(1);
    const color = PROB_COLORS[label] || "#818cf8";
    const row = document.createElement("div");
    row.className = "prob-row";
    row.innerHTML = `<span class="prob-label">${label}</span><div class="prob-track"><div class="prob-fill" style="width:0%;background:${color}"></div></div><span class="prob-value">${pct}%</span>`;
    dom.probBars.appendChild(row);
  }
  setTimeout(() => {
    dom.probBars.querySelectorAll(".prob-fill").forEach((bar, i) => {
      bar.style.width = `${(sorted[i][1] * 100).toFixed(1)}%`;
    });
  }, 200);
  dom.probSection.classList.remove("hidden");
}

function renderFeatures(features) {
  if (!features || Object.keys(features).length === 0) return;
  const lexKeys = ["url_length","num_dots","num_slashes","num_digits","num_special_chars","has_https","has_ip","has_at_symbol","has_dash","subdomain_count","entropy","suspicious_keywords","brand_similarity","tld_risk_score","path_length"];
  const contKeys = ["num_forms","num_iframes","num_anchors","num_scripts","has_login_form","external_link_ratio","has_redirect","input_fields","password_fields","js_obfuscation_score"];
  const domKeys = ["domain_age","time_to_expiry","has_whois","has_dns_record","ssl_valid","cert_validity_days","domain_reputation","hosting_country_risk"];

  function renderGroup(container, keys, data) {
    container.innerHTML = "";
    for (const key of keys) {
      const val = data[key];
      if (val === undefined) continue;
      const item = document.createElement("div");
      item.className = "feature-item";
      item.innerHTML = `<span class="feature-name">${FEATURE_LABELS[key] || key}</span><span class="feature-value ${getFeatureClass(key, val)}">${formatFeatureValue(key, val)}</span>`;
      container.appendChild(item);
    }
  }
  const all = { ...(features.lexical || {}), ...(features.content || {}), ...(features.domain || {}) };
  renderGroup(dom.lexicalItems, lexKeys, all);
  renderGroup(dom.contentItems, contKeys, all);
  renderGroup(dom.domainItems, domKeys, all);
  dom.featuresSection.classList.remove("hidden");
}

function renderHistory(history) {
  dom.historyContent.innerHTML = "";
  if (!history || history.length === 0) { dom.historyContent.innerHTML = '<div class="empty-history">No scans yet</div>'; return; }
  for (const item of history.slice(0, 8)) {
    const style = RISK_STYLES[item.risk_level] || RISK_STYLES.safe;
    const diff = Date.now() - item.timestamp;
    const mins = Math.floor(diff / 60000);
    const timeAgo = mins < 1 ? "now" : mins < 60 ? `${mins}m` : `${Math.floor(mins / 60)}h`;
    let displayUrl = item.url;
    try { const u = new URL(item.url); displayUrl = u.hostname + (u.pathname !== "/" ? u.pathname : ""); } catch (_) {}
    if (displayUrl.length > 30) displayUrl = displayUrl.slice(0, 30) + "…";
    const el = document.createElement("div");
    el.className = "history-item";
    el.innerHTML = `<span class="history-dot" style="background:${style.color}"></span><span class="history-url" title="${item.url}">${displayUrl}</span><span class="history-verdict" style="color:${style.color}">${item.prediction}</span><span class="history-time">${timeAgo}</span>`;
    dom.historyContent.appendChild(el);
  }
}

function setupCollapsible(toggleBtn, content) {
  toggleBtn.addEventListener("click", () => {
    const isOpen = content.classList.contains("expanded");
    content.classList.toggle("collapsed", !isOpen);
    content.classList.toggle("expanded", !isOpen);
    toggleBtn.classList.toggle("active", !isOpen);
  });
}

async function checkBackend() {
  try {
    const resp = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    if (resp.ok) { dom.backendStatus.textContent = "Backend online"; dom.backendStatus.className = "backend-status online"; return true; }
  } catch (_) {}
  dom.backendStatus.textContent = "Backend offline"; dom.backendStatus.className = "backend-status offline"; return false;
}

function showError(msg) {
  dom.scanStatus.classList.add("hidden"); dom.verdictCard.classList.add("hidden");
  dom.probSection.classList.add("hidden"); dom.featuresSection.classList.add("hidden");
  dom.errorMsg.textContent = msg; dom.errorCard.classList.remove("hidden");
}

function renderResult(scan) {
  dom.scanStatus.classList.add("hidden"); dom.errorCard.classList.add("hidden");
  renderVerdict(scan);
  if (scan.probabilities) renderProbabilities(scan.probabilities);
  if (scan.features) renderFeatures(scan.features);
}

function pollForResult(tabId, attempts = 0) {
  if (attempts > 60) { showError("Scan timed out."); return; }
  setTimeout(async () => {
    const result = await chrome.storage.local.get(`scan_${tabId}`);
    const scan = result[`scan_${tabId}`];
    if (scan && scan.status === "complete") {
      dom.rescanBtn.classList.remove("spinning"); renderResult(scan);
      const histData = await chrome.storage.local.get("scanHistory");
      renderHistory(histData.scanHistory || []);
    } else if (scan && scan.status === "error") {
      dom.rescanBtn.classList.remove("spinning"); showError(scan.error || "Analysis failed.");
    } else { pollForResult(tabId, attempts + 1); }
  }, 500);
}

async function init() {
  setupCollapsible(dom.featuresToggle, dom.featuresContent);
  setupCollapsible(dom.historyToggle, dom.historyContent);
  checkBackend();
  const histData = await chrome.storage.local.get("scanHistory");
  renderHistory(histData.scanHistory || []);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { showError("No active tab found."); return; }
  let displayUrl = tab.url || "N/A";
  try { const u = new URL(displayUrl); displayUrl = u.hostname + (u.pathname !== "/" ? u.pathname : ""); } catch (_) {}
  dom.currentUrl.textContent = displayUrl;
  dom.currentUrl.title = tab.url;
  const result = await chrome.storage.local.get(`scan_${tab.id}`);
  const scan = result[`scan_${tab.id}`];
  if (!scan) { dom.scanningState.querySelector("span").textContent = "Waiting for scan…"; return; }
  if (scan.status === "scanning") { pollForResult(tab.id); return; }
  if (scan.status === "error") { showError(scan.error || "Backend unreachable."); return; }
  renderResult(scan);
  dom.rescanBtn.addEventListener("click", () => {
    dom.rescanBtn.classList.add("spinning");
    dom.verdictCard.classList.add("hidden"); dom.probSection.classList.add("hidden");
    dom.featuresSection.classList.add("hidden"); dom.errorCard.classList.add("hidden");
    dom.scanStatus.classList.remove("hidden");
    dom.scanningState.querySelector("span").textContent = "Re-scanning…";
    chrome.runtime.sendMessage({ action: "rescan", url: tab.url, tabId: tab.id }, () => { pollForResult(tab.id); });
  });
}

document.addEventListener("DOMContentLoaded", init);
