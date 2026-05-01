// ─── WebDetector Background Service Worker ───────────────────
// Listens for tab navigations, calls the backend API, caches results,
// updates badge, and fires notifications for dangerous URLs.

const API_BASE = "http://localhost:8000";
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_HISTORY = 20;

// ─── URL Filtering ────────────────────────────────────────────
const IGNORED_PREFIXES = [
  "chrome://",
  "chrome-extension://",
  "edge://",
  "about:",
  "data:",
  "file://",
  "devtools://",
  "view-source:",
  "chrome-search://",
];

function shouldScan(url) {
  if (!url) return false;
  const lower = url.toLowerCase();
  return !IGNORED_PREFIXES.some((p) => lower.startsWith(p));
}

// ─── Badge Colours ────────────────────────────────────────────
const BADGE_CONFIG = {
  safe:     { text: "✓",  color: "#22c55e" },
  low:      { text: "!",  color: "#eab308" },
  medium:   { text: "!!",  color: "#f97316" },
  high:     { text: "⚠",  color: "#ef4444" },
  critical: { text: "⛔", color: "#dc2626" },
  scanning: { text: "…",  color: "#6366f1" },
  error:    { text: "?",  color: "#6b7280" },
  unknown:  { text: "–",  color: "#6b7280" },
};

function setBadge(tabId, riskLevel) {
  const cfg = BADGE_CONFIG[riskLevel] || BADGE_CONFIG.unknown;
  chrome.action.setBadgeText({ text: cfg.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: cfg.color, tabId });
}

// ─── Cache ────────────────────────────────────────────────────
const cache = new Map(); // url → { result, timestamp }

function getCached(url) {
  const entry = cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(url);
    return null;
  }
  return entry.result;
}

function setCache(url, result) {
  cache.set(url, { result, timestamp: Date.now() });
  // Evict oldest if too large
  if (cache.size > 100) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
}

// ─── Scan History ─────────────────────────────────────────────
async function addToHistory(result) {
  const data = await chrome.storage.local.get("scanHistory");
  const history = data.scanHistory || [];
  history.unshift({
    url: result.url,
    prediction: result.prediction,
    risk_level: result.risk_level,
    confidence: result.confidence,
    timestamp: Date.now(),
  });
  // Keep only last N
  await chrome.storage.local.set({
    scanHistory: history.slice(0, MAX_HISTORY),
  });
}

// ─── API Call ─────────────────────────────────────────────────
async function analyseUrl(url, tabId) {
  // Check cache first
  const cached = getCached(url);
  if (cached) {
    setBadge(tabId, cached.risk_level);
    await chrome.storage.local.set({ [`scan_${tabId}`]: cached });
    return;
  }

  // Show scanning badge
  setBadge(tabId, "scanning");
  await chrome.storage.local.set({
    [`scan_${tabId}`]: { status: "scanning", url },
  });

  try {
    const resp = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const result = await resp.json();
    result.status = "complete";

    // Cache + persist
    setCache(url, result);
    await chrome.storage.local.set({ [`scan_${tabId}`]: result });
    await addToHistory(result);

    // Badge
    setBadge(tabId, result.risk_level);

    // Notification for dangerous URLs
    if (["high", "critical"].includes(result.risk_level)) {
      chrome.notifications.create(`alert_${tabId}_${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: `⚠️ ${result.risk_level.toUpperCase()} RISK — ${result.prediction.toUpperCase()}`,
        message: `${url}\nConfidence: ${(result.confidence * 100).toFixed(1)}%\nThis site may be dangerous!`,
        priority: 2,
      });
    }
  } catch (err) {
    console.error("[WebDetector] API error:", err);
    setBadge(tabId, "error");
    await chrome.storage.local.set({
      [`scan_${tabId}`]: {
        status: "error",
        url,
        error: err.message,
      },
    });
  }
}

// ─── Tab Listeners ────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only scan when navigation completes (not on every update)
  if (changeInfo.status === "complete" && tab.url && shouldScan(tab.url)) {
    analyseUrl(tab.url, tabId);
  }
});

// Also scan when user switches tabs (show cached result)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab.url && shouldScan(tab.url)) {
    const cached = getCached(tab.url);
    if (cached) {
      setBadge(activeInfo.tabId, cached.risk_level);
    }
  }
});

// ─── Message handler for popup requesting re-scan ─────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "rescan" && message.url && message.tabId) {
    // Clear cache for this URL
    cache.delete(message.url);
    analyseUrl(message.url, message.tabId);
    sendResponse({ status: "started" });
  }
  return true;
});
