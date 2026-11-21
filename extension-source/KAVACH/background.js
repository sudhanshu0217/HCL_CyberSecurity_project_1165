const DEFAULT_TTL_MINUTES = 15;
const BLOCK_THRESHOLD = 50; // Strictly blocks when risk > 50%

const PROTECTED_BRANDS = [
  "google.com", "paypal.com", "microsoft.com", "apple.com",
  "amazon.com", "netflix.com", "facebook.com", "instagram.com",
  "github.com", "linkedin.com", "bankofamerica.com", "chase.com",
  "irctc.co.in", "sbi.co.in", "hdfcbank.com", "icicibank.com"
];

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".club", ".tk", ".ml", ".ga", ".cf", ".gq",
  ".work", ".zip", ".click", ".loan", ".win", ".bid"
];

const PHISHING_KEYWORDS = [
  "login", "verify", "update", "secure", "account",
  "banking", "confirm", "signin", "wallet", "auth", "kyc", "otp"
];

// Initialize storage on install
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get([
    "settings",
    "urlCache",
    "allowlist",
    "sessionBypass"
  ]);
  if (!existing.settings) {
    await chrome.storage.local.set({
      settings: {
        enabled: true,
        ttlMinutes: DEFAULT_TTL_MINUTES,
        theme: "dark"
      },
      urlCache: {},
      allowlist: [],
      sessionBypass: []
    });
  }
});

// Levenshtein Distance for typosquatting detection
function getLevenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

function getRootDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const twoPartTlds = ["co.in", "co.uk", "org.uk", "com.au", "co.jp"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

// Real-Time Heuristic Risk Engine (0% - 100%)
function analyzeUrlHeuristics(rawUrl) {
  let score = 0;
  const reasons = [];

  try {
    const urlObj = new URL(rawUrl);
    const hostname = urlObj.hostname.toLowerCase();
    const fullUrl = rawUrl.toLowerCase();
    const rootDomain = getRootDomain(hostname);

    // 1. Punycode / IDN Homograph Attack (+55%)
    if (hostname.includes("xn--")) {
      score += 55;
      reasons.push("Punycode/IDN homograph characters detected in domain (+55%).");
    }

    // 2. Direct IPv4 Host Address (+55%)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      score += 55;
      reasons.push("Direct IP address used instead of a registered domain (+55%).");
    }

    // 3. '@' Redirect Obfuscation (+60%)
    if (fullUrl.includes("@")) {
      score += 60;
      reasons.push("URL contains '@' credential/redirect obfuscation (+60%).");
    }

    // 4. Excessive Subdomains (+25%)
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount >= 3) {
      score += 25;
      reasons.push(`Excessive subdomain nesting (${dotCount} levels) (+25%).`);
    }

    // 5. High-Risk TLD (+30%)
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      score += 30;
      reasons.push("High-risk Top-Level Domain (TLD) detected (+30%).");
    }

    // 6. Brand Impersonation & Typosquatting (+55%)
    for (const brand of PROTECTED_BRANDS) {
      const brandBase = brand.split(".")[0];
      if (rootDomain !== brand) {
        if (hostname.includes(brandBase)) {
          score += 55;
          reasons.push(`Brand impersonation: "${brandBase}" found in untrusted domain (+55%).`);
          break;
        }
        const dist = getLevenshteinDistance(rootDomain, brand);
        if (dist > 0 && dist <= 2) {
          score += 55;
          reasons.push(`Typosquatting alert: Domain closely mimics "${brand}" (+55%).`);
          break;
        }
      }
    }

    // 7. Sensitive Keywords + HTTP (+40% / +25%)
    const matchedKeywords = PHISHING_KEYWORDS.filter(kw => fullUrl.includes(kw));
    if (matchedKeywords.length > 0 && urlObj.protocol === "http:") {
      score += 40;
      reasons.push(`Sensitive keywords (${matchedKeywords.slice(0, 3).join(", ")}) over unencrypted HTTP (+40%).`);
    } else if (matchedKeywords.length >= 2) {
      score += 25;
      reasons.push("Multiple credential-harvesting keywords in URL (+25%).");
    }

    // 8. Abnormally Long URL (+15%)
    if (rawUrl.length > 100) {
      score += 15;
      reasons.push("Abnormally long URL (>100 characters) (+15%).");
    }
  } catch {
    return { score: 0, status: "safe", blocked: false, reasons: ["Internal or non-HTTP URL."] };
  }

  score = Math.min(score, 100);
  const blocked = score > BLOCK_THRESHOLD; // Strictly > 50%
  let status = "safe";
  if (blocked) status = "danger";
  else if (score >= 25) status = "warning";

  return { score, status, blocked, reasons };
}

// Deterministic rule ID from hostname for declarativeNetRequest
function getRuleIdForHost(hostname) {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = (hash * 31 + hostname.charCodeAt(i)) % 900000;
  }
  return Math.max(10, hash + 10);
}

// Add/Remove native browser network rule when blocked (>50%)
async function syncDynamicBlockRule(hostname, shouldBlock) {
  const ruleId = getRuleIdForHost(hostname);
  try {
    if (shouldBlock) {
      const redirectUrl = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent("http://" + hostname)}`
      );
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [ruleId],
        addRules: [
          {
            id: ruleId,
            priority: 1,
            action: {
              type: "redirect",
              redirect: { url: redirectUrl }
            },
            condition: {
              urlFilter: `||${hostname}^`,
              resourceTypes: ["main_frame"]
            }
          }
        ]
      });
    } else {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [ruleId]
      });
    }
  } catch {
    // Fallback handled by webNavigation + content.js
  }
}

// Core Evaluation Pipeline with TTL Cache + Allowlist + Manual Override Check
async function evaluateUrl(url) {
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    return { status: "internal", score: 0, blocked: false, reasons: ["Browser internal page"], cached: false };
  }

  const data = await chrome.storage.local.get([
    "settings",
    "urlCache",
    "allowlist",
    "sessionBypass"
  ]);
  const settings = data.settings || { enabled: true, ttlMinutes: DEFAULT_TTL_MINUTES };
  const allowlist = data.allowlist || [];
  const sessionBypass = data.sessionBypass || [];
  const urlCache = data.urlCache || {};

  if (!settings.enabled) {
    return { status: "disabled", score: 0, blocked: false, reasons: ["Protection paused by user"], cached: false };
  }

  const hostname = new URL(url).hostname.toLowerCase();

  // Check Permanent Allowlist or Manual "Access the Site" Override
  if (allowlist.includes(hostname)) {
    await syncDynamicBlockRule(hostname, false);
    return {
      status: "safe",
      score: 0,
      blocked: false,
      reasons: ["Trusted via User Allowlist"],
      cached: false,
      allowlisted: true
    };
  }

  if (sessionBypass.includes(hostname)) {
    await syncDynamicBlockRule(hostname, false);
    return {
      status: "warning",
      score: 0,
      blocked: false,
      reasons: ["Manually unlocked via 'Access the Site' for this session."],
      cached: false,
      bypassed: true
    };
  }

  // Check TTL Cache
  const now = Date.now();
  const ttlMs = (settings.ttlMinutes || DEFAULT_TTL_MINUTES) * 60 * 1000;
  const cachedEntry = urlCache[hostname];

  if (cachedEntry && (now - cachedEntry.timestamp < ttlMs)) {
    const verdict = {
      ...cachedEntry.result,
      cached: true,
      expiresInSec: Math.max(1, Math.round((ttlMs - (now - cachedEntry.timestamp)) / 1000))
    };
    await syncDynamicBlockRule(hostname, verdict.blocked);
    return verdict;
  }

  // Fresh Heuristic Analysis
  const result = analyzeUrlHeuristics(url);
  urlCache[hostname] = { timestamp: now, result };
  await chrome.storage.local.set({ urlCache });
  await syncDynamicBlockRule(hostname, result.blocked);

  return {
    ...result,
    cached: false,
    expiresInSec: Math.round(ttlMs / 1000)
  };
}

function updateBadge(tabId, verdict) {
  if (verdict.blocked || verdict.status === "danger") {
    chrome.action.setBadgeText({ tabId, text: "BLK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
  } else if (verdict.status === "warning") {
    chrome.action.setBadgeText({ tabId, text: `${verdict.score}%` });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
  } else if (verdict.status === "safe") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// Intercept BEFORE page loads and lock onto blocked.html if Risk > 50%
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http://") && !details.url.startsWith("https://")) return;

  const verdict = await evaluateUrl(details.url);
  updateBadge(details.tabId, verdict);

  if (verdict.blocked) {
    const blockPageUrl = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(details.url)}`
    );
    chrome.tabs.update(details.tabId, { url: blockPageUrl });
  }
});

// Secondary Tab Update Check
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    const verdict = await evaluateUrl(tab.url);
    updateBadge(tabId, verdict);

    if (verdict.blocked) {
      const blockPageUrl = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(tab.url)}`
      );
      chrome.tabs.update(tabId, { url: blockPageUrl });
    }
  }
});

// Handle Popup & Quarantine Page Commands
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_CURRENT_STATUS") {
    evaluateUrl(message.url).then(sendResponse);
    return true;
  }

  // User manually clicked "Access the Site" on blocked.html
  if (message.type === "MANUAL_ACCESS_SITE") {
    chrome.storage.local.get(["sessionBypass", "urlCache"], async (data) => {
      const hostname = new URL(message.url).hostname.toLowerCase();
      const bypassSet = new Set(data.sessionBypass || []);
      bypassSet.add(hostname);

      const urlCache = data.urlCache || {};
      delete urlCache[hostname];

      await chrome.storage.local.set({
        sessionBypass: Array.from(bypassSet),
        urlCache
      });
      await syncDynamicBlockRule(hostname, false);
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === "ALLOWLIST_DOMAIN") {
    chrome.storage.local.get(["allowlist", "urlCache"], async (data) => {
      const allowlist = new Set(data.allowlist || []);
      allowlist.add(message.hostname);
      const urlCache = data.urlCache || {};
      delete urlCache[message.hostname];

      await chrome.storage.local.set({
        allowlist: Array.from(allowlist),
        urlCache
      });
      await syncDynamicBlockRule(message.hostname, false);
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === "CLEAR_CACHE") {
    chrome.storage.local.set({ urlCache: {}, sessionBypass: [] }).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
});