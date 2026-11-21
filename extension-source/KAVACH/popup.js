document.addEventListener("DOMContentLoaded", async () => {
  const themeToggle = document.getElementById("themeToggle");
  const protectionToggle = document.getElementById("protectionToggle");
  const statusCard = document.getElementById("statusCard");
  const statusBadge = document.getElementById("statusBadge");
  const riskScore = document.getElementById("riskScore");
  const currentDomainEl = document.getElementById("currentDomain");
  const reasonsList = document.getElementById("reasonsList");
  const trustSiteBtn = document.getElementById("trustSiteBtn");
  const rescanBtn = document.getElementById("rescanBtn");
  const ttlSelect = document.getElementById("ttlSelect");
  const cacheStatusText = document.getElementById("cacheStatusText");
  const cacheCountText = document.getElementById("cacheCountText");
  const clearCacheBtn = document.getElementById("clearCacheBtn");
  const allowlistContainer = document.getElementById("allowlistContainer");
  const allowlistCount = document.getElementById("allowlistCount");

  let activeHostname = "";

  function applyTheme(theme) {
    if (theme === "system") {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      document.documentElement.setAttribute("data-theme", prefersDark ? "dark" : "light");
    } else {
      document.documentElement.setAttribute("data-theme", theme);
    }
  }

  async function loadState() {
    const data = await chrome.storage.local.get(["settings", "urlCache", "allowlist"]);
    const settings = data.settings || { enabled: true, ttlMinutes: 15, theme: "dark" };
    const urlCache = data.urlCache || {};
    const allowlist = data.allowlist || [];

    applyTheme(settings.theme);
    protectionToggle.checked = settings.enabled;
    ttlSelect.value = String(settings.ttlMinutes || 15);
    cacheCountText.textContent = `${Object.keys(urlCache).length} domains cached`;

    renderAllowlist(allowlist);
  }

  function renderAllowlist(allowlist) {
    allowlistCount.textContent = allowlist.length;
    allowlistContainer.innerHTML = "";
    if (allowlist.length === 0) {
      const empty = document.createElement("span");
      empty.className = "label-sub";
      empty.textContent = "No trusted domains added yet.";
      allowlistContainer.appendChild(empty);
      return;
    }

    allowlist.forEach((domain) => {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `${domain} `;

      const removeBtn = document.createElement("button");
      removeBtn.textContent = "×";
      removeBtn.title = "Remove";
      removeBtn.addEventListener("click", async () => {
        const updated = allowlist.filter((d) => d !== domain);
        await chrome.storage.local.set({ allowlist: updated });
        await loadState();
        await inspectActiveTab();
      });

      chip.appendChild(removeBtn);
      allowlistContainer.appendChild(chip);
    });
  }

  async function inspectActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Check if the tab is currently quarantined on blocked.html
    let targetUrl = tab?.url || "";
    if (targetUrl.startsWith(chrome.runtime.getURL("blocked.html"))) {
      const params = new URLSearchParams(new URL(targetUrl).search);
      targetUrl = params.get("url") || "";
    }

    if (!targetUrl || !targetUrl.startsWith("http")) {
      currentDomainEl.textContent = "Browser Internal Page";
      statusBadge.textContent = "N/A";
      riskScore.textContent = "";
      reasonsList.innerHTML = "<li>Protection active for HTTP/HTTPS websites.</li>";
      trustSiteBtn.disabled = true;
      rescanBtn.disabled = true;
      cacheStatusText.textContent = "Not applicable";
      return;
    }

    activeHostname = new URL(targetUrl).hostname.toLowerCase();
    currentDomainEl.textContent = activeHostname;

    chrome.runtime.sendMessage({ type: "GET_CURRENT_STATUS", url: targetUrl }, async (verdict) => {
      if (!verdict) return;

      statusCard.className = "status-card";
      if (verdict.blocked || verdict.status === "danger") statusCard.classList.add("status-danger");
      else if (verdict.status === "warning") statusCard.classList.add("status-warning");
      else statusCard.classList.add("status-safe");

      statusBadge.textContent = verdict.blocked ? "BLOCKED" : verdict.status.toUpperCase();
      riskScore.textContent = `Risk: ${verdict.score}%`;

      reasonsList.innerHTML = "";
      if (verdict.reasons && verdict.reasons.length > 0) {
        verdict.reasons.forEach((reason) => {
          const li = document.createElement("li");
          li.textContent = reason;
          reasonsList.appendChild(li);
        });
      } else {
        const li = document.createElement("li");
        li.textContent = "Site passed all real-time security checks.";
        reasonsList.appendChild(li);
      }

      cacheStatusText.textContent = verdict.cached
        ? `Cache HIT (TTL expires in ${verdict.expiresInSec}s)`
        : `Fresh Scan (Cached for ${ttlSelect.value}m)`;

      trustSiteBtn.disabled = Boolean(verdict.allowlisted);
      trustSiteBtn.textContent = verdict.allowlisted ? "Trusted" : "Trust This Site";

      const cacheData = await chrome.storage.local.get("urlCache");
      cacheCountText.textContent = `${Object.keys(cacheData.urlCache || {}).length} domains cached`;
    });
  }

  themeToggle.addEventListener("click", async () => {
    const current = document.documentElement.getAttribute("data-theme");
    const nextTheme = current === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
    const data = await chrome.storage.local.get("settings");
    await chrome.storage.local.set({ settings: { ...data.settings, theme: nextTheme } });
  });

  protectionToggle.addEventListener("change", async () => {
    const data = await chrome.storage.local.get("settings");
    await chrome.storage.local.set({
      settings: { ...data.settings, enabled: protectionToggle.checked }
    });
    inspectActiveTab();
  });

  ttlSelect.addEventListener("change", async () => {
    const data = await chrome.storage.local.get("settings");
    await chrome.storage.local.set({
      settings: { ...data.settings, ttlMinutes: Number(ttlSelect.value) }
    });
    inspectActiveTab();
  });

  trustSiteBtn.addEventListener("click", () => {
    if (!activeHostname) return;
    chrome.runtime.sendMessage({ type: "ALLOWLIST_DOMAIN", hostname: activeHostname }, async () => {
      await loadState();
      await inspectActiveTab();
    });
  });

  rescanBtn.addEventListener("click", async () => {
    if (!activeHostname) return;
    const data = await chrome.storage.local.get("urlCache");
    const urlCache = data.urlCache || {};
    delete urlCache[activeHostname];
    await chrome.storage.local.set({ urlCache });
    await loadState();
    await inspectActiveTab();
  });

  clearCacheBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CLEAR_CACHE" }, async () => {
      await loadState();
      await inspectActiveTab();
    });
  });

  await loadState();
  await inspectActiveTab();
});