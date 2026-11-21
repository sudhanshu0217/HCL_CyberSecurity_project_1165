document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "";

  const blockedUrlEl = document.getElementById("blockedUrl");
  const riskPercentEl = document.getElementById("riskPercent");
  const reasonsList = document.getElementById("reasonsList");
  const goBackBtn = document.getElementById("goBackBtn");
  const accessSiteBtn = document.getElementById("accessSiteBtn");
  const permanentTrustCheck = document.getElementById("permanentTrustCheck");
  const themeToggle = document.getElementById("themeToggle");

  blockedUrlEl.textContent = targetUrl || "Unknown URL";

  // Sync theme with user settings
  const storage = await chrome.storage.local.get("settings");
  const theme = storage.settings?.theme || "dark";
  document.documentElement.setAttribute("data-theme", theme === "light" ? "light" : "dark");

  themeToggle.addEventListener("click", async () => {
    const current = document.documentElement.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    const data = await chrome.storage.local.get("settings");
    await chrome.storage.local.set({ settings: { ...data.settings, theme: next } });
  });

  // Fetch exact risk breakdown for the blocked URL
  if (targetUrl) {
    chrome.runtime.sendMessage({ type: "GET_CURRENT_STATUS", url: targetUrl }, (verdict) => {
      if (!verdict) return;
      riskPercentEl.textContent = `${verdict.score}%`;
      reasonsList.innerHTML = "";
      (verdict.reasons || []).forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsList.appendChild(li);
      });
    });
  }

  // Safe Return Button
  goBackBtn.addEventListener("click", () => {
    if (window.history.length > 2) {
      window.history.go(-2);
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Manual "Access the Site" Button (Unlocks the block and navigates)
  accessSiteBtn.addEventListener("click", () => {
    if (!targetUrl) return;
    accessSiteBtn.disabled = true;
    accessSiteBtn.textContent = "Unlocking Site...";

    const hostname = new URL(targetUrl).hostname.toLowerCase();

    if (permanentTrustCheck.checked) {
      chrome.runtime.sendMessage({ type: "ALLOWLIST_DOMAIN", hostname }, () => {
        window.location.replace(targetUrl);
      });
    } else {
      chrome.runtime.sendMessage({ type: "MANUAL_ACCESS_SITE", url: targetUrl }, () => {
        window.location.replace(targetUrl);
      });
    }
  });
});