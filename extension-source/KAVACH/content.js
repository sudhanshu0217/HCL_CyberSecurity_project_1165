function verifyPageSafety() {
  if (!window.location.href.startsWith("http")) return;

  chrome.runtime.sendMessage(
    { type: "GET_CURRENT_STATUS", url: window.location.href },
    (verdict) => {
      if (verdict && verdict.blocked) {
        // Immediately halt page rendering and redirect to quarantine screen
        window.stop();
        window.location.replace(
          chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(window.location.href)}`)
        );
      }
    }
  );
}

verifyPageSafety();