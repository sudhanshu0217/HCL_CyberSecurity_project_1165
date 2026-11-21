/* =====================================================================
   KAVACH website script
   ---------------------------------------------------------------------
   ONE-CLICK INSTALL: browsers do NOT allow a website to silently install
   an extension (security rule since 2018). The only real one-click install
   is via the official store. Publish KAVACH to the Chrome Web Store
   (and/or Edge Add-ons), then paste the links below. After that, the
   "Add to Browser" buttons open the store page where the user presses
   a single "Add to Chrome" button, and the extension installs automatically.

   Until you paste the links, the buttons download the extension zip and
   show a short guided install popup instead.
   ===================================================================== */
var KAVACH_CONFIG = {
  CHROME_EXTENSION_ID: "", // easiest: paste ONLY the 32-letter ID from your Chrome Web Store listing
  CHROME_STORE_URL: "",   // e.g. "https://chromewebstore.google.com/detail/kavach/abcdefghijklmnopabcdefghijklmnop"
  EDGE_STORE_URL:   "",   // e.g. "https://microsoftedge.microsoft.com/addons/detail/kavach/xxxxxxxx"
  ZIP_PATH: "downloads/KAVACH-extension.zip"
};

(function () {
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* ---- Browser detection ---- */
  var ua = navigator.userAgent;
  var isEdge = /Edg\//.test(ua);
  var isFirefox = /Firefox\//.test(ua);
  var isSafari = /Safari\//.test(ua) && !/Chrome|Chromium|Edg/.test(ua);
  var isMobile = /Android|iPhone|iPad|iPod/i.test(ua);
  var browserName = isEdge ? "Edge" : isFirefox ? "Firefox" : isSafari ? "Safari" : "Chrome";

  if (!KAVACH_CONFIG.CHROME_STORE_URL && KAVACH_CONFIG.CHROME_EXTENSION_ID) {
    KAVACH_CONFIG.CHROME_STORE_URL = "https://chromewebstore.google.com/detail/" + KAVACH_CONFIG.CHROME_EXTENSION_ID;
  }
  var storeUrl = isEdge ? (KAVACH_CONFIG.EDGE_STORE_URL || KAVACH_CONFIG.CHROME_STORE_URL) : KAVACH_CONFIG.CHROME_STORE_URL;

  /* ---- Install buttons ---- */
  var modal = $("#modal");
  function openModal() { modal.hidden = false; $("#modalClose").focus(); }
  function closeModal() { modal.hidden = true; }

  function triggerDownload() {
    var a = document.createElement("a");
    a.href = KAVACH_CONFIG.ZIP_PATH; a.download = "KAVACH-extension.zip";
    document.body.appendChild(a); a.click(); a.remove();
  }

  function install() {
    if (storeUrl) { window.open(storeUrl, "_blank", "noopener"); return; }  // real one-click install
    triggerDownload();
    $("#mTitle").textContent = "Your download has started";
    openModal();
  }

  $$(".js-install").forEach(function (b) {
    if (storeUrl) b.textContent = b.textContent.replace(/Browser/, isEdge ? "Edge" : "Chrome");
    b.addEventListener("click", install);
  });

  var note = $("#browserNote");
  if (note) {
    if (isFirefox || isSafari) note.textContent = "KAVACH works on Chrome, Edge, Brave and other Chromium browsers.";
    else if (isMobile) note.textContent = "Open this page on a desktop computer to install.";
    else note.textContent = "Detected browser: " + browserName + (storeUrl ? "" : " (manual install until the store listing is live)");
  }

  $("#modalClose").addEventListener("click", closeModal);
  modal.addEventListener("click", function (e) { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeModal(); });

  var copyBtn = $("#copyExt");
  copyBtn.addEventListener("click", function () {
    var txt = isEdge ? "edge://extensions" : "chrome://extensions";
    var done = function () { copyBtn.textContent = "Copied ✓"; setTimeout(function () { copyBtn.textContent = txt; }, 1600); };
    if (navigator.clipboard) navigator.clipboard.writeText(txt).then(done, done); else done();
  });
  if (isEdge) copyBtn.textContent = "edge://extensions";

  /* ---- Nav ---- */
  var nav = $("#nav");
  function onScroll() { nav.classList.toggle("scrolled", window.scrollY > 20); }
  window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
  $("#burger").addEventListener("click", function () { $("#navLinks").classList.toggle("open"); });
  $$("#navLinks a").forEach(function (a) { a.addEventListener("click", function () { $("#navLinks").classList.remove("open"); }); });

  /* ---- Reveal on scroll ---- */
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
    }, { threshold: 0.12 });
    $$(".reveal").forEach(function (el, i) { el.style.transitionDelay = (i % 3) * 90 + "ms"; io.observe(el); });
  } else { $$(".reveal").forEach(function (el) { el.classList.add("in"); }); }

  /* ---- Count-up stats ---- */
  function countUp(el) {
    var target = +el.dataset.count, suf = el.dataset.suffix || "", t0 = null;
    function step(t) {
      if (!t0) t0 = t;
      var p = Math.min((t - t0) / 1100, 1);
      el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))) + suf;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  if ("IntersectionObserver" in window) {
    var so = new IntersectionObserver(function (es) {
      es.forEach(function (e) { if (e.isIntersecting) { countUp(e.target); so.unobserve(e.target); } });
    }, { threshold: 0.6 });
    $$("[data-count]").forEach(function (el) { so.observe(el); });
  } else { $$("[data-count]").forEach(function (el) { el.textContent = el.dataset.count + (el.dataset.suffix || ""); }); }

  /* ---- Live demo ---- */
  var form = $("#demoForm"), input = $("#demoUrl");
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  function scan(url) {
    var r = window.kavachAnalyze(url);
    var chip = $("#gStatus"), list = $("#gReasons");
    if (!r) {
      list.innerHTML = '<li class="warn">That doesn\'t look like a valid web address. Try something like example.com</li>';
      return;
    }
    $("#gaugeArc").setAttribute("stroke-dasharray", r.score + " 100");
    $("#needle").style.transform = "rotate(" + (-90 + r.score * 1.8) + "deg)";
    var n = 0, target = r.score, start = performance.now();
    (function tick(t) {
      var p = Math.min((t - start) / 900, 1); n = Math.round(target * p);
      $("#gScore").textContent = n + "%";
      if (p < 1) requestAnimationFrame(tick);
    })(start);

    chip.className = "chip " + (r.status === "danger" ? "bad" : r.status === "warning" ? "warn" : "ok");
    chip.textContent = r.status === "danger" ? "BLOCKED" : r.status === "warning" ? "WARNING" : "SAFE";

    if (!r.reasons.length) list.innerHTML = '<li class="good">No threat indicators found for <b>' + esc(r.host) + "</b>. The site would load normally.</li>";
    else list.innerHTML = r.reasons.map(function (x) { return '<li class="' + (r.blocked ? "bad" : "warn") + '">' + esc(x) + "</li>"; }).join("");
  }

  form.addEventListener("submit", function (e) { e.preventDefault(); if (input.value.trim()) scan(input.value); });
  $$(".samples button").forEach(function (b) {
    b.addEventListener("click", function () { input.value = b.dataset.url; scan(b.dataset.url); });
  });

  $("#year").textContent = new Date().getFullYear();
})();
