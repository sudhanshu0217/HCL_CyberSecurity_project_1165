/* KAVACH risk engine (port of the extension's background.js heuristics) used by the live demo. */
(function () {
  var BLOCK_THRESHOLD = 50;
  var BRANDS = ["google.com","paypal.com","microsoft.com","apple.com","amazon.com","netflix.com","facebook.com","instagram.com","github.com","linkedin.com","bankofamerica.com","chase.com","irctc.co.in","sbi.co.in","hdfcbank.com","icicibank.com"];
  var TLDS = [".xyz",".top",".club",".tk",".ml",".ga",".cf",".gq",".work",".zip",".click",".loan",".win",".bid"];
  var KEYWORDS = ["login","verify","update","secure","account","banking","confirm","signin","wallet","auth","kyc","otp"];

  function lev(a, b) {
    var m = [], i, j;
    for (i = 0; i <= a.length; i++) { m[i] = [i]; }
    for (j = 0; j <= b.length; j++) { m[0][j] = j; }
    for (i = 1; i <= a.length; i++) for (j = 1; j <= b.length; j++) {
      m[i][j] = Math.min(m[i-1][j] + 1, m[i][j-1] + 1, m[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1));
    }
    return m[a.length][b.length];
  }
  function rootDomain(h) {
    var p = h.split(".");
    if (p.length <= 2) return h;
    var two = ["co.in","co.uk","org.uk","com.au","co.jp"];
    var last2 = p.slice(-2).join(".");
    if (two.indexOf(last2) > -1 && p.length >= 3) return p.slice(-3).join(".");
    return last2;
  }

  window.kavachAnalyze = function (raw) {
    raw = (raw || "").trim();
    if (!/^https?:\/\//i.test(raw)) raw = "http://" + raw;   // bare domains are treated as plain HTTP
    var score = 0, reasons = [], u;
    try { u = new URL(raw); } catch (e) { return null; }
    var host = u.hostname.toLowerCase(), full = raw.toLowerCase(), root = rootDomain(host);

    if (host.indexOf("xn--") > -1) { score += 55; reasons.push("Punycode/IDN homograph characters detected in domain (+55%)."); }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) { score += 55; reasons.push("Direct IP address used instead of a registered domain (+55%)."); }
    if (full.indexOf("@") > -1) { score += 60; reasons.push("URL contains '@' credential/redirect obfuscation (+60%)."); }
    var dots = (host.match(/\./g) || []).length;
    if (dots >= 3) { score += 25; reasons.push("Excessive subdomain nesting (" + dots + " levels) (+25%)."); }
    if (TLDS.some(function (t) { return host.endsWith(t); })) { score += 30; reasons.push("High-risk Top-Level Domain (TLD) detected (+30%)."); }

    for (var i = 0; i < BRANDS.length; i++) {
      var brand = BRANDS[i], base = brand.split(".")[0];
      if (root !== brand) {
        if (host.indexOf(base) > -1) { score += 55; reasons.push('Brand impersonation: "' + base + '" found in untrusted domain (+55%).'); break; }
        var d = lev(root, brand);
        if (d > 0 && d <= 2) { score += 55; reasons.push('Typosquatting alert: Domain closely mimics "' + brand + '" (+55%).'); break; }
      }
    }

    var kw = KEYWORDS.filter(function (k) { return full.indexOf(k) > -1; });
    if (kw.length > 0 && u.protocol === "http:") { score += 40; reasons.push("Sensitive keywords (" + kw.slice(0, 3).join(", ") + ") over unencrypted HTTP (+40%)."); }
    else if (kw.length >= 2) { score += 25; reasons.push("Multiple credential-harvesting keywords in URL (+25%)."); }
    if (raw.length > 100) { score += 15; reasons.push("Abnormally long URL (>100 characters) (+15%)."); }

    score = Math.min(score, 100);
    var blocked = score > BLOCK_THRESHOLD;
    var status = blocked ? "danger" : (score >= 25 ? "warning" : "safe");
    return { score: score, status: status, blocked: blocked, reasons: reasons, host: host };
  };
})();
