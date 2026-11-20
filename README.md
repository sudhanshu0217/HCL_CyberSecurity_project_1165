# KAVACH – Website + Extension

website/                      -> upload to any host (GitHub Pages / Netlify / Cloudflare Pages)
extension-source/KAVACH/      -> your extension source (unchanged)
KAVACH-chrome-store-upload.zip -> ready to upload to the Chrome Web Store (manifest.json at zip root)

## Make the button install the extension in ONE click (3 steps)
Browsers forbid websites from installing extensions silently (since 2018). The official one-click route is the Web Store:
1. Go to https://chrome.google.com/webstore/devconsole  (one-time $5 developer fee).
   Upload KAVACH-chrome-store-upload.zip. Privacy policy URL: https://YOUR-SITE/privacy.html
   Justification for "all websites" permission: "Checks each URL for phishing risk before the page loads."
2. After approval (usually a few days) copy the 32-letter extension ID from your listing URL.
3. Open website/js/main.js and set:  CHROME_EXTENSION_ID: "abcdefghijklmnopabcdefghijklmnop"
   Done: "Add to Browser" now opens your store page where the user clicks one "Add to Chrome" button.
   (Optional) Microsoft Edge: publish at https://partner.microsoft.com/dashboard/microsoftedge and set EDGE_STORE_URL.

Until the ID is set, the button downloads the zip and shows a guided manual-install popup.
