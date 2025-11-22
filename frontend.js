// frontend.js - simple client-side phishing checks
function checkURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultEl = document.getElementById("result");

  if (!url) {
    resultEl.innerText = "⚠️ Please enter a URL.";
    resultEl.style.color = "orange";
    return;
  }

  // normalize (ensure protocol for checks)
  let normalized = url;
  if (!/^https?:\/\//i.test(normalized)) normalized = "http://" + normalized;

  // simple rules
  let reasons = [];

  // 1) IP address in hostname
  const ipPattern = /^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/;
  if (ipPattern.test(normalized)) reasons.push("Contains an IP address instead of a domain.");

  // 2) suspicious tokens
  const suspectTokens = ["@", "%", "--", "verify", "secure-login", "update-account", "free-gift"];
  suspectTokens.forEach(t => { if (normalized.toLowerCase().includes(t)) reasons.push(`Contains suspicious token: "${t}"`); });

  // 3) very long URL
  if (normalized.length > 75) reasons.push("URL is very long (often used by phishing).");

  // 4) too many subdomains (e.g. a.b.c.d.e.example.com)
  try {
    const hostname = new URL(normalized).hostname;
    if (hostname.split(".").length - 1 >= 4) reasons.push("Many subdomains (possible impersonation).");
  } catch (e) {
    reasons.push("Malformed URL.");
  }

  // show result
  if (reasons.length === 0) {
    resultEl.innerText = "✅ Looks safe (basic checks).";
    resultEl.style.color = "green";
  } else {
    resultEl.innerText = "⚠️ Suspicious — " + reasons.join(" ");
    resultEl.style.color = "red";
  }
}
