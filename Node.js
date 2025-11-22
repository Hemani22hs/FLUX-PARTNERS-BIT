/tics --- */
function hasIPAddressHost(hostname){
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function suspiciousPatterns(urlObj){
  const reasons = [];
  const urlStr = urlObj.href;
  if(urlStr.includes("@")) reasons.push("contains @ (possible credential-stealing redirect)");
  if(urlObj.pathname && urlObj.pathname.length > 100) reasons.push("very long path");
  if((urlObj.hostname.split(".").length - 1) >= 4) reasons.push("many subdomains");
  if(urlStr.includes("%0A") || urlStr.includes("%0D")) reasons.push("encoded newline sequences");
  return reasons;
}

function detectPunycode(hostname){
  // punycode encoded domain look like xn--...
  if(hostname.startsWith("xn--") || hostname.includes(".xn--")) return true;
  return false;
}
/ phishing-guard.js
// Node 18+ recommended
import express from "express";
import dns from "dns/promises";
import { URL } from "url";
import https from "https";
import net from "net";
import punycode from "punycode/"; // npm i punycode
import levenshtein from "fast-levenshtein"; // npm i fast-levenshtein

const app = express();
app.use(express.json());

/* --- Config: tweak these lists for your environment --- */
const TRUSTED_DOMAINS = [
  "google.com", "gmail.com", "facebook.com", "amazon.com",
  "bank.com" // add your org's real domains here
];

const BLACKLIST = [
  "bad-phish.example",
  "malware.example"
];

function scoreToVerdict(score){
  if(score >= 75) return "phishing";
  if(score >= 40) return "suspicious";
  return "safe";
}

/* --- Heuris
async function getCertInfo(hostname){
  return new Promise((resolve) => {
    const socket = net.connect(443, hostname, () => {
      const tlsSocket = new tls.TLSSocket(socket, { servername: hostname });
      tlsSocket.once("secureConnect", () => {
        const cert = tlsSocket.getPeerCertificate(true);
        tlsSocket.end();
        resolve({ ok: true, cert });
      });
      tlsSocket.on("error", (err) => {
        resolve({ ok: false, error: err?.message || "TLS error" });
      });
    });
    socket.on("error", (err) => {
      resolve({ ok: false, error: err?.message || "connect failed" });
    });
  });
}

/* Because using "tls" directly is sometimes simpler: */
import tls from "tls";
async function getTlsCert(hostname){
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 5000
    }, () => {
      try{
        const cert = socket.getPeerCertificate(true);
        socket.end();
        resolve({ ok: true, cert });
      }catch(e){
        socket.end();
        resolve({ ok: false, error: e.message });
      }
    });
    socket.on("error", (err) => resolve({ ok: false, error: err.message }));
    socket.on("timeout", () => { socket.destroy(); resolve({ ok:false, error: "timeout" }); });
  });
}

/* Levenshtein min distance to trusted list */
function minLevenshtein(hostnameBase){
  let min = Infinity, nearest = null;
  for(const t of TRUSTED_DOMAINS){
    const d = levenshtein.get(hostnameBase, t);
    if(d < min){ min = d; nearest = t; }
  }
  return { min, nearest };
}

/* --- Main endpoint --- */
app.post("/api/check", async (req, res) => {
  const { url } = req.body || {};
  if(!url) return res.status(400).json({ error: "Missing url in body" });

  let parsed;
  try {
    parsed = new URL(url);
  } catch(e){
    return res.status(400).json({ error: "Invalid URL" });
  }

  const reasons = [];
  let score = 0; // higher -> more suspicious

  const hostname = parsed.hostname.toLowerCase();
  const hostnameBase = hostname.replace(/^www\./, "");

  // 1) Blacklist
  if(BLACKLIST.includes(hostnameBase)){
    reasons.push("domain is in local blacklist");
    score += 80;
  }

  // 2) IP host
  if(hasIPAddressHost(hostnameBase)){
    reasons.push("host is an IP address");
    score += 40;
  }

  // 3) punycode/homograph
  if(detectPunycode(hostnameBase)){
    reasons.push("punycode / possible homograph domain (xn--)");
    score += 50;
  }

  // 4) typosquatting via Levenshtein to trusted list
  const { min, nearest } = minLevenshtein(hostnameBase);
  if(min <= 2 && nearest){
    reasons.push(`hostname is very similar to trusted domain "${nearest}" (levenshtein=${min})`);
    score += 45 - (min * 10); // smaller distance -> more suspicious
  }

  // 5) suspicious URL patterns
  const patternReasons = suspiciousPatterns(parsed);
  if(patternReasons.length){
    reasons.push(...patternReasons);
    score += patternReasons.length * 10;
  }

  // 6) DNS checks (domain exists?)
  try{
    const a = await dns.lookup(hostnameBase);
    if(!a || !a.address) {
      reasons.push("DNS lookup failed / no A record");
      score += 40;
    }
  }catch(e){
    reasons.push("DNS lookup failed");
    score += 40;
  }

  // 7) TLS certificate inspection (if https)
  if(parsed.protocol === "https:"){
    try{
      const { ok, cert, error } = await getTlsCert(hostnameBase);
      if(!ok){
        reasons.push(`TLS connection failed: ${error}`);
        score += 30;
      } else {
        // cert: { valid_from, valid_to, issuer, subject, subjectaltname, ... }
        if(cert && cert.valid_to){
          const validTo = new Date(cert.valid_to);
          const validFrom = new Date(cert.valid_from);
          const daysValid = (validTo - validFrom) / (1000*60*60*24);
          if(daysValid < 30) { reasons.push("TLS cert is short-lived (<30 days)"); score += 20; }
          if(validTo < new Date()) { reasons.push("TLS cert expired"); score += 50; }
          // check issuer trivial
          const issuer = cert.issuer?.O || cert.issuer?.CN || "";
          if(issuer && issuer.toLowerCase().includes("self-signed")){ reasons.push("self-signed certificate"); score += 40; }
        } else {
          reasons.push("unable to read TLS certificate");
          score += 20;
        }
      }
    }catch(e){
      reasons.push("error checking TLS certificate");
      score += 10;
    }
  } else {
    // Not https
    reasons.push("site not using HTTPS");
    score += 30;
  }

  // Final normalization
  if(score < 0) score = 0;
  if(score > 100) score = 100;

  const verdict = scoreToVerdict(score);

  return res.json({
    url: parsed.href,
    hostname: hostnameBase,
    verdict,
    score,
    reasons
  });
});

/* --- Run server --- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Phishing guard listening on ${PORT}`));
