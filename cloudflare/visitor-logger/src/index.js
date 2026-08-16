const LOG_PATH = "/_visitor-logs";
const AUDIT_PATH = "/_visitor-audit";
const RETRO_REPORT_PATH = "/_visitor-retro-report";
const ANALYTICS_PATH = "/_analytics";
const MAX_RESULTS = 500;
const CLASSIFIER_VERSION = "3.0.0";
const ALLOWED_EVENTS = new Set(["page_view", "visible_10s", "visible_20s", "internal_click", "page_hidden"]);
const ALLOWED_UTM = ["utm_source", "utm_medium", "utm_campaign"];
const ASSET_RE = /\.(?:avif|css|gif|ico|jpe?g|js|json|map|mp4|pdf|png|svg|webm|webp|woff2?|ttf|xml)$/i;

const TARGET_CITIES = new Set([
  "henryetta", "dewar", "schulter", "okmulgee", "morris", "hitchita",
  "okemah", "weleetka", "dustin", "eufaula", "beggs",
]);
const TARGET_ZIPS = new Set([
  "74437", "74431", "74460", "74447", "74445", "74438",
  "74859", "74880", "74839", "74432", "74421",
]);
const CLOUD_ASNS = new Set([
  16509, 14618, 15169, 396982, 8075, 8074, 14061, 24940, 63949,
  16276, 20473, 46606, 42831, 31898, 394362, 54113, 13335, 28753,
  51167, 174,
]);
const SCANNER_PATTERNS = [
  /(?:^|\/)\.env(?:$|\/)/i, /(?:^|\/)\.git(?:$|\/)/i,
  /(?:^|\/)wp-(?:admin|login|config)/i, /xmlrpc/i, /phpmyadmin|\/pma(?:\/|$)/i,
  /(?:^|\/)(?:shell|eval|actuator|swagger|boaform)(?:\/|$)/i,
  /setup\.cgi|hnap|solr/i, /\.(?:php|asp|aspx)$/i,
  /(?:^|\/)(?:backup|dump)(?:\.|\/|$)/i,
];
const TOOL_UA_RE = /curl|python-requests|go-http-client|wget|zgrab|nmap|netsparker|nikto|sqlmap|headlesschrome|phantomjs|puppeteer|selenium|httpx|masscan|censys/i;
const CLAIMED_BOT_UA_RE = /googlebot|bingbot|duckduckbot|yandexbot|slurp|baidu|facebookexternalhit|twitterbot|linkedinbot|pinterest|applebot|gptbot|claudebot|bytespider/i;
const HISTORICAL_DISCOVERY_RE = /^(?:\/robots\.txt|\/sitemap(?:[-_][^/]*)?\.xml|\/(?:admin|administrator|login)(?:\/|$))/i;
const OWNED_REFERRER_HOSTS = new Set(["matferg.com", "matspoems.com", "mfergus93.github.io"]);

function clampText(value, length) {
  return value ? String(value).slice(0, length) : null;
}

function isScannerPath(pathname) {
  return SCANNER_PATTERNS.some((pattern) => pattern.test(pathname));
}

function isPageVisit(request, url) {
  if (request.method !== "GET" || url.pathname === LOG_PATH || url.pathname === ANALYTICS_PATH || ASSET_RE.test(url.pathname)) return false;
  const destination = request.headers.get("Sec-Fetch-Dest") || "";
  const accept = request.headers.get("Accept") || "";
  const pagePath = url.pathname === "/" || url.pathname.endsWith("/") || url.pathname.endsWith(".html");
  return destination === "document" || (pagePath && accept.includes("text/html"));
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.get("Cookie") || "").split(";").map((part) => part.trim().split(/=(.*)/s)).filter(([key]) => key));
}

function visitorIdentity(request) {
  const cookies = parseCookies(request);
  return {
    visitorId: /^[a-f0-9-]{36}$/i.test(cookies.mf_vid || "") ? cookies.mf_vid : crypto.randomUUID(),
    sessionId: /^[a-f0-9-]{36}$/i.test(cookies.mf_sid || "") ? cookies.mf_sid : crypto.randomUUID(),
  };
}

function normalizeSource(url, referrer) {
  if (!referrer) return "direct";
  try {
    const host = new URL(referrer).hostname.replace(/^www\./, "").toLowerCase();
    const siteHost = url.hostname.replace(/^www\./, "").toLowerCase();
    if (host === siteHost) return "internal";
    if (hostMatches(host, ["facebook.com", "fb.com"])) return "facebook";
    if (hostMatches(host, ["linkedin.com", "lnkd.in"])) return "linkedin";
    if (hostMatches(host, ["google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.co.in", "google.com.au", "google.co.jp"])) return "google";
    if (hostMatches(host, ["bing.com"])) return "bing";
    return host;
  } catch {
    return "direct";
  }
}

function hostMatches(host, trustedRoots) {
  return trustedRoots.some((root) => host === root || host.endsWith(`.${root}`));
}

function isReferredSource(source) {
  return Boolean(source && source !== "direct" && source !== "internal");
}

function isHostingNetwork(asn, organization = "") {
  return Boolean((asn && CLOUD_ASNS.has(Number(asn))) || /amazon|google cloud|microsoft|azure|digitalocean|hetzner|linode|akamai|ovh|vultr|choopa|hostinger|m247|oracle cloud|fly\.io|fastly|leaseweb|contabo/i.test(organization));
}

function attributionData(request, url) {
  const referrer = safeReferrer(request);
  const referrerSource = normalizeSource(url, referrer);
  const utmSource = clampText(url.searchParams.get(ALLOWED_UTM[0]), 80);
  return {
    source: utmSource?.toLowerCase() || referrerSource,
    sourceEvidence: utmSource ? "utm_claim" : referrerSource === "direct" ? "direct" : referrerSource === "internal" ? "internal" : "http_referrer",
    serverReferred: isReferredSource(referrerSource),
    utmSource,
    utmMedium: clampText(url.searchParams.get(ALLOWED_UTM[1]), 80),
    utmCampaign: clampText(url.searchParams.get(ALLOWED_UTM[2]), 120),
  };
}

function safeReferrer(request) {
  return sanitizeReferrer(request.headers.get("Referer"));
}

function sanitizeReferrer(raw) {
  if (!raw) return null;
  try {
    const ref = new URL(raw);
    return clampText(`${ref.origin}${ref.pathname}`, 500);
  } catch {
    return null;
  }
}

function isExternalReferrer(request, url) {
  const raw = request.headers.get("Referer");
  if (!raw) return false;
  try {
    return new URL(raw).hostname.replace(/^www\./, "") !== url.hostname.replace(/^www\./, "");
  } catch {
    return false;
  }
}

function classifyRequest(request, url) {
  const ua = request.headers.get("User-Agent") || "";
  const asn = request.cf?.asn ? Number(request.cf.asn) : null;
  const asOrganization = request.cf?.asOrganization || "";
  const verifiedBot = request.cf?.botManagement?.verifiedBot === true;

  if (isScannerPath(url.pathname)) {
    return { score: 0, confidence: "bot", category: "vulnerability_scanner", reasons: ["scanner path"], blocked: true, asn, asOrganization, verifiedBot };
  }
  if (TOOL_UA_RE.test(ua)) {
    return { score: 0, confidence: "bot", category: "automated_tool", reasons: ["automation or scanner user-agent"], blocked: true, asn, asOrganization, verifiedBot };
  }
  if (verifiedBot) {
    return { score: 10, confidence: "verified_bot", category: "verified_bot", reasons: ["Cloudflare verified bot"], blocked: false, asn, asOrganization, verifiedBot };
  }

  // Request scores are deliberately conservative. Human classification is
  // determined from the complete session, not a single browser-looking hit.
  let score = 25;
  const reasons = [];
  if (isPageVisit(request, url)) { score += 10; reasons.push("document navigation"); }
  if (request.headers.get("Accept-Language")) { score += 5; reasons.push("accept-language present"); }
  if (request.headers.get("Sec-CH-UA")) { score += 5; reasons.push("client hints present"); }
  if (asn && CLOUD_ASNS.has(asn)) { score -= 20; reasons.push(`hosting ASN AS${asn}`); }
  else if (isHostingNetwork(asn, asOrganization)) {
    score -= 20; reasons.push("hosting network organization");
  }
  if (isExternalReferrer(request, url)) { score += 10; reasons.push("external referrer"); }
  if (CLAIMED_BOT_UA_RE.test(ua)) { score -= 20; reasons.push("unverified crawler claim"); }
  if (Number.isFinite(request.cf?.botManagement?.score)) {
    if (request.cf.botManagement.score <= 29) { score -= 30; reasons.push("low Cloudflare bot score"); }
    else if (request.cf.botManagement.score >= 80) { score += 5; reasons.push("high Cloudflare bot score"); }
  }
  if (request.cf?.botManagement?.jsDetection?.passed === true) { score += 5; reasons.push("Cloudflare JavaScript detection passed"); }
  score = Math.max(0, Math.min(100, score));
  const confidence = score < 20 ? "bot" : "uncertain";
  return { score, confidence, category: confidence, reasons, blocked: false, asn, asOrganization, verifiedBot };
}

function requestData(request, url, result) {
  const bot = request.cf?.botManagement || {};
  return {
    ip: request.headers.get("CF-Connecting-IP") || "unknown",
    country: request.cf?.country || null,
    city: request.cf?.city || null,
    region: request.cf?.region || request.cf?.regionCode || null,
    postalCode: request.cf?.postalCode || null,
    path: clampText(url.pathname, 500),
    referrer: safeReferrer(request),
    userAgent: clampText(request.headers.get("User-Agent") || "", 1000),
    botScore: Number.isFinite(bot.score) ? bot.score : null,
    ja3Hash: clampText(bot.ja3Hash, 128),
    ja4: clampText(typeof bot.ja4 === "string" ? bot.ja4 : JSON.stringify(bot.ja4 || null), 500),
    jsDetectionPassed: typeof bot.jsDetection?.passed === "boolean" ? (bot.jsDetection.passed ? 1 : 0) : null,
    ...result,
  };
}

function parseDeviceBrowser(ua) {
  if (!ua) return "Unknown";
  const browser = ua.includes("Edg/") ? "Edge" : ua.includes("Chrome/") ? "Chrome" : ua.includes("Firefox/") ? "Firefox" : ua.includes("Safari/") ? "Safari" : "Browser";
  const os = ua.includes("Windows") ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : ua.includes("Android") ? "Android" : ua.includes("Mac OS") ? "Mac" : ua.includes("Linux") ? "Linux" : "Desktop";
  return `${browser}/${os}`;
}

function bearerToken(request) {
  const value = request.headers.get("Authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : "";
}

function isAuthorized(request, env) {
  return Boolean(env.LOG_API_TOKEN && bearerToken(request) === env.LOG_API_TOKEN);
}

async function sendEmail(env, siteName, subject, text) {
  if (!env.RESEND_API_KEY) return false;
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: `${siteName} Reports <onboarding@resend.dev>`, to: ["mcferguson9@gmail.com"], subject, text }),
  });
  if (!response.ok) throw new Error(`Resend ${response.status}: ${(await response.text()).slice(0, 300)}`);
  return true;
}

async function logSecurityEvent(data, env) {
  await env.VISITOR_DB.prepare(
    `INSERT INTO security_events
      (occurred_at, ip_address, country, city, region, postal_code, path, user_agent, category, reason, asn, as_organization)
     VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
  ).bind(data.ip, data.country, data.city, data.region, data.postalCode, data.path, data.userAgent, data.category, data.reasons.join("; "), data.asn, clampText(data.asOrganization, 250)).run();
}

async function logVisit(data, identity, attribution, env) {
  const referred = attribution.serverReferred ? 1 : 0;
  await env.VISITOR_DB.batch([
    env.VISITOR_DB.prepare(
    `INSERT INTO visits
      (visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, confidence, category, reasons, asn, as_organization, verified_bot,
       visitor_id, session_id, source, source_evidence, utm_source, utm_medium, utm_campaign, classifier_version, bot_score, ja3_hash, ja4, js_detection_passed)
     VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)`
    ).bind(data.ip, data.country, data.city, data.region, data.postalCode, data.path, data.referrer, data.userAgent, data.score, data.confidence, data.category, data.reasons.join("; "), data.asn, clampText(data.asOrganization, 250), data.verifiedBot ? 1 : 0, identity.visitorId, identity.sessionId, attribution.source, attribution.sourceEvidence, attribution.utmSource, attribution.utmMedium, attribution.utmCampaign, CLASSIFIER_VERSION, data.botScore, data.ja3Hash, data.ja4, data.jsDetectionPassed),
    env.VISITOR_DB.prepare(
      `INSERT INTO visitor_profiles (visitor_id, first_seen_at, last_seen_at, first_source, last_source, first_referrer, last_referrer, last_referred_at, known_referred_visitor)
       VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?2, ?2, ?3, ?3, CASE WHEN ?4=1 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') END, ?4)
       ON CONFLICT(visitor_id) DO UPDATE SET last_seen_at=excluded.last_seen_at,
         last_source=CASE WHEN excluded.last_source='internal' THEN visitor_profiles.last_source ELSE excluded.last_source END,
         last_referrer=CASE WHEN excluded.last_source='internal' THEN visitor_profiles.last_referrer ELSE excluded.last_referrer END,
         last_referred_at=CASE WHEN excluded.known_referred_visitor=1 THEN excluded.last_seen_at ELSE visitor_profiles.last_referred_at END,
         known_referred_visitor=MAX(visitor_profiles.known_referred_visitor, excluded.known_referred_visitor)`
    ).bind(identity.visitorId, attribution.source, data.referrer, referred),
    env.VISITOR_DB.prepare(
      `INSERT INTO sessions (session_id, visitor_id, started_at, last_event_at, entry_path, source, source_evidence, referrer, utm_source, utm_medium, utm_campaign, status, score, classifier_version)
       VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'uncertain', ?10, ?11)
       ON CONFLICT(session_id) DO UPDATE SET last_event_at=excluded.last_event_at`
    ).bind(identity.sessionId, identity.visitorId, data.path, attribution.source, attribution.sourceEvidence, data.referrer, attribution.utmSource, attribution.utmMedium, attribution.utmCampaign, data.score, CLASSIFIER_VERSION),
    env.VISITOR_DB.prepare(
      `INSERT INTO classification_events (occurred_at, visitor_id, session_id, event_type, classifier_version, score, confidence, reasons)
       VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, 'request_observed', ?3, ?4, ?5, ?6)`
    ).bind(identity.visitorId, identity.sessionId, CLASSIFIER_VERSION, data.score, data.confidence, data.reasons.join("; ")),
  ]);
}

async function readLogs(request, env, url) {
  if (!isAuthorized(request, env)) return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
  if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET" } });
  const requested = Number.parseInt(url.searchParams.get("limit") || "100", 10);
  const limit = Number.isFinite(requested) ? Math.min(Math.max(requested, 1), MAX_RESULTS) : 100;
  const ip = url.searchParams.get("ip");
  const columns = "id, visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, confidence, category, reasons, asn, as_organization, verified_bot, visitor_id, session_id, source, source_evidence, utm_source, utm_medium, utm_campaign, classifier_version, bot_score, ja3_hash, ja4, js_detection_passed";
  const statement = ip
    ? env.VISITOR_DB.prepare(`SELECT ${columns} FROM visits WHERE ip_address = ?1 ORDER BY visited_at DESC LIMIT ?2`).bind(ip, limit)
    : env.VISITOR_DB.prepare(`SELECT ${columns} FROM visits ORDER BY visited_at DESC LIMIT ?1`).bind(limit);
  const { results } = await statement.all();
  return Response.json({ count: results.length, visits: results }, { headers: { "Cache-Control": "no-store" } });
}

async function readAudit(request, env, url) {
  if (!isAuthorized(request, env)) return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
  if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET" } });
  const sessionId = url.searchParams.get("session_id") || "";
  if (!/^[a-f0-9-]{36}$/i.test(sessionId)) return new Response("A valid session_id is required", { status: 400, headers: { "Cache-Control": "no-store" } });
  const session = await env.VISITOR_DB.prepare(`SELECT * FROM sessions WHERE session_id=?1`).bind(sessionId).first();
  if (!session) return new Response("Not Found", { status: 404, headers: { "Cache-Control": "no-store" } });
  const [visits, analytics, classifications, profile, security] = await Promise.all([
    env.VISITOR_DB.prepare(`SELECT * FROM visits WHERE session_id=?1 ORDER BY visited_at`).bind(sessionId).all(),
    env.VISITOR_DB.prepare(`SELECT * FROM analytics_events WHERE session_id=?1 ORDER BY occurred_at`).bind(sessionId).all(),
    env.VISITOR_DB.prepare(`SELECT * FROM classification_events WHERE session_id=?1 ORDER BY occurred_at`).bind(sessionId).all(),
    env.VISITOR_DB.prepare(`SELECT * FROM visitor_profiles WHERE visitor_id=?1`).bind(session.visitor_id).first(),
    env.VISITOR_DB.prepare(
      `SELECT * FROM security_events WHERE ip_address IN (SELECT DISTINCT ip_address FROM visits WHERE session_id=?1)
       AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', datetime(?2, '-30 minutes'))
       AND occurred_at <= strftime('%Y-%m-%dT%H:%M:%fZ', datetime(?3, '+30 minutes')) ORDER BY occurred_at`
    ).bind(sessionId, session.started_at, session.last_event_at).all(),
  ]);
  const relatedSecurityEvents = security.results.map((event) => ({ ...event, association: "same_ip_time_window" }));
  return Response.json({ session, profile, visits: visits.results, analytics_events: analytics.results, classification_events: classifications.results, related_security_events: relatedSecurityEvents }, { headers: { "Cache-Control": "no-store" } });
}

function scoreStoredVisit(visit) {
  const reasons = String(visit.reasons || "").split("; ");
  if (reasons.includes("Cloudflare verified bot")) return 10;
  let score = 25;
  if (reasons.includes("document navigation")) score += 10;
  if (reasons.includes("accept-language present")) score += 5;
  if (reasons.includes("client hints present")) score += 5;
  if (reasons.includes("external referrer")) score += 10;
  if (reasons.some((reason) => reason.startsWith("hosting ASN"))) score -= 20;
  if (reasons.includes("hosting network organization")) score -= 20;
  if (reasons.includes("unverified crawler claim")) score -= 20;
  if (reasons.includes("low Cloudflare bot score")) score -= 30;
  if (reasons.includes("high Cloudflare bot score")) score += 5;
  if (reasons.includes("Cloudflare JavaScript detection passed")) score += 5;
  return Math.max(0, Math.min(100, score));
}

function buildSessions(visits) {
  const SESSION_GAP_MS = 30 * 60 * 1000;
  const active = new Map();
  const sessions = [];
  const sorted = [...visits].sort((a, b) => Date.parse(a.visited_at) - Date.parse(b.visited_at));

  for (const visit of sorted) {
    const key = visit.session_id || `${visit.ip_address}|${visit.user_agent || ""}`;
    const time = Date.parse(visit.visited_at);
    let session = active.get(key);
    if (!session || !Number.isFinite(time) || time - session.lastTime > SESSION_GAP_MS) {
      session = { ...visit, firstTime: time, lastTime: time, pages: 0, paths: [], referrers: [], visits: [], requestScores: [], requestReasons: [] };
      sessions.push(session);
      active.set(key, session);
    }
    session.pages += 1;
    session.lastTime = time;
    session.visits.push(visit);
    if (!session.paths.includes(visit.path)) session.paths.push(visit.path);
    if (visit.referrer && !session.referrers.includes(visit.referrer)) session.referrers.push(visit.referrer);
    // Recompute from stored evidence so records created by older scoring
    // versions cannot retain an inflated human score in a new digest.
    session.requestScores.push(scoreStoredVisit(visit));
    if (visit.reasons) session.requestReasons.push(...String(visit.reasons).split("; "));
  }

  for (const session of sessions) {
    session.durationSeconds = Math.max(0, Math.round((session.lastTime - session.firstTime) / 1000));
    session.distinctRoutes = session.paths.length;
    let score = session.requestScores.length ? Math.max(...session.requestScores) : 25;
    const reasons = [...new Set(session.requestReasons.filter(Boolean))];

    const impossibleBurst = session.pages >= 3 && session.durationSeconds <= 2;
    const routeSweep = session.distinctRoutes >= 5 && session.durationSeconds < 10;
    if (impossibleBurst || routeSweep) {
      score = 0;
      reasons.push(impossibleBurst ? "impossible page velocity" : "rapid route sweep");
    } else {
      if (session.pages >= 2 && session.distinctRoutes >= 2 && session.durationSeconds >= 15) {
        score += 25;
        reasons.push("multiple paced page transitions");
      } else if (session.pages >= 2 && session.distinctRoutes >= 2 && session.durationSeconds >= 5) {
        score += 15;
        reasons.push("paced page transitions");
      }
      if (session.durationSeconds >= 20) {
        score += 10;
        reasons.push("meaningful elapsed time");
      }
    }
    score = Math.max(0, Math.min(100, score));
    session.score = score;
    session.confidence = score >= 65 ? "human" : score < 20 ? "bot" : "uncertain";
    session.reasons = reasons;
  }
  return sessions;
}

function externalReferrerForSite(referrers, siteName) {
  const siteHost = siteName.replace(/^www\./, "").toLowerCase();
  return (referrers || []).find((referrer) => {
    try {
      return new URL(referrer).hostname.replace(/^www\./, "").toLowerCase() !== siteHost;
    } catch {
      return false;
    }
  }) || null;
}

function historicalPathKind(pathname) {
  const path = String(pathname || "/").split(/[?#]/, 1)[0] || "/";
  if (isScannerPath(path) || HISTORICAL_DISCOVERY_RE.test(path)) return "probe";
  if (ASSET_RE.test(path) || /\.(?:md|txt|webmanifest|zip)$/i.test(path) || /^\/(?:assets|images)(?:\/|$)/i.test(path) || /^\/favicon(?:\.[a-z0-9]+)?$/i.test(path)) return "asset";
  return "page";
}

function isOwnedReferrer(referrer) {
  try {
    return OWNED_REFERRER_HOSTS.has(new URL(referrer).hostname.replace(/^www\./, "").toLowerCase());
  } catch {
    return false;
  }
}

function classifyRetroSession(session, siteName) {
  const externalReferrer = externalReferrerForSite(session.referrers, siteName);
  if (!externalReferrer) return null;
  let score = 25;
  const reasons = ["server-recorded external HTTP referrer"];
  score += 15;
  const ua = session.user_agent || "";
  if (/Mozilla\/5\.0/.test(ua) && !TOOL_UA_RE.test(ua) && !CLAIMED_BOT_UA_RE.test(ua)) {
    score += 5;
    reasons.push("browser-format user-agent");
  }
  if (isHostingNetwork(session.asn, session.as_organization || "")) {
    score -= 20;
    reasons.push("hosting network");
  }
  if (Number.isFinite(session.bot_score)) {
    if (session.bot_score <= 29) { score -= 30; reasons.push("low Cloudflare bot score"); }
    else if (session.bot_score >= 80) { score += 5; reasons.push("high Cloudflare bot score"); }
  }

  const scanner = session.paths.some(isScannerPath);
  const automatedUa = TOOL_UA_RE.test(ua) || CLAIMED_BOT_UA_RE.test(ua) || Boolean(session.verified_bot);
  const impossibleBurst = session.pages >= 3 && session.durationSeconds <= 2;
  const routeSweep = session.distinctRoutes >= 5 && session.durationSeconds < 10;
  if (scanner || automatedUa || impossibleBurst || routeSweep) {
    score = 0;
    if (scanner) reasons.push("scanner path");
    if (automatedUa) reasons.push("bot/tool user-agent or verified bot");
    if (impossibleBurst) reasons.push("impossible page velocity");
    if (routeSweep) reasons.push("rapid route sweep");
  } else {
    if (session.pages >= 2 && session.distinctRoutes >= 2 && session.durationSeconds >= 15) {
      score += 20;
      reasons.push("paced multi-page session");
    } else if (session.pages >= 2 && session.distinctRoutes >= 2 && session.durationSeconds >= 5) {
      score += 10;
      reasons.push("possible paced navigation");
    }
    if (session.durationSeconds >= 20) { score += 10; reasons.push("meaningful observed span"); }
  }
  score = Math.max(0, Math.min(100, score));
  const classification = score >= 60 ? "likely_human" : score < 20 ? "likely_automated" : "uncertain";
  return { ...session, externalReferrer, source: normalizeSource(new URL(`https://${siteName}/`), externalReferrer), score, classification, reasons, classifierVersion: "retro-v2" };
}

function buildHistoricReferralIpGroups(visits, siteName) {
  const siteUrl = new URL(`https://${siteName}/`);
  const normalized = visits.map((visit) => ({ ...visit, historicalKind: historicalPathKind(visit.path) }));
  const externalRows = normalized
    .filter((visit) => Boolean(externalReferrerForSite([visit.referrer], siteName)))
    .sort((a, b) => Date.parse(a.visited_at) - Date.parse(b.visited_at));
  const referredIps = new Set(externalRows.map((visit) => visit.ip_address || "unknown"));
  const rowsByIp = new Map();

  for (const visit of normalized) {
    const ip = visit.ip_address || "unknown";
    if (!referredIps.has(ip)) continue;
    if (!rowsByIp.has(ip)) rowsByIp.set(ip, []);
    rowsByIp.get(ip).push(visit);
  }

  const referredPageSessions = buildSessions(normalized.filter((visit) => visit.historicalKind === "page"))
    .map((session) => classifyRetroSession(session, siteName))
    .filter(Boolean);
  const pageSessionsByIp = new Map();
  for (const session of referredPageSessions) {
    const ip = session.ip_address || "unknown";
    if (!pageSessionsByIp.has(ip)) pageSessionsByIp.set(ip, []);
    pageSessionsByIp.get(ip).push(session);
  }

  const groups = [...referredIps].map((ip) => {
    const allRows = (rowsByIp.get(ip) || []).sort((a, b) => Date.parse(a.visited_at) - Date.parse(b.visited_at));
    const referrals = allRows.filter((visit) => Boolean(externalReferrerForSite([visit.referrer], siteName)));
    const rows = allRows.filter((visit) => referrals.some((referral) => {
      const elapsed = Date.parse(visit.visited_at) - Date.parse(referral.visited_at);
      return Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= 30 * 60 * 1000;
    }));
    const pageSessions = pageSessionsByIp.get(ip) || [];
    const pages = pageSessions.flatMap((session) => session.visits || []);
    const assets = rows.filter((visit) => visit.historicalKind === "asset");
    const probes = rows.filter((visit) => visit.historicalKind === "probe");
    const routes = [...new Set(pageSessions.flatMap((session) => session.paths || []))];
    const referrers = [...new Set(referrals.map((visit) => externalReferrerForSite([visit.referrer], siteName)).filter(Boolean))];
    const sources = [...new Set(referrers.map((referrer) => normalizeSource(siteUrl, referrer)))];
    const devices = [...new Set(rows.map((visit) => parseDeviceBrowser(visit.user_agent)).filter(Boolean))];
    const locations = [...new Set(rows.map((visit) => [visit.city, visit.region, visit.country].filter(Boolean).join(", ") || "Unknown"))];
    const networks = [...new Set(rows.map((visit) => [visit.asn ? `AS${visit.asn}` : null, visit.as_organization].filter(Boolean).join(" ")).filter(Boolean))];
    const firstTime = rows.length ? Date.parse(rows[0].visited_at) : NaN;
    const lastTime = rows.length ? Date.parse(rows.at(-1).visited_at) : NaN;
    const pageFirstTime = pages.length ? Date.parse(pages[0].visited_at) : NaN;
    const delayedAssetBurst = pages.length === 1 && assets.some((asset) => {
      const delay = Date.parse(asset.visited_at) - pageFirstTime;
      return delay >= 5 * 60 * 1000 && delay <= 30 * 60 * 1000;
    });
    const flags = new Set();
    const strongAutomationReasons = new Set();
    if (probes.length) {
      flags.add("scanner or discovery path");
      strongAutomationReasons.add("scanner or discovery path");
    }
    if (delayedAssetBurst) {
      flags.add("delayed asset-only retrieval after one HTML page");
      strongAutomationReasons.add("delayed asset-only retrieval after one HTML page");
    }
    if (rows.some((visit) => isHostingNetwork(visit.asn, visit.as_organization || ""))) flags.add("hosting network");
    if (rows.some((visit) => TOOL_UA_RE.test(visit.user_agent || "") || CLAIMED_BOT_UA_RE.test(visit.user_agent || "") || Boolean(visit.verified_bot))) {
      flags.add("bot/tool user-agent or verified bot");
      strongAutomationReasons.add("bot/tool user-agent or verified bot");
    }
    if (rows.some((visit) => Number.isFinite(visit.bot_score) && visit.bot_score <= 29)) {
      flags.add("low Cloudflare bot score");
      strongAutomationReasons.add("low Cloudflare bot score");
    }

    return {
      siteName, ip, rows, referrals, pages, assets, probes, pageSessions, routes, referrers, sources, devices, locations, networks,
      firstSeen: Number.isFinite(firstTime) ? rows[0].visited_at : null,
      lastSeen: Number.isFinite(lastTime) ? rows.at(-1).visited_at : null,
      pageSpanSeconds: pageSessions.reduce((total, session) => total + Math.max(0, session.durationSeconds || 0), 0),
      sourceCategory: referrers.length && referrers.every(isOwnedReferrer) ? "owned_referral" : "external_referral",
      flags, strongAutomationReasons,
    };
  });

  const groupByIp = new Map(groups.map((group) => [group.ip, group]));
  for (let left = 0; left < externalRows.length; left += 1) {
    const a = externalRows[left];
    const aTime = Date.parse(a.visited_at);
    const aSource = normalizeSource(siteUrl, a.referrer);
    for (let right = left + 1; right < externalRows.length; right += 1) {
      const b = externalRows[right];
      if (a.ip_address === b.ip_address) continue;
      const seconds = (Date.parse(b.visited_at) - aTime) / 1000;
      if (!Number.isFinite(seconds)) continue;
      if (seconds > 90) break;
      if (aSource !== normalizeSource(siteUrl, b.referrer)) continue;
      const aGroup = groupByIp.get(a.ip_address || "unknown");
      const bGroup = groupByIp.get(b.ip_address || "unknown");
      if (!aGroup || !bGroup) continue;
      const technicalCluster = a.historicalKind === "probe" && b.historicalKind === "probe";
      const duplicateSinglePage = seconds <= 2 && a.path === b.path && a.referrer === b.referrer && a.user_agent === b.user_agent && aGroup.pages.length <= 1 && bGroup.pages.length <= 1;
      if (technicalCluster) {
        aGroup.flags.add("cross-IP technical reconnaissance cluster");
        bGroup.flags.add("cross-IP technical reconnaissance cluster");
        aGroup.strongAutomationReasons.add("cross-IP technical reconnaissance cluster");
        bGroup.strongAutomationReasons.add("cross-IP technical reconnaissance cluster");
      } else if (duplicateSinglePage) {
        aGroup.flags.add("near-simultaneous duplicate referral across IPs");
        bGroup.flags.add("near-simultaneous duplicate referral across IPs");
        aGroup.strongAutomationReasons.add("near-simultaneous duplicate referral across IPs");
        bGroup.strongAutomationReasons.add("near-simultaneous duplicate referral across IPs");
      }
    }
  }

  for (const group of groups) {
    const automatedSession = group.pageSessions.some((session) => session.classification === "likely_automated");
    const humanSession = group.pageSessions.some((session) => session.classification === "likely_human");
    const strongAutomation = group.strongAutomationReasons.size > 0 || automatedSession;
    if (strongAutomation && humanSession) group.classification = "mixed";
    else if (strongAutomation) group.classification = "likely_automated";
    else if (humanSession) group.classification = "likely_human";
    else group.classification = "uncertain";

    const strongHuman = group.pageSessions.some((session) => session.pages >= 2 && session.distinctRoutes >= 2 && session.durationSeconds >= 15);
    group.evidenceQuality = strongAutomation || strongHuman ? "strong" : group.pages.length >= 2 || group.pageSessions.length >= 2 ? "moderate" : "weak";
    group.identityQuality = "low";
    const sessionReasons = group.pageSessions.flatMap((session) => session.reasons || []);
    group.reasons = [...new Set([...group.flags, ...sessionReasons])];
  }

  const order = { likely_human: 0, uncertain: 1, mixed: 2, likely_automated: 3 };
  return groups.sort((a, b) => order[a.classification] - order[b.classification] || Date.parse(a.firstSeen) - Date.parse(b.firstSeen));
}

function formatHistoricReferralIpReport(siteName, visits, groups) {
  const counts = {
    likely_human: groups.filter((group) => group.classification === "likely_human").length,
    uncertain: groups.filter((group) => group.classification === "uncertain").length,
    mixed: groups.filter((group) => group.classification === "mixed").length,
    likely_automated: groups.filter((group) => group.classification === "likely_automated").length,
  };
  const lines = groups.map((group, index) => {
    const network = group.networks.join("; ") || "Unknown network";
    const pageEvidence = `${group.pages.length} HTML page request(s), ${group.routes.length} HTML route(s), ${group.pageSessions.length} reconstructed page session(s), ${group.pageSpanSeconds}s page span`;
    return `${index + 1}. ${group.classification.toUpperCase()} | IP ${group.ip}\n   Source: ${group.sources.join(", ") || "Unknown"} | ${group.sourceCategory.replace("_", " ")}\n   Seen: ${group.firstSeen} to ${group.lastSeen}\n   Page evidence: ${pageEvidence}\n   Excluded from page metrics: ${group.assets.length} asset request(s), ${group.probes.length} probe/discovery request(s)\n   Location/device: ${group.locations.join("; ")} | ${group.devices.join("; ")}\n   Network: ${network}\n   Evidence quality: ${group.evidenceQuality.toUpperCase()} | Identity quality: LOW (IP is not a person)\n   Why: ${group.reasons.join("; ") || "server-recorded external referral without enough historical behavior"}`;
  });
  return {
    counts,
    body: [
      `CORRECTED historical referred visitors by unique IP for ${siteName}`,
      "Classifier: retro-v2 (HTML-page-only behavioral metrics)",
      `Generated: ${new Date().toISOString()}`,
      `Visits examined: ${visits.length}`,
      `Unique referred IP groups: ${groups.length}`,
      `Likely human: ${counts.likely_human} | Uncertain: ${counts.uncertain} | Mixed: ${counts.mixed} | Likely automated: ${counts.likely_automated}`,
      "",
      "This report supersedes the earlier retro-v1 referral report. HTML pages, assets, and technical probes are classified before session reconstruction. Assets never increase page count, route count, or page span. Scanner/discovery paths remain automation evidence but are not counted as pages.",
      "",
      "Limitations: pre-instrumentation traffic lacks reliable visitor/session IDs and visible engagement. Sessions use historically available server evidence and a 30-minute inactivity boundary. Exact IP is only a grouping key; shared, mobile, proxy, and changing addresses prevent person-level identification. Current network enrichment may not describe historical ownership.",
      "",
      ...lines,
    ].join("\n"),
  };
}

async function sendHistoricReferralReport(request, env, siteName, url) {
  if (!isAuthorized(request, env)) return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { Allow: "POST" } });
  const { results: visits } = await env.VISITOR_DB.prepare(
    `SELECT visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, asn, as_organization, verified_bot, bot_score, session_id
     FROM visits ORDER BY visited_at ASC LIMIT 20000`
  ).all();
  const groups = buildHistoricReferralIpGroups(visits, siteName);
  const { counts, body } = formatHistoricReferralIpReport(siteName, visits, groups);
  const shouldEmail = url.searchParams.get("email") !== "0";
  const sent = shouldEmail ? await sendEmail(env, siteName, `CORRECTED historical referred IPs - ${siteName} (${groups.length} IPs)`, body) : true;
  if (!sent) return new Response("Email service unavailable", { status: 503, headers: { "Cache-Control": "no-store" } });
  return Response.json({ site: siteName, classifier_version: "retro-v2", visits_examined: visits.length, referred_ip_groups: groups.length, counts, emailed: shouldEmail, report: shouldEmail ? undefined : body }, { headers: { "Cache-Control": "no-store" } });
}

function classifySessionEvidence(session, events, knownReferredVisitor = false) {
  let score = Number(session.score || 25);
  const reasons = [...(session.reasons || [])];
  const eventTypes = new Set(events.map((event) => event.event_type));
  const hiddenSeconds = Math.max(0, ...events.filter((event) => event.event_type === "page_hidden").map((event) => Number(event.visible_seconds || 0)));
  if (session.confidence === "bot") return { score: 0, confidence: "bot", reasons };
  if (eventTypes.has("visible_20s") || hiddenSeconds >= 20) { score += 35; reasons.push("20 seconds visible engagement"); }
  else if (eventTypes.has("visible_10s") || hiddenSeconds >= 10) { score += 20; reasons.push("10 seconds visible engagement"); }
  if (eventTypes.has("internal_click")) { score += 10; reasons.push("internal click"); }
  const serverObservedReferral = session.source_evidence === "http_referrer";
  if (knownReferredVisitor && !serverObservedReferral) { score += 10; reasons.push("previously server-referred visitor"); }
  if (!knownReferredVisitor && !serverObservedReferral) { score -= 5; reasons.push("no server-observed referral"); }
  score = Math.max(0, Math.min(100, score));
  return { score, confidence: score >= 65 ? "human" : score < 20 ? "bot" : "uncertain", reasons: [...new Set(reasons)] };
}

async function evaluateLiveSession(identity, env, siteName) {
  const [visitRows, eventRows, profile, storedSession] = await Promise.all([
    env.VISITOR_DB.prepare(`SELECT visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, reasons, source, asn, as_organization FROM visits WHERE session_id=?1 ORDER BY visited_at`).bind(identity.sessionId).all(),
    env.VISITOR_DB.prepare(`SELECT event_type, visible_seconds, path, occurred_at FROM analytics_events WHERE session_id=?1 ORDER BY occurred_at`).bind(identity.sessionId).all(),
    env.VISITOR_DB.prepare(`SELECT known_referred_visitor FROM visitor_profiles WHERE visitor_id=?1`).bind(identity.visitorId).first(),
    env.VISITOR_DB.prepare(`SELECT status, alerted_at, source, source_evidence, entry_path, referrer, utm_source, utm_medium, utm_campaign FROM sessions WHERE session_id=?1`).bind(identity.sessionId).first(),
  ]);
  if (!visitRows.results.length || !storedSession) return null;
  const session = buildSessions(visitRows.results)[0];
  session.source = storedSession.source || session.source || "direct";
  session.source_evidence = storedSession.source_evidence || session.source_evidence || "direct";
  const result = classifySessionEvidence(session, eventRows.results, Boolean(profile?.known_referred_visitor));
  const changed = storedSession.status !== result.confidence;
  await env.VISITOR_DB.batch([
    env.VISITOR_DB.prepare(`UPDATE sessions SET last_event_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), status=?1, score=?2, reasons=?3, classifier_version=?4 WHERE session_id=?5`).bind(result.confidence, result.score, result.reasons.join("; "), CLASSIFIER_VERSION, identity.sessionId),
    ...(changed ? [env.VISITOR_DB.prepare(
      `INSERT INTO classification_events (occurred_at, visitor_id, session_id, event_type, classifier_version, score, confidence, reasons)
       VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, 'classification_changed', ?3, ?4, ?5, ?6)`
    ).bind(identity.visitorId, identity.sessionId, CLASSIFIER_VERSION, result.score, result.confidence, result.reasons.join("; "))] : []),
  ]);

  if (result.confidence === "human" && !storedSession.alerted_at) {
    const claimed = await env.VISITOR_DB.prepare(`UPDATE sessions SET alerted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE session_id=?1 AND alerted_at IS NULL`).bind(identity.sessionId).run();
    if (Number(claimed.meta?.changes || 0) === 1) {
      const target = TARGET_CITIES.has((session.city || "").toLowerCase().trim()) || TARGET_ZIPS.has((session.postal_code || "").trim());
      let sent = false;
      try {
        sent = await sendEmail(env, siteName, `${target ? "Target-area " : ""}probable human on ${siteName}`, [
          `Probable human visitor on ${siteName}`, `Location: ${session.city || "Unknown"}, ${session.region || ""} ${session.postal_code || ""}`,
          `Source: ${storedSession.source || "direct"} (${storedSession.source_evidence || "unknown evidence"})`, `Referrer: ${storedSession.referrer || "none"}`,
          `Campaign: ${storedSession.utm_campaign || "none"}`, `Entry: ${storedSession.entry_path}`,
          `Device: ${parseDeviceBrowser(session.user_agent)}`, `Pages: ${session.pages}; routes: ${session.distinctRoutes}; observed span: ${session.durationSeconds}s`,
          `Confidence: ${result.score}%`, `Why: ${result.reasons.join("; ")}`,
        ].join("\n"));
      } catch (error) {
        console.error("Real-time alert failed", error);
      }
      if (!sent) {
        await env.VISITOR_DB.prepare(`UPDATE sessions SET alerted_at=NULL WHERE session_id=?1`).bind(identity.sessionId).run();
        return result;
      }
      await env.VISITOR_DB.prepare(
        `INSERT INTO classification_events (occurred_at, visitor_id, session_id, event_type, classifier_version, score, confidence, reasons)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, 'alert_sent', ?3, ?4, 'human', ?5)`
      ).bind(identity.visitorId, identity.sessionId, CLASSIFIER_VERSION, result.score, result.reasons.join("; ")).run();
    }
  }
  return result;
}

function validateEngagement(eventType, claimedSeconds, startedAt, now = Date.now()) {
  const started = Date.parse(startedAt || "");
  const elapsedSeconds = Number.isFinite(started) ? Math.max(0, Math.floor((now - started) / 1000)) : 0;
  const claimed = Math.min(Math.max(Number(claimedSeconds || 0), 0), 3600);
  if (eventType === "visible_10s" && elapsedSeconds < 9) return { eventType: "rejected_visible_10s", visibleSeconds: 0 };
  if (eventType === "visible_20s" && elapsedSeconds < 18) return { eventType: "rejected_visible_20s", visibleSeconds: 0 };
  if (eventType.startsWith("visible_") || eventType === "page_hidden") return { eventType, visibleSeconds: Math.min(claimed, elapsedSeconds) };
  return { eventType, visibleSeconds: claimed };
}

async function handleAnalytics(request, env, siteName, identity) {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { Allow: "POST" } });
  const origin = request.headers.get("Origin");
  if (!origin || new URL(origin).hostname.replace(/^www\./, "") !== siteName.replace(/^www\./, "")) return new Response("Forbidden", { status: 403 });
  if (Number(request.headers.get("Content-Length") || 0) > 4096) return new Response("Payload Too Large", { status: 413 });
  let payload;
  try { payload = await request.json(); } catch { return new Response("Bad Request", { status: 400 }); }
  if (!ALLOWED_EVENTS.has(payload.event)) return new Response("Bad Request", { status: 400 });
  const path = clampText(String(payload.path || "/").split("?")[0], 500);
  const storedSession = await env.VISITOR_DB.prepare(`SELECT started_at FROM sessions WHERE session_id=?1`).bind(identity.sessionId).first();
  const validated = validateEngagement(payload.event, payload.visible_seconds, storedSession?.started_at);
  const browserReferrer = sanitizeReferrer(payload.referrer);
  const browserSource = normalizeSource(new URL(request.url), browserReferrer);
  await env.VISITOR_DB.batch([
    env.VISITOR_DB.prepare(
    `INSERT INTO analytics_events (occurred_at, visitor_id, session_id, event_type, path, visible_seconds, referrer, classifier_version)
     VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4, ?5, ?6, ?7)`
    ).bind(identity.visitorId, identity.sessionId, validated.eventType, path, validated.visibleSeconds, browserReferrer, CLASSIFIER_VERSION),
    ...(isReferredSource(browserSource) ? [
      env.VISITOR_DB.prepare(`UPDATE sessions SET source=CASE WHEN source='direct' THEN ?1 ELSE source END, source_evidence=CASE WHEN source='direct' THEN 'browser_referrer_claim' ELSE source_evidence END, referrer=COALESCE(referrer, ?2) WHERE session_id=?3`).bind(browserSource, browserReferrer, identity.sessionId),
    ] : []),
  ]);
  await evaluateLiveSession(identity, env, siteName);
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}

async function sendDailyDigest(env, siteName) {
  const [{ results: visits }, security, { results: storedSessions }] = await Promise.all([
    env.VISITOR_DB.prepare(`SELECT visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, confidence, category, reasons, asn, as_organization, visitor_id, session_id, source, utm_source, utm_medium, utm_campaign FROM visits WHERE visited_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-24 hours') ORDER BY visited_at ASC`).all(),
    env.VISITOR_DB.prepare(`SELECT COUNT(*) AS count FROM security_events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-24 hours')`).first(),
    env.VISITOR_DB.prepare(`SELECT session_id, status, score, reasons, source, source_evidence, referrer, utm_source, utm_medium, utm_campaign FROM sessions WHERE started_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-24 hours')`).all(),
  ]);
  const sessions = buildSessions(visits);
  const evaluated = new Map(storedSessions.map((session) => [session.session_id, session]));
  for (const session of sessions) {
    const stored = evaluated.get(session.session_id);
    if (!stored) continue;
    session.confidence = stored.status;
    session.score = stored.score;
    session.reasons = String(stored.reasons || "").split("; ").filter(Boolean);
    session.source = stored.source;
    session.source_evidence = stored.source_evidence;
    session.referrer = stored.referrer || session.referrer;
    session.utm_source = stored.utm_source;
    session.utm_medium = stored.utm_medium;
    session.utm_campaign = stored.utm_campaign;
  }
  const humans = sessions.filter((s) => s.confidence === "human");
  const uncertain = sessions.filter((s) => s.confidence === "uncertain");
  const bots = sessions.filter((s) => s.confidence === "bot");
  const targetHumans = humans.filter((s) => TARGET_CITIES.has((s.city || "").toLowerCase().trim()) || TARGET_ZIPS.has((s.postal_code || "").trim()));
  const formatSession = (s) => `${s.visited_at} | ${s.city || "Unknown"}, ${s.region || ""} | ${s.pages} page(s), ${s.distinctRoutes} route(s), ${s.durationSeconds}s | Entry: ${s.paths[0]} | Source: ${s.source || "direct"} (${s.source_evidence || "unknown evidence"}) | Referrer: ${s.referrer || "none"} | UTM: ${[s.utm_source, s.utm_medium, s.utm_campaign].filter(Boolean).join("/") || "none"} | ${parseDeviceBrowser(s.user_agent)} | ${s.score}% | ${s.reasons.join("; ")}`;
  const lines = humans.length ? humans.map(formatSession).join("\n") : "No probable human sessions recorded.";
  const targetLines = targetHumans.length ? targetHumans.map(formatSession).join("\n") : "No probable target-area human sessions recorded.";
  await sendEmail(env, siteName, `Visitor digest: ${humans.length} human, ${uncertain.length} uncertain`, [
    `Daily visitor report for ${siteName}`, `Probable humans: ${humans.length}`,
    `Uncertain: ${uncertain.length}`, `Automated sessions: ${bots.length}`,
    `Blocked scanner/tool requests: ${Number(security?.count || 0)}`, `Logged page views: ${visits.length}`,
    "", "TARGET-AREA PROBABLE HUMAN SESSIONS", targetLines,
    "", "ALL PROBABLE HUMAN SESSIONS", lines,
  ].join("\n"));
}

async function retryPendingAlerts(env, siteName) {
  const { results } = await env.VISITOR_DB.prepare(
    `SELECT s.*, v.city, v.region, v.postal_code, v.user_agent
     FROM sessions s LEFT JOIN visits v ON v.id=(SELECT MIN(v2.id) FROM visits v2 WHERE v2.session_id=s.session_id)
     WHERE s.status='human' AND s.alerted_at IS NULL
       AND s.started_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-24 hours')
     ORDER BY s.started_at LIMIT 50`
  ).all();
  for (const session of results) {
    const claimed = await env.VISITOR_DB.prepare(`UPDATE sessions SET alerted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE session_id=?1 AND alerted_at IS NULL`).bind(session.session_id).run();
    if (Number(claimed.meta?.changes || 0) !== 1) continue;
    let sent = false;
    try {
      sent = await sendEmail(env, siteName, `Probable human on ${siteName}`, [
        `Probable human visitor on ${siteName}`, `Location: ${session.city || "Unknown"}, ${session.region || ""} ${session.postal_code || ""}`,
        `Source: ${session.source || "direct"} (${session.source_evidence || "unknown evidence"})`, `Referrer: ${session.referrer || "none"}`,
        `Campaign: ${session.utm_campaign || "none"}`, `Entry: ${session.entry_path}`,
        `Device: ${parseDeviceBrowser(session.user_agent)}`, `Confidence: ${session.score}%`, `Why: ${session.reasons || "session evidence"}`,
      ].join("\n"));
    } catch (error) {
      console.error("Scheduled alert retry failed", error);
    }
    if (!sent) {
      await env.VISITOR_DB.prepare(`UPDATE sessions SET alerted_at=NULL WHERE session_id=?1`).bind(session.session_id).run();
      continue;
    }
    await env.VISITOR_DB.prepare(
      `INSERT INTO classification_events (occurred_at, visitor_id, session_id, event_type, classifier_version, score, confidence, reasons)
       VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, 'alert_sent', ?3, ?4, 'human', ?5)`
    ).bind(session.visitor_id, session.session_id, CLASSIFIER_VERSION, session.score, `${session.reasons || ""}; scheduled retry`).run();
  }
}

function secureOriginResponse(response, identity, siteName) {
  const secured = new Response(response.body, response);
  secured.headers.set("X-Content-Type-Options", "nosniff");
  secured.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  secured.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (identity) {
    const domain = siteName ? `; Domain=${siteName}` : "";
    secured.headers.append("Set-Cookie", `mf_vid=${identity.visitorId}; Max-Age=2592000; Path=/${domain}; Secure; HttpOnly; SameSite=Lax`);
    secured.headers.append("Set-Cookie", `mf_sid=${identity.sessionId}; Max-Age=1800; Path=/${domain}; Secure; HttpOnly; SameSite=Lax`);
  }
  return secured;
}

export { attributionData, buildHistoricReferralIpGroups, buildSessions, classifyRequest, classifyRetroSession, classifySessionEvidence, externalReferrerForSite, historicalPathKind, hostMatches, isReferredSource, normalizeSource, parseDeviceBrowser, sanitizeReferrer, scoreStoredVisit, validateEngagement };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const siteName = env.SITE_NAME || url.hostname.replace(/^www\./, "");
    if (url.pathname === LOG_PATH) return readLogs(request, env, url);
    if (url.pathname === AUDIT_PATH) return readAudit(request, env, url);
    if (url.pathname === RETRO_REPORT_PATH) return sendHistoricReferralReport(request, env, siteName, url);
    const identity = visitorIdentity(request);
    if (url.pathname === ANALYTICS_PATH) return handleAnalytics(request, env, siteName, identity);

    if (url.searchParams.get("test_alert") === "1" || url.searchParams.get("test_digest") === "1") {
      if (!isAuthorized(request, env)) return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
      try {
        if (url.searchParams.get("test_digest") === "1") await sendDailyDigest(env, siteName);
        else await sendEmail(env, siteName, `Test visitor alert for ${siteName}`, "Authenticated test alert.");
        return new Response("Test email dispatched.", { headers: { "Cache-Control": "no-store" } });
      } catch (error) {
        console.error("Test email failed", error);
        return new Response("Email dispatch failed.", { status: 502, headers: { "Cache-Control": "no-store" } });
      }
    }

    const result = classifyRequest(request, url);
    const data = requestData(request, url, result);
    const attribution = attributionData(request, url);
    if (result.blocked) {
      ctx.waitUntil(logSecurityEvent(data, env).catch((error) => console.error("Security event logging failed", error)));
      return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" } });
    }
    if (isPageVisit(request, url)) {
      ctx.waitUntil(logVisit(data, identity, attribution, env).catch((error) => console.error("Visit logging failed", error)));
    }
    return secureOriginResponse(await fetch(request), isPageVisit(request, url) ? identity : null, siteName);
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil((async () => {
      const siteName = env.SITE_NAME || "matferg.com";
      await retryPendingAlerts(env, siteName);
      await sendDailyDigest(env, siteName);
      const parsed = Number.parseInt(env.RETENTION_DAYS || "30", 10);
      const days = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 1), 365) : 30;
      const age = `-${days} days`;
      await Promise.all([
        env.VISITOR_DB.prepare(`DELETE FROM visits WHERE visited_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
        env.VISITOR_DB.prepare(`DELETE FROM security_events WHERE occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
        env.VISITOR_DB.prepare(`DELETE FROM analytics_events WHERE occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
        env.VISITOR_DB.prepare(`DELETE FROM classification_events WHERE occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
        env.VISITOR_DB.prepare(`DELETE FROM sessions WHERE started_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
        env.VISITOR_DB.prepare(`DELETE FROM visitor_profiles WHERE last_seen_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
      ]);
    })());
  },
};
