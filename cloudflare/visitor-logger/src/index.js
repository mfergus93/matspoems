const LOG_PATH = "/_visitor-logs";
const MAX_RESULTS = 500;
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

function clampText(value, length) {
  return value ? String(value).slice(0, length) : null;
}

function isScannerPath(pathname) {
  return SCANNER_PATTERNS.some((pattern) => pattern.test(pathname));
}

function isPageVisit(request, url) {
  if (request.method !== "GET" || url.pathname === LOG_PATH || ASSET_RE.test(url.pathname)) return false;
  const destination = request.headers.get("Sec-Fetch-Dest") || "";
  const accept = request.headers.get("Accept") || "";
  const pagePath = url.pathname === "/" || url.pathname.endsWith("/") || url.pathname.endsWith(".html");
  return destination === "document" || (pagePath && accept.includes("text/html"));
}

function safeReferrer(request) {
  const raw = request.headers.get("Referer");
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
  if (isExternalReferrer(request, url)) { score += 10; reasons.push("external referrer"); }
  if (CLAIMED_BOT_UA_RE.test(ua)) { score -= 20; reasons.push("unverified crawler claim"); }
  score = Math.max(0, Math.min(100, score));
  const confidence = score < 20 ? "bot" : "uncertain";
  return { score, confidence, category: confidence, reasons, blocked: false, asn, asOrganization, verifiedBot };
}

function requestData(request, url, result) {
  return {
    ip: request.headers.get("CF-Connecting-IP") || "unknown",
    country: request.cf?.country || null,
    city: request.cf?.city || null,
    region: request.cf?.region || request.cf?.regionCode || null,
    postalCode: request.cf?.postalCode || null,
    path: clampText(url.pathname, 500),
    referrer: safeReferrer(request),
    userAgent: clampText(request.headers.get("User-Agent") || "", 1000),
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

async function logVisit(data, env) {
  await env.VISITOR_DB.prepare(
    `INSERT INTO visits
      (visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, confidence, category, reasons, asn, as_organization, verified_bot)
     VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)`
  ).bind(data.ip, data.country, data.city, data.region, data.postalCode, data.path, data.referrer, data.userAgent, data.score, data.confidence, data.category, data.reasons.join("; "), data.asn, clampText(data.asOrganization, 250), data.verifiedBot ? 1 : 0).run();

}

async function readLogs(request, env, url) {
  if (!isAuthorized(request, env)) return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
  if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET" } });
  const requested = Number.parseInt(url.searchParams.get("limit") || "100", 10);
  const limit = Number.isFinite(requested) ? Math.min(Math.max(requested, 1), MAX_RESULTS) : 100;
  const ip = url.searchParams.get("ip");
  const columns = "id, visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, confidence, category, reasons, asn, as_organization, verified_bot";
  const statement = ip
    ? env.VISITOR_DB.prepare(`SELECT ${columns} FROM visits WHERE ip_address = ?1 ORDER BY visited_at DESC LIMIT ?2`).bind(ip, limit)
    : env.VISITOR_DB.prepare(`SELECT ${columns} FROM visits ORDER BY visited_at DESC LIMIT ?1`).bind(limit);
  const { results } = await statement.all();
  return Response.json({ count: results.length, visits: results }, { headers: { "Cache-Control": "no-store" } });
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
  if (reasons.includes("unverified crawler claim")) score -= 20;
  return Math.max(0, Math.min(100, score));
}

function buildSessions(visits) {
  const SESSION_GAP_MS = 30 * 60 * 1000;
  const active = new Map();
  const sessions = [];
  const sorted = [...visits].sort((a, b) => Date.parse(a.visited_at) - Date.parse(b.visited_at));

  for (const visit of sorted) {
    const key = `${visit.ip_address}|${visit.user_agent || ""}`;
    const time = Date.parse(visit.visited_at);
    let session = active.get(key);
    if (!session || !Number.isFinite(time) || time - session.lastTime > SESSION_GAP_MS) {
      session = { ...visit, firstTime: time, lastTime: time, pages: 0, paths: [], requestScores: [], requestReasons: [] };
      sessions.push(session);
      active.set(key, session);
    }
    session.pages += 1;
    session.lastTime = time;
    if (!session.paths.includes(visit.path)) session.paths.push(visit.path);
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

async function sendDailyDigest(env, siteName) {
  const [{ results: visits }, security] = await Promise.all([
    env.VISITOR_DB.prepare(`SELECT visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent, score, confidence, category, reasons, asn, as_organization FROM visits WHERE visited_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-24 hours') ORDER BY visited_at ASC`).all(),
    env.VISITOR_DB.prepare(`SELECT COUNT(*) AS count FROM security_events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-24 hours')`).first(),
  ]);
  const sessions = buildSessions(visits);
  const humans = sessions.filter((s) => s.confidence === "human");
  const uncertain = sessions.filter((s) => s.confidence === "uncertain");
  const bots = sessions.filter((s) => s.confidence === "bot");
  const targetHumans = humans.filter((s) => TARGET_CITIES.has((s.city || "").toLowerCase().trim()) || TARGET_ZIPS.has((s.postal_code || "").trim()));
  const formatSession = (s) => `${s.visited_at} | ${s.city || "Unknown"}, ${s.region || ""} | ${s.pages} page(s), ${s.distinctRoutes} route(s), ${s.durationSeconds}s | ${s.paths.join(", ")} | ${parseDeviceBrowser(s.user_agent)} | ${s.score}% | ${s.reasons.join("; ")}`;
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

function secureOriginResponse(response) {
  const secured = new Response(response.body, response);
  secured.headers.set("X-Content-Type-Options", "nosniff");
  secured.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  secured.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return secured;
}

export { buildSessions, classifyRequest, parseDeviceBrowser, scoreStoredVisit };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const siteName = env.SITE_NAME || url.hostname.replace(/^www\./, "");
    if (url.pathname === LOG_PATH) return readLogs(request, env, url);

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
    if (result.blocked) {
      ctx.waitUntil(logSecurityEvent(data, env).catch((error) => console.error("Security event logging failed", error)));
      return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" } });
    }
    if (isPageVisit(request, url)) {
      ctx.waitUntil(logVisit(data, env).catch((error) => console.error("Visit logging failed", error)));
    }
    return secureOriginResponse(await fetch(request));
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil((async () => {
      const siteName = env.SITE_NAME || "matferg.com";
      await sendDailyDigest(env, siteName);
      const parsed = Number.parseInt(env.RETENTION_DAYS || "30", 10);
      const days = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 1), 365) : 30;
      const age = `-${days} days`;
      await Promise.all([
        env.VISITOR_DB.prepare(`DELETE FROM visits WHERE visited_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
        env.VISITOR_DB.prepare(`DELETE FROM security_events WHERE occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1)`).bind(age).run(),
      ]);
    })());
  },
};
