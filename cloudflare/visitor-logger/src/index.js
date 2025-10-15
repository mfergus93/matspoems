const LOG_PATH = "/_visitor-logs";
const MAX_RESULTS = 500;

function isHtmlVisit(request, url) {
  if (request.method !== "GET" || url.pathname === LOG_PATH) return false;

  const destination = request.headers.get("Sec-Fetch-Dest");
  const accept = request.headers.get("Accept") || "";
  const looksLikePage =
    url.pathname === "/" ||
    url.pathname.endsWith("/") ||
    url.pathname.endsWith(".html");

  return destination === "document" || (looksLikePage && accept.includes("text/html"));
}

function bearerToken(request) {
  const authorization = request.headers.get("Authorization") || "";
  return authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
}

const TARGET_CITIES = [
  "henryetta", "dewar", "schulter", "okmulgee", "morris",
  "hitchita", "okemah", "weleetka", "dustin", "eufaula", "beggs"
];

const TARGET_ZIPS = [
  "74437", "74431", "74460", "74447", "74445",
  "74438", "74859", "74880", "74839", "74432", "74421"
];

async function sendEmailAlert(visitData, env) {
  const recipient = "mcferguson9@gmail.com";
  const subject = `🚨 Target Visitor Alert: ${visitData.city}, ${visitData.region} (${visitData.postalCode})`;
  const bodyText = `A visitor from your target area just visited matspoems.com!

Location: ${visitData.city}, ${visitData.region} ${visitData.postalCode} (${visitData.country || "US"})
IP Address: ${visitData.ip}
Path: ${visitData.path}
Time: ${new Date().toISOString()}
User Agent: ${visitData.userAgent || "Unknown"}
Referrer: ${visitData.referrer || "Direct"}
`;

  if (env.RESEND_API_KEY) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: "Matt's Poems <onboarding@resend.dev>",
          to: [recipient],
          subject: subject,
          text: bodyText,
        }),
      });
      return;
    } catch (err) {
      console.error("Resend email error:", err);
    }
  }

  try {
    await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: recipient, name: "Matt" }] }],
        from: { email: "alerts@matspoems.com", name: "Matt's Poems Visitor Alert" },
        subject: subject,
        content: [{ type: "text/plain", value: bodyText }],
      }),
    });
  } catch (err) {
    console.error("Mailchannels email error:", err);
  }
}

async function logVisit(request, env, url) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const country = request.cf?.country || null;
  const city = request.cf?.city || null;
  const region = request.cf?.region || request.cf?.regionCode || null;
  const postalCode = request.cf?.postalCode || null;

  await env.VISITOR_DB.prepare(
    `INSERT INTO visits
      (visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent)
     VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
  )
    .bind(
      ip,
      country,
      city,
      region,
      postalCode,
      `${url.pathname}${url.search}`,
      request.headers.get("Referer"),
      request.headers.get("User-Agent"),
    )
    .run();

  const visitorCity = (city || "").toLowerCase().trim();
  const visitorZip = (postalCode || "").trim();
  const isTargetVisitor = TARGET_CITIES.includes(visitorCity) || TARGET_ZIPS.includes(visitorZip);

  if (isTargetVisitor) {
    await sendEmailAlert(
      {
        ip,
        country,
        city: city || "Unknown City",
        region: region || "OK",
        postalCode: postalCode || "Unknown ZIP",
        path: `${url.pathname}${url.search}`,
        referrer: request.headers.get("Referer"),
        userAgent: request.headers.get("User-Agent"),
      },
      env,
    );
  }
}

async function readLogs(request, env, url) {
  if (!env.LOG_API_TOKEN || bearerToken(request) !== env.LOG_API_TOKEN) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const requestedLimit = Number.parseInt(url.searchParams.get("limit") || "100", 10);
  const limit = Number.isFinite(requestedLimit)
    ? Math.min(Math.max(requestedLimit, 1), MAX_RESULTS)
    : 100;
  const ip = url.searchParams.get("ip");

  const statement = ip
    ? env.VISITOR_DB.prepare(
        `SELECT id, visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent
         FROM visits WHERE ip_address = ?1
         ORDER BY visited_at DESC LIMIT ?2`,
      ).bind(ip, limit)
    : env.VISITOR_DB.prepare(
        `SELECT id, visited_at, ip_address, country, city, region, postal_code, path, referrer, user_agent
         FROM visits ORDER BY visited_at DESC LIMIT ?1`,
      ).bind(limit);

  const { results } = await statement.all();

  return new Response(JSON.stringify({ count: results.length, visits: results }, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

async function sendDailyDigest(env, siteName = "matspoems.com") {
  const recipient = "mcferguson9@gmail.com";

  const summaryStmt = env.VISITOR_DB.prepare(
    `SELECT 
        COALESCE(postal_code, 'Unknown ZIP') as zip,
        COALESCE(city, 'Unknown City') as city,
        COALESCE(region, '') as region,
        COALESCE(country, 'US') as country,
        COUNT(*) as visit_count
     FROM visits
     WHERE visited_at >= datetime('now', '-24 hours')
     GROUP BY zip, city, region, country
     ORDER BY visit_count DESC`,
  );

  const totalStmt = env.VISITOR_DB.prepare(
    `SELECT COUNT(*) as total FROM visits WHERE visited_at >= datetime('now', '-24 hours')`,
  );

  const { results: summaryResults } = await summaryStmt.all();
  const { results: totalResults } = await totalStmt.all();
  const totalVisits = totalResults[0]?.total || 0;

  let locationListText = "";
  if (summaryResults.length === 0) {
    locationListText = "No visitors logged in the last 24 hours.";
  } else {
    locationListText = summaryResults
      .map(
        (r) =>
          `• ZIP ${r.zip} (${r.city}${r.region ? ", " + r.region : ""}): ${r.visit_count} visit${r.visit_count > 1 ? "s" : ""}`,
      )
      .join("\n");
  }

  const subject = `📊 Daily Visitor Summary (${siteName}): ${totalVisits} Visit${totalVisits !== 1 ? "s" : ""} in Last 24 Hours`;
  const bodyText = `Daily Visitor Report for ${siteName}
Time Period: Last 24 Hours

Total Visits: ${totalVisits}

ZIP Code & Location Breakdown:
-----------------------------------------
${locationListText}

-----------------------------------------
Report generated automatically by Cloudflare Worker.`;

  if (env.RESEND_API_KEY) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: `${siteName} Reports <onboarding@resend.dev>`,
          to: [recipient],
          subject: subject,
          text: bodyText,
        }),
      });
      return;
    } catch (err) {
      console.error("Resend daily digest error:", err);
    }
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === LOG_PATH) {
      return readLogs(request, env, url);
    }

    if (url.searchParams.get("test_alert") === "1") {
      await sendEmailAlert(
        {
          ip: request.headers.get("CF-Connecting-IP") || "127.0.0.1",
          country: request.cf?.country || "US",
          city: "Henryetta (TEST)",
          region: "OK",
          postalCode: "74437",
          path: "/test-email-alert",
          referrer: "Test Dispatch",
          userAgent: request.headers.get("User-Agent") || "Antigravity Agent",
        },
        env,
      );
      return new Response("Test alert email dispatched for matspoems.com to mcferguson9@gmail.com!");
    }

    if (url.searchParams.get("test_digest") === "1") {
      await sendDailyDigest(env, "matspoems.com");
      return new Response("Daily ZIP code digest dispatched for matspoems.com to mcferguson9@gmail.com!");
    }

    if (isHtmlVisit(request, url)) {
      ctx.waitUntil(
        logVisit(request, env, url).catch((error) => {
          console.error("Failed to record visit", error);
        }),
      );
    }

    return fetch(request);
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(
      (async () => {
        await sendDailyDigest(env, "matspoems.com");
        const configuredDays = Number.parseInt(env.RETENTION_DAYS || "30", 10);
        const retentionDays = Number.isFinite(configuredDays)
          ? Math.min(Math.max(configuredDays, 1), 365)
          : 30;
        await env.VISITOR_DB.prepare(
          `DELETE FROM visits WHERE visited_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)`,
        )
          .bind(`-${retentionDays} days`)
          .run();
      })(),
    );
  },
};
