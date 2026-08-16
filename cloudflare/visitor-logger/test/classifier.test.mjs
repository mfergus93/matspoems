import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { attributionData, buildSessions, classifyRequest, classifySessionEvidence, isReferredSource, normalizeSource, parseDeviceBrowser, sanitizeReferrer, validateEngagement } from "../src/index.js";

const base = {
  ip_address: "203.0.113.1", user_agent: "Mozilla/5.0", country: "US",
  city: "Test", region: "OK", postal_code: "00000", referrer: null,
  score: 40, confidence: "uncertain", reasons: "document navigation; accept-language present",
};
const visit = (time, path = "/", extra = {}) => ({ ...base, visited_at: time, path, ...extra });

test("single page stays uncertain", () => {
  assert.equal(buildSessions([visit("2026-08-15T10:00:00.000Z")])[0].confidence, "uncertain");
});
test("two pages in one second stay uncertain", () => {
  const session = buildSessions([visit("2026-08-15T10:00:00.000Z"), visit("2026-08-15T10:00:01.000Z", "/two")])[0];
  assert.equal(session.confidence, "uncertain");
});

test("three pages in one second are automated", () => {
  const session = buildSessions([visit("2026-08-15T10:00:00.000Z"), visit("2026-08-15T10:00:00.500Z", "/two"), visit("2026-08-15T10:00:01.000Z", "/three")])[0];
  assert.equal(session.confidence, "bot");
});

test("seventeen pages in two seconds are automated", () => {
  const rows = Array.from({ length: 17 }, (_, i) => visit(new Date(Date.parse("2026-08-15T10:00:00.000Z") + i * 125).toISOString(), `/${i}`));
  assert.equal(buildSessions(rows)[0].confidence, "bot");
});

test("two distinct pages over thirty seconds can be human", () => {
  const session = buildSessions([visit("2026-08-15T10:00:00.000Z"), visit("2026-08-15T10:00:30.000Z", "/two")])[0];
  assert.equal(session.confidence, "human");
});

test("three paced pages over five minutes are human", () => {
  const session = buildSessions([visit("2026-08-15T10:00:00.000Z"), visit("2026-08-15T10:02:00.000Z", "/two"), visit("2026-08-15T10:05:00.000Z", "/three")])[0];
  assert.equal(session.confidence, "human");
});

test("cloud ASN single page is not human", () => {
  const request = new Request("https://matspoems.com/", { headers: { Accept: "text/html", "Accept-Language": "en", "Sec-Fetch-Dest": "document" } });
  Object.defineProperty(request, "cf", { value: { asn: 16509, asOrganization: "Amazon" } });
  assert.notEqual(classifyRequest(request, new URL(request.url)).confidence, "human");
});

test("Cloudflare verified Googlebot remains verified", () => {
  const request = new Request("https://matspoems.com/", { headers: { "User-Agent": "Googlebot" } });
  Object.defineProperty(request, "cf", { value: { botManagement: { verifiedBot: true } } });
  assert.equal(classifyRequest(request, new URL(request.url)).confidence, "verified_bot");
});

test("low Cloudflare bot score is a strong negative when available", () => {
  const request = new Request("https://matspoems.com/", { headers: { Accept: "text/html", "Accept-Language": "en", "Sec-Fetch-Dest": "document" } });
  Object.defineProperty(request, "cf", { value: { botManagement: { score: 10, verifiedBot: false } } });
  assert.equal(classifyRequest(request, new URL(request.url)).confidence, "bot");
});

test("iPhone is iOS, not Mac", () => {
  assert.equal(parseDeviceBrowser("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17 Safari/604.1"), "Safari/iOS");
});

test("31 minute gap creates two sessions", () => {
  assert.equal(buildSessions([visit("2026-08-15T10:00:00.000Z"), visit("2026-08-15T10:31:00.000Z", "/two")]).length, 2);
});

test("engagement and prior referral are explicit session evidence", () => {
  const session = buildSessions([visit("2026-08-15T10:00:00.000Z", "/", { source: "direct" })])[0];
  const result = classifySessionEvidence(session, [{ event_type: "visible_20s", visible_seconds: 20 }], true);
  assert.equal(result.confidence, "human");
});

test("source normalization recognizes Facebook", () => {
  assert.equal(normalizeSource(new URL("https://matspoems.com/"), "https://l.facebook.com/path?q=x"), "facebook");
});

test("lookalike referrer domains are never trusted brands", () => {
  assert.equal(normalizeSource(new URL("https://matspoems.com/"), "https://notfacebook.com/path"), "notfacebook.com");
  assert.equal(normalizeSource(new URL("https://matspoems.com/"), "https://linkedin.com.attacker.example/path"), "linkedin.com.attacker.example");
  assert.equal(normalizeSource(new URL("https://matspoems.com/"), "https://google.com.evil/path"), "google.com.evil");
});

test("UTM is reporting attribution, not durable referral proof", () => {
  const request = new Request("https://matspoems.com/?utm_source=facebook&utm_medium=social");
  const attribution = attributionData(request, new URL(request.url));
  assert.equal(attribution.source, "facebook");
  assert.equal(attribution.sourceEvidence, "utm_claim");
  assert.equal(attribution.serverReferred, false);
});

test("UTM and browser claims do not avoid the unknown-referral penalty", () => {
  const direct = classifySessionEvidence({ score: 40, reasons: [], source: "direct", source_evidence: "direct", confidence: "uncertain" }, [], false);
  const utm = classifySessionEvidence({ score: 40, reasons: [], source: "facebook", source_evidence: "utm_claim", confidence: "uncertain" }, [], false);
  const browser = classifySessionEvidence({ score: 40, reasons: [], source: "facebook", source_evidence: "browser_referrer_claim", confidence: "uncertain" }, [], false);
  assert.equal(utm.score, direct.score);
  assert.equal(browser.score, direct.score);
});

test("HTTP referrer is server-observed referral evidence", () => {
  const request = new Request("https://matspoems.com/", { headers: { Referer: "https://www.facebook.com/profile?tracking=x" } });
  const attribution = attributionData(request, new URL(request.url));
  assert.equal(attribution.sourceEvidence, "http_referrer");
  assert.equal(attribution.serverReferred, true);
});

test("same-site referrer is internal and never creates referral history", () => {
  const source = normalizeSource(new URL("https://matspoems.com/photography.html"), "https://www.matspoems.com/");
  assert.equal(source, "internal");
  assert.equal(isReferredSource(source), false);
});

test("browser referrer query and fragment are removed", () => {
  assert.equal(sanitizeReferrer("https://matspoems.com/foo?secret=123#part"), "https://matspoems.com/foo");
});

test("premature visibility claims are rejected and hidden time is capped", () => {
  const start = "2026-08-15T10:00:00.000Z";
  assert.equal(validateEngagement("visible_20s", 20, start, Date.parse(start) + 1000).eventType, "rejected_visible_20s");
  assert.equal(validateEngagement("visible_20s", 20, start, Date.parse(start) + 19000).eventType, "visible_20s");
  assert.equal(validateEngagement("visible_20s", 3600, start, Date.parse(start) + 20000).visibleSeconds, 20);
  assert.equal(validateEngagement("page_hidden", 999, start, Date.parse(start) + 5000).visibleSeconds, 5);
});

test("visitor profiles are included in retention cleanup", async () => {
  const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
  assert.match(source, /DELETE FROM visitor_profiles WHERE last_seen_at/);
});

test("complete audit endpoint and scheduled alert retry remain wired", async () => {
  const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
  assert.match(source, /const AUDIT_PATH = "\/_visitor-audit"/);
  assert.match(source, /async function retryPendingAlerts/);
  assert.match(source, /alerted_at IS NULL/);
  assert.match(source, /association: "same_ip_time_window"/);
});

