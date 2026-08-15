# Visitor analytics and scanner protection

This Cloudflare Worker fronts `matspoems.com`. It forwards normal traffic to
GitHub Pages, records top-level HTML page visits in D1, and blocks
high-confidence vulnerability scanners and automated tools.

Page records include the timestamp, IP address, approximate Cloudflare
location, path without query parameters, sanitized referrer, user agent,
network, and classification evidence. Blocked requests are stored separately in
`security_events`. Both tables use the configured 30-day retention period.

Daily reporting uses a conservative session classifier. Visits are split after
30 minutes of inactivity; single browser-looking requests remain uncertain;
and impossible page velocity or rapid route sweeps are classified as automated.
Target-area visits are highlighted only after session-level evaluation.

The `/_visitor-logs` endpoint and both email-test query parameters require
`Authorization: Bearer <LOG_API_TOKEN>`. Keep that token and `RESEND_API_KEY` in
Wrangler secrets; never commit them.

## Existing database upgrade

Apply this once before deploying the hardened Worker:

```powershell
npx wrangler@latest d1 execute matspoems-visitors --remote --file migrations/0001_harden_logging.sql
```

Fresh databases can instead be initialized with `schema.sql`.

## Validate and deploy

```powershell
npm install
npm run check
npm run deploy
```

Raw IP addresses may constitute personal data. The public site links to a
privacy notice. Keep Cloudflare access restricted and use these records only for
the disclosed security and audience-measurement purposes. Classification is
probabilistic and does not identify a visitor as a real-world person.
