# Visitor IP Logger for matspoems.com

Cloudflare Worker that runs in front of `matspoems.com`, records HTML visits in Cloudflare D1 database, and forwards requests to GitHub Pages origin (`mfergus93.github.io`).

## Setup & Deployment Instructions

### 1. Namecheap & Cloudflare Setup
1. Log into **Cloudflare** and add `matspoems.com` as a new Website/Zone.
2. Cloudflare will provide 2 Nameservers (e.g., `amy.ns.cloudflare.com`, `bob.ns.cloudflare.com`).
3. Log into **Namecheap**:
   - Go to **Domain List** -> Manage `matspoems.com`.
   - Under **Nameservers**, change from Namecheap BasicDNS to **Custom DNS**.
   - Enter the two Cloudflare nameservers provided.
4. In **Cloudflare DNS**:
   - Create a CNAME record: `CNAME` `@` -> `mfergus93.github.io` (Proxy status: **Proxied / Orange Cloud**).
   - Create a CNAME record: `CNAME` `www` -> `mfergus93.github.io` (Proxy status: **Proxied / Orange Cloud**).

### 2. GitHub Repository Settings
1. Go to repository **mfergus93/matspoems** on GitHub.
2. Go to **Settings** -> **Pages**.
3. Under **Custom Domain**, enter `matspoems.com` and save.
4. Ensure `CNAME` file exists in the repository root (already created).

### 3. Deploy Cloudflare Worker & D1 Database

From this directory (`cloudflare/visitor-logger`):

1. **Login to Wrangler**:
   ```powershell
   npx wrangler@latest login
   ```

2. **Create D1 Database**:
   ```powershell
   npx wrangler@latest d1 create matspoems-visitors
   ```
   Copy the returned `database_id` and replace `"REPLACE_WITH_DATABASE_ID"` in `wrangler.jsonc`.

3. **Initialize Database Schema**:
   ```powershell
   npx wrangler@latest d1 execute matspoems-visitors --remote --file schema.sql
   ```

4. **Set Secret Log Access Token**:
   ```powershell
   npx wrangler@latest secret put LOG_API_TOKEN
   ```
   Enter a secret 32+ character random string when prompted.

5. **Deploy Worker**:
   ```powershell
   npx wrangler@latest deploy
   ```

### 4. Reading Logs
Run the PowerShell helper to view recent visitor logs:
```powershell
.\view-logs.ps1 -Limit 100
```
