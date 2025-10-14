// server.js — Arrowhead QBO Bridge (simple, read-only)
// Runs on Node/Express. Uses Postgres to store QBO tokens.
// Endpoints: /oauth/start, /cb, /qbo/query, /qbo/customers, /qbo/invoices, /qbo/reports/:name

import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import pg from "pg";

const app = express();
app.use(express.json({ limit: "512kb" }));

// ---- env ----
const {
  DATABASE_URL,
  QBO_CLIENT_ID,
  QBO_CLIENT_SECRET,
  QBO_REDIRECT_URI,
  QBO_AUTH_URL = "https://appcenter.intuit.com/connect/oauth2",
  QBO_TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
  QBO_API_BASE = "https://quickbooks.api.intuit.com/v3/company",
  ENC_KEY = "PLEASE_SET_32_CHAR_KEY_IN_RENDER_ENV"
} = process.env;

const pool = new pg.Pool({ connectionString: DATABASE_URL });

// ---- small helpers ----
const ALGO = "aes-256-gcm";
function seal(plain) {
  const iv = crypto.randomBytes(12);
  const key = Buffer.from(ENC_KEY.padEnd(32, "0")).slice(0, 32);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}
function open(sealed) {
  const buf = Buffer.from(sealed, "base64");
  const iv = buf.slice(0, 12);
  const tag = buf.slice(12, 28);
  const enc = buf.slice(28);
  const key = Buffer.from(ENC_KEY.padEnd(32, "0")).slice(0, 32);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

async function ensureTables() {
  await pool.query(`
    create table if not exists qbo_tokens (
      realm_id            text primary key,
      company_name        text,
      access_token_enc    text not null,
      refresh_token_enc   text not null,
      access_expires_at   timestamptz not null,
      refresh_expires_at  timestamptz not null,
      updated_at          timestamptz not null default now()
    );
  `);
}
ensureTables().catch(err => console.error("DB init error:", err));

// ---- tiny pages ----
app.get("/", (_req, res) => res.send("Arrowhead QBO Bridge is running."));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---- OAuth start ----
app.get("/oauth/start", (req, res) => {
  if (!QBO_CLIENT_ID || !QBO_CLIENT_SECRET || !QBO_REDIRECT_URI) {
    return res
      .status(500)
      .send("Missing QBO_CLIENT_ID / QBO_CLIENT_SECRET / QBO_REDIRECT_URI env vars.");
  }
  const state = crypto.randomBytes(16).toString("hex");
  const scope = "com.intuit.quickbooks.accounting";
  const url = new URL(QBO_AUTH_URL);
  url.searchParams.set("client_id", QBO_CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", QBO_REDIRECT_URI);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  res.redirect(url.toString());
});

// ---- OAuth callback ----
app.get("/cb", async (req, res) => {
  try {
    const { code, realmId } = req.query;
    if (!code || !realmId) return res.status(400).send("Missing code or realmId");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: code.toString(),
      redirect_uri: QBO_REDIRECT_URI
    });

    const auth = Buffer.from(`${QBO_CLIENT_ID}:${QBO_CLIENT_SECRET}`).toString("base64");
    const resp = await fetch(QBO_TOKEN_URL, {
      method: "POST",
      headers: {
        "Authorization": `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });
    if (!resp.ok) {
      const t = await resp.text();
      return res.status(500).send("Token exchange failed: " + t);
    }
    const j = await resp.json();
    const now = Date.now();
    const accessExp = new Date(now + (j.expires_in || 3600) * 1000);
    const refreshExp = j.x_refresh_token_expires_in
      ? new Date(now + j.x_refresh_token_expires_in * 1000)
      : new Date(now + 60 * 24 * 3600 * 1000); // ~60 days fallback

    await pool.query(
      `insert into qbo_tokens (realm_id, company_name, access_token_enc, refresh_token_enc,
                               access_expires_at, refresh_expires_at)
       values ($1,$2,$3,$4,$5,$6)
       on conflict (realm_id) do update set
         access_token_enc=excluded.access_token_enc,
         refresh_token_enc=excluded.refresh_token_enc,
         access_expires_at=excluded.access_expires_at,
         refresh_expires_at=excluded.refresh_expires_at,
         updated_at=now()`,
      [
        realmId.toString(),
        null,
        seal(j.access_token),
        seal(j.refresh_token),
        accessExp,
        refreshExp
      ]
    );

    res.send(`Connected! Realm ${realmId} is now authorized.`);
  } catch (e) {
    res.status(500).send("Callback error: " + (e.message || e));
  }
});

// ---- token helpers ----
async function refreshAccessToken(refreshToken) {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken
  });
  const auth = Buffer.from(`${QBO_CLIENT_ID}:${QBO_CLIENT_SECRET}`).toString("base64");
  const resp = await fetch(QBO_TOKEN_URL, {
    method: "POST",
    headers: { "Authorization": `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  if (!resp.ok) throw new Error(await resp.text());
  return await resp.json();
}

async function loadTokens(realmId) {
  const { rows } = await pool.query("select * from qbo_tokens where realm_id=$1", [realmId]);
  if (!rows.length) throw new Error("Unknown realmId. Authorize first via /oauth/start.");
  const r = rows[0];
  let access = open(r.access_token_enc);
  let refresh = open(r.refresh_token_enc);

  if (Date.now() >= new Date(r.access_expires_at).getTime() - 60_000) {
    const refreshed = await refreshAccessToken(refresh);
    access = refreshed.access_token;
    refresh = refreshed.refresh_token || refresh;
    await pool.query(
      `update qbo_tokens
         set access_token_enc=$1, refresh_token_enc=$2,
             access_expires_at=to_timestamp($3/1000),
             refresh_expires_at=to_timestamp($4/1000),
             updated_at=now()
       where realm_id=$5`,
      [
        seal(access),
        seal(refresh),
        Date.now() + refreshed.expires_in * 1000,
        Date.now() + (refreshed.x_refresh_token_expires_in || 0) * 1000,
        realmId
      ]
    );
  }
  return { accessToken: access };
}

async function qboGet(realmId, path, accessToken) {
  const url = `${QBO_API_BASE}/${realmId}${path}`;
  const resp = await fetch(url, {
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Accept": "application/json",
      "User-Agent": "Arrowhead-QBO-Bridge/1.0"
    }
  });
  if (!resp.ok) throw new Error(`QBO ${resp.status}: ${await resp.text()}`);
  return await resp.json();
}

// ---- data endpoints (read-only) ----
app.get("/qbo/query", async (req, res) => {
  try {
    const { realmId, q } = req.query;
    if (!realmId || !q) return res.status(400).json({ error: "realmId and q required" });
    const { accessToken } = await loadTokens(realmId.toString());
    const data = await qboGet(
      realmId.toString(),
      `/query?minorversion=70&query=${encodeURIComponent(q.toString())}`,
      accessToken
    );
    res.json(data.QueryResponse || data);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get("/qbo/customers", async (req, res) => {
  try {
    const { realmId, startPosition = 1, maxResults = 50 } = req.query;
    const { accessToken } = await loadTokens(realmId.toString());
    const q = `select DisplayName, Id, Balance from Customer startposition ${startPosition} maxresults ${maxResults}`;
    const data = await qboGet(
      realmId.toString(),
      `/query?minorversion=70&query=${encodeURIComponent(q)}`,
      accessToken
    );
    res.json(data.QueryResponse?.Customer || []);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get("/qbo/invoices", async (req, res) => {
  try {
    const { realmId, startPosition = 1, maxResults = 50 } = req.query;
    const { accessToken } = await loadTokens(realmId.toString());
    const q = `select Id, TxnDate, Balance, TotalAmt, CustomerRef from Invoice startposition ${startPosition} maxresults ${maxResults}`;
    const data = await qboGet(
      realmId.toString(),
      `/query?minorversion=70&query=${encodeURIComponent(q)}`,
      accessToken
    );
    res.json(data.QueryResponse?.Invoice || []);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get("/qbo/reports/:name", async (req, res) => {
  try {
    const { realmId, start_date, end_date, accounting_method = "Accrual" } = req.query;
    const { accessToken } = await loadTokens(realmId.toString());
    const qs = new URLSearchParams({ start_date, end_date, accounting_method });
    const data = await qboGet(realmId.toString(), `/reports/${req.params.name}?${qs.toString()}`, accessToken);
    res.json(data);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// ---- start server ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Arrowhead QBO Bridge listening on ${PORT}`));
