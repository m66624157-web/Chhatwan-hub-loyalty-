import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import Database from "better-sqlite3";
import QRCode from "qrcode";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const db = new Database(path.join(__dirname, "loyalty.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS customers(
 id TEXT PRIMARY KEY,name TEXT NOT NULL,phone TEXT NOT NULL UNIQUE,
 consent INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS visits(
 id TEXT PRIMARY KEY,customer_id TEXT NOT NULL,created_at TEXT NOT NULL,
 FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rewards(
 id TEXT PRIMARY KEY,customer_id TEXT NOT NULL,reward TEXT NOT NULL,
 reward_type TEXT NOT NULL DEFAULT 'custom',unlocked_at TEXT NOT NULL,claimed_at TEXT,
 FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
`);

function set(k, v) {
  db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(k, String(v));
}
function get(k, d) {
  const r = db.prepare("SELECT value FROM settings WHERE key=?").get(k);
  return r ? r.value : d;
}
function bool(v) { return String(v) === "true"; }
function isoNow() { return new Date().toISOString(); }
function normalizePhone(raw) {
  let p = String(raw || "").replace(/\D/g, "");
  if (p.startsWith("0")) p = "91" + p.slice(1);
  if (p.length === 10) p = "91" + p;
  return p;
}
function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}
function makeCustomerToken(customerId) {
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const payload = `${customerId}.${exp}`;
  return `${payload}.${sign(payload)}`;
}
function verifyCustomerToken(token) {
  try {
    const [id, exp, sig] = String(token || "").split(".");
    if (!id || !exp || !sig || Number(exp) < Date.now()) return null;
    const payload = `${id}.${exp}`;
    const a = Buffer.from(sig);
    const b = Buffer.from(sign(payload));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return id;
  } catch { return null; }
}

if (!get("visits_required")) set("visits_required", process.env.VISITS_REQUIRED || 5);
if (!get("reward_enabled")) set("reward_enabled", process.env.REWARD_ENABLED || "true");
if (!get("reward_type")) set("reward_type", process.env.REWARD_TYPE || "discount");
if (!get("reward_text")) set("reward_text", process.env.REWARD_TEXT || "₹200 OFF");
if (!get("cooldown_hours")) set("cooldown_hours", process.env.COOLDOWN_HOURS || 24);
if (!get("google_review_url")) set("google_review_url", process.env.GOOGLE_REVIEW_URL || "");
if (!get("whatsapp_enabled")) set("whatsapp_enabled", process.env.WHATSAPP_ENABLED || "false");

const adminSessions = new Map();
function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  const exp = token ? adminSessions.get(token) : null;
  if (!token || !exp || exp < Date.now()) {
    if (token) adminSessions.delete(token);
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}
function customerAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  const id = verifyCustomerToken(token);
  if (!id) return res.status(401).json({ error: "Customer session expired" });
  const customer = db.prepare("SELECT * FROM customers WHERE id=?").get(id);
  if (!customer) return res.status(401).json({ error: "Customer not found" });
  req.customer = customer;
  next();
}

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));
const apiLimit = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });
const authLimit = rateLimit({ windowMs: 15 * 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use("/api", apiLimit);

app.post("/api/login", authLimit, (req, res) => {
  const pass = String(req.body.password || "");
  const stored = String(process.env.ADMIN_PASSWORD || "");
  if (!stored || pass !== stored) return res.status(401).json({ error: "Invalid password" });
  const token = crypto.randomBytes(32).toString("hex");
  adminSessions.set(token, Date.now() + 12 * 60 * 60 * 1000);
  res.json({ token, expiresIn: 12 * 60 * 60 });
});
app.post("/api/logout", adminAuth, (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (token) adminSessions.delete(token);
  res.json({ ok: true });
});

app.get("/api/settings", adminAuth, (req, res) => res.json(settingsPayload()));
function settingsPayload() {
  return {
    visitsRequired: Number(get("visits_required", 5)),
    rewardEnabled: bool(get("reward_enabled", "true")),
    rewardType: get("reward_type", "custom"),
    reward: get("reward_text", "Reward"),
    cooldownHours: Number(get("cooldown_hours", 24)),
    googleReviewUrl: get("google_review_url", ""),
    whatsappEnabled: bool(get("whatsapp_enabled", "false")),
    whatsappConfigured: Boolean(process.env.WHATSAPP_ACCESS_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID && process.env.WHATSAPP_TEMPLATE_NAME),
    joinUrl: `${BASE_URL}/join`
  };
}
app.put("/api/settings", adminAuth, (req, res) => {
  const s = req.body || {};
  if (s.visitsRequired != null) set("visits_required", Math.max(1, Math.min(100, Number(s.visitsRequired) || 5)));
  if (s.rewardEnabled != null) set("reward_enabled", !!s.rewardEnabled);
  if (s.rewardType != null) set("reward_type", ["discount", "gift", "custom"].includes(String(s.rewardType)) ? String(s.rewardType) : "custom");
  if (s.reward != null) set("reward_text", String(s.reward).slice(0, 120));
  if (s.cooldownHours != null) set("cooldown_hours", Math.max(0, Math.min(720, Number(s.cooldownHours) || 0)));
  if (s.googleReviewUrl != null) set("google_review_url", String(s.googleReviewUrl).slice(0, 500));
  if (s.whatsappEnabled != null) set("whatsapp_enabled", !!s.whatsappEnabled);
  res.json({ ok: true, settings: settingsPayload() });
});

app.get("/api/stats", adminAuth, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.json({
    customers: db.prepare("SELECT COUNT(*) c FROM customers").get().c,
    todayVisits: db.prepare("SELECT COUNT(*) c FROM visits WHERE substr(created_at,1,10)=?").get(today).c,
    unlocked: db.prepare("SELECT COUNT(*) c FROM rewards WHERE claimed_at IS NULL").get().c,
    claimed: db.prepare("SELECT COUNT(*) c FROM rewards WHERE claimed_at IS NOT NULL").get().c
  });
});

app.get("/api/customers", adminAuth, (req, res) => {
  const q = String(req.query.q || "").trim();
  const rows = q
    ? db.prepare(`SELECT c.*,COUNT(v.id) visits, MAX(v.created_at) last_visit FROM customers c LEFT JOIN visits v ON v.customer_id=c.id WHERE c.name LIKE ? OR c.phone LIKE ? GROUP BY c.id ORDER BY c.created_at DESC`).all(`%${q}%`, `%${q}%`)
    : db.prepare(`SELECT c.*,COUNT(v.id) visits, MAX(v.created_at) last_visit FROM customers c LEFT JOIN visits v ON v.customer_id=c.id GROUP BY c.id ORDER BY c.created_at DESC LIMIT 500`).all();
  res.json(rows);
});
app.get("/api/customer/:id", adminAuth, (req, res) => {
  const c = db.prepare("SELECT * FROM customers WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  res.json({
    customer: c,
    visits: db.prepare("SELECT * FROM visits WHERE customer_id=? ORDER BY created_at DESC").all(c.id),
    rewards: db.prepare("SELECT * FROM rewards WHERE customer_id=? ORDER BY unlocked_at DESC").all(c.id)
  });
});

function registerOrFindCustomer(name, phone, consent) {
  let c = db.prepare("SELECT * FROM customers WHERE phone=?").get(phone);
  if (!c) {
    c = { id: crypto.randomUUID(), name, phone, consent: 1, created_at: isoNow() };
    db.prepare("INSERT INTO customers(id,name,phone,consent,created_at) VALUES(?,?,?,?,?)").run(c.id, c.name, c.phone, 1, c.created_at);
  } else {
    db.prepare("UPDATE customers SET name=?,consent=? WHERE id=?").run(name || c.name, consent ? 1 : c.consent, c.id);
    c = db.prepare("SELECT * FROM customers WHERE id=?").get(c.id);
  }
  return c;
}

app.post("/api/customer/register", authLimit, (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 80);
  const phone = normalizePhone(req.body.phone);
  const consent = !!req.body.consent;
  if (name.length < 2 || phone.length < 10 || !consent) return res.status(400).json({ error: "Name, valid WhatsApp number and consent are required" });
  const c = registerOrFindCustomer(name, phone, consent);
  const result = recordVisit(c.id);
  res.json({ customer: c, customerToken: makeCustomerToken(c.id), ...result, settings: customerSettings() });
});

function customerSettings() {
  return {
    visitsRequired: Number(get("visits_required", 5)),
    rewardEnabled: bool(get("reward_enabled", "true")),
    rewardType: get("reward_type", "custom"),
    reward: get("reward_text", "Reward"),
    googleReviewUrl: get("google_review_url", ""),
    cooldownHours: Number(get("cooldown_hours", 24))
  };
}

function recordVisit(customerId) {
  const cooldown = Number(get("cooldown_hours", 24)) * 3600000;
  const now = Date.now();
  const last = db.prepare("SELECT created_at FROM visits WHERE customer_id=? ORDER BY created_at DESC LIMIT 1").get(customerId);
  const countBefore = db.prepare("SELECT COUNT(*) c FROM visits WHERE customer_id=?").get(customerId).c;
  if (last && cooldown > 0 && now - new Date(last.created_at).getTime() < cooldown) {
    return { count: countBefore, reward: null, cooldown: true, nextVisitAt: new Date(new Date(last.created_at).getTime() + cooldown).toISOString() };
  }
  const iso = new Date(now).toISOString();
  db.prepare("INSERT INTO visits(id,customer_id,created_at) VALUES(?,?,?)").run(crypto.randomUUID(), customerId, iso);
  const count = countBefore + 1;
  const threshold = Number(get("visits_required", 5));
  let reward = null;
  if (bool(get("reward_enabled", "true")) && count >= threshold && count % threshold === 0) {
    const active = db.prepare("SELECT * FROM rewards WHERE customer_id=? AND claimed_at IS NULL").get(customerId);
    if (!active) {
      reward = {
        id: crypto.randomUUID(), customerId,
        reward: get("reward_text", "Reward"),
        reward_type: get("reward_type", "custom"),
        unlocked_at: iso, claimed_at: null
      };
      db.prepare("INSERT INTO rewards(id,customer_id,reward,reward_type,unlocked_at,claimed_at) VALUES(?,?,?,?,?,NULL)").run(reward.id, reward.customerId, reward.reward, reward.reward_type, reward.unlocked_at);
      sendWhatsApp(customerId, reward.reward).catch(err => console.error("WhatsApp error:", err.message));
    }
  }
  return { count, reward, cooldown: false, nextVisitAt: null };
}

app.get("/api/customer/me", customerAuth, (req, res) => {
  const c = req.customer;
  res.json(customerView(c));
});
app.post("/api/customer/me/visit", customerAuth, (req, res) => {
  const result = recordVisit(req.customer.id);
  res.json({ ...result, ...customerView(req.customer) });
});
function customerView(c) {
  return {
    customer: c,
    visits: db.prepare("SELECT id,created_at FROM visits WHERE customer_id=? ORDER BY created_at DESC").all(c.id),
    rewards: db.prepare("SELECT id,reward,reward_type,unlocked_at,claimed_at FROM rewards WHERE customer_id=? ORDER BY unlocked_at DESC").all(c.id),
    settings: customerSettings()
  };
}

app.post("/api/customer/:id/visit", adminAuth, (req, res) => {
  const c = db.prepare("SELECT * FROM customers WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  res.json(recordVisit(c.id));
});
app.post("/api/reward/:id/claim", adminAuth, (req, res) => {
  const r = db.prepare("SELECT * FROM rewards WHERE id=?").get(req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.claimed_at) return res.status(400).json({ error: "Reward already claimed" });
  db.prepare("UPDATE rewards SET claimed_at=? WHERE id=?").run(isoNow(), r.id);
  res.json({ ok: true });
});
app.get("/api/rewards", adminAuth, (req, res) => res.json(db.prepare(`SELECT r.*,c.name,c.phone FROM rewards r JOIN customers c ON c.id=r.customer_id ORDER BY r.unlocked_at DESC LIMIT 500`).all()));

app.get("/api/export", adminAuth, (req, res) => {
  const payload = {
    exportedAt: isoNow(),
    settings: settingsPayload(),
    customers: db.prepare("SELECT * FROM customers ORDER BY created_at DESC").all(),
    visits: db.prepare("SELECT * FROM visits ORDER BY created_at DESC").all(),
    rewards: db.prepare("SELECT * FROM rewards ORDER BY unlocked_at DESC").all()
  };
  res.json(payload);
});

app.get("/api/qr", adminAuth, async (req, res) => {
  const url = `${BASE_URL}/join`;
  res.type("png").send(await QRCode.toBuffer(url, { width: 1200, margin: 3, errorCorrectionLevel: "H" }));
});
app.get("/api/health", (req, res) => res.json({ ok: true, baseUrl: BASE_URL }));

app.get("/join", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

async function sendWhatsApp(customerId, reward) {
  if (!bool(get("whatsapp_enabled", "false"))) return;
  const c = db.prepare("SELECT * FROM customers WHERE id=?").get(customerId);
  const token = process.env.WHATSAPP_ACCESS_TOKEN;
  const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const templateName = process.env.WHATSAPP_TEMPLATE_NAME;
  if (!c || !token || !phoneId || !templateName) return;
  const version = process.env.WHATSAPP_GRAPH_VERSION || "v23.0";
  const r = await fetch(`https://graph.facebook.com/${version}/${phoneId}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      messaging_product: "whatsapp", to: c.phone, type: "template",
      template: {
        name: templateName,
        language: { code: process.env.WHATSAPP_TEMPLATE_LANGUAGE || "en_US" },
        components: [{ type: "body", parameters: [{ type: "text", text: reward }] }]
      }
    })
  });
  if (!r.ok) throw new Error(await r.text());
}

setInterval(() => {
  const now = Date.now();
  for (const [token, exp] of adminSessions) if (exp < now) adminSessions.delete(token);
}, 60_000).unref();

app.listen(PORT, () => console.log(`Chhatwan Hub running on ${BASE_URL}`));
