// ZYVORA STREAMER - independent license server
// Node.js 18+; no third-party packages required.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error("Set ADMIN_PASSWORD to a strong password (at least 12 characters).");
  process.exit(1);
}

const DATA = path.join(__dirname, "data");
const PRIVATE_FILE = path.join(DATA, "license-private.pem");
const PUBLIC_FILE = path.join(DATA, "license-public.pem");
fs.mkdirSync(DATA, { recursive: true, mode: 0o700 });

let privateKey, publicKey;
if (fs.existsSync(PRIVATE_FILE) && fs.existsSync(PUBLIC_FILE)) {
  privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE_FILE));
  publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_FILE));
} else {
  const pair = crypto.generateKeyPairSync("ed25519");
  privateKey = pair.privateKey;
  publicKey = pair.publicKey;
  fs.writeFileSync(PRIVATE_FILE, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(PUBLIC_FILE, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
}
const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const sessions = new Map();
const revokedFile = path.join(DATA, "revoked.json");
if (!fs.existsSync(revokedFile)) fs.writeFileSync(revokedFile, "[]", { mode: 0o600 });

function json(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => { raw += chunk; if (raw.length > 20000) reject(new Error("Request too large")); });
    req.on("end", () => {
      try { resolve(JSON.parse(raw || "{}")); } catch { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}
function b64url(buf) { return Buffer.from(buf).toString("base64url"); }
function signLicense(payload) {
  const encoded = b64url(Buffer.from(JSON.stringify(payload)));
  const signature = crypto.sign(null, Buffer.from(encoded), privateKey);
  return encoded + "." + b64url(signature);
}
function getRevoked() { try { return JSON.parse(fs.readFileSync(revokedFile, "utf8")); } catch { return []; } }
function isAuthed(req) {
  const token = req.headers.authorization || "";
  const session = token.startsWith("Bearer ") ? token.slice(7) : "";
  return sessions.has(session);
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (req.method === "GET" && url.pathname === "/") {
    const html = fs.readFileSync(path.join(__dirname, "public", "index.html"));
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "X-Content-Type-Options": "nosniff" });
    return res.end(html);
  }
  if (req.method === "GET" && url.pathname === "/api/public-key") return json(res, 200, { publicKey: publicPem });
  if (req.method === "POST" && url.pathname === "/api/login") {
    try {
      const body = await readBody(req);
      if (typeof body.password !== "string" || !crypto.timingSafeEqual(
        Buffer.from(body.password.padEnd(ADMIN_PASSWORD.length).slice(0, ADMIN_PASSWORD.length)),
        Buffer.from(ADMIN_PASSWORD)
      ) || body.password.length !== ADMIN_PASSWORD.length) return json(res, 401, { error: "Incorrect admin password" });
      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, Date.now() + 8 * 60 * 60 * 1000);
      return json(res, 200, { token });
    } catch (e) { return json(res, 400, { error: e.message }); }
  }
  if (req.method === "POST" && url.pathname === "/api/issue") {
    if (!isAuthed(req)) return json(res, 401, { error: "Admin login required" });
    try {
      const body = await readBody(req);
      const customer = String(body.customer || "").trim().slice(0, 80);
      const deviceId = String(body.deviceId || "").trim().slice(0, 160);
      if (!customer) return json(res, 400, { error: "Customer name is required" });
      const payload = {
        product: "ZYVORA STREAMER",
        licenseId: crypto.randomUUID(),
        customer,
        deviceId: deviceId || null, // null = not device-bound; bind only if your app enforces it
        issuedAt: new Date().toISOString(),
        expiresAt: null, // lifetime license
        type: "lifetime"
      };
      return json(res, 200, { license: signLicense(payload), payload });
    } catch (e) { return json(res, 400, { error: e.message }); }
  }
  if (req.method === "POST" && url.pathname === "/api/verify") {
    try {
      const body = await readBody(req);
      const parts = String(body.license || "").split(".");
      if (parts.length !== 2) return json(res, 400, { valid: false, error: "Malformed license" });
      const ok = crypto.verify(null, Buffer.from(parts[0]), publicKey, Buffer.from(parts[1], "base64url"));
      if (!ok) return json(res, 200, { valid: false, error: "Invalid signature" });
      const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
      if (payload.product !== "ZYVORA STREAMER" || payload.type !== "lifetime" || payload.expiresAt !== null)
        return json(res, 200, { valid: false, error: "Wrong product or license type" });
      if (getRevoked().includes(payload.licenseId)) return json(res, 200, { valid: false, error: "License revoked" });
      if (payload.deviceId && payload.deviceId !== String(body.deviceId || ""))
        return json(res, 200, { valid: false, error: "Device does not match" });
      return json(res, 200, { valid: true, license: payload });
    } catch (e) { return json(res, 400, { valid: false, error: e.message }); }
  }
  if (req.method === "POST" && url.pathname === "/api/revoke") {
    if (!isAuthed(req)) return json(res, 401, { error: "Admin login required" });
    try {
      const body = await readBody(req);
      const id = String(body.licenseId || "").trim();
      if (!id) return json(res, 400, { error: "licenseId required" });
      const revoked = getRevoked();
      if (!revoked.includes(id)) revoked.push(id);
      fs.writeFileSync(revokedFile, JSON.stringify(revoked, null, 2), { mode: 0o600 });
      return json(res, 200, { success: true });
    } catch (e) { return json(res, 400, { error: e.message }); }
  }
  json(res, 404, { error: "Not found" });
});
server.listen(PORT, "0.0.0.0", () => console.log(`ZYVORA license server running on port ${PORT}`));
