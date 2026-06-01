"use strict";

// ============================================================
//  MONIME PAYMENT BACKEND  —  server.js
//  Full integration: Payment Codes, Payments, Checkout Sessions,
//  Webhooks, SSE real-time status, Colored Receipt generation
//  Node.js 18+ (uses built-in fetch)
// ============================================================

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const morgan     = require("morgan");
const rateLimit  = require("express-rate-limit");
const crypto     = require("crypto");
const { v4: uuidv4 } = require("uuid");

// ─── HARDCODED CREDENTIALS (remove before going to production) ───────────────
const MONIME_ACCESS_TOKEN  = "mon_TEOFVaDJVyZKghBCZsmxV1OTjtqYjeu3GEfB5ZFYRZJP05PBzSZSuBFpwgs9Ijaa";
const MONIME_SPACE_ID      = "spc-k6RT8s86xFLkXGPiEs7fDPm5nsF";
const MONIME_WEBHOOK_SECRET = "PASTE_YOUR_WEBHOOK_SECRET_FROM_DASHBOARD_HERE"; // from Monime dashboard
const PORT                 = process.env.PORT || 4000;
const BASE_URL             = "https://api.monime.io";
const API_VERSION          = "caph.2025-08-23";

// ─── PROVIDER CODES ──────────────────────────────────────────────────────────
const PROVIDERS = {
  ORANGE_MONEY : "m17",  // Orange Money Sierra Leone
  AFRICELL     : "m18",  // Africell Money Sierra Leone
};

// ─── IN-MEMORY STORE  (replace with a real DB in production) ─────────────────
// Tracks active payment codes and connected SSE clients
const paymentStore = new Map();
// paymentStore[id] = { amount, currency, status, ussdCode, receipt, sseClients: Set }

// ─── APP SETUP ────────────────────────────────────────────────────────────────
const app = express();

// Trust the first proxy (required on Render, Railway, Heroku, etc.)
// Fixes: ERR_ERL_UNEXPECTED_X_FORWARDED_FOR from express-rate-limit
app.set("trust proxy", 1);

app.use(cors({ origin: "*", methods: ["GET","POST","PATCH","DELETE","OPTIONS"], allowedHeaders: ["*"] }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("dev"));

// Parse JSON and capture raw body at the same time (needed for webhook HMAC check)
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); },
}));

// Fallback raw body for non-JSON content-types (e.g. Monime sending text/plain)
app.use((req, _res, next) => {
  if (!req.rawBody) {
    let raw = "";
    req.on("data", (chunk) => { raw += chunk.toString(); });
    req.on("end", () => { req.rawBody = raw; next(); });
  } else {
    next();
  }
});

// Rate limiter — 120 requests per minute per IP
app.use("/api/", rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPER UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/** Build standard Monime request headers */
function monimeHeaders(withIdempotency = false) {
  const headers = {
    "Authorization"  : `Bearer ${MONIME_ACCESS_TOKEN}`,
    "Monime-Space-Id": MONIME_SPACE_ID,
    "Monime-Version" : API_VERSION,
    "Content-Type"   : "application/json",
  };
  if (withIdempotency) headers["Idempotency-Key"] = uuidv4();
  return headers;
}

/** Wrapper around Monime API — handles errors and parses JSON */
async function monimeFetch(method, path, body = null) {
  const isPost   = ["POST", "PATCH"].includes(method.toUpperCase());
  const response = await fetch(`${BASE_URL}${path}`, {
    method  : method.toUpperCase(),
    headers : monimeHeaders(isPost),
    body    : body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!response.ok) {
    const err = new Error(data?.error?.message || data?.message || `Monime API error ${response.status}`);
    err.status = response.status;
    err.monimeError = data;
    throw err;
  }
  return data;
}

/** Verify HMAC-SHA256 webhook signature from Monime */
function verifyWebhookSignature(rawBody, signatureHeader) {
  if (!MONIME_WEBHOOK_SECRET || MONIME_WEBHOOK_SECRET.startsWith("PASTE_")) return true; // skip if not set
  try {
    const expected = "sha256=" + crypto.createHmac("sha256", MONIME_WEBHOOK_SECRET)
      .update(rawBody, "utf8").digest("hex");
    return crypto.timingSafeEqual(Buffer.from(signatureHeader || ""), Buffer.from(expected));
  } catch { return false; }
}

/** Format amount — Monime stores values in cents */
function fmtAmount(value, currency = "SLE") {
  return `${currency} ${(value / 100).toFixed(2)}`;
}

/** Format date nicely */
function fmtDate(isoString) {
  if (!isoString) return "—";
  return new Date(isoString).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

// ─── SSE helpers ─────────────────────────────────────────────────────────────
/** Register an SSE client for a payment code */
function addSSEClient(codeId, res) {
  if (!paymentStore.has(codeId)) paymentStore.set(codeId, { sseClients: new Set() });
  const entry = paymentStore.get(codeId);
  if (!entry.sseClients) entry.sseClients = new Set();
  entry.sseClients.add(res);
}

/** Push an event to all subscribed SSE clients for a code */
function notifySSEClients(codeId, eventType, payload) {
  const entry = paymentStore.get(codeId);
  if (!entry?.sseClients) return;
  const msg = `event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of entry.sseClients) {
    try { client.write(msg); } catch { entry.sseClients.delete(client); }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RECEIPT GENERATION  —  Returns a full HTML page (green=success, red=failed)
// ═══════════════════════════════════════════════════════════════════════════════
function generateReceipt(data) {
  const {
    status,           // "completed" | "failed" | "expired" | "cancelled"
    paymentCodeId,
    ussdCode,
    amount,
    currency,
    paidAt,
    customerName,
    networkRef,
    providerId,
    orderNumber,
    sessionId,
    description,
    channel,
    metadata = {},
  } = data;

  const isSuccess = status === "completed";
  const isFailed  = !isSuccess;

  const primaryColor  = isSuccess ? "#16a34a" : "#dc2626";  // green / red
  const bgColor       = isSuccess ? "#f0fdf4" : "#fef2f2";
  const borderColor   = isSuccess ? "#86efac" : "#fca5a5";
  const headerBg      = isSuccess ? "#dcfce7" : "#fee2e2";
  const badgeBg       = isSuccess ? "#22c55e" : "#ef4444";
  const icon          = isSuccess ? "✅" : "❌";
  const label         = isSuccess ? "PAYMENT SUCCESSFUL" : `PAYMENT ${status.toUpperCase()}`;
  const providerName  = providerId === PROVIDERS.ORANGE_MONEY
    ? "Orange Money Sierra Leone"
    : providerId === PROVIDERS.AFRICELL
      ? "Africell Money Sierra Leone"
      : (providerId || "Mobile Money");

  const rows = [
    ["Receipt Type",    "USSD Payment Receipt"],
    ["Status",          label],
    ["Amount",          fmtAmount(amount, currency)],
    ...(ussdCode ? [["USSD Code", ussdCode]] : []),
    ...(customerName ? [["Customer", customerName]] : []),
    ...(providerName && isSuccess ? [["Network", providerName]] : []),
    ...(networkRef ? [["Network Ref", networkRef]] : []),
    ...(channel ? [["Channel", channel]] : []),
    ...(orderNumber ? [["Order No.", orderNumber]] : []),
    ...(paymentCodeId ? [["Payment Code ID", paymentCodeId]] : []),
    ...(sessionId ? [["Session ID", sessionId]] : []),
    ...(description ? [["Description", description]] : []),
    ["Date / Time",     fmtDate(paidAt || new Date().toISOString())],
    ...(isFailed ? [["Reason", "Payment was not completed. Please try again."]] : []),
    ...Object.entries(metadata).map(([k, v]) => [k, String(v)]),
  ];

  const tableRows = rows.map(([label, value]) => `
    <tr>
      <td style="padding:10px 14px;font-weight:600;color:#374151;background:#f9fafb;border-bottom:1px solid ${borderColor};width:40%;font-size:13px;">${label}</td>
      <td style="padding:10px 14px;color:#111827;border-bottom:1px solid ${borderColor};font-size:13px;word-break:break-all;">${value}</td>
    </tr>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Payment Receipt — ${label}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:${bgColor};min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:32px 16px}
    .card{background:#fff;border:2px solid ${borderColor};border-radius:16px;width:100%;max-width:560px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.10)}
    .header{background:${headerBg};padding:28px 24px;text-align:center;border-bottom:2px solid ${borderColor}}
    .icon{font-size:48px;display:block;margin-bottom:10px}
    .badge{display:inline-block;background:${badgeBg};color:#fff;font-size:13px;font-weight:700;letter-spacing:1.2px;padding:5px 18px;border-radius:999px;margin-bottom:8px}
    .amount-big{font-size:36px;font-weight:800;color:${primaryColor};margin-bottom:4px}
    .brand{font-size:12px;color:#6b7280;margin-top:6px;letter-spacing:.5px}
    table{width:100%;border-collapse:collapse}
    .footer{padding:18px 24px;background:${bgColor};border-top:2px solid ${borderColor};text-align:center}
    .footer p{font-size:12px;color:#6b7280;margin-top:4px}
    .print-btn{display:inline-block;margin-top:12px;padding:9px 22px;background:${primaryColor};color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border-radius:8px}
    @media print{.print-btn{display:none}body{background:#fff;padding:0}.card{box-shadow:none;border:1px solid #ccc}}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <span class="icon">${icon}</span>
      <div class="badge">${label}</div>
      <div class="amount-big">${fmtAmount(amount, currency)}</div>
      <div class="brand">Powered by Monime · Sierra Leone</div>
    </div>
    <table>${tableRows}</table>
    <div class="footer">
      ${isSuccess
        ? "<p style=\"color:#16a34a;font-weight:600\">Thank you! Your payment has been received.</p>"
        : "<p style=\"color:#dc2626;font-weight:600\">Your payment could not be completed.</p>"}
      <p>Keep this receipt for your records.</p>
      <button class="print-btn" onclick="window.print()">🖨️ Print Receipt</button>
    </div>
  </div>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ROUTE: HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/", (_req, res) => {
  res.json({
    service : "Monime Payment Backend",
    version : "1.0.0",
    status  : "running",
    time    : new Date().toISOString(),
    webhook : "POST /api/webhooks/monime",
    docs    : {
      paymentCodes    : "POST /api/payment-codes",
      payments        : "GET  /api/payments",
      checkoutSessions: "POST /api/checkout-sessions",
      receipt         : "GET  /api/receipts/:id",
      sseStream       : "GET  /api/payment-codes/:id/stream",
    },
  });
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString(), space: MONIME_SPACE_ID });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  PAYMENT CODES — USSD Payment Flow
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/payment-codes
 * Body: { amount, currency?, name?, description?, duration?, mode?, customerName?, providers? }
 * Creates a Payment Code and returns the USSD code for the customer to dial.
 */
app.post("/api/payment-codes", async (req, res) => {
  try {
    const {
      amount,                           // SLE amount (e.g. 50)
      currency     = "SLE",
      name         = "Payment Request",
      description,
      duration     = "30m",             // how long USSD code is valid (Golang format)
      mode         = "one_time",        // "one_time" | "recurrent"
      customerName,
      providers    = ["m17", "m18"],    // Orange Money + Africell Money by default
      reference,                        // your internal reference
      metadata     = {},
      // Recurrent-mode options:
      expectedPaymentCount,
    } = req.body;

    if (!amount || isNaN(Number(amount))) {
      return res.status(400).json({ error: "amount is required and must be a number (in SLE, e.g. 50)" });
    }

    const amountCents = Math.round(Number(amount) * 100);

    const body = {
      mode,
      name,
      enable   : true,
      duration,
      amount   : { currency, value: amountCents },
      authorizedProviders: providers,
      ...(description && { description }),
      ...(reference   && { reference }),
      ...(customerName && { customer: { name: customerName } }),
      ...(Object.keys(metadata).length && { metadata }),
      ...(mode === "recurrent" && expectedPaymentCount && {
        recurrentPaymentTarget: { expectedPaymentCount },
      }),
    };

    const data = await monimeFetch("POST", "/v1/payment-codes", body);
    const code = data.result;

    // Store in memory for SSE / receipt lookup
    paymentStore.set(code.id, {
      id          : code.id,
      amount      : amountCents,
      currency,
      status      : code.status,
      ussdCode    : code.ussdCode,
      name        : code.name,
      customerName,
      description,
      reference,
      metadata,
      createdAt   : code.createTime,
      expiresAt   : code.expireTime,
      sseClients  : new Set(),
    });

    res.status(201).json({
      success    : true,
      id         : code.id,
      ussdCode   : code.ussdCode,
      status     : code.status,
      amount     : fmtAmount(amountCents, currency),
      amountCents,
      currency,
      mode       : code.mode,
      expiresAt  : code.expireTime,
      message    : `Customer should dial ${code.ussdCode} to complete payment`,
      raw        : code,
    });
  } catch (err) {
    console.error("[POST /api/payment-codes]", err.message);
    res.status(err.status || 500).json({ error: err.message, detail: err.monimeError });
  }
});

/**
 * GET /api/payment-codes
 * Query: limit, after, status
 */
app.get("/api/payment-codes", async (req, res) => {
  try {
    const { limit = 20, after, status } = req.query;
    const params = new URLSearchParams({ limit });
    if (after)  params.set("after", after);
    if (status) params.set("status", status);
    const data = await monimeFetch("GET", `/v1/payment-codes?${params}`);
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * GET /api/payment-codes/:id
 * Returns latest state of a single payment code.
 */
app.get("/api/payment-codes/:id", async (req, res) => {
  try {
    const data = await monimeFetch("GET", `/v1/payment-codes/${req.params.id}`);
    const code = data.result;

    // Sync local store
    if (paymentStore.has(code.id)) {
      const entry = paymentStore.get(code.id);
      entry.status = code.status;
      if (code.processedPaymentData) entry.processedPaymentData = code.processedPaymentData;
    }

    res.json({ success: true, result: code });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * GET /api/payment-codes/:id/status
 * Lightweight status poll — returns status + USSD code only.
 */
app.get("/api/payment-codes/:id/status", async (req, res) => {
  try {
    const data = await monimeFetch("GET", `/v1/payment-codes/${req.params.id}`);
    const code = data.result;
    const entry = paymentStore.get(code.id) || {};

    const response = {
      id       : code.id,
      status   : code.status,
      ussdCode : code.ussdCode,
      amount   : fmtAmount(entry.amount || 0, entry.currency || "SLE"),
      expiresAt: code.expireTime,
    };

    if (code.status === "completed" && code.processedPaymentData) {
      response.paidAmount = fmtAmount(code.processedPaymentData.amount.value, code.processedPaymentData.amount.currency);
      response.networkRef = code.processedPaymentData.channelData?.reference;
      response.paidAt     = code.processedPaymentData.channelData?.completedAt;
      response.receiptUrl = `/api/receipts/${code.id}`;
    }

    res.json({ success: true, ...response });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * GET /api/payment-codes/:id/stream
 * Server-Sent Events — frontend subscribes here and gets live updates.
 * The webhook handler (below) pushes events to these clients.
 */
app.get("/api/payment-codes/:id/stream", (req, res) => {
  const { id } = req.params;

  res.set({
    "Content-Type"               : "text/event-stream",
    "Cache-Control"              : "no-cache",
    "Connection"                 : "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });
  res.flushHeaders();

  // Send initial connection confirmation
  res.write(`event: connected\ndata: ${JSON.stringify({ id, message: "Listening for payment updates" })}\n\n`);

  // Send current status immediately
  monimeFetch("GET", `/v1/payment-codes/${id}`)
    .then(({ result: code }) => {
      res.write(`event: status\ndata: ${JSON.stringify({
        id      : code.id,
        status  : code.status,
        ussdCode: code.ussdCode,
        expiresAt: code.expireTime,
      })}\n\n`);
    })
    .catch(() => {});

  // Heartbeat every 25 seconds to keep connection alive
  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 25_000);

  addSSEClient(id, res);

  req.on("close", () => {
    clearInterval(heartbeat);
    const entry = paymentStore.get(id);
    if (entry?.sseClients) entry.sseClients.delete(res);
  });
});

/**
 * PATCH /api/payment-codes/:id
 * Body: { name?, description?, enable?, duration? }
 */
app.patch("/api/payment-codes/:id", async (req, res) => {
  try {
    const { name, description, enable, duration } = req.body;
    const body = {};
    if (name        !== undefined) body.name        = name;
    if (description !== undefined) body.description = description;
    if (enable      !== undefined) body.enable      = enable;
    if (duration    !== undefined) body.duration    = duration;

    const data = await monimeFetch("PATCH", `/v1/payment-codes/${req.params.id}`, body);
    res.json({ success: true, result: data.result });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * DELETE /api/payment-codes/:id
 */
app.delete("/api/payment-codes/:id", async (req, res) => {
  try {
    const data = await monimeFetch("DELETE", `/v1/payment-codes/${req.params.id}`);
    paymentStore.delete(req.params.id);
    res.json({ success: true, deleted: true, raw: data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  PAYMENTS  (the financial record after a payment completes)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/payments
 * Query: limit, after, orderNumber, reference, status, channel
 */
app.get("/api/payments", async (req, res) => {
  try {
    const { limit = 20, after, orderNumber, reference, status, channel } = req.query;
    const params = new URLSearchParams({ limit });
    if (after)       params.set("after", after);
    if (orderNumber) params.set("orderNumber", orderNumber);
    if (reference)   params.set("reference", reference);
    if (status)      params.set("status", status);
    if (channel)     params.set("channel", channel);
    const data = await monimeFetch("GET", `/v1/payments?${params}`);
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * GET /api/payments/:id
 */
app.get("/api/payments/:id", async (req, res) => {
  try {
    const data = await monimeFetch("GET", `/v1/payments/${req.params.id}`);
    res.json({ success: true, result: data.result });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * PATCH /api/payments/:id
 * Body: { reference?, metadata? }
 */
app.patch("/api/payments/:id", async (req, res) => {
  try {
    const { reference, metadata } = req.body;
    const body = {};
    if (reference !== undefined) body.reference = reference;
    if (metadata  !== undefined) body.metadata  = metadata;
    const data = await monimeFetch("PATCH", `/v1/payments/${req.params.id}`, body);
    res.json({ success: true, result: data.result });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  CHECKOUT SESSIONS  (hosted payment page — multi-method)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/checkout-sessions
 * Body: { lineItems, name, successUrl, cancelUrl, reference?, description?, metadata? }
 */
app.post("/api/checkout-sessions", async (req, res) => {
  try {
    const {
      lineItems,
      name         = "Checkout",
      description,
      successUrl,
      cancelUrl,
      reference,
      callbackState,
      paymentOptions,
      brandingOptions,
      metadata = {},
    } = req.body;

    if (!lineItems || !Array.isArray(lineItems) || !lineItems.length) {
      return res.status(400).json({ error: "lineItems array is required and must not be empty" });
    }
    if (!successUrl) return res.status(400).json({ error: "successUrl is required" });

    const body = {
      name,
      lineItems,
      successUrl,
      ...(cancelUrl      && { cancelUrl }),
      ...(description    && { description }),
      ...(reference      && { reference }),
      ...(callbackState  && { callbackState }),
      ...(paymentOptions && { paymentOptions }),
      ...(brandingOptions && { brandingOptions }),
      ...(Object.keys(metadata).length && { metadata }),
    };

    const data = await monimeFetch("POST", "/v1/checkout-sessions", body);
    const session = data.result;

    res.status(201).json({
      success     : true,
      id          : session.id,
      redirectUrl : session.redirectUrl,
      status      : session.status,
      expiresAt   : session.expireTime,
      message     : "Redirect your customer to redirectUrl to complete payment",
      raw         : session,
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message, detail: err.monimeError });
  }
});

/**
 * GET /api/checkout-sessions
 * Query: limit, after
 */
app.get("/api/checkout-sessions", async (req, res) => {
  try {
    const { limit = 20, after } = req.query;
    const params = new URLSearchParams({ limit });
    if (after) params.set("after", after);
    const data = await monimeFetch("GET", `/v1/checkout-sessions?${params}`);
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * GET /api/checkout-sessions/:id
 */
app.get("/api/checkout-sessions/:id", async (req, res) => {
  try {
    const data = await monimeFetch("GET", `/v1/checkout-sessions/${req.params.id}`);
    res.json({ success: true, result: data.result });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * DELETE /api/checkout-sessions/:id
 * Only works if the session is still "pending" (customer hasn't opened the page).
 */
app.delete("/api/checkout-sessions/:id", async (req, res) => {
  try {
    const data = await monimeFetch("DELETE", `/v1/checkout-sessions/${req.params.id}`);
    res.json({ success: true, deleted: true, raw: data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  RECEIPTS  —  HTML colored receipt (green=success, red=failed/expired)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/receipts/:id
 * Fetches the latest payment code state from Monime and renders a receipt.
 * Clients can also POST receipt data directly for custom receipts.
 */
app.get("/api/receipts/:id", async (req, res) => {
  try {
    const data = await monimeFetch("GET", `/v1/payment-codes/${req.params.id}`);
    const code = data.result;
    const entry = paymentStore.get(code.id) || {};
    const paid  = code.processedPaymentData;

    const receiptData = {
      status        : code.status,
      paymentCodeId : code.id,
      ussdCode      : code.ussdCode,
      amount        : entry.amount || code.amount?.value || 0,
      currency      : entry.currency || code.amount?.currency || "SLE",
      customerName  : entry.customerName || code.customer?.name,
      description   : entry.description || code.description,
      paidAt        : paid?.channelData?.completedAt || code.createTime,
      networkRef    : paid?.channelData?.reference,
      providerId    : paid?.channelData?.providerId,
      channel       : paid ? "momo" : undefined,
      orderNumber   : paid?.channelData?.reference,
      metadata      : entry.metadata || code.metadata || {},
    };

    const html = generateReceipt(receiptData);
    res.setHeader("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * GET /api/receipts/checkout/:id
 * Receipt for a completed checkout session.
 */
app.get("/api/receipts/checkout/:id", async (req, res) => {
  try {
    const data = await monimeFetch("GET", `/v1/checkout-sessions/${req.params.id}`);
    const session = data.result;

    const totalCents = (session.lineItems?.data || []).reduce(
      (sum, item) => sum + (item.price?.value || 0) * (item.quantity || 1), 0
    );

    const receiptData = {
      status        : session.status === "completed" ? "completed" : "failed",
      sessionId     : session.id,
      amount        : totalCents,
      currency      : (session.lineItems?.data?.[0]?.price?.currency) || "SLE",
      description   : session.name,
      orderNumber   : session.orderNumber,
      paidAt        : session.updateTime,
      metadata      : session.metadata || {},
    };

    const html = generateReceipt(receiptData);
    res.setHeader("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

/**
 * POST /api/receipts/custom
 * Generate a receipt from custom data (no Monime lookup).
 * Body: { status, amount, currency, ... any receipt fields }
 */
app.post("/api/receipts/custom", (req, res) => {
  try {
    const html = generateReceipt(req.body);
    res.setHeader("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  WEBHOOK HANDLER  —  Monime sends events here
//  Register this URL in Monime dashboard:  https://YOUR_DOMAIN/api/webhooks/monime
// ═══════════════════════════════════════════════════════════════════════════════
app.post("/api/webhooks/monime", (req, res) => {
  // Verify the signature first
  const signature = req.headers["monime-signature"] || req.headers["x-monime-signature"] || "";
  if (!verifyWebhookSignature(req.rawBody, signature)) {
    console.warn("[WEBHOOK] Invalid signature — rejected");
    return res.status(401).json({ error: "Invalid webhook signature" });
  }

  let event;
  try {
    event = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Invalid JSON body" });
  }

  console.log(`[WEBHOOK] Received event: ${event.type}`);

  // ── payment_code.processed ────────────────────────────────────────────────
  if (event.type === "payment_code.processed") {
    const code = event.data;
    const paid = code.processedPaymentData;
    const entry = paymentStore.get(code.id);

    if (entry) {
      entry.status = code.status;
      entry.processedPaymentData = paid;
    }

    const isSuccess = code.status === "completed";
    const payload = {
      id          : code.id,
      status      : code.status,
      ussdCode    : code.ussdCode,
      amount      : paid ? fmtAmount(paid.amount.value, paid.amount.currency) : fmtAmount(entry?.amount || 0),
      networkRef  : paid?.channelData?.reference,
      providerId  : paid?.channelData?.providerId,
      paidAt      : paid?.channelData?.completedAt,
      receiptUrl  : `/api/receipts/${code.id}`,
      notification: isSuccess
        ? { type: "success", title: "Payment Received!", message: `${fmtAmount(paid?.amount?.value || 0, paid?.amount?.currency)} paid successfully.` }
        : { type: "failed",  title: "Payment Failed",   message: `Payment code ${code.ussdCode} was not completed.` },
    };

    // Push to all SSE clients watching this code
    notifySSEClients(code.id, isSuccess ? "payment_success" : "payment_failed", payload);

    console.log(`[WEBHOOK] payment_code ${code.id} → ${code.status}`);
  }

  // ── checkout_session.completed ────────────────────────────────────────────
  if (event.type === "checkout_session.completed") {
    const session = event.data;
    console.log(`[WEBHOOK] checkout_session ${session.id} completed — order: ${session.orderNumber}`);
    notifySSEClients(session.id, "checkout_completed", {
      id         : session.id,
      orderNumber: session.orderNumber,
      status     : session.status,
      receiptUrl : `/api/receipts/checkout/${session.id}`,
      notification: { type: "success", title: "Payment Complete!", message: "Checkout session completed." },
    });
  }

  // ── checkout_session.expired ──────────────────────────────────────────────
  if (event.type === "checkout_session.expired") {
    const session = event.data;
    console.log(`[WEBHOOK] checkout_session ${session.id} expired`);
    notifySSEClients(session.id, "checkout_expired", {
      id          : session.id,
      status      : "expired",
      notification: { type: "failed", title: "Session Expired", message: "The checkout session has expired." },
    });
  }

  // ── payment_code.expired ──────────────────────────────────────────────────
  if (event.type === "payment_code.expired") {
    const code = event.data;
    const entry = paymentStore.get(code.id);
    if (entry) entry.status = "expired";
    notifySSEClients(code.id, "payment_expired", {
      id          : code.id,
      status      : "expired",
      ussdCode    : code.ussdCode,
      notification: { type: "failed", title: "Code Expired", message: `USSD code ${code.ussdCode} has expired.` },
    });
  }

  // Always respond quickly — Monime retries if it doesn't get 200
  res.status(200).json({ received: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  GENERIC MONIME PROXY  (for any Monime API call not covered above)
// ═══════════════════════════════════════════════════════════════════════════════
app.all("/api/proxy/*", async (req, res) => {
  try {
    const path = "/" + req.params[0];
    const data = await monimeFetch(req.method, path, ["POST","PATCH"].includes(req.method) ? req.body : null);
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message, detail: err.monimeError });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  GLOBAL ERROR HANDLER
// ═══════════════════════════════════════════════════════════════════════════════
app.use((err, _req, res, _next) => {
  console.error("[UNHANDLED]", err);
  res.status(500).json({ error: "Internal server error", detail: err.message });
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found", availableAt: "/" });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  START SERVER
// ═══════════════════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log("");
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║          MONIME PAYMENT BACKEND — RUNNING            ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log(`║  Port     : ${PORT}                                      ║`);
  console.log(`║  Space ID : ${MONIME_SPACE_ID}   ║`);
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  WEBHOOK URL (paste this in Monime dashboard):       ║");
  console.log("║  https://YOUR_DOMAIN/api/webhooks/monime             ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  KEY ENDPOINTS:                                      ║");
  console.log("║  POST /api/payment-codes      → generate USSD code  ║");
  console.log("║  GET  /api/payment-codes/:id/stream → SSE updates   ║");
  console.log("║  GET  /api/receipts/:id       → colored receipt      ║");
  console.log("║  POST /api/webhooks/monime    → Monime events        ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  console.log("");
});
