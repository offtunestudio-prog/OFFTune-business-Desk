const enc = new TextEncoder();
const models = new Set([
  "gemini-3.8-live",
  "gemini-3.8-live-extended-thinking",
  "gemini-3.1-flash-live-preview",
]);

function corsHeaders(origin, allowed) {
  const headers = new Headers({ Vary: "Origin" });
  if (origin && allowed.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    headers.set("Access-Control-Max-Age", "300");
  }
  return headers;
}

function json(body, status, headers) {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "application/json; charset=utf-8");
  responseHeaders.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers: responseHeaders });
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

async function verifyTicket(ticket, secret) {
  const [encoded, signature, extra] = ticket.split(".");
  if (!encoded || !signature || extra) return null;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("HMAC", key, fromBase64Url(signature), enc.encode(encoded)))) return null;
  let claims;
  try { claims = JSON.parse(new TextDecoder().decode(fromBase64Url(encoded))); } catch (_) { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (claims.aud !== "offtune-gemini-live" || !claims.sub || !claims.jti || !Number.isInteger(claims.exp)
      || claims.exp <= now || claims.exp > now + 60 || !models.has(claims.model)
      || claims.config?.model !== `models/${claims.model}`) return null;
  return claims;
}

function googleError(status) {
  if (status === 400) return "Google rejected the Gemini Live model or session settings. Check the selected model.";
  if (status === 401 || status === 403) return "Google rejected the Gemini key or project access. Check the key and project plan in AI Studio.";
  if (status === 404) return "Google could not find this Gemini Live model for the configured project.";
  if (status === 429) return "Gemini is temporarily rate limited. Try again later.";
  return "The secure voice service could not start a Gemini session. Check its configuration and try again.";
}

export class TicketGuard {
  constructor(state) { this.state = state; }

  async fetch(request) {
    if (request.method !== "POST") return new Response(null, { status: 405 });
    const consumed = await this.state.storage.transaction(async (txn) => {
      if (await txn.get("consumed")) return true;
      await txn.put("consumed", true);
      return false;
    });
    if (consumed) return new Response(null, { status: 409 });
    await this.state.storage.setAlarm(Date.now() + 60_000);
    return new Response(null, { status: 204 });
  }

  async alarm() { await this.state.storage.deleteAll(); }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = new Set(String(env.APP_ORIGINS || "").split(",").map((item) => item.trim()).filter(Boolean));
    const headers = corsHeaders(origin, allowed);

    if (request.method === "OPTIONS") {
      return origin && allowed.has(origin) ? new Response(null, { status: 204, headers }) : new Response(null, { status: 403 });
    }
    if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/live-token") {
      return json({ error: "Not found" }, 404, headers);
    }
    if (!origin || !allowed.has(origin)) return json({ error: "This app origin is not allowed." }, 403, headers);
    if (!env.GEMINI_API_KEY || String(env.GEMINI_LIVE_BRIDGE_SECRET || "").length < 32 || !env.TICKET_GUARD) {
      return json({ error: "The secure voice service is not fully configured." }, 503, headers);
    }

    const authorization = request.headers.get("Authorization") || "";
    const match = authorization.match(/^Bearer ([A-Za-z0-9_.-]{1,20000})$/);
    if (!match) return json({ error: "The voice session ticket is missing or invalid." }, 401, headers);
    const claims = await verifyTicket(match[1], env.GEMINI_LIVE_BRIDGE_SECRET);
    if (!claims) return json({ error: "The voice session ticket is invalid or expired. Start again." }, 401, headers);

    const guardId = env.TICKET_GUARD.idFromName(claims.jti);
    const guard = env.TICKET_GUARD.get(guardId);
    const consumed = await guard.fetch("https://ticket-guard/consume", { method: "POST" });
    if (!consumed.ok) return json({ error: "This voice session ticket has already been used. Start again." }, 409, headers);

    const now = Date.now();
    let upstream;
    try {
      upstream = await fetch("https://generativelanguage.googleapis.com/v1beta/auth_tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
        body: JSON.stringify({
          uses: 1,
          expireTime: new Date(now + 30 * 60_000).toISOString(),
          newSessionExpireTime: new Date(now + 60_000).toISOString(),
          bidiGenerateContentSetup: claims.config,
        }),
      });
    } catch (_) {
      return json({ error: "The voice service could not reach Google. Try again later." }, 502, headers);
    }
    if (!upstream.ok) return json({ error: googleError(upstream.status) }, upstream.status === 429 ? 429 : 502, headers);

    let result;
    try { result = await upstream.json(); } catch (_) { return json({ error: "Google returned an unreadable session response." }, 502, headers); }
    if (typeof result.name !== "string" || !result.name) return json({ error: "Google did not issue a live session token." }, 502, headers);
    return json({ token: result.name, model: claims.model, config: claims.config }, 200, headers);
  },
};
