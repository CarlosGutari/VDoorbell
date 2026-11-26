import { DurableObject } from "cloudflare:workers";

type AppEnv = Env & {
  ADMIN_API_KEY?: string;
  TEST_ACCESS_KEY?: string;
  SESSION_SECRET?: string;
  ASSETS: { fetch(request: Request): Promise<Response> };
};

type ChatMessage = { id: string; text: string; createdAt: string; from: "visitor" | "admin" };
type ChatData = { createdAt: string; messages: ChatMessage[] };
type SessionRole = "tester" | "admin";
const HOUR = 3600;

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
function reject(status: number, error: string) { return json({ error }, status); }
function getCookie(req: Request, name: string): string {
  const pair = req.headers.get("Cookie")?.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return pair ? pair.slice(name.length + 1) : "";
}
function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s: string): Uint8Array {
  const data = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4));
  return Uint8Array.from(data, c => c.charCodeAt(0));
}
async function sha256(s: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
}
function equal(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function matches(candidate: string, secret: string): Promise<boolean> {
  if (!secret || !candidate || candidate.length > 512) return false;
  return equal(await sha256(candidate), await sha256(secret));
}
async function sign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))));
}
async function session(role: SessionRole, secret: string): Promise<string> {
  const raw = b64url(new TextEncoder().encode(JSON.stringify({ r: role, exp: Math.floor(Date.now() / 1000) + 12 * HOUR })));
  return `${raw}.${await sign(raw, secret)}`;
}
async function hasSession(request: Request, role: SessionRole, secret: string): Promise<boolean> {
  const token = getCookie(request, role === "admin" ? "tv_admin" : "tv_gate");
  const parts = token.split(".");
  if (parts.length !== 2 || parts[0].length > 512 || !/^[A-Za-z0-9_-]+$/.test(parts[0])) return false;
  try {
    if (!equal(parts[1], await sign(parts[0], secret))) return false;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
    return data.r === role && Number.isInteger(data.exp) && data.exp > Date.now() / 1000;
  } catch { return false; }
}
function setSessionCookie(url: URL, name: string, value: string): string {
  const secure = url.protocol === "https:" ? "; Secure" : "";
  return `${name}=${value}; Path=/; Max-Age=${12 * HOUR}; HttpOnly; SameSite=Strict${secure}`;
}
function expiredCookie(url: URL, name: string): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict${url.protocol === "https:" ? "; Secure" : ""}`;
}
async function bodyValue(request: Request, field: string, max = 2200): Promise<string | null> {
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) return null;
  if (Number(request.headers.get("Content-Length") || 0) > 4096) return null;
  try {
    const obj = await request.json() as Record<string, unknown>;
    const v = obj && typeof obj[field] === "string" ? obj[field].trim() : "";
    return v.length > 0 && v.length <= max ? v : null;
  } catch { return null; }
}

export class MyDurableObject extends DurableObject<Env> {
  // Central registry and throttling, stored in the object named __registry__.
  async throttle(key: string, limit: number, windowSeconds: number): Promise<boolean> {
    const slot = `lim:${key}`;
    const prev = await this.ctx.storage.get<{ n: number; end: number }>(slot);
    const now = Date.now();
    const next = !prev || prev.end < now ? { n: 1, end: now + windowSeconds * 1000 } : { n: prev.n + 1, end: prev.end };
    await this.ctx.storage.put(slot, next);
    return next.n <= limit;
  }
  async registerChat(id: string): Promise<void> {
    const ids = await this.ctx.storage.get<string[]>("chatIds") ?? [];
    if (!ids.includes(id)) { ids.push(id); await this.ctx.storage.put("chatIds", ids); }
  }
  async listChatIds(): Promise<string[]> { return await this.ctx.storage.get<string[]>("chatIds") ?? []; }
  async unregisterChat(id: string): Promise<void> {
    await this.ctx.storage.put("chatIds", (await this.listChatIds()).filter(x => x !== id));
  }
  async initialize(token: string): Promise<void> {
    if (await this.ctx.storage.get("chat")) throw new Error("Already initialized");
    await this.ctx.storage.put({ tokenHash: await sha256(token), chat: { createdAt: new Date().toISOString(), messages: [] } satisfies ChatData });
  }
  private async authorized(token: string): Promise<boolean> {
    const stored = await this.ctx.storage.get<string>("tokenHash");
    return !!stored && !!token && equal(stored, await sha256(token));
  }
  async getMessages(token: string): Promise<ChatData | null> {
    if (!(await this.authorized(token))) return null;
    return await this.ctx.storage.get<ChatData>("chat") ?? null;
  }
  async adminGet(): Promise<ChatData | null> { return await this.ctx.storage.get<ChatData>("chat") ?? null; }
  async sendMessage(token: string | null, text: string, from: "visitor" | "admin"): Promise<ChatMessage | null> {
    if (from === "visitor" && !(await this.authorized(token ?? ""))) return null;
    const chat = await this.ctx.storage.get<ChatData>("chat");
    if (!chat) return null;
    if (chat.messages.length >= 100) throw new Error("Message limit reached");
    const message: ChatMessage = { id: crypto.randomUUID(), text, from, createdAt: new Date().toISOString() };
    chat.messages.push(message);
    await this.ctx.storage.put("chat", chat);
    return message;
  }
  async adminDelete(): Promise<void> { await this.ctx.storage.deleteAll(); }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const e = env as AppEnv;
    const url = new URL(request.url);
    const path = url.pathname;
    if (!e.ADMIN_API_KEY || !e.TEST_ACCESS_KEY || !e.SESSION_SECRET || e.SESSION_SECRET.length < 32)
      return reject(503, "Server secrets not configured");
    if (request.method !== "GET" && request.method !== "HEAD") {
      const origin = request.headers.get("Origin");
      if (origin && origin !== url.origin) return reject(403, "Origin not allowed");
    }
    const registry = env.MY_DURABLE_OBJECT.getByName("__registry__");
    const ip = request.headers.get("CF-Connecting-IP") ?? "local";
    // Hash for short-term quotas; avoid storing raw IP addresses.
    const ipKey = (await sha256(ip + e.SESSION_SECRET)).slice(0, 24);
    const gate = await hasSession(request, "tester", e.SESSION_SECRET);
    const admin = gate && await hasSession(request, "admin", e.SESSION_SECRET);

    if (path === "/api/test/login" && request.method === "POST") {
      if (!await registry.throttle(`gate:${ipKey}`, 12, HOUR)) return reject(429, "Too many attempts");
      const code = await bodyValue(request, "code", 512);
      if (!code || !await matches(code, e.TEST_ACCESS_KEY)) return reject(401, "Invalid test code");
      const response = json({ ok: true });
      response.headers.append("Set-Cookie", setSessionCookie(url, "tv_gate", await session("tester", e.SESSION_SECRET)));
      return response;
    }
    if (path === "/api/test/status") return json({ authenticated: gate });
    if (!gate) {
      if (path === "/login.html" || path === "/") {
        return e.ASSETS.fetch(new Request(new URL("/login.html", url), request));
      }
      if (path.startsWith("/api/")) return reject(401, "Test access required");
      return Response.redirect(`${url.origin}/login.html`, 302);
    }
    if (path === "/login.html" || path === "/") return Response.redirect(`${url.origin}/index.html`, 302);

    if (path === "/api/admin/login" && request.method === "POST") {
      if (!await registry.throttle(`admin:${ipKey}`, 8, HOUR)) return reject(429, "Too many attempts");
      const key = await bodyValue(request, "key", 512);
      if (!key || !await matches(key, e.ADMIN_API_KEY)) return reject(401, "Invalid admin key");
      const response = json({ ok: true });
      response.headers.append("Set-Cookie", setSessionCookie(url, "tv_admin", await session("admin", e.SESSION_SECRET)));
      return response;
    }
    if (path === "/api/admin/status") return json({ authenticated: admin });
    if (path === "/api/admin/logout" && request.method === "POST") {
      const response = json({ ok: true });
      response.headers.append("Set-Cookie", expiredCookie(url, "tv_admin"));
      return response;
    }

    if (path.startsWith("/api/admin/")) {
      if (!admin) return reject(401, "Admin login required");
      if (path === "/api/admin/chats" && request.method === "GET") {
        const ids = await registry.listChatIds();
        const chats = await Promise.all(ids.map(async id => {
          const d = await env.MY_DURABLE_OBJECT.getByName(id).adminGet();
          return d ? { id, createdAt: d.createdAt, messageCount: d.messages.length, lastMessage: d.messages.at(-1) ?? null } : null;
        }));
        return json({ chats: chats.filter(Boolean) });
      }
      const match = path.match(/^\/api\/admin\/chats\/([0-9a-f-]{36})(\/messages)?$/);
      if (!match) return reject(404, "Not found");
      const id = match[1];
      const stub = env.MY_DURABLE_OBJECT.getByName(id);
      if (request.method === "GET" && !match[2]) {
        const chat = await stub.adminGet();
        return chat ? json(chat) : reject(404, "Not found");
      }
      if (request.method === "POST" && match[2]) {
        const text = await bodyValue(request, "text", 2000);
        if (!text) return reject(400, "Invalid message");
        try {
          const msg = await stub.sendMessage(null, text, "admin");
          return msg ? json(msg, 201) : reject(404, "Not found");
        } catch { return reject(400, "Message limit reached"); }
      }
      if (request.method === "DELETE" && !match[2]) {
        if (!await stub.adminGet()) return reject(404, "Not found");
        await stub.adminDelete();
        await registry.unregisterChat(id);
        return json({ deleted: true });
      }
      return reject(405, "Method not allowed");
    }

    if (path === "/api/chats" && request.method === "POST") {
      if (!await registry.throttle(`new:${ipKey}`, 12, HOUR)) return reject(429, "Too many chats; try later");
      const chatId = crypto.randomUUID();
      const token = crypto.randomUUID() + crypto.randomUUID();
      await env.MY_DURABLE_OBJECT.getByName(chatId).initialize(token);
      await registry.registerChat(chatId);
      return json({ chatId, token }, 201);
    }
    const match = path.match(/^\/api\/chats\/([0-9a-f-]{36})\/messages$/);
    if (match) {
      const token = request.headers.get("Authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1] ?? "";
      if (!token) return reject(401, "Unauthorized");
      const stub = env.MY_DURABLE_OBJECT.getByName(match[1]);
      if (request.method === "GET") {
        const d = await stub.getMessages(token);
        return d ? json(d) : reject(401, "Unauthorized");
      }
      if (request.method === "POST") {
        const text = await bodyValue(request, "text", 2000);
        if (!text) return reject(400, "Invalid message");
        try {
          const msg = await stub.sendMessage(token, text, "visitor");
          return msg ? json(msg, 201) : reject(401, "Unauthorized");
        } catch { return reject(400, "Message limit reached"); }
      }
      return reject(405, "Method not allowed");
    }
    if (path.startsWith("/api/")) return reject(404, "Not found");
    // Assets remain on the same origin as the API.
    return e.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
