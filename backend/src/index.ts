
import { DurableObject } from "cloudflare:workers";

type ChatMessage = {
  id: string;
  text: string;
  createdAt: string;
  from: "visitor" | "admin";
};

type ChatData = {
  createdAt: string;
  messages: ChatMessage[];
};

type AppEnv = Env & { ADMIN_API_KEY?: string };

function json(data: unknown, status = 200): Response {
  return Response.json(data, { status });
}

async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export class MyDurableObject extends DurableObject<Env> {
  // Métodos del registro central de chats

  async registerChat(id: string): Promise<void> {
    const ids = await this.ctx.storage.get<string[]>("chatIds") ?? [];
    if (!ids.includes(id)) {
      ids.push(id);
      await this.ctx.storage.put("chatIds", ids);
    }
  }

  async listChatIds(): Promise<string[]> {
    return await this.ctx.storage.get<string[]>("chatIds") ?? [];
  }

  async unregisterChat(id: string): Promise<void> {
    const ids = await this.listChatIds();
    await this.ctx.storage.put(
      "chatIds",
      ids.filter((existing) => existing !== id)
    );
  }

  // Métodos de cada conversación

  async initialize(token: string): Promise<void> {
    const existing = await this.ctx.storage.get<ChatData>("chat");
    if (existing) throw new Error("Already initialized");

    await this.ctx.storage.put({
      tokenHash: await hashToken(token),
      chat: {
        createdAt: new Date().toISOString(),
        messages: [],
      } satisfies ChatData,
    });
  }

  private async authorized(token: string): Promise<boolean> {
    if (!token) return false;
    const hash = await this.ctx.storage.get<string>("tokenHash");
    return !!hash && hash === await hashToken(token);
  }

  async getMessages(token: string): Promise<ChatData | null> {
    if (!(await this.authorized(token))) return null;
    return await this.ctx.storage.get<ChatData>("chat") ?? null;
  }

  async adminGet(): Promise<ChatData | null> {
    return await this.ctx.storage.get<ChatData>("chat") ?? null;
  }

  async sendMessage(
    token: string | null,
    text: string,
    from: "visitor" | "admin"
  ): Promise<ChatMessage | null> {
    if (from === "visitor" && !(await this.authorized(token ?? ""))) {
      return null;
    }

    const chat = await this.ctx.storage.get<ChatData>("chat");
    if (!chat) return null;

    if (chat.messages.length >= 100) {
      throw new Error("Message limit reached");
    }

    const message: ChatMessage = {
      id: crypto.randomUUID(),
      text,
      from,
      createdAt: new Date().toISOString(),
    };

    chat.messages.push(message);
    await this.ctx.storage.put("chat", chat);

    return message;
  }

  async adminDelete(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

export default {
  async fetch(request, env): Promise<Response> {
    const appEnv = env as AppEnv;
    const url = new URL(request.url);
    const path = url.pathname;
    const registry = env.MY_DURABLE_OBJECT.getByName("__registry__");

    const bearer = request.headers.get("Authorization")
      ?.replace(/^Bearer /i, "") ?? "";

    const adminHeader = request.headers.get("X-Admin-Key") ?? "";
    const isAdmin = !!appEnv.ADMIN_API_KEY &&
      adminHeader === appEnv.ADMIN_API_KEY;

    // API administrativa: requiere clave privada
    if (path.startsWith("/api/admin/")) {
      if (!isAdmin) return json({ error: "Unauthorized" }, 401);

      if (path === "/api/admin/chats" && request.method === "GET") {
        const ids = await registry.listChatIds();

        const chats = await Promise.all(ids.map(async (id) => {
          const stub = env.MY_DURABLE_OBJECT.getByName(id);
          const chat = await stub.adminGet();

          return chat ? {
            id,
            createdAt: chat.createdAt,
            messageCount: chat.messages.length,
            lastMessage: chat.messages.at(-1) ?? null,
          } : null;
        }));

        return json({ chats: chats.filter(Boolean) });
      }

      const match = path.match(
        /^\/api\/admin\/chats\/([0-9a-f-]{36})(?:\/messages)?$/
      );

      if (!match) return json({ error: "Not found" }, 404);

      const id = match[1];
      const stub = env.MY_DURABLE_OBJECT.getByName(id);

      if (request.method === "GET") {
        const chat = await stub.adminGet();
        return chat ? json(chat) : json({ error: "Not found" }, 404);
      }

      if (request.method === "DELETE" &&
          path === `/api/admin/chats/${id}`) {
        const existing = await stub.adminGet();
        if (!existing) return json({ error: "Not found" }, 404);

        await stub.adminDelete();
        await registry.unregisterChat(id);
        return json({ deleted: true });
      }

      if (request.method === "POST" &&
          path.endsWith("/messages")) {
        const body = await readMessage(request);
        if (!body) return json({ error: "Invalid message" }, 400);

        try {
          const msg = await stub.sendMessage(null, body, "admin");
          return msg ? json(msg, 201) : json({ error: "Not found" }, 404);
        } catch {
          return json({ error: "Message limit reached" }, 400);
        }
      }

      return json({ error: "Method not allowed" }, 405);
    }

    // Crear conversación
    if (path === "/api/chats" && request.method === "POST") {
      const chatId = crypto.randomUUID();
      const token = crypto.randomUUID() + crypto.randomUUID();
      const stub = env.MY_DURABLE_OBJECT.getByName(chatId);

      await stub.initialize(token);
      await registry.registerChat(chatId);

      return json({ chatId, token }, 201);
    }

    // API del visitante
    const match = path.match(
      /^\/api\/chats\/([0-9a-f-]{36})\/messages$/
    );

    if (!match) return json({ error: "Not found" }, 404);
    if (!bearer) return json({ error: "Unauthorized" }, 401);

    const stub = env.MY_DURABLE_OBJECT.getByName(match[1]);

    if (request.method === "GET") {
      const chat = await stub.getMessages(bearer);
      return chat ? json(chat) : json({ error: "Unauthorized" }, 401);
    }

    if (request.method === "POST") {
      const body = await readMessage(request);
      if (!body) return json({ error: "Invalid message" }, 400);

      try {
        const msg = await stub.sendMessage(bearer, body, "visitor");
        return msg ? json(msg, 201) : json({ error: "Unauthorized" }, 401);
      } catch {
        return json({ error: "Message limit reached" }, 400);
      }
    }

    return json({ error: "Method not allowed" }, 405);
  },
} satisfies ExportedHandler<Env>;

async function readMessage(request: Request): Promise<string | null> {
  try {
    const body: unknown = await request.json();
    if (!body || typeof body !== "object" || !("text" in body)) {
      return null;
    }

    const text = (body as { text: unknown }).text;
    if (typeof text !== "string" ||
        !text.trim() || text.length > 2000) {
      return null;
    }

    return text.trim();
  } catch {
    return null;
  }
}
