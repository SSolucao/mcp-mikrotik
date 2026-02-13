import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const { RouterOSAPI } = require("node-routeros");

type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LOG_LEVEL = (process.env.MIKROTIK_MCP_LOG_LEVEL ?? "info").toLowerCase() as LogLevel;

function nowMs(): number {
  return Date.now();
}

function shouldLog(level: Exclude<LogLevel, "silent">): boolean {
  const order: Record<Exclude<LogLevel, "silent">, number> = {
    debug: 10,
    info: 20,
    warn: 30,
    error: 40,
  };
  const configured = (LOG_LEVEL === "silent" ? "error" : LOG_LEVEL) as Exclude<LogLevel, "silent">;
  return order[level] >= order[configured];
}

function log(level: Exclude<LogLevel, "silent">, event: string, data?: unknown): void {
  if (!shouldLog(level)) return;
  const payload = data === undefined ? "" : ` ${JSON.stringify(data)}`;
  process.stderr.write(`[${level}] ${event}${payload}\n`);
}

function sendPlain(res: ServerResponse, status: number, message: string): void {
  res.statusCode = status;
  res.setHeader("content-type", "text/plain; charset=utf-8");
  res.end(message);
}

function getHeader(req: IncomingMessage, headerName: string): string | undefined {
  const value = req.headers[headerName.toLowerCase()];
  if (Array.isArray(value)) return value[0];
  return value;
}

function isAuthorizedRequest(req: IncomingMessage, authToken: string): boolean {
  const authHeader = getHeader(req, "authorization");
  if (!authHeader) return false;
  const [scheme, token] = authHeader.split(" ", 2);
  return scheme?.toLowerCase() === "bearer" && token === authToken;
}

function redactConnForLogs(conn: { host: string; port: number; user: string }): {
  host: string;
  port: number;
  user: string;
} {
  return { host: conn.host, port: conn.port, user: conn.user };
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  if (chunks.length === 0) return undefined;

  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  if (!raw) return undefined;

  return JSON.parse(raw) as unknown;
}

function summarizeJsonRpcForLogs(body: unknown): unknown {
  if (!body || typeof body !== "object") return body;
  const b = body as Record<string, unknown>;
  // Do not log params because it may contain passwords.
  return {
    jsonrpc: b.jsonrpc,
    id: b.id,
    method: b.method,
  };
}

const ConnSchema = z
  .object({
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535).default(8728),
    user: z.string().min(1),
    password: z.string().min(1),
    timeoutMs: z.number().int().min(1000).max(120_000).optional(),
  })
  .strict();

type Conn = z.infer<typeof ConnSchema>;

const RunToolShape = {
  conn: ConnSchema,
  // RouterOS API command path, e.g. "/system/resource/print"
  command: z.string().min(1),
  // Raw API words, e.g. ["=numbers=0", "=disabled=yes"] or ["?.id=*1"]
  words: z.array(z.string().min(1)).optional(),
} as const;

const RunSchema = z.object(RunToolShape).strict();
type RunInput = z.infer<typeof RunSchema>;

const PrintToolShape = {
  conn: ConnSchema,
  // Resource path without trailing /print, e.g. "/ip/firewall/filter"
  resource: z.string().min(1),
  // Limits which fields are returned (strongly recommended to reduce tokens).
  proplist: z.array(z.string().min(1)).optional(),
  // Simple equality filters applied server-side as RouterOS query words.
  where: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  // Advanced: raw query words (ex.: "?=disabled=no", "?~comment=allow").
  queryWords: z.array(z.string().min(1)).optional(),
  // Hard cap on returned items to avoid huge LLM responses.
  maxItems: z.number().int().min(1).max(2000).default(50),
  // If true, uses RouterOS count-only.
  countOnly: z.boolean().optional(),
} as const;

const PrintSchema = z.object(PrintToolShape).strict();
type PrintInput = z.infer<typeof PrintSchema>;

function toRosValue(value: string | number | boolean): string {
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

function normalizeResource(resource: string): string {
  const r = resource.trim();
  if (!r) return r;
  if (r.startsWith("/")) return r.replace(/\/+$/g, "");
  return `/${r}`.replace(/\/+$/g, "");
}

function summarizeResultForTokens(result: unknown, maxItems: number): unknown {
  if (Array.isArray(result)) {
    const total = result.length;
    const items = result.slice(0, maxItems);
    return {
      ok: true,
      total,
      returned: items.length,
      truncated: total > items.length,
      items,
    };
  }
  return { ok: true, result };
}


async function runRouterOsCommand(input: RunInput): Promise<unknown> {
  const timeout = input.conn.timeoutMs ?? 45_000;

  const api = new RouterOSAPI({
    host: input.conn.host,
    user: input.conn.user,
    password: input.conn.password,
    port: input.conn.port,
    timeout,
  });

  const startedAt = nowMs();
  try {
    await api.connect();

    const words = input.words ?? [];
    // node-routeros uses: write(command, paramsArray)
    const result = await api.write(input.command, words);
    return {
      ok: true,
      tookMs: nowMs() - startedAt,
      result,
    };
  } finally {
    try {
      api.close();
    } catch {
      // ignore
    }
  }
}

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "mcp-mikrotik",
    version: "0.2.0",
  });

  server.tool(
    "mikrotik__run",
    "Executa um comando via RouterOS API. Multi-tenant: conexao (host/porta/user/senha) vai no input da tool.",
    RunToolShape,
    async (input: RunInput) => {
      const connForLogs = redactConnForLogs({
        host: input.conn.host,
        port: input.conn.port,
        user: input.conn.user,
      });
      log("info", "tool.mikrotik__run", {
        conn: connForLogs,
        command: input.command,
        wordsCount: input.words?.length ?? 0,
      });

      const data = await runRouterOsCommand(input);
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
      };
    },
  );

  server.tool(
    "mikrotik__print",
    "Lista itens de um recurso via `<resource>/print` com suporte a proplist/filtros e truncamento para reduzir tokens.",
    PrintToolShape,
    async (input: PrintInput) => {
      const resource = normalizeResource(input.resource);
      const command = resource.endsWith("/print") ? resource : `${resource}/print`;

      const words: string[] = [];

      if (input.countOnly) {
        words.push("=count-only=yes");
      }

      if (input.proplist && input.proplist.length > 0) {
        words.push(`=.proplist=${input.proplist.join(",")}`);
      }

      if (input.where) {
        for (const [key, value] of Object.entries(input.where as Record<string, string | number | boolean>)) {
          // RouterOS query equality: ?=key=value
          words.push(`?=${key}=${toRosValue(value)}`);
        }
      }

      if (input.queryWords && input.queryWords.length > 0) {
        words.push(...input.queryWords);
      }

      const connForLogs = redactConnForLogs({ host: input.conn.host, port: input.conn.port, user: input.conn.user });
      log("info", "tool.mikrotik__print", {
        conn: connForLogs,
        command,
        maxItems: input.maxItems,
        wordsCount: words.length,
        hasProplist: Boolean(input.proplist?.length),
        hasWhere: Boolean(input.where && Object.keys(input.where).length),
      });

      const data = await runRouterOsCommand({ conn: input.conn, command, words });

      if (input.countOnly) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      const result = (data as any)?.result;
      const summarized = {
        ...(typeof data === "object" && data !== null ? (data as any) : { ok: true }),
        result: undefined,
        summary: summarizeResultForTokens(result, input.maxItems),
      };

      return { content: [{ type: "text", text: JSON.stringify(summarized, null, 2) }] };
    },
  );

  const FirewallListBaseShape = {
    conn: ConnSchema,
    chain: z.string().optional(),
    disabled: z.boolean().optional(),
    commentContains: z.string().min(1).optional(),
    proplist: z.array(z.string().min(1)).optional(),
    maxItems: z.number().int().min(1).max(2000).default(100),
  } as const;

  type FirewallListInput = {
    conn: Conn;
    chain?: string;
    disabled?: boolean;
    commentContains?: string;
    proplist?: string[];
    maxItems: number;
  };

  async function firewallList(resource: string, input: FirewallListInput, defaultProplist: string[]): Promise<unknown> {
    const where: Record<string, string | number | boolean> = {};
    if (input.chain) where.chain = input.chain;
    if (typeof input.disabled === "boolean") where.disabled = input.disabled;

    const queryWords: string[] = [];
    if (input.commentContains) {
      // RouterOS query regex/contains: ?~comment=...
      queryWords.push(`?~comment=${input.commentContains}`);
    }

    const command = `${normalizeResource(resource)}/print`;
    const words: string[] = [];

    const proplist = input.proplist?.length ? input.proplist : defaultProplist;
    if (proplist.length) {
      words.push(`=.proplist=${proplist.join(",")}`);
    }
    for (const [key, value] of Object.entries(where)) {
      words.push(`?=${key}=${toRosValue(value)}`);
    }
    if (queryWords.length) words.push(...queryWords);

    const data = await runRouterOsCommand({ conn: input.conn, command, words });
    const result = (data as any)?.result;
    return {
      ...(typeof data === "object" && data !== null ? (data as any) : { ok: true }),
      result: undefined,
      summary: summarizeResultForTokens(result, input.maxItems),
    };
  }

  server.tool(
    "mikrotik__firewall_filter_list",
    "Lista regras de /ip/firewall/filter com truncamento e proplist (economiza tokens).",
    FirewallListBaseShape,
    async (input: FirewallListInput) => {
      const defaultProplist = [
        ".id",
        "chain",
        "action",
        "protocol",
        "src-address",
        "dst-address",
        "src-port",
        "dst-port",
        "in-interface",
        "out-interface",
        "comment",
        "disabled",
      ];
      const data = await firewallList("/ip/firewall/filter", input, defaultProplist);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    "mikrotik__firewall_mangle_list",
    "Lista regras de /ip/firewall/mangle com truncamento e proplist (economiza tokens).",
    FirewallListBaseShape,
    async (input: FirewallListInput) => {
      const defaultProplist = [
        ".id",
        "chain",
        "action",
        "protocol",
        "src-address",
        "dst-address",
        "src-port",
        "dst-port",
        "in-interface",
        "out-interface",
        "comment",
        "disabled",
      ];
      const data = await firewallList("/ip/firewall/mangle", input, defaultProplist);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    "mikrotik__firewall_nat_list",
    "Lista regras de /ip/firewall/nat com truncamento e proplist (economiza tokens).",
    FirewallListBaseShape,
    async (input: FirewallListInput) => {
      const defaultProplist = [
        ".id",
        "chain",
        "action",
        "protocol",
        "src-address",
        "dst-address",
        "src-port",
        "dst-port",
        "to-addresses",
        "to-ports",
        "in-interface",
        "out-interface",
        "comment",
        "disabled",
      ];
      const data = await firewallList("/ip/firewall/nat", input, defaultProplist);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    "mikrotik__system_identity_get",
    "Retorna /system/identity/print (pequeno, ideal para testes).",
    { conn: ConnSchema },
    async (input: { conn: Conn }) => {
      const data = await runRouterOsCommand({ conn: input.conn, command: "/system/identity/print" });
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    "mikrotik__system_resource_get",
    "Retorna /system/resource/print (pequeno, ideal para version/uptime).",
    { conn: ConnSchema },
    async (input: { conn: Conn }) => {
      const data = await runRouterOsCommand({ conn: input.conn, command: "/system/resource/print" });
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    },
  );

  server.tool(
    "mikrotik__examples",
    "Exemplos de uso para comandos comuns.",
    {},
    async () => {
      const examples = {
        printResource: {
          conn: { host: "10.0.0.1", port: 8728, user: "admin", password: "***" },
          command: "/system/resource/print",
        },
        listInterfaces: {
          conn: { host: "10.0.0.1", port: 8728, user: "admin", password: "***" },
          command: "/interface/print",
        },
        disableInterfaceById: {
          conn: { host: "10.0.0.1", port: 8728, user: "admin", password: "***" },
          command: "/interface/set",
          words: ["=numbers=*1", "=disabled=yes"],
        },
      };
      return { content: [{ type: "text", text: JSON.stringify(examples, null, 2) }] };
    },
  );

  return server;
}

type SessionRuntime = {
  server: McpServer;
  transport: StreamableHTTPServerTransport;
};

async function main(): Promise<void> {
  const transportMode = (process.env.MIKROTIK_MCP_TRANSPORT ?? "http").toLowerCase();
  process.stderr.write(`[boot] transport=${transportMode}\n`);

  if (transportMode === "stdio") {
    process.stderr.write("[boot] starting stdio transport\n");
    const server = createMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    return;
  }

  if (transportMode !== "http") {
    throw new Error("MIKROTIK_MCP_TRANSPORT invalido. Use `http` ou `stdio`. ");
  }

  const host = process.env.MIKROTIK_MCP_HOST ?? "0.0.0.0";
  const port = Number(process.env.MIKROTIK_MCP_PORT ?? "3333");
  const mcpPath = process.env.MIKROTIK_MCP_PATH ?? "/mcp";
  const authToken = process.env.MIKROTIK_MCP_AUTH_TOKEN;
  process.stderr.write(
    `[boot] http host=${host} port=${port} path=${mcpPath} authToken=${authToken ? "set" : "missing"}\n`,
  );

  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("MIKROTIK_MCP_PORT invalida.");
  }
  if (!mcpPath.startsWith("/")) {
    throw new Error("MIKROTIK_MCP_PATH deve comecar com '/'.");
  }
  if (!authToken) {
    throw new Error("MIKROTIK_MCP_AUTH_TOKEN e obrigatorio em modo HTTP.");
  }

  const sessions = new Map<string, SessionRuntime>();

  const httpServer = createServer(async (req, res) => {
    const reqId = randomUUID().slice(0, 8);
    const startedAt = nowMs();

    try {
      const method = (req.method ?? "GET").toUpperCase();
      const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const sessionId = getHeader(req, "mcp-session-id");
      const sessionShort = sessionId ? `${sessionId.slice(0, 8)}…` : undefined;
      const remote = req.socket.remoteAddress ?? undefined;

      log("debug", "http.request", {
        reqId,
        method,
        path: requestUrl.pathname,
        session: sessionShort,
        remote,
      });

      if (requestUrl.pathname === "/healthz" && method === "GET") {
        sendPlain(res, 200, "ok");
        log("debug", "http.response", { reqId, status: 200, durationMs: nowMs() - startedAt });
        return;
      }

      if (requestUrl.pathname !== mcpPath) {
        sendPlain(res, 404, "Not found");
        log("debug", "http.response", { reqId, status: 404, durationMs: nowMs() - startedAt });
        return;
      }

      if (!isAuthorizedRequest(req, authToken)) {
        sendPlain(res, 401, "Unauthorized");
        log("warn", "http.unauthorized", {
          reqId,
          method,
          path: requestUrl.pathname,
          session: sessionShort,
          remote,
        });
        return;
      }

      if (method === "POST") {
        let body: unknown;
        try {
          body = await readJsonBody(req);
        } catch {
          sendPlain(res, 400, "Invalid JSON body");
          log("warn", "http.bad_json", { reqId, durationMs: nowMs() - startedAt });
          return;
        }

        log("debug", "mcp.rpc", { reqId, session: sessionShort, rpc: summarizeJsonRpcForLogs(body) });

        if (sessionId) {
          const existing = sessions.get(sessionId);
          if (!existing) {
            sendPlain(res, 400, "Invalid or missing session ID");
            log("warn", "mcp.session_invalid", { reqId, session: sessionShort });
            return;
          }
          await existing.transport.handleRequest(req, res, body);
          return;
        }

        if (!isInitializeRequest(body)) {
          sendPlain(res, 400, "Bad Request: No valid session ID provided");
          log("warn", "mcp.missing_session", { reqId, rpc: summarizeJsonRpcForLogs(body) });
          return;
        }

        const server = createMcpServer();
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid: string) => {
            sessions.set(sid, { server, transport });
            log("info", "mcp.session_initialized", {
              reqId,
              session: `${sid.slice(0, 8)}…`,
              sessions: sessions.size,
            });
          },
        });

        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid) {
            sessions.delete(sid);
            log("info", "mcp.session_closed", { session: `${sid.slice(0, 8)}…`, sessions: sessions.size });
          }
        };

        await server.connect(transport);
        await transport.handleRequest(req, res, body);
        return;
      }

      if (method === "GET" || method === "DELETE") {
        if (!sessionId) {
          sendPlain(res, 400, "Invalid or missing session ID");
          log("warn", "mcp.session_missing", { reqId, method });
          return;
        }
        const existing = sessions.get(sessionId);
        if (!existing) {
          sendPlain(res, 400, "Invalid or missing session ID");
          log("warn", "mcp.session_invalid", { reqId, session: sessionShort });
          return;
        }
        log("debug", "mcp.stream", { reqId, method, session: sessionShort });
        await existing.transport.handleRequest(req, res);
        return;
      }

      sendPlain(res, 405, "Method not allowed");
      log("debug", "http.response", { reqId, status: 405, durationMs: nowMs() - startedAt });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal server error";
      sendPlain(res, 500, message);
      log("error", "http.error", { error: message });
    }
  });

  httpServer.on("error", (err: unknown) => {
    const message = err instanceof Error ? err.stack ?? err.message : String(err);
    process.stderr.write(`[http] server error: ${message}\n`);
    process.exit(1);
  });

  httpServer.listen(port, host, () => {
    process.stderr.write(`MIKROTIK MCP HTTP server ouvindo em http://${host}:${port}${mcpPath}\n`);
  });

  process.on("SIGINT", async () => {
    for (const { transport, server } of sessions.values()) {
      await transport.close().catch(() => {});
      await server.close().catch(() => {});
    }
    sessions.clear();
    httpServer.close(() => process.exit(0));
  });
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
