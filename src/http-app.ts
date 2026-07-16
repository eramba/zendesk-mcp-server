import { timingSafeEqual } from "node:crypto";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildZendeskServer } from "./server.js";
import { ZendeskClient } from "./zendesk-client.js";

export type HttpAppOptions = {
  host: string;
  allowedHosts: string[];
  bearerToken: string;
  client: ZendeskClient;
  serverFactory?: typeof buildZendeskServer;
};

function bearerMatches(header: string | undefined, expected: string): boolean {
  if (!header) return false;
  const match = /^Bearer ([^\s]+)$/i.exec(header);
  if (!match) return false;

  const actualBuffer = Buffer.from(match[1], "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

export function createHttpApp({
  host,
  allowedHosts,
  bearerToken,
  client,
  serverFactory = buildZendeskServer,
}: HttpAppOptions) {
  const app = createMcpExpressApp({ host, allowedHosts });

  app.get("/healthz", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.use("/mcp", (req, res, next) => {
    if (!bearerMatches(req.headers.authorization, bearerToken)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized" },
        id: null,
      });
      return;
    }
    next();
  });

  app.get("/mcp", (_req, res) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  });

  app.delete("/mcp", (_req, res) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  });

  app.post("/mcp", async (req, res) => {
    let server: ReturnType<typeof buildZendeskServer> | undefined;
    let transport: StreamableHTTPServerTransport | undefined;
    let closed = false;

    const closeResources = async () => {
      if (closed) return;
      closed = true;
      if (transport) await transport.close().catch(() => undefined);
      if (server) await server.close().catch(() => undefined);
    };

    res.once("close", () => {
      void closeResources();
    });

    try {
      server = serverFactory(client);
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      await closeResources();
      const message = error instanceof Error ? error.message : "Unknown error";
      console.error("Error handling MCP request:", message);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  return app;
}
