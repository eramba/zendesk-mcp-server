import type { RequestHandler } from "express";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SafeAuthError } from "./internal-auth/errors.js";
import type { UserClientResolverLike } from "./internal-auth/client-resolver.js";
import { buildZendeskServer } from "./server.js";

export type HttpAppOptions = {
  host: string;
  allowedHosts: string[];
  authenticateBearer(token: string): { userId: string } | undefined;
  resolver: UserClientResolverLike;
  linkHandlers: {
    link: RequestHandler;
    callback: RequestHandler;
  };
  serverFactory?: typeof buildZendeskServer;
};

function bearerFromHeader(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const match = /^Bearer ([^\s]+)$/i.exec(header);
  return match?.[1];
}

export function createHttpApp({
  host,
  allowedHosts,
  authenticateBearer,
  resolver,
  linkHandlers,
  serverFactory = buildZendeskServer,
}: HttpAppOptions) {
  const app = createMcpExpressApp({ host, allowedHosts });

  app.get("/healthz", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.get("/oauth/link", linkHandlers.link);
  app.get("/oauth/callback", linkHandlers.callback);

  app.use("/mcp", (req, res, next) => {
    const bearer = bearerFromHeader(req.headers.authorization);
    let authenticated: { userId: string } | undefined;
    try {
      authenticated = bearer ? authenticateBearer(bearer) : undefined;
    } catch {
      console.error("MCP bearer lookup unavailable");
      res.status(503).json({
        jsonrpc: "2.0",
        error: {
          code: -32002,
          message: "Authentication temporarily unavailable",
        },
        id: null,
      });
      return;
    }
    if (!authenticated) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized" },
        id: null,
      });
      return;
    }
    res.locals.userId = authenticated.userId;
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
    const controller = new AbortController();

    const closeResources = async () => {
      if (closed) return;
      closed = true;
      if (transport) await transport.close().catch(() => undefined);
      if (server) await server.close().catch(() => undefined);
    };

    const abort = () => controller.abort();
    req.once("aborted", abort);
    res.once("close", () => {
      abort();
      void closeResources();
    });

    try {
      const client = await resolver.resolve(
        res.locals.userId as string,
        controller.signal,
      );
      server = serverFactory(client);
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      await closeResources();
      if (!res.headersSent) {
        let status = 500;
        let code = -32603;
        let message = "Internal server error";
        if (error instanceof SafeAuthError) {
          console.error(
            `MCP credential resolution failed (${error.category}, ${error.correlationId})`,
          );
          if (
            error.category === "reauthorization_required" ||
            error.category === "unauthorized"
          ) {
            status = 401;
            code = -32001;
            message = "Unauthorized";
            res.setHeader("WWW-Authenticate", "Bearer");
          } else {
            status = 503;
            code = -32002;
            message = "Authentication temporarily unavailable";
          }
        } else {
          console.error("Error handling MCP request");
        }
        res.status(status).json({
          jsonrpc: "2.0",
          error: { code, message },
          id: null,
        });
      }
    } finally {
      req.removeListener("aborted", abort);
    }
  });

  return app;
}
