import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Express, Router } from "express";
import type { ZendeskBrokerOAuthProvider } from "./oauth/zendesk-broker-provider.js";
import type { ZendeskClientResolverLike } from "./oauth/zendesk-client-resolver.js";
import { buildZendeskServer } from "./server.js";

export type HttpAppOptions = {
  host: string;
  allowedHosts: string[];
  provider: ZendeskBrokerOAuthProvider;
  resolver: ZendeskClientResolverLike;
  oauthRouter: Router;
  resourceMetadataUrl: string;
  isReady: () => boolean;
  serverFactory?: typeof buildZendeskServer;
};

export function createHttpApp(options: HttpAppOptions): Express {
  const {
    host,
    allowedHosts,
    provider,
    resolver,
    oauthRouter,
    resourceMetadataUrl,
    isReady,
    serverFactory = buildZendeskServer,
  } = options;
  const app = createMcpExpressApp({ host, allowedHosts });

  app.get("/healthz", (_req, res) => {
    const ready = isReady();
    res.status(ready ? 200 : 503).json({ ok: ready });
  });

  app.use(oauthRouter);

  app.use(
    "/mcp",
    requireBearerAuth({
      verifier: provider,
      requiredScopes: ["zendesk:read", "zendesk:write"],
      resourceMetadataUrl,
    }),
  );

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
    let responseClosed = false;
    let resourcesClosed = false;
    let resourcesClosing: Promise<void> | undefined;

    const closeResources = (): Promise<void> => {
      if (resourcesClosing) return resourcesClosing;
      if (resourcesClosed || (!transport && !server)) return Promise.resolve();
      resourcesClosed = true;
      const allocatedTransport = transport;
      const allocatedServer = server;
      resourcesClosing = (async () => {
        if (allocatedTransport) {
          await allocatedTransport.close().catch(() => undefined);
        }
        if (allocatedServer) await allocatedServer.close().catch(() => undefined);
      })();
      return resourcesClosing;
    };

    res.once("close", () => {
      responseClosed = true;
      void closeResources();
    });

    try {
      const principalId = req.auth?.extra?.principalId;
      if (typeof principalId !== "string") {
        throw new Error("Authenticated principal is unavailable");
      }
      const client = await resolver.resolve(principalId);
      if (responseClosed) return;
      server = serverFactory(client);
      if (responseClosed) {
        await closeResources();
        return;
      }
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      if (responseClosed) {
        await closeResources();
        return;
      }
      await server.connect(transport);
      if (responseClosed) {
        await closeResources();
        return;
      }
      await transport.handleRequest(req, res, req.body);
    } catch {
      await closeResources();
      if (responseClosed) return;
      console.error("Error handling MCP request");
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
