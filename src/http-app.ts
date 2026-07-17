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

type PendingHttpRuntimeOptions = {
  host: string;
  allowedHosts: string[];
  serverFactory?: typeof buildZendeskServer;
  [legacyOption: string]: unknown;
};

function hasOAuthDependencies(
  options: HttpAppOptions | PendingHttpRuntimeOptions,
): options is HttpAppOptions {
  return (
    "provider" in options &&
    "resolver" in options &&
    "oauthRouter" in options &&
    "resourceMetadataUrl" in options &&
    "isReady" in options
  );
}

export function createHttpApp(options: HttpAppOptions): Express;
/** @deprecated Removed by the Task 20 HTTP runtime composition. */
export function createHttpApp(options: PendingHttpRuntimeOptions): Express;
export function createHttpApp(
  options: HttpAppOptions | PendingHttpRuntimeOptions,
): Express {
  if (!hasOAuthDependencies(options)) {
    throw new Error("OAuth HTTP dependencies are required");
  }
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
      const principalId = req.auth?.extra?.principalId;
      if (typeof principalId !== "string") {
        throw new Error("Authenticated principal is unavailable");
      }
      const client = await resolver.resolve(principalId);
      server = serverFactory(client);
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch {
      await closeResources();
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
