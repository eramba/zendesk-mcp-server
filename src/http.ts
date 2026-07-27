#!/usr/bin/env node
import "dotenv/config";
import { readHttpConfig, readZendeskConfig } from "./config.js";
import { createHttpApp } from "./http-app.js";
import { ZendeskClient } from "./zendesk-client.js";

function main() {
  const zendeskConfig = readZendeskConfig();
  const httpConfig = readHttpConfig();
  const client = new ZendeskClient({
    subdomain: zendeskConfig.subdomain,
    auth: {
      kind: "api-token",
      email: zendeskConfig.email,
      token: zendeskConfig.apiKey,
    },
  });
  const app = createHttpApp({
    host: httpConfig.host,
    allowedHosts: httpConfig.allowedHosts,
    bearerToken: httpConfig.bearerToken,
    client,
  });

  const listener = app.listen(httpConfig.port, httpConfig.host, () => {
    console.error(
      `Zendesk MCP Streamable HTTP server listening on ${httpConfig.host}:${httpConfig.port}`,
    );
  });

  listener.on("error", (error) => {
    console.error("HTTP listener error:", error.message);
    process.exitCode = 1;
  });

  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`Received ${signal}; stopping HTTP listener`);

    const timer = setTimeout(() => {
      console.error("HTTP shutdown grace period expired");
      listener.closeAllConnections();
      process.exitCode = 1;
    }, 10_000);
    timer.unref();

    listener.close((error) => {
      clearTimeout(timer);
      if (error) {
        console.error("HTTP shutdown error:", error.message);
        process.exitCode = 1;
      }
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  console.error("Fatal HTTP server error:", message);
  process.exit(1);
}
