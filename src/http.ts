#!/usr/bin/env node
import "dotenv/config";
import { readHttpOAuthConfig } from "./config.js";
import { createHttpRuntime } from "./http-runtime.js";

function main() {
  const config = readHttpOAuthConfig();
  const runtime = createHttpRuntime(config);

  const listener = runtime.app.listen(config.port, config.host, () => {
    console.error(
      `Zendesk MCP Streamable HTTP server listening on ${config.host}:${config.port}`,
    );
  });

  listener.on("error", (error) => {
    console.error("HTTP listener error:", error.message);
    runtime.close();
    process.exitCode = 1;
  });

  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`Received ${signal}; stopping HTTP listener`);
    runtime.beginShutdown();

    const timer = setTimeout(() => {
      console.error("HTTP shutdown grace period expired");
      listener.closeAllConnections();
      runtime.close();
      process.exitCode = 1;
    }, 10_000);
    timer.unref();

    listener.close((error) => {
      clearTimeout(timer);
      if (error) {
        console.error("HTTP shutdown error:", error.message);
        process.exitCode = 1;
      }
      runtime.close();
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
