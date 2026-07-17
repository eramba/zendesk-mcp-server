#!/usr/bin/env node
import "dotenv/config";
import type { Server } from "node:http";

import { readHttpOAuthConfig } from "./config.js";
import { attachHttpListener, createHttpRuntime } from "./http-runtime.js";

const SHUTDOWN_GRACE_MS = 10_000;

function closeListener(listener: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => {
      console.error("HTTP shutdown grace period expired");
      process.exitCode = 1;
      listener.closeAllConnections();
      finish();
    }, SHUTDOWN_GRACE_MS);
    timer.unref();

    listener.close((error) => finish(error ?? undefined));
  });
}

function main() {
  const config = readHttpOAuthConfig();
  const runtime = createHttpRuntime(config);

  const listener = runtime.app.listen(config.port, config.host, () => {
    console.error(
      `Zendesk MCP Streamable HTTP server listening on ${config.host}:${config.port}`,
    );
  });
  attachHttpListener(runtime, () => closeListener(listener));
  runtime.startWorker();

  listener.on("error", (error) => {
    console.error("HTTP listener error:", error.message);
    process.exitCode = 1;
  });

  let shutdownStarted = false;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    console.error(`Received ${signal}; stopping HTTP listener`);
    void runtime.shutdown(signal).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : "Unknown error";
      console.error("HTTP shutdown error:", message);
      process.exitCode = 1;
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
