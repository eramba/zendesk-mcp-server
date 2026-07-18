#!/usr/bin/env node
import "dotenv/config";

import { readHttpOAuthConfig } from "./config.js";
import { startHttpLifecycle } from "./http-lifecycle.js";
import { createHttpRuntime } from "./http-runtime.js";

function main() {
  const config = readHttpOAuthConfig();
  const runtime = createHttpRuntime(config);

  const listener = runtime.app.listen(config.port, config.host, () => {
    console.error(
      `Zendesk MCP Streamable HTTP server listening on ${config.host}:${config.port}`,
    );
  });
  startHttpLifecycle(runtime, listener);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  console.error("Fatal HTTP server error:", message);
  process.exit(1);
}
