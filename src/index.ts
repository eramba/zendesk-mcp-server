#!/usr/bin/env node
import "dotenv/config";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readZendeskConfig } from "./config.js";
import { buildZendeskServer } from "./server.js";
import { ZendeskClient } from "./zendesk-client.js";

async function main() {
  const config = readZendeskConfig();

  const client = new ZendeskClient({
    subdomain: config.subdomain,
    auth: {
      kind: "api-token",
      email: config.email,
      token: config.apiKey,
    },
  });
  const server = buildZendeskServer(client);

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Zendesk MCP server (TypeScript) running on stdio");
}

main().catch((error) => {
  console.error("Fatal server error:", error);
  process.exit(1);
});
