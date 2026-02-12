#!/usr/bin/env node
import "dotenv/config";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildZendeskServer } from "./server.js";
import { ZendeskClient } from "./zendesk-client.js";

type Env = {
  ZENDESK_SUBDOMAIN: string;
  ZENDESK_EMAIL: string;
  ZENDESK_API_KEY: string;
};

function readEnv(): Env {
  const required = ["ZENDESK_SUBDOMAIN", "ZENDESK_EMAIL", "ZENDESK_API_KEY"] as const;

  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }

  return {
    ZENDESK_SUBDOMAIN: process.env.ZENDESK_SUBDOMAIN as string,
    ZENDESK_EMAIL: process.env.ZENDESK_EMAIL as string,
    ZENDESK_API_KEY: process.env.ZENDESK_API_KEY as string,
  };
}

async function main() {
  const env = readEnv();

  const client = new ZendeskClient(
    env.ZENDESK_SUBDOMAIN,
    env.ZENDESK_EMAIL,
    env.ZENDESK_API_KEY,
  );
  const server = buildZendeskServer(client);

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Zendesk MCP server (TypeScript) running on stdio");
}

main().catch((error) => {
  console.error("Fatal server error:", error);
  process.exit(1);
});
