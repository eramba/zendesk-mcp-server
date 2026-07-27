import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZendeskClient } from "../zendesk-client.js";
import { registerDirectoryTools } from "./directory.js";
import { registerMetadataTools } from "./metadata.js";
import { registerTicketTools } from "./tickets.js";
import { registerWorkflowTools } from "./workflows.js";

export function registerZendeskTools(
  server: McpServer,
  client: ZendeskClient,
): void {
  registerTicketTools(server, client);
  registerDirectoryTools(server, client);
  registerWorkflowTools(server, client);
  registerMetadataTools(server, client);
}
