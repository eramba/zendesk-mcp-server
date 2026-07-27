import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZendeskClient } from "../zendesk-client.js";
import { jsonText, toolError } from "./shared.js";

export function registerMetadataTools(
  server: McpServer,
  client: ZendeskClient,
): void {
  server.registerTool(
    "list_ticket_fields",
    {
      description: "List Zendesk ticket fields (including custom fields)",
      inputSchema: {},
    },
    async () => {
      try {
        return jsonText(await client.listTicketFields());
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
