import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZendeskClient } from "../zendesk-client.js";
import {
  cursorPaginationSchema,
  jsonText,
  toolError,
} from "./shared.js";

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

  server.registerTool(
    "get_ticket_metrics",
    {
      description: "Retrieve reply, wait, and resolution metrics for a ticket",
      inputSchema: { ticket_id: z.number().int().positive() },
    },
    async ({ ticket_id }) => {
      try {
        return jsonText(await client.getTicketMetrics(ticket_id));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "list_ticket_forms",
    {
      description: "List active Zendesk ticket forms",
      inputSchema: cursorPaginationSchema,
    },
    async ({ page_size, after }) => {
      try {
        const page = await client.listTicketForms({ pageSize: page_size, after });
        const { items: forms, ...pagination } = page;
        return jsonText({ forms, ...pagination });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "list_custom_statuses",
    {
      description: "List active Zendesk custom ticket statuses",
      inputSchema: {},
    },
    async () => {
      try {
        return jsonText(await client.listCustomStatuses());
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
