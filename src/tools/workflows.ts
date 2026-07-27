import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZendeskClient } from "../zendesk-client.js";
import { cursorPaginationSchema, jsonText, toolError } from "./shared.js";

export function registerWorkflowTools(
  server: McpServer,
  client: ZendeskClient,
): void {
  server.registerTool(
    "list_views",
    {
      description: "List active Zendesk views visible to the authenticated agent",
      inputSchema: cursorPaginationSchema,
    },
    async ({ page_size, after }) => {
      try {
        const page = await client.listViews({ pageSize: page_size, after });
        const { items: views, ...pagination } = page;
        return jsonText({ views, ...pagination });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "list_view_tickets",
    {
      description: "List Zendesk tickets contained in a visible view",
      inputSchema: {
        view_id: z.number().int().positive(),
        ...cursorPaginationSchema,
      },
    },
    async ({ view_id, page_size, after }) => {
      try {
        const page = await client.listViewTickets(view_id, {
          pageSize: page_size,
          after,
        });
        const { items: tickets, ...pagination } = page;
        return jsonText({ tickets, ...pagination });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "list_assignable_groups",
    {
      description: "List groups available for ticket assignment",
      inputSchema: cursorPaginationSchema,
    },
    async ({ page_size, after }) => {
      try {
        const page = await client.listAssignableGroups({
          pageSize: page_size,
          after,
        });
        const { items: groups, ...pagination } = page;
        return jsonText({ groups, ...pagination });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "list_group_members",
    {
      description: "List memberships and users for a Zendesk group",
      inputSchema: {
        group_id: z.number().int().positive(),
        ...cursorPaginationSchema,
      },
    },
    async ({ group_id, page_size, after }) => {
      try {
        const page = await client.listGroupMembers(group_id, {
          pageSize: page_size,
          after,
        });
        const { items: memberships, ...rest } = page;
        return jsonText({ memberships, ...rest });
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
