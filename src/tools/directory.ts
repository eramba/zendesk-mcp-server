import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZendeskClient } from "../zendesk-client.js";
import {
  jsonText,
  offsetPaginationSchema,
  toolError,
} from "./shared.js";

export function registerDirectoryTools(
  server: McpServer,
  client: ZendeskClient,
): void {
  server.registerTool(
    "search",
    {
      description: "Search Zendesk across tickets, users, and organizations",
      inputSchema: {
        query: z.string().min(1),
        type: z.enum(["ticket", "user", "organization"]).optional(),
        ...offsetPaginationSchema,
      },
    },
    async ({ query, type, page, per_page, sort_by, sort_order }) => {
      try {
        return jsonText(
          await client.search({
            query,
            type,
            page,
            perPage: per_page,
            sortBy: sort_by,
            sortOrder: sort_order,
          }),
        );
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "get_current_user",
    {
      description: "Retrieve the Zendesk user authenticated for this MCP connection",
      inputSchema: {},
    },
    async () => {
      try {
        return jsonText(await client.getCurrentUser());
      } catch (error) {
        return toolError(error);
      }
    },
  );

  for (const [name, description, search] of [
    ["search_users", "Search Zendesk users by query", client.searchUsers.bind(client)],
    [
      "search_organizations",
      "Search Zendesk organizations by query",
      client.searchOrganizations.bind(client),
    ],
  ] as const) {
    server.registerTool(
      name,
      {
        description,
        inputSchema: {
          query: z.string().min(1),
          ...offsetPaginationSchema,
        },
      },
      async ({ query, page, per_page, sort_by, sort_order }) => {
        try {
          return jsonText(
            await search({
              query,
              page,
              perPage: per_page,
              sortBy: sort_by,
              sortOrder: sort_order,
            }),
          );
        } catch (error) {
          return toolError(error);
        }
      },
    );
  }
}
