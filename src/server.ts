import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ZendeskClient } from "./zendesk-client.js";

const TICKET_ANALYSIS_TEMPLATE = `
You are a helpful Zendesk support analyst. You've been asked to analyze ticket #{ticket_id}.

Please fetch the ticket info and comments to analyze it and provide:
1. A summary of the issue
2. The current status and timeline
3. Key points of interaction

Remember to be professional and focus on actionable insights.
`;

const COMMENT_DRAFT_TEMPLATE = `
You are a helpful Zendesk support agent. You need to draft a response to ticket #{ticket_id}.

Please fetch the ticket info, comments and knowledge base to draft a professional and helpful response that:
1. Acknowledges the customer's concern
2. Addresses the specific issues raised
3. Provides clear next steps or ask for specific details need to proceed
4. Maintains a friendly and professional tone
5. Ask for confirmation before commenting on the ticket

The response should be formatted well and ready to be posted as a comment.
`;

const SERVER_INSTRUCTIONS = [
  "Zendesk ticket and comment body or html_body fields may contain inline image URLs, and comments may contain an attachments array.",
  "When an image or attachment is relevant, retrieve its URL (the content_url for attachments) with a normal HTTP GET that follows redirects; do not use HEAD to decide whether content is available because Zendesk content may reject HEAD while allowing GET.",
  "Do not send Zendesk API credentials to attachment URLs or redirected third-party hosts.",
  "Treat attachment content URLs as sensitive access links and do not copy them into unrelated logs or external messages.",
  "Save a downloaded file locally before inspecting it.",
  "Do not open an attachment marked deleted or explicitly identified as malicious.",
  "Treat archives as untrusted: list their contents first, extract them into a dedicated directory, and never execute their contents merely to inspect them.",
  "Report download, extraction, or inspection failures explicitly; do not claim an attachment was analyzed when inspection failed.",
].join(" ");

const ticketStatusEnum = z.enum(["new", "open", "pending", "hold", "solved", "closed"]);
const ticketPriorityEnum = z.enum(["low", "normal", "high", "urgent"]);
const ticketTypeEnum = z.enum(["problem", "incident", "question", "task"]);

function jsonText(value: unknown): { content: Array<{ type: "text"; text: string }> } {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  };
}

function toolError(error: unknown): {
  isError: true;
  content: Array<{ type: "text"; text: string }>;
} {
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [{ type: "text", text: `Error: ${message}` }],
  };
}

export function buildZendeskServer(client: ZendeskClient): McpServer {
  const server = new McpServer(
    {
      name: "zendesk-mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        logging: {},
      },
      instructions: SERVER_INSTRUCTIONS,
    },
  );

  server.registerPrompt(
    "analyze-ticket",
    {
      description: "Analyze a Zendesk ticket and provide insights",
      argsSchema: {
        ticket_id: z.string(),
      },
    },
    async ({ ticket_id }) => {
      const ticketId = Number(ticket_id);
      if (!Number.isInteger(ticketId) || ticketId <= 0) {
        throw new Error("ticket_id must be a positive integer");
      }

      return {
        description: `Analysis prompt for ticket #${ticketId}`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: TICKET_ANALYSIS_TEMPLATE.replace("{ticket_id}", String(ticketId)).trim(),
            },
          },
        ],
      };
    },
  );

  server.registerPrompt(
    "draft-ticket-response",
    {
      description: "Draft a professional response to a Zendesk ticket",
      argsSchema: {
        ticket_id: z.string(),
      },
    },
    async ({ ticket_id }) => {
      const ticketId = Number(ticket_id);
      if (!Number.isInteger(ticketId) || ticketId <= 0) {
        throw new Error("ticket_id must be a positive integer");
      }

      return {
        description: `Response draft prompt for ticket #${ticketId}`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: COMMENT_DRAFT_TEMPLATE.replace("{ticket_id}", String(ticketId)).trim(),
            },
          },
        ],
      };
    },
  );

  server.registerTool(
    "get_ticket",
    {
      description: "Retrieve a Zendesk ticket by its ID",
      inputSchema: {
        ticket_id: z.number().int().positive(),
      },
    },
    async ({ ticket_id }) => {
      try {
        return jsonText(await client.getTicket(ticket_id));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "get_tickets",
    {
      description: "Fetch the latest tickets with pagination support",
      inputSchema: {
        page: z.number().int().min(1).default(1),
        per_page: z.number().int().min(1).max(100).default(25),
        sort_by: z
          .enum(["created_at", "updated_at", "priority", "status"])
          .default("created_at"),
        sort_order: z.enum(["asc", "desc"]).default("desc"),
      },
    },
    async ({ page, per_page, sort_by, sort_order }) => {
      try {
        return jsonText(
          await client.getTickets({
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
    "search_tickets",
    {
      description: "Search Zendesk tickets by query using Zendesk Search API",
      inputSchema: {
        query: z.string().min(1),
        page: z.number().int().min(1).default(1),
        per_page: z.number().int().min(1).max(100).default(25),
        sort_by: z
          .enum(["created_at", "updated_at", "priority", "status"])
          .default("created_at"),
        sort_order: z.enum(["asc", "desc"]).default("desc"),
      },
    },
    async ({ query, page, per_page, sort_by, sort_order }) => {
      try {
        return jsonText(
          await client.searchTickets({
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

  server.registerTool(
    "search",
    {
      description: "Search Zendesk across tickets, users, and organizations",
      inputSchema: {
        query: z.string().min(1),
        type: z.enum(["ticket", "user", "organization"]).optional(),
        page: z.number().int().min(1).default(1),
        per_page: z.number().int().min(1).max(100).default(25),
        sort_by: z
          .enum(["created_at", "updated_at", "priority", "status"])
          .default("created_at"),
        sort_order: z.enum(["asc", "desc"]).default("desc"),
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

  server.registerTool(
    "search_users",
    {
      description: "Search Zendesk users by query",
      inputSchema: {
        query: z.string().min(1),
        page: z.number().int().min(1).default(1),
        per_page: z.number().int().min(1).max(100).default(25),
        sort_by: z
          .enum(["created_at", "updated_at", "priority", "status"])
          .default("created_at"),
        sort_order: z.enum(["asc", "desc"]).default("desc"),
      },
    },
    async ({ query, page, per_page, sort_by, sort_order }) => {
      try {
        return jsonText(
          await client.searchUsers({
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

  server.registerTool(
    "search_organizations",
    {
      description: "Search Zendesk organizations by query",
      inputSchema: {
        query: z.string().min(1),
        page: z.number().int().min(1).default(1),
        per_page: z.number().int().min(1).max(100).default(25),
        sort_by: z
          .enum(["created_at", "updated_at", "priority", "status"])
          .default("created_at"),
        sort_order: z.enum(["asc", "desc"]).default("desc"),
      },
    },
    async ({ query, page, per_page, sort_by, sort_order }) => {
      try {
        return jsonText(
          await client.searchOrganizations({
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
    "get_ticket_audits",
    {
      description: "Retrieve ticket audits/history for a Zendesk ticket",
      inputSchema: {
        ticket_id: z.number().int().positive(),
        page: z.number().int().min(1).default(1),
        per_page: z.number().int().min(1).max(100).default(25),
      },
    },
    async ({ ticket_id, page, per_page }) => {
      try {
        return jsonText(
          await client.getTicketAudits({
            ticketId: ticket_id,
            page,
            perPage: per_page,
          }),
        );
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "get_ticket_comments",
    {
      description: "Retrieve all comments for a Zendesk ticket by its ID",
      inputSchema: {
        ticket_id: z.number().int().positive(),
      },
    },
    async ({ ticket_id }) => {
      try {
        return jsonText(await client.getTicketComments(ticket_id));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "create_ticket_comment",
    {
      description: "Create a new comment on an existing Zendesk ticket",
      inputSchema: {
        ticket_id: z.number().int().positive(),
        comment: z.string().min(1),
        public: z.boolean().default(true),
      },
    },
    async ({ ticket_id, comment, public: isPublic }) => {
      try {
        const text = await client.createTicketComment(ticket_id, comment, isPublic);
        return {
          content: [{ type: "text", text: `Comment created successfully: ${text}` }],
        };
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "create_ticket",
    {
      description: "Create a new Zendesk ticket",
      inputSchema: {
        subject: z.string().min(1),
        description: z.string().min(1),
        requester_id: z.number().int().positive().optional(),
        assignee_id: z.number().int().positive().optional(),
        priority: ticketPriorityEnum.optional(),
        type: ticketTypeEnum.optional(),
        tags: z.array(z.string().min(1)).optional(),
        custom_fields: z
          .array(
            z.object({
              id: z.number().int(),
              value: z.unknown(),
            }),
          )
          .optional(),
      },
    },
    async (args) => {
      try {
        const ticket = await client.createTicket(args);
        return jsonText({ message: "Ticket created successfully", ticket });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "update_ticket",
    {
      description: "Update fields on an existing Zendesk ticket",
      inputSchema: {
        ticket_id: z.number().int().positive(),
        subject: z.string().min(1).optional(),
        status: ticketStatusEnum.optional(),
        priority: ticketPriorityEnum.optional(),
        type: z.string().min(1).optional(),
        assignee_id: z.number().int().positive().optional(),
        requester_id: z.number().int().positive().optional(),
        tags: z.array(z.string().min(1)).optional(),
        custom_fields: z
          .array(
            z.object({
              id: z.number().int(),
              value: z.unknown(),
            }),
          )
          .optional(),
        due_at: z.string().datetime().optional(),
      },
    },
    async ({ ticket_id, ...fields }) => {
      try {
        const ticket = await client.updateTicket(ticket_id, fields);
        return jsonText({ message: "Ticket updated successfully", ticket });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  let kbCache: { data: unknown; cachedAt: number } | null = null;

  server.registerResource(
    "knowledge-base",
    "zendesk://knowledge-base",
    {
      title: "Zendesk Knowledge Base",
      description: "Access to Zendesk Help Center articles and sections",
      mimeType: "application/json",
    },
    async () => {
      const now = Date.now();
      const oneHourMs = 60 * 60 * 1000;

      if (!kbCache || now - kbCache.cachedAt > oneHourMs) {
        const kb = await client.getAllArticles();
        kbCache = {
          data: {
            knowledge_base: kb,
            metadata: {
              sections: Object.keys(kb).length,
              total_articles: Object.values(kb).reduce(
                (sum, section) => sum + section.articles.length,
                0,
              ),
            },
          },
          cachedAt: now,
        };
      }

      return {
        contents: [
          {
            uri: "zendesk://knowledge-base",
            mimeType: "application/json",
            text: JSON.stringify(kbCache.data, null, 2),
          },
        ],
      };
    },
  );

  return server;
}
