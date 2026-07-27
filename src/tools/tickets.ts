import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZendeskClient } from "../zendesk-client.js";
import {
  collaboratorSchema,
  emailCcChangeSchema,
  followerChangeSchema,
  jsonText,
  offsetPaginationSchema,
  ticketPriorityEnum,
  ticketStatusEnum,
  ticketTypeEnum,
  toolError,
} from "./shared.js";

const customFieldsSchema = z.array(
  z.object({ id: z.number().int(), value: z.unknown() }),
);

const ticketWriteSchema = {
  subject: z.string().min(1).optional(),
  status: ticketStatusEnum.optional(),
  priority: ticketPriorityEnum.optional(),
  type: ticketTypeEnum.optional(),
  assignee_id: z.number().int().positive().optional(),
  requester_id: z.number().int().positive().optional(),
  organization_id: z.number().int().positive().optional(),
  group_id: z.number().int().positive().optional(),
  brand_id: z.number().int().positive().optional(),
  ticket_form_id: z.number().int().positive().optional(),
  custom_status_id: z.number().int().positive().optional(),
  problem_id: z.number().int().positive().optional(),
  tags: z.array(z.string().min(1)).optional(),
  collaborator_ids: z.array(z.number().int().positive()).optional(),
  additional_collaborators: z.array(collaboratorSchema).optional(),
  followers: z.array(followerChangeSchema).optional(),
  email_ccs: z.array(emailCcChangeSchema).max(48).optional(),
  custom_fields: customFieldsSchema.optional(),
  due_at: z.string().datetime().optional(),
};

export function registerTicketTools(
  server: McpServer,
  client: ZendeskClient,
): void {
  server.registerTool(
    "get_ticket",
    {
      description: "Retrieve a Zendesk ticket by its ID",
      inputSchema: { ticket_id: z.number().int().positive() },
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
      inputSchema: offsetPaginationSchema,
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
      inputSchema: { query: z.string().min(1), ...offsetPaginationSchema },
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
      inputSchema: { ticket_id: z.number().int().positive() },
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
        expected_updated_at: z.string().datetime(),
      },
    },
    async ({ ticket_id, comment, public: isPublic, expected_updated_at }) => {
      try {
        const ticket = await client.createTicketComment({
          ticketId: ticket_id,
          comment,
          public: isPublic,
          expectedUpdatedAt: expected_updated_at,
        });
        return jsonText({ message: "Comment created successfully", ticket });
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
        ...ticketWriteSchema,
        subject: z.string().min(1),
        description: z.string().min(1),
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
        ...ticketWriteSchema,
        expected_updated_at: z.string().datetime(),
      },
    },
    async ({ ticket_id, expected_updated_at, ...fields }) => {
      try {
        const ticket = await client.updateTicket(
          ticket_id,
          fields,
          expected_updated_at,
        );
        return jsonText({ message: "Ticket updated successfully", ticket });
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
