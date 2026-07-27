import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ZendeskClient } from "./zendesk-client.js";
import { registerZendeskTools } from "./tools/index.js";

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

  registerZendeskTools(server, client);

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
