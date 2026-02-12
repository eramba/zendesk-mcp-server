import type {
  TicketListResult,
  ZendeskComment,
  ZendeskKnowledgeBase,
  ZendeskTicket,
} from "./types.js";

type TicketPayload = {
  id?: number;
  subject?: string;
  description?: string;
  status?: string;
  priority?: string;
  type?: string;
  created_at?: string;
  updated_at?: string;
  requester_id?: number;
  assignee_id?: number;
  organization_id?: number;
  tags?: string[];
};

type ZendeskApiError = {
  error?: string;
  description?: string;
  details?: unknown;
  title?: string;
};

function normalizeTicket(ticket: TicketPayload): ZendeskTicket {
  return {
    id: Number(ticket.id),
    subject: ticket.subject ?? null,
    description: ticket.description ?? null,
    status: ticket.status ?? null,
    priority: ticket.priority ?? null,
    type: ticket.type ?? null,
    created_at: ticket.created_at ?? null,
    updated_at: ticket.updated_at ?? null,
    requester_id: ticket.requester_id ?? null,
    assignee_id: ticket.assignee_id ?? null,
    organization_id: ticket.organization_id ?? null,
    tags: Array.isArray(ticket.tags) ? ticket.tags : [],
  };
}

export class ZendeskClient {
  private readonly baseUrl: string;
  private readonly authHeader: string;

  constructor(subdomain: string, email: string, token: string) {
    this.baseUrl = `https://${subdomain}.zendesk.com/api/v2`;
    this.authHeader =
      "Basic " + Buffer.from(`${email}/token:${token}`).toString("base64");
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Authorization: this.authHeader,
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
    });

    if (!response.ok) {
      const bodyText = await response.text();
      let parsedError: ZendeskApiError | undefined;

      try {
        parsedError = JSON.parse(bodyText) as ZendeskApiError;
      } catch {
        parsedError = undefined;
      }

      const detail = parsedError
        ? [
            parsedError.title,
            parsedError.error,
            parsedError.description,
            parsedError.details ? JSON.stringify(parsedError.details) : undefined,
          ]
            .filter(Boolean)
            .join(" | ")
        : bodyText;

      throw new Error(
        `Zendesk API error ${response.status} ${response.statusText}${detail ? `: ${detail}` : ""}`,
      );
    }

    return (await response.json()) as T;
  }

  async getTicket(ticketId: number): Promise<ZendeskTicket> {
    const data = await this.request<{ ticket: TicketPayload }>(`/tickets/${ticketId}.json`);
    return normalizeTicket(data.ticket);
  }

  async getTicketComments(ticketId: number): Promise<ZendeskComment[]> {
    const data = await this.request<{
      comments: Array<{
        id: number;
        author_id?: number;
        body?: string;
        html_body?: string;
        public?: boolean;
        created_at?: string;
      }>;
    }>(`/tickets/${ticketId}/comments.json`);

    return data.comments.map((comment) => ({
      id: Number(comment.id),
      author_id: comment.author_id ?? null,
      body: comment.body ?? null,
      html_body: comment.html_body ?? null,
      public: Boolean(comment.public),
      created_at: comment.created_at ?? null,
    }));
  }

  async getTickets(options: {
    page: number;
    perPage: number;
    sortBy: string;
    sortOrder: "asc" | "desc";
  }): Promise<TicketListResult> {
    const query = new URLSearchParams({
      page: String(options.page),
      per_page: String(Math.min(options.perPage, 100)),
      sort_by: options.sortBy,
      sort_order: options.sortOrder,
    });

    const data = await this.request<{
      tickets: TicketPayload[];
      next_page: string | null;
      previous_page: string | null;
    }>(`/tickets.json?${query.toString()}`);

    const tickets = data.tickets.map(normalizeTicket);

    return {
      tickets,
      page: options.page,
      per_page: Math.min(options.perPage, 100),
      count: tickets.length,
      sort_by: options.sortBy,
      sort_order: options.sortOrder,
      has_more: data.next_page !== null,
      next_page: data.next_page ? options.page + 1 : null,
      previous_page: data.previous_page && options.page > 1 ? options.page - 1 : null,
    };
  }

  async createTicket(input: {
    subject: string;
    description: string;
    requester_id?: number;
    assignee_id?: number;
    priority?: string;
    type?: string;
    tags?: string[];
    custom_fields?: Array<{ id: number; value: unknown }>;
  }): Promise<ZendeskTicket> {
    const data = await this.request<{ ticket: TicketPayload }>("/tickets.json", {
      method: "POST",
      body: JSON.stringify({
        ticket: {
          subject: input.subject,
          comment: { body: input.description, public: true },
          description: input.description,
          requester_id: input.requester_id,
          assignee_id: input.assignee_id,
          priority: input.priority,
          type: input.type,
          tags: input.tags,
          custom_fields: input.custom_fields,
        },
      }),
    });

    return normalizeTicket(data.ticket);
  }

  async updateTicket(
    ticketId: number,
    fields: {
      subject?: string;
      status?: string;
      priority?: string;
      type?: string;
      assignee_id?: number;
      requester_id?: number;
      tags?: string[];
      custom_fields?: Array<{ id: number; value: unknown }>;
      due_at?: string;
    },
  ): Promise<ZendeskTicket> {
    const data = await this.request<{ ticket: TicketPayload }>(`/tickets/${ticketId}.json`, {
      method: "PUT",
      body: JSON.stringify({
        ticket: fields,
      }),
    });

    return normalizeTicket(data.ticket);
  }

  async createTicketComment(ticketId: number, comment: string, isPublic = true): Promise<string> {
    await this.request<{ ticket: TicketPayload }>(`/tickets/${ticketId}.json`, {
      method: "PUT",
      body: JSON.stringify({
        ticket: {
          comment: {
            body: comment,
            public: isPublic,
          },
        },
      }),
    });

    return comment;
  }

  async getAllArticles(): Promise<ZendeskKnowledgeBase> {
    const sectionMap = new Map<number, { name: string; description: string | null }>();
    let nextSectionsPath: string | null = "/help_center/sections.json?page[size]=100";

    while (nextSectionsPath) {
      const data = await this.request<{
        sections: Array<{ id: number; name: string; description?: string }>;
        links?: { next?: string | null };
        next_page?: string | null;
      }>(nextSectionsPath);

      for (const section of data.sections) {
        sectionMap.set(section.id, {
          name: section.name,
          description: section.description ?? null,
        });
      }

      nextSectionsPath = this.nextPath(data.links?.next ?? data.next_page ?? null);
    }

    const kb: ZendeskKnowledgeBase = {};

    for (const [sectionId, section] of sectionMap) {
      const articles: ZendeskKnowledgeBase[string]["articles"] = [];
      let nextArticlesPath: string | null = `/help_center/sections/${sectionId}/articles.json?page[size]=100`;

      while (nextArticlesPath) {
        const data = await this.request<{
          articles: Array<{
            id: number;
            title: string;
            body?: string;
            updated_at?: string;
            html_url?: string;
          }>;
          links?: { next?: string | null };
          next_page?: string | null;
        }>(nextArticlesPath);

        for (const article of data.articles) {
          articles.push({
            id: article.id,
            title: article.title,
            body: article.body ?? null,
            updated_at: article.updated_at ?? null,
            url: article.html_url ?? null,
          });
        }

        nextArticlesPath = this.nextPath(data.links?.next ?? data.next_page ?? null);
      }

      kb[section.name] = {
        section_id: sectionId,
        description: section.description,
        articles,
      };
    }

    return kb;
  }

  private nextPath(nextUrl: string | null): string | null {
    if (!nextUrl) {
      return null;
    }

    if (nextUrl.startsWith("http://") || nextUrl.startsWith("https://")) {
      const parsed = new URL(nextUrl);
      return `${parsed.pathname}${parsed.search}`;
    }

    return nextUrl;
  }
}
