import type {
  TicketAuditListResult,
  TicketFieldListResult,
  TicketListResult,
  TicketSearchResult,
  ZendeskAttachment,
  ZendeskComment,
  ZendeskKnowledgeBase,
  ZendeskOrganization,
  ZendeskSearchResult,
  ZendeskTicket,
  ZendeskTicketAudit,
  ZendeskTicketAuditEvent,
  ZendeskTicketField,
  ZendeskUser,
} from "./types.js";
import { SafeAuthError } from "./internal-auth/errors.js";

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
  submitter_id?: number;
  assignee_id?: number;
  organization_id?: number;
  group_id?: number;
  brand_id?: number;
  ticket_form_id?: number;
  custom_status_id?: number;
  custom_fields?: Array<{ id?: number; value?: unknown }>;
  collaborator_ids?: number[];
  email_cc_ids?: number[];
  follower_ids?: number[];
  problem_id?: number;
  due_at?: string;
  external_id?: string;
  recipient?: string;
  has_incidents?: boolean;
  allow_attachments?: boolean;
  satisfaction_rating?: { id?: number; score?: string; comment?: string };
  via?: { channel?: string };
  tags?: string[];
  result_type?: string;
};

type AttachmentPayload = {
  id?: number;
  file_name?: string;
  content_type?: string;
  size?: number;
  content_url?: string;
  inline?: boolean;
  deleted?: boolean;
  malware_scan_result?: string;
};

type CommentPayload = {
  id?: number;
  author_id?: number;
  body?: string;
  html_body?: string;
  public?: boolean;
  created_at?: string;
  attachments?: AttachmentPayload[];
};

type UserPayload = {
  id?: number;
  name?: string;
  email?: string;
  alias?: string;
  phone?: string;
  verified?: boolean;
  role?: string;
  role_type?: number;
  custom_role_id?: number;
  default_group_id?: number;
  locale?: string;
  locale_id?: number;
  time_zone?: string;
  external_id?: string;
  tags?: string[];
  user_fields?: Record<string, unknown>;
  last_login_at?: string;
  created_at?: string;
  updated_at?: string;
  organization_id?: number;
  suspended?: boolean;
  active?: boolean;
  result_type?: string;
};

type OrganizationPayload = {
  id?: number;
  name?: string;
  details?: string;
  notes?: string;
  domain_names?: string[];
  external_id?: string;
  group_id?: number;
  organization_fields?: Record<string, unknown>;
  shared_comments?: boolean;
  created_at?: string;
  updated_at?: string;
  shared_tickets?: boolean;
  tags?: string[];
  result_type?: string;
};

type SearchResultPayload = TicketPayload | UserPayload | OrganizationPayload;

type TicketFieldPayload = {
  id?: number;
  title?: string;
  type?: string;
  description?: string;
  required?: boolean;
  visible_in_portal?: boolean;
  active?: boolean;
  position?: number;
  custom_field_options?: Array<{
    id?: number;
    name?: string;
    value?: string;
  }>;
};

type TicketAuditEventPayload = {
  id?: number;
  type?: string;
  field_name?: string;
  value?: unknown;
  previous_value?: unknown;
  body?: string;
};

type TicketAuditPayload = {
  id?: number;
  author_id?: number;
  created_at?: string;
  events?: TicketAuditEventPayload[];
};

type ZendeskApiError = {
  error?: string;
};

export type OAuthUnauthorizedResult =
  | { kind: "retry"; accessToken: string }
  | { kind: "reauthorization_required"; correlationId: string }
  | { kind: "stale_failure"; correlationId: string };

export type ZendeskAuthentication =
  | {
      kind: "api-token";
      email: string;
      token: string;
    }
  | {
      kind: "oauth";
      accessToken: string;
      onUnauthorized(input: {
        terminal: boolean;
        signal: AbortSignal;
      }): Promise<OAuthUnauthorizedResult>;
    };

export type ZendeskClientOptions = {
  subdomain: string;
  auth: ZendeskAuthentication;
  timeoutMs?: number;
  signal?: AbortSignal;
  fetch?: typeof fetch;
};

const MAX_ERROR_BODY_BYTES = 16 * 1024;

async function readErrorCode(
  response: Response,
): Promise<string | undefined> {
  const reader = response.body?.getReader();
  if (!reader) return undefined;

  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      byteLength += result.value.byteLength;
      if (byteLength > MAX_ERROR_BODY_BYTES) {
        await reader.cancel();
        return undefined;
      }
      chunks.push(result.value);
    }
  } catch {
    return undefined;
  }

  try {
    const text = new TextDecoder().decode(
      Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))),
    );
    const parsed = JSON.parse(text) as ZendeskApiError;
    return typeof parsed.error === "string" ? parsed.error : undefined;
  } catch {
    return undefined;
  }
}

function categoryForStatus(status: number): {
  category:
    | "unauthorized"
    | "forbidden"
    | "rate_limited"
    | "temporarily_unavailable"
    | "invalid_response";
  retryable: boolean;
} {
  if (status === 401) return { category: "unauthorized", retryable: false };
  if (status === 403) return { category: "forbidden", retryable: false };
  if (status === 429) return { category: "rate_limited", retryable: true };
  if (status >= 500) {
    return { category: "temporarily_unavailable", retryable: true };
  }
  return { category: "invalid_response", retryable: false };
}

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
    submitter_id: ticket.submitter_id ?? null,
    assignee_id: ticket.assignee_id ?? null,
    organization_id: ticket.organization_id ?? null,
    group_id: ticket.group_id ?? null,
    brand_id: ticket.brand_id ?? null,
    ticket_form_id: ticket.ticket_form_id ?? null,
    custom_status_id: ticket.custom_status_id ?? null,
    custom_fields: Array.isArray(ticket.custom_fields)
      ? ticket.custom_fields.map((field) => ({
          id: Number(field.id),
          value: field.value ?? null,
        }))
      : [],
    collaborator_ids: Array.isArray(ticket.collaborator_ids)
      ? ticket.collaborator_ids.map(Number)
      : [],
    email_cc_ids: Array.isArray(ticket.email_cc_ids)
      ? ticket.email_cc_ids.map(Number)
      : [],
    follower_ids: Array.isArray(ticket.follower_ids)
      ? ticket.follower_ids.map(Number)
      : [],
    problem_id: ticket.problem_id ?? null,
    due_at: ticket.due_at ?? null,
    external_id: ticket.external_id ?? null,
    recipient: ticket.recipient ?? null,
    has_incidents: Boolean(ticket.has_incidents),
    allow_attachments: Boolean(ticket.allow_attachments),
    satisfaction_rating: ticket.satisfaction_rating
      ? {
          id: ticket.satisfaction_rating.id ?? null,
          score: ticket.satisfaction_rating.score ?? null,
          comment: ticket.satisfaction_rating.comment ?? null,
        }
      : null,
    via: ticket.via ? { channel: ticket.via.channel ?? null } : null,
    tags: Array.isArray(ticket.tags) ? ticket.tags : [],
  };
}

function normalizeAttachment(attachment: AttachmentPayload): ZendeskAttachment {
  return {
    id: Number(attachment.id),
    file_name: attachment.file_name ?? null,
    content_type: attachment.content_type ?? null,
    size: attachment.size ?? null,
    content_url: attachment.content_url ?? null,
    inline: Boolean(attachment.inline),
    deleted: Boolean(attachment.deleted),
    malware_scan_result: attachment.malware_scan_result ?? null,
  };
}

function normalizeComment(comment: CommentPayload): ZendeskComment {
  return {
    id: Number(comment.id),
    author_id: comment.author_id ?? null,
    body: comment.body ?? null,
    html_body: comment.html_body ?? null,
    public: Boolean(comment.public),
    created_at: comment.created_at ?? null,
    attachments: Array.isArray(comment.attachments)
      ? comment.attachments.map(normalizeAttachment)
      : [],
  };
}

function normalizeUser(user: UserPayload): ZendeskUser {
  return {
    id: Number(user.id),
    name: user.name ?? null,
    email: user.email ?? null,
    alias: user.alias ?? null,
    phone: user.phone ?? null,
    verified: Boolean(user.verified),
    role: user.role ?? null,
    role_type: user.role_type ?? null,
    custom_role_id: user.custom_role_id ?? null,
    default_group_id: user.default_group_id ?? null,
    locale: user.locale ?? null,
    locale_id: user.locale_id ?? null,
    time_zone: user.time_zone ?? null,
    external_id: user.external_id ?? null,
    tags: Array.isArray(user.tags) ? user.tags : [],
    user_fields: user.user_fields ?? {},
    last_login_at: user.last_login_at ?? null,
    created_at: user.created_at ?? null,
    updated_at: user.updated_at ?? null,
    organization_id: user.organization_id ?? null,
    suspended: Boolean(user.suspended),
    active: Boolean(user.active),
  };
}

function normalizeOrganization(organization: OrganizationPayload): ZendeskOrganization {
  return {
    id: Number(organization.id),
    name: organization.name ?? null,
    details: organization.details ?? null,
    notes: organization.notes ?? null,
    domain_names: Array.isArray(organization.domain_names)
      ? organization.domain_names
      : [],
    external_id: organization.external_id ?? null,
    group_id: organization.group_id ?? null,
    organization_fields: organization.organization_fields ?? {},
    shared_comments: Boolean(organization.shared_comments),
    created_at: organization.created_at ?? null,
    updated_at: organization.updated_at ?? null,
    shared_tickets: Boolean(organization.shared_tickets),
    tags: Array.isArray(organization.tags) ? organization.tags : [],
  };
}

function normalizeTicketField(field: TicketFieldPayload): ZendeskTicketField {
  return {
    id: Number(field.id),
    title: field.title ?? null,
    type: field.type ?? null,
    description: field.description ?? null,
    required: Boolean(field.required),
    visible_in_portal: Boolean(field.visible_in_portal),
    active: Boolean(field.active),
    position: field.position ?? null,
    custom_field_options: Array.isArray(field.custom_field_options)
      ? field.custom_field_options.map((option) => ({
          id: Number(option.id),
          name: option.name ?? "",
          value: option.value ?? "",
        }))
      : [],
  };
}

function normalizeTicketAuditEvent(event: TicketAuditEventPayload): ZendeskTicketAuditEvent {
  return {
    id: Number(event.id),
    type: event.type ?? null,
    field_name: event.field_name ?? null,
    value: event.value ?? null,
    previous_value: event.previous_value ?? null,
    body: event.body ?? null,
  };
}

function normalizeTicketAudit(audit: TicketAuditPayload): ZendeskTicketAudit {
  return {
    id: Number(audit.id),
    author_id: audit.author_id ?? null,
    created_at: audit.created_at ?? null,
    events: Array.isArray(audit.events) ? audit.events.map(normalizeTicketAuditEvent) : [],
  };
}

export class ZendeskClient {
  private readonly baseUrl: string;
  private readonly origin: string;
  private readonly auth: ZendeskAuthentication;
  private readonly timeoutMs: number;
  private readonly outerSignal: AbortSignal | undefined;
  private readonly fetchFn: typeof fetch;

  constructor(options: ZendeskClientOptions) {
    this.origin = `https://${options.subdomain}.zendesk.com`;
    this.baseUrl = `${this.origin}/api/v2`;
    this.auth = options.auth;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.outerSignal = options.signal;
    this.fetchFn = options.fetch ?? fetch;
  }

  private authorization(accessToken?: string): string {
    if (this.auth.kind === "api-token") {
      return (
        "Basic " +
        Buffer.from(`${this.auth.email}/token:${this.auth.token}`).toString(
          "base64",
        )
      );
    }
    return `Bearer ${accessToken ?? this.auth.accessToken}`;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (this.outerSignal?.aborted) abort();
    this.outerSignal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, this.timeoutMs);

    try {
      let accessToken =
        this.auth.kind === "oauth" ? this.auth.accessToken : undefined;
      let response = await this.fetchOnce(
        path,
        init,
        this.authorization(accessToken),
        controller.signal,
      );
      let errorCode = response.ok ? undefined : await readErrorCode(response);

      if (
        this.auth.kind === "oauth" &&
        response.status === 401 &&
        errorCode === "invalid_token"
      ) {
        const recovery = await this.recoverUnauthorized(false, controller.signal);
        if (recovery.kind !== "retry") {
          throw this.recoveryError(recovery);
        }

        accessToken = recovery.accessToken;
        response = await this.fetchOnce(
          path,
          init,
          this.authorization(accessToken),
          controller.signal,
        );
        errorCode = response.ok ? undefined : await readErrorCode(response);

        if (response.status === 401 && errorCode === "invalid_token") {
          const terminal = await this.recoverUnauthorized(
            true,
            controller.signal,
          );
          if (terminal.kind !== "retry") {
            throw this.recoveryError(terminal);
          }
          throw new SafeAuthError("unauthorized", { status: 401 });
        }
      }

      if (!response.ok) {
        const classified = categoryForStatus(response.status);
        throw new SafeAuthError(classified.category, {
          retryable: classified.retryable,
          status: response.status,
        });
      }

      try {
        return (await response.json()) as T;
      } catch {
        throw new SafeAuthError("invalid_response");
      }
    } catch (error) {
      if (error instanceof SafeAuthError) throw error;
      if (controller.signal.aborted) {
        throw new SafeAuthError("aborted", { retryable: true });
      }
      throw new SafeAuthError("temporarily_unavailable", { retryable: true });
    } finally {
      clearTimeout(timer);
      this.outerSignal?.removeEventListener("abort", abort);
    }
  }

  private async fetchOnce(
    path: string,
    init: RequestInit | undefined,
    authorization: string,
    signal: AbortSignal,
  ): Promise<Response> {
    const headers = new Headers(init?.headers);
    if (!headers.has("content-type")) {
      headers.set("Content-Type", "application/json");
    }
    if (!headers.has("accept")) headers.set("Accept", "application/json");
    headers.set("Authorization", authorization);

    return this.fetchFn(`${this.baseUrl}${path}`, {
      ...init,
      headers,
      redirect: "error",
      signal,
    });
  }

  private async recoverUnauthorized(
    terminal: boolean,
    signal: AbortSignal,
  ): Promise<OAuthUnauthorizedResult> {
    if (this.auth.kind !== "oauth") {
      throw new SafeAuthError("unauthorized", { status: 401 });
    }
    try {
      return await this.auth.onUnauthorized({ terminal, signal });
    } catch (error) {
      if (error instanceof SafeAuthError) throw error;
      throw new SafeAuthError("temporarily_unavailable", { retryable: true });
    }
  }

  private recoveryError(
    recovery: Exclude<OAuthUnauthorizedResult, { kind: "retry" }>,
  ): SafeAuthError {
    return new SafeAuthError(
      recovery.kind === "reauthorization_required"
        ? "reauthorization_required"
        : "unauthorized",
      {
        correlationId: recovery.correlationId,
        status: 401,
      },
    );
  }

  async getTicket(ticketId: number): Promise<ZendeskTicket> {
    const data = await this.request<{ ticket: TicketPayload }>(`/tickets/${ticketId}.json`);
    return normalizeTicket(data.ticket);
  }

  async getTicketComments(ticketId: number): Promise<ZendeskComment[]> {
    const comments: ZendeskComment[] = [];
    let nextCommentsPath: string | null =
      `/tickets/${ticketId}/comments.json?include_inline_images=true&page[size]=100`;

    while (nextCommentsPath) {
      const data = await this.request<{
        comments: CommentPayload[];
        links?: { next?: string | null };
        meta?: { has_more: boolean };
        next_page?: string | null;
      }>(nextCommentsPath);

      comments.push(...data.comments.map(normalizeComment));
      const nextUrl = data.meta
        ? data.meta.has_more
          ? (data.links?.next ?? null)
          : null
        : (data.next_page ?? data.links?.next ?? null);
      nextCommentsPath = this.nextPath(nextUrl);
    }

    return comments;
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

  async searchTickets(options: {
    query: string;
    page: number;
    perPage: number;
    sortBy: string;
    sortOrder: "asc" | "desc";
  }): Promise<TicketSearchResult> {
    const query = new URLSearchParams({
      query: options.query,
      page: String(options.page),
      per_page: String(Math.min(options.perPage, 100)),
      sort_by: options.sortBy,
      sort_order: options.sortOrder,
    });

    const data = await this.request<{
      results: TicketPayload[];
      next_page: string | null;
      previous_page: string | null;
    }>(`/search.json?${query.toString()}`);

    const tickets = data.results
      .filter((result) => result.result_type === "ticket")
      .map(normalizeTicket);

    return {
      query: options.query,
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

  async search(options: {
    query: string;
    type?: "ticket" | "user" | "organization";
    page: number;
    perPage: number;
    sortBy: string;
    sortOrder: "asc" | "desc";
  }): Promise<ZendeskSearchResult> {
    const searchQuery = options.type ? `type:${options.type} ${options.query}` : options.query;
    const query = new URLSearchParams({
      query: searchQuery,
      page: String(options.page),
      per_page: String(Math.min(options.perPage, 100)),
      sort_by: options.sortBy,
      sort_order: options.sortOrder,
    });

    const data = await this.request<{
      results: SearchResultPayload[];
      next_page: string | null;
      previous_page: string | null;
    }>(`/search.json?${query.toString()}`);

    const tickets = data.results
      .filter((result) => result.result_type === "ticket")
      .map((result) => normalizeTicket(result as TicketPayload));
    const users = data.results
      .filter((result) => result.result_type === "user")
      .map((result) => normalizeUser(result as UserPayload));
    const organizations = data.results
      .filter((result) => result.result_type === "organization")
      .map((result) => normalizeOrganization(result as OrganizationPayload));

    return {
      query: options.query,
      type: options.type ?? "any",
      tickets,
      users,
      organizations,
      page: options.page,
      per_page: Math.min(options.perPage, 100),
      count: data.results.length,
      sort_by: options.sortBy,
      sort_order: options.sortOrder,
      has_more: data.next_page !== null,
      next_page: data.next_page ? options.page + 1 : null,
      previous_page: data.previous_page && options.page > 1 ? options.page - 1 : null,
    };
  }

  async getCurrentUser(): Promise<ZendeskUser> {
    const data = await this.request<{ user: UserPayload }>("/users/me.json");
    return normalizeUser(data.user);
  }

  async searchUsers(options: {
    query: string;
    page: number;
    perPage: number;
    sortBy: string;
    sortOrder: "asc" | "desc";
  }): Promise<ZendeskSearchResult> {
    return this.search({
      ...options,
      type: "user",
    });
  }

  async searchOrganizations(options: {
    query: string;
    page: number;
    perPage: number;
    sortBy: string;
    sortOrder: "asc" | "desc";
  }): Promise<ZendeskSearchResult> {
    return this.search({
      ...options,
      type: "organization",
    });
  }

  async listTicketFields(): Promise<TicketFieldListResult> {
    const fields: ZendeskTicketField[] = [];
    let nextPagePath: string | null = "/ticket_fields.json?per_page=100";

    while (nextPagePath) {
      const data = await this.request<{
        ticket_fields: TicketFieldPayload[];
        next_page: string | null;
      }>(nextPagePath);

      fields.push(...data.ticket_fields.map(normalizeTicketField));
      nextPagePath = this.nextPath(data.next_page);
    }

    return {
      fields,
      count: fields.length,
    };
  }

  async getTicketAudits(options: {
    ticketId: number;
    page: number;
    perPage: number;
  }): Promise<TicketAuditListResult> {
    const query = new URLSearchParams({
      page: String(options.page),
      per_page: String(Math.min(options.perPage, 100)),
    });

    const data = await this.request<{
      audits: TicketAuditPayload[];
      next_page: string | null;
      previous_page: string | null;
    }>(`/tickets/${options.ticketId}/audits.json?${query.toString()}`);

    const audits = data.audits.map(normalizeTicketAudit);

    return {
      ticket_id: options.ticketId,
      audits,
      page: options.page,
      per_page: Math.min(options.perPage, 100),
      count: audits.length,
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
      if (parsed.origin !== this.origin) {
        throw new SafeAuthError("invalid_response");
      }
      const apiPrefix = "/api/v2";
      const pathname = parsed.pathname.startsWith(`${apiPrefix}/`)
        ? parsed.pathname.slice(apiPrefix.length)
        : parsed.pathname;
      return `${pathname}${parsed.search}`;
    }

    return nextUrl;
  }
}
