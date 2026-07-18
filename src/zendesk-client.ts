import { randomUUID } from "node:crypto";

import {
  ReauthorizationRequiredError,
  ZendeskUpstreamError,
  type ZendeskErrorCategory,
} from "./oauth/errors.js";
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
  role?: string;
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
  created_at?: string;
  updated_at?: string;
  shared_tickets?: boolean;
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

export type BasicZendeskAuth = {
  kind: "api_token";
  email: string;
  apiToken: string;
};

export type OAuthUnauthorizedResult =
  | {
      kind: "retry";
      accessToken: string;
      principalEpoch: number;
      credentialVersion: number;
    }
  | { kind: "reauthorization_required"; correlationId: string }
  | { kind: "stale_failure"; correlationId: string };

export type OAuthZendeskAuth = {
  kind: "oauth";
  accessToken: string;
  principalEpoch: number;
  credentialVersion: number;
  onUnauthorized: (input: {
    principalEpoch: number;
    credentialVersion: number;
    terminal: boolean;
    signal: AbortSignal;
  }) => Promise<OAuthUnauthorizedResult>;
};

export type ZendeskClientOptions = {
  subdomain: string;
  auth: BasicZendeskAuth | OAuthZendeskAuth;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
};

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_ERROR_BODY_BYTES = 8 * 1024;

function upstreamError(
  category: ZendeskErrorCategory,
  status: number | undefined,
  retryable: boolean,
  correlationId: string = randomUUID(),
): ZendeskUpstreamError {
  return new ZendeskUpstreamError(category, status, retryable, correlationId);
}

function classifyStatus(status: number): { category: ZendeskErrorCategory; retryable: boolean } {
  if (status === 401) return { category: "unauthorized", retryable: false };
  if (status === 403) return { category: "forbidden", retryable: false };
  if (status === 429) return { category: "rate_limited", retryable: true };
  if (status >= 500) return { category: "temporarily_unavailable", retryable: true };
  return { category: "invalid_request", retryable: false };
}

function createRequestSignal(
  timeoutMs: number,
  outerSignals: readonly (AbortSignal | null | undefined)[],
): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const activeSignals = outerSignals.filter(
    (signal): signal is AbortSignal => signal !== undefined && signal !== null,
  );
  for (const signal of activeSignals) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  const timer = setTimeout(abort, timeoutMs);
  return {
    signal: controller.signal,
    dispose: () => {
      clearTimeout(timer);
      for (const signal of activeSignals) signal.removeEventListener("abort", abort);
    },
  };
}

function awaitWithAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      signal.removeEventListener("abort", onAbort);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
    if (signal.aborted) onAbort();
  });
}

async function consumeBoundedBody(response: Response, signal: AbortSignal): Promise<void> {
  const reader = response.body?.getReader();
  if (!reader) return;
  let bytesRead = 0;
  let complete = false;
  try {
    while (bytesRead < MAX_ERROR_BODY_BYTES) {
      const result = await awaitWithAbort(reader.read(), signal);
      if (result.done) {
        complete = true;
        break;
      }
      bytesRead += result.value.byteLength;
    }
  } finally {
    if (!complete) {
      await awaitWithAbort(reader.cancel(), signal).catch(() => undefined);
    }
    reader.releaseLock();
  }
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
    assignee_id: ticket.assignee_id ?? null,
    organization_id: ticket.organization_id ?? null,
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
    role: user.role ?? null,
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
    created_at: organization.created_at ?? null,
    updated_at: organization.updated_at ?? null,
    shared_tickets: Boolean(organization.shared_tickets),
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
  private auth: BasicZendeskAuth | OAuthZendeskAuth;
  private readonly timeoutMs: number;
  private readonly fetch: typeof globalThis.fetch;

  constructor(options: ZendeskClientOptions) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new Error("timeoutMs must be a positive integer");
    }
    this.baseUrl = `https://${options.subdomain}.zendesk.com/api/v2`;
    this.auth = { ...options.auth };
    this.timeoutMs = timeoutMs;
    this.fetch = options.fetch ?? globalThis.fetch;
  }

  private authorization(auth: BasicZendeskAuth | OAuthZendeskAuth): string {
    if (auth.kind === "oauth") return `Bearer ${auth.accessToken}`;
    return "Basic " + Buffer.from(`${auth.email}/token:${auth.apiToken}`).toString("base64");
  }

  private async fetchOnce(
    path: string,
    init: RequestInit | undefined,
    auth: BasicZendeskAuth | OAuthZendeskAuth,
    signal: AbortSignal,
  ): Promise<Response> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const headers = new Headers(init?.headers);
    headers.set("Authorization", this.authorization(auth));
    if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    if (!headers.has("Accept")) headers.set("Accept", "application/json");
    return awaitWithAbort(this.fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers,
      signal,
    }), signal);
  }

  private unauthorizedResult(
    result: OAuthUnauthorizedResult,
    status: number,
  ): never {
    if (result.kind === "reauthorization_required") {
      throw new ReauthorizationRequiredError(result.correlationId);
    }
    if (result.kind === "stale_failure") {
      throw upstreamError("unauthorized", status, false, result.correlationId);
    }
    throw upstreamError("unauthorized", status, false);
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
    outerSignal?: AbortSignal,
  ): Promise<T> {
    const { signal, dispose } = createRequestSignal(
      this.timeoutMs,
      [init?.signal, outerSignal],
    );
    try {
      let requestAuth = this.auth;
      let response = await this.fetchOnce(path, init, requestAuth, signal);

      if (response.status === 401 && requestAuth.kind === "oauth") {
        await consumeBoundedBody(response, signal);
        const firstResult = await awaitWithAbort(requestAuth.onUnauthorized({
          principalEpoch: requestAuth.principalEpoch,
          credentialVersion: requestAuth.credentialVersion,
          terminal: false,
          signal,
        }), signal);
        if (firstResult.kind !== "retry") this.unauthorizedResult(firstResult, response.status);

        requestAuth = {
          ...requestAuth,
          accessToken: firstResult.accessToken,
          principalEpoch: firstResult.principalEpoch,
          credentialVersion: firstResult.credentialVersion,
        };
        this.auth = requestAuth;
        response = await this.fetchOnce(path, init, requestAuth, signal);
        if (response.status === 401) {
          await consumeBoundedBody(response, signal);
          const terminalResult = await awaitWithAbort(requestAuth.onUnauthorized({
            principalEpoch: requestAuth.principalEpoch,
            credentialVersion: requestAuth.credentialVersion,
            terminal: true,
            signal,
          }), signal);
          this.unauthorizedResult(terminalResult, response.status);
        }
      }

      if (!response.ok) {
        await consumeBoundedBody(response, signal);
        if (signal.aborted) throw upstreamError("aborted", undefined, false);
        const classification = classifyStatus(response.status);
        throw upstreamError(classification.category, response.status, classification.retryable);
      }

      try {
        return (await awaitWithAbort(response.json(), signal)) as T;
      } catch (error) {
        if (signal.aborted) throw upstreamError("aborted", undefined, false);
        if (error instanceof ZendeskUpstreamError) throw error;
        throw upstreamError("invalid_response", response.status, false);
      }
    } catch (error) {
      if (error instanceof ZendeskUpstreamError || error instanceof ReauthorizationRequiredError) {
        throw error;
      }
      if (signal.aborted) throw upstreamError("aborted", undefined, false);
      throw upstreamError("temporarily_unavailable", undefined, true);
    } finally {
      dispose();
    }
  }

  async getTicket(ticketId: number, signal?: AbortSignal): Promise<ZendeskTicket> {
    const data = await this.request<{ ticket: TicketPayload }>(
      `/tickets/${ticketId}.json`,
      undefined,
      signal,
    );
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
      const apiPrefix = "/api/v2";
      const pathname = parsed.pathname.startsWith(`${apiPrefix}/`)
        ? parsed.pathname.slice(apiPrefix.length)
        : parsed.pathname;
      return `${pathname}${parsed.search}`;
    }

    return nextUrl;
  }
}
