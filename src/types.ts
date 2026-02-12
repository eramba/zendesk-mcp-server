export type ZendeskTicket = {
  id: number;
  subject: string | null;
  description: string | null;
  status: string | null;
  priority: string | null;
  type?: string | null;
  created_at: string | null;
  updated_at: string | null;
  requester_id: number | null;
  assignee_id: number | null;
  organization_id?: number | null;
  tags?: string[];
};

export type ZendeskComment = {
  id: number;
  author_id: number | null;
  body: string | null;
  html_body: string | null;
  public: boolean;
  created_at: string | null;
};

export type ZendeskUser = {
  id: number;
  name: string | null;
  email: string | null;
  role: string | null;
  created_at: string | null;
  updated_at: string | null;
  organization_id: number | null;
  suspended: boolean;
  active: boolean;
};

export type ZendeskOrganization = {
  id: number;
  name: string | null;
  details: string | null;
  notes: string | null;
  created_at: string | null;
  updated_at: string | null;
  shared_tickets: boolean;
};

export type TicketListResult = {
  tickets: ZendeskTicket[];
  page: number;
  per_page: number;
  count: number;
  sort_by: string;
  sort_order: "asc" | "desc";
  has_more: boolean;
  next_page: number | null;
  previous_page: number | null;
};

export type TicketSearchResult = {
  query: string;
  tickets: ZendeskTicket[];
  page: number;
  per_page: number;
  count: number;
  sort_by: string;
  sort_order: "asc" | "desc";
  has_more: boolean;
  next_page: number | null;
  previous_page: number | null;
};

export type ZendeskSearchResult = {
  query: string;
  type: "ticket" | "user" | "organization" | "any";
  tickets: ZendeskTicket[];
  users: ZendeskUser[];
  organizations: ZendeskOrganization[];
  page: number;
  per_page: number;
  count: number;
  sort_by: string;
  sort_order: "asc" | "desc";
  has_more: boolean;
  next_page: number | null;
  previous_page: number | null;
};

export type ZendeskTicketField = {
  id: number;
  title: string | null;
  type: string | null;
  description: string | null;
  required: boolean;
  visible_in_portal: boolean;
  active: boolean;
  position: number | null;
  custom_field_options: Array<{
    id: number;
    name: string;
    value: string;
  }>;
};

export type TicketFieldListResult = {
  fields: ZendeskTicketField[];
  count: number;
};

export type ZendeskTicketAuditEvent = {
  id: number;
  type: string | null;
  field_name: string | null;
  value: unknown;
  previous_value: unknown;
  body: string | null;
};

export type ZendeskTicketAudit = {
  id: number;
  author_id: number | null;
  created_at: string | null;
  events: ZendeskTicketAuditEvent[];
};

export type TicketAuditListResult = {
  ticket_id: number;
  audits: ZendeskTicketAudit[];
  page: number;
  per_page: number;
  count: number;
  has_more: boolean;
  next_page: number | null;
  previous_page: number | null;
};

export type ZendeskSectionArticles = {
  section_id: number;
  description: string | null;
  articles: Array<{
    id: number;
    title: string;
    body: string | null;
    updated_at: string | null;
    url: string | null;
  }>;
};

export type ZendeskKnowledgeBase = Record<string, ZendeskSectionArticles>;
