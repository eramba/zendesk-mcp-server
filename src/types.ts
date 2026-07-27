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
  submitter_id: number | null;
  assignee_id: number | null;
  organization_id: number | null;
  group_id: number | null;
  brand_id: number | null;
  ticket_form_id: number | null;
  custom_status_id: number | null;
  custom_fields: ZendeskCustomFieldValue[];
  collaborator_ids: number[];
  email_cc_ids: number[];
  follower_ids: number[];
  problem_id: number | null;
  due_at: string | null;
  external_id: string | null;
  recipient: string | null;
  has_incidents: boolean;
  allow_attachments: boolean;
  satisfaction_rating: ZendeskSatisfactionRating | null;
  via: ZendeskVia | null;
  tags: string[];
};

export type ZendeskCustomFieldValue = {
  id: number;
  value: unknown;
};

export type ZendeskVia = {
  channel: string | null;
};

export type ZendeskSatisfactionRating = {
  id: number | null;
  score: string | null;
  comment: string | null;
};

export type ZendeskCollaborator =
  | number
  | string
  | { name: string; email: string };

export type ZendeskFollowerChange =
  | { user_id: number; action?: "put" | "delete" }
  | { user_email: string; action?: "put" | "delete" };

export type ZendeskEmailCcChange =
  | { user_id: number; action?: "put" | "delete" }
  | {
      user_email: string;
      user_name?: string;
      action?: "put" | "delete";
    };

export type ZendeskTicketWriteFields = {
  subject?: string;
  status?: string;
  priority?: string;
  type?: string;
  assignee_id?: number;
  requester_id?: number;
  organization_id?: number;
  group_id?: number;
  brand_id?: number;
  ticket_form_id?: number;
  custom_status_id?: number;
  problem_id?: number;
  tags?: string[];
  custom_fields?: ZendeskCustomFieldValue[];
  due_at?: string;
  collaborator_ids?: number[];
  additional_collaborators?: ZendeskCollaborator[];
  followers?: ZendeskFollowerChange[];
  email_ccs?: ZendeskEmailCcChange[];
};

export type ZendeskAttachment = {
  id: number;
  file_name: string | null;
  content_type: string | null;
  size: number | null;
  content_url: string | null;
  inline: boolean;
  deleted: boolean;
  malware_scan_result: string | null;
};

export type ZendeskComment = {
  id: number;
  author_id: number | null;
  body: string | null;
  html_body: string | null;
  public: boolean;
  created_at: string | null;
  attachments: ZendeskAttachment[];
};

export type ZendeskUser = {
  id: number;
  name: string | null;
  email: string | null;
  alias: string | null;
  phone: string | null;
  verified: boolean;
  role: string | null;
  role_type: number | null;
  custom_role_id: number | null;
  default_group_id: number | null;
  locale: string | null;
  locale_id: number | null;
  time_zone: string | null;
  external_id: string | null;
  tags: string[];
  user_fields: Record<string, unknown>;
  last_login_at: string | null;
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
  domain_names: string[];
  external_id: string | null;
  group_id: number | null;
  organization_fields: Record<string, unknown>;
  shared_comments: boolean;
  created_at: string | null;
  updated_at: string | null;
  shared_tickets: boolean;
  tags: string[];
};

export type CursorInput = {
  pageSize: number;
  after?: string;
};

export type CursorPage<T> = {
  items: T[];
  page_size: number;
  has_more: boolean;
  next_cursor: string | null;
};

export type ZendeskUserTicketRelationship =
  | "requested"
  | "assigned"
  | "ccd"
  | "followed";

export type ZendeskView = {
  id: number;
  title: string | null;
  description: string | null;
  active: boolean;
  default: boolean;
  position: number | null;
  created_at: string | null;
  updated_at: string | null;
};

export type ZendeskGroup = {
  id: number;
  name: string | null;
  description: string | null;
  default: boolean;
  deleted: boolean;
  is_public: boolean;
  created_at: string | null;
  updated_at: string | null;
};

export type ZendeskGroupMembership = {
  id: number;
  user_id: number;
  group_id: number;
  default: boolean;
  created_at: string | null;
  updated_at: string | null;
};

export type ZendeskGroupMembersPage = CursorPage<ZendeskGroupMembership> & {
  users: ZendeskUser[];
};

export type ZendeskMetricDuration = {
  calendar: number | null;
  business: number | null;
};

export type ZendeskTicketMetrics = {
  id: number;
  ticket_id: number;
  assigned_at: string | null;
  initially_assigned_at: string | null;
  solved_at: string | null;
  status_updated_at: string | null;
  requester_updated_at: string | null;
  assignee_updated_at: string | null;
  latest_comment_added_at: string | null;
  replies: number;
  reopens: number;
  assignee_stations: number;
  group_stations: number;
  reply_time_in_minutes: ZendeskMetricDuration;
  requester_wait_time_in_minutes: ZendeskMetricDuration;
  agent_wait_time_in_minutes: ZendeskMetricDuration;
  on_hold_time_in_minutes: ZendeskMetricDuration;
  first_resolution_time_in_minutes: ZendeskMetricDuration;
  full_resolution_time_in_minutes: ZendeskMetricDuration;
};

export type ZendeskTicketForm = {
  id: number;
  name: string | null;
  display_name: string | null;
  active: boolean;
  default: boolean;
  position: number | null;
  ticket_field_ids: number[];
  created_at: string | null;
  updated_at: string | null;
};

export type ZendeskCustomStatus = {
  id: number;
  active: boolean;
  default: boolean;
  agent_label: string | null;
  end_user_label: string | null;
  description: string | null;
  end_user_description: string | null;
  status_category: string | null;
  created_at: string | null;
  updated_at: string | null;
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
