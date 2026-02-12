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
