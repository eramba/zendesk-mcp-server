export type ZendeskErrorCategory =
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "invalid_request"
  | "temporarily_unavailable"
  | "invalid_grant"
  | "invalid_response"
  | "aborted";

export class ZendeskUpstreamError extends Error {
  constructor(
    readonly category: ZendeskErrorCategory,
    readonly status: number | undefined,
    readonly retryable: boolean,
    readonly correlationId: string,
  ) {
    super(`Zendesk request failed (${category}; correlation ${correlationId})`);
    this.name = "ZendeskUpstreamError";
  }
}

export class ReauthorizationRequiredError extends Error {
  constructor(readonly correlationId: string) {
    super(`Zendesk authorization must be renewed with codex mcp login zendesk (correlation ${correlationId})`);
    this.name = "ReauthorizationRequiredError";
  }
}
