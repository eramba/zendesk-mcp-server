import { randomUUID } from "node:crypto";

export type SafeAuthErrorCategory =
  | "invalid_grant"
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "temporarily_unavailable"
  | "invalid_response"
  | "conflict"
  | "aborted"
  | "reauthorization_required";

export class SafeAuthError extends Error {
  readonly category: SafeAuthErrorCategory;
  readonly correlationId: string;
  readonly retryable: boolean;
  readonly status: number | undefined;

  constructor(
    category: SafeAuthErrorCategory,
    options: {
      retryable?: boolean;
      status?: number;
      correlationId?: string;
    } = {},
  ) {
    const correlationId = options.correlationId ?? randomUUID();
    super(
      category === "conflict"
        ? `Ticket changed since it was last read. Fetch it again and retry. (reference: ${correlationId})`
        : `Zendesk authentication failed (${correlationId})`,
    );
    this.name = "SafeAuthError";
    this.category = category;
    this.correlationId = correlationId;
    this.retryable = options.retryable ?? false;
    this.status = options.status;
  }
}
