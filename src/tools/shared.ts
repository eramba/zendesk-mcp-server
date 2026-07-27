import { z } from "zod";

export const ticketStatusEnum = z.enum([
  "new",
  "open",
  "pending",
  "hold",
  "solved",
  "closed",
]);
export const ticketPriorityEnum = z.enum(["low", "normal", "high", "urgent"]);
export const ticketTypeEnum = z.enum(["problem", "incident", "question", "task"]);

const ticketWriteActionEnum = z.enum(["put", "delete"]);
export const collaboratorSchema = z.union([
  z.number().int().positive(),
  z.string().email(),
  z.object({ name: z.string().min(1), email: z.string().email() }),
]);
export const followerChangeSchema = z.union([
  z.object({
    user_id: z.number().int().positive(),
    action: ticketWriteActionEnum.default("put"),
  }),
  z.object({
    user_email: z.string().email(),
    action: ticketWriteActionEnum.default("put"),
  }),
]);
export const emailCcChangeSchema = z.union([
  z.object({
    user_id: z.number().int().positive(),
    action: ticketWriteActionEnum.default("put"),
  }),
  z.object({
    user_email: z.string().email(),
    user_name: z.string().min(1).optional(),
    action: ticketWriteActionEnum.default("put"),
  }),
]);

export const offsetPaginationSchema = {
  page: z.number().int().min(1).default(1),
  per_page: z.number().int().min(1).max(100).default(25),
  sort_by: z
    .enum(["created_at", "updated_at", "priority", "status"])
    .default("created_at"),
  sort_order: z.enum(["asc", "desc"]).default("desc"),
};

export const cursorPaginationSchema = {
  page_size: z.number().int().min(1).max(100).default(25),
  after: z.string().min(1).max(2048).optional(),
};

export function jsonText(value: unknown): {
  content: Array<{ type: "text"; text: string }>;
} {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  };
}

export function toolError(error: unknown): {
  isError: true;
  content: Array<{ type: "text"; text: string }>;
} {
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [{ type: "text", text: `Error: ${message}` }],
  };
}
