export const MCP_SCOPES = ["zendesk:read", "zendesk:write"] as const;
export const MCP_SCOPE = MCP_SCOPES.join(" ");
export const ZENDESK_SCOPES = [
  "read",
  "tickets:write",
] as const;

export const LOGIN_TTL_SECONDS = 10 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 10 * 60;
export const MCP_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MCP_REFRESH_RETRY_SECONDS = 60;
export const REFRESH_SKEW_SECONDS = 60;

export const OAUTH_PATHS = {
  authorize: "/authorize",
  token: "/token",
  register: "/register",
  revoke: "/revoke",
  consent: "/oauth/consent",
  zendeskCallback: "/oauth/zendesk/callback",
  protectedResourceMetadata: "/.well-known/oauth-protected-resource/mcp",
  authorizationServerMetadata: "/.well-known/oauth-authorization-server",
} as const;

export function normalizeMcpScopes(scopes: readonly string[]): string[] {
  const unique = [...new Set(scopes)];
  if (
    unique.length !== MCP_SCOPES.length ||
    !MCP_SCOPES.every((scope) => unique.includes(scope))
  ) {
    throw new Error(`scope must be exactly ${MCP_SCOPE}`);
  }
  return [...MCP_SCOPES];
}
