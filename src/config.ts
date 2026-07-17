import { isAbsolute } from "node:path";

export type Environment = Readonly<Record<string, string | undefined>>;

export type ZendeskConfig = {
  subdomain: string;
  email: string;
  apiKey: string;
};

export type HttpConfig = {
  host: string;
  port: number;
  bearerToken: string;
  allowedHosts: string[];
};

type ListenerConfig = {
  host: string;
  port: number;
  allowedHosts: string[];
};

const ZENDESK_KEYS = [
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_EMAIL",
  "ZENDESK_API_KEY",
] as const;

function isBlank(value: string | undefined): boolean {
  return value === undefined || value.trim() === "";
}

function readListenerConfig(env: Environment): ListenerConfig {
  const rawPort = env.PORT ?? "3000";
  if (!/^\d+$/.test(rawPort)) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  const allowedHosts = [
    ...new Set(
      (env.MCP_ALLOWED_HOSTS ?? "localhost,127.0.0.1")
        .split(",")
        .map((host) => host.trim())
        .filter(Boolean),
    ),
  ];
  if (allowedHosts.length === 0) {
    throw new Error("MCP_ALLOWED_HOSTS must contain at least one hostname");
  }
  return { host: env.HOST?.trim() || "0.0.0.0", port, allowedHosts };
}

export function readZendeskConfig(
  env: Environment = process.env,
): ZendeskConfig {
  const missing = ZENDESK_KEYS.filter((key) => isBlank(env[key]));
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }

  return {
    subdomain: env.ZENDESK_SUBDOMAIN as string,
    email: env.ZENDESK_EMAIL as string,
    apiKey: env.ZENDESK_API_KEY as string,
  };
}

export function readHttpConfig(env: Environment = process.env): HttpConfig {
  if (isBlank(env.MCP_BEARER_TOKEN)) {
    throw new Error("Missing required environment variable: MCP_BEARER_TOKEN");
  }

  return {
    ...readListenerConfig(env),
    bearerToken: env.MCP_BEARER_TOKEN as string,
  };
}

export type HttpOAuthConfig = {
  host: string;
  port: number;
  allowedHosts: string[];
  publicBaseUrl: URL;
  issuerUrl: URL;
  mcpResourceUrl: URL;
  zendeskCallbackUrl: URL;
  zendeskSubdomain: string;
  zendeskOAuthClientId: string;
  zendeskOAuthClientSecret: string;
  oauthEncryptionKey: Buffer;
  oauthDbPath: string;
  mcpAccessTokenTtlSeconds: number;
  zendeskHttpTimeoutMs: number;
};

const HTTP_OAUTH_REQUIRED_KEYS = [
  "PUBLIC_BASE_URL",
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_OAUTH_CLIENT_ID",
  "ZENDESK_OAUTH_CLIENT_SECRET",
  "OAUTH_ENCRYPTION_KEY",
  "OAUTH_DB_PATH",
] as const;

function boundedInteger(
  name: string,
  raw: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = raw ?? String(fallback);
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

export function readHttpOAuthConfig(
  env: Environment = process.env,
): HttpOAuthConfig {
  const missing = HTTP_OAUTH_REQUIRED_KEYS.filter((key) => isBlank(env[key]));
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }

  const publicBaseUrl = new URL(env.PUBLIC_BASE_URL as string);
  const originOnly =
    publicBaseUrl.protocol === "https:" &&
    publicBaseUrl.username === "" &&
    publicBaseUrl.password === "" &&
    publicBaseUrl.pathname === "/" &&
    publicBaseUrl.search === "" &&
    publicBaseUrl.hash === "";
  if (!originOnly) throw new Error("PUBLIC_BASE_URL must be an origin-only HTTPS origin");

  const listener = readListenerConfig(env);
  if (!listener.allowedHosts.includes(publicBaseUrl.hostname)) {
    throw new Error("PUBLIC_BASE_URL hostname must appear in MCP_ALLOWED_HOSTS");
  }

  const zendeskSubdomain = env.ZENDESK_SUBDOMAIN as string;
  if (!/^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.test(zendeskSubdomain)) {
    throw new Error("ZENDESK_SUBDOMAIN must be one DNS label");
  }

  const encryptionKey = Buffer.from(env.OAUTH_ENCRYPTION_KEY as string, "base64");
  if (encryptionKey.length !== 32) {
    throw new Error("OAUTH_ENCRYPTION_KEY must decode to exactly 32 decoded bytes");
  }

  const databasePath = env.OAUTH_DB_PATH as string;
  if (!isAbsolute(databasePath)) {
    throw new Error("OAUTH_DB_PATH must be an absolute path");
  }

  return {
    host: listener.host,
    port: listener.port,
    allowedHosts: listener.allowedHosts,
    publicBaseUrl: new URL(publicBaseUrl.origin),
    issuerUrl: new URL(publicBaseUrl.origin),
    mcpResourceUrl: new URL("/mcp", publicBaseUrl),
    zendeskCallbackUrl: new URL("/oauth/zendesk/callback", publicBaseUrl),
    zendeskSubdomain: zendeskSubdomain.toLowerCase(),
    zendeskOAuthClientId: env.ZENDESK_OAUTH_CLIENT_ID as string,
    zendeskOAuthClientSecret: env.ZENDESK_OAUTH_CLIENT_SECRET as string,
    oauthEncryptionKey: encryptionKey,
    oauthDbPath: databasePath,
    mcpAccessTokenTtlSeconds: boundedInteger(
      "MCP_ACCESS_TOKEN_TTL_SECONDS",
      env.MCP_ACCESS_TOKEN_TTL_SECONDS,
      900,
      60,
      3600,
    ),
    zendeskHttpTimeoutMs: boundedInteger(
      "ZENDESK_HTTP_TIMEOUT_MS",
      env.ZENDESK_HTTP_TIMEOUT_MS,
      15000,
      1000,
      60000,
    ),
  };
}
