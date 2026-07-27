import { isIP } from "node:net";
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

export type HttpOAuthConfig = {
  host: string;
  port: number;
  allowedHosts: string[];
  publicBaseUrl: URL;
  zendeskSubdomain: string;
  zendeskOAuthClientId: string;
  zendeskOAuthClientSecret: string;
  oauthEncryptionKey: Buffer;
  oauthDbPath: string;
  zendeskCallbackUrl: URL;
};

const ZENDESK_KEYS = [
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_EMAIL",
  "ZENDESK_API_KEY",
] as const;

const HTTP_OAUTH_KEYS = [
  "PUBLIC_BASE_URL",
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_OAUTH_CLIENT_ID",
  "ZENDESK_OAUTH_CLIENT_SECRET",
  "OAUTH_ENCRYPTION_KEY",
  "OAUTH_DB_PATH",
] as const;

function isBlank(value: string | undefined): boolean {
  return value === undefined || value.trim() === "";
}

function readNetworkConfig(env: Environment): {
  host: string;
  port: number;
  allowedHosts: string[];
} {
  const rawPort = env.PORT ?? "3000";
  if (!/^\d+$/.test(rawPort)) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }

  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }

  const rawAllowedHosts = env.MCP_ALLOWED_HOSTS ?? "localhost,127.0.0.1";
  const allowedHosts = [
    ...new Set(
      rawAllowedHosts
        .split(",")
        .map((host) => host.trim())
        .filter(Boolean),
    ),
  ];

  if (allowedHosts.length === 0) {
    throw new Error("MCP_ALLOWED_HOSTS must contain at least one hostname");
  }

  return {
    host: env.HOST?.trim() || "0.0.0.0",
    port,
    allowedHosts,
  };
}

function isLoopbackHost(hostname: string): boolean {
  const unwrapped = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (unwrapped.toLowerCase() === "localhost" || unwrapped === "::1") {
    return true;
  }
  return isIP(unwrapped) === 4 && unwrapped.startsWith("127.");
}

function readPublicBaseUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("PUBLIC_BASE_URL must be a canonical HTTPS origin");
  }

  const secure = url.protocol === "https:";
  const loopbackDevelopment =
    url.protocol === "http:" && isLoopbackHost(url.hostname);
  if (
    (!secure && !loopbackDevelopment) ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("PUBLIC_BASE_URL must be a canonical HTTPS origin");
  }
  return url;
}

function readEncryptionKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(
      "OAUTH_ENCRYPTION_KEY must be canonical base64url for exactly 32 bytes",
    );
  }
  const key = Buffer.from(value, "base64url");
  if (key.length !== 32 || key.toString("base64url") !== value) {
    throw new Error(
      "OAUTH_ENCRYPTION_KEY must be canonical base64url for exactly 32 bytes",
    );
  }
  return key;
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

export function readHttpOAuthConfig(
  env: Environment = process.env,
): HttpOAuthConfig {
  const missing = HTTP_OAUTH_KEYS.filter((key) => isBlank(env[key]));
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`,
    );
  }

  const publicBaseUrl = readPublicBaseUrl(env.PUBLIC_BASE_URL as string);
  const zendeskSubdomain = (env.ZENDESK_SUBDOMAIN as string)
    .trim()
    .toLowerCase();
  if (
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(zendeskSubdomain)
  ) {
    throw new Error("ZENDESK_SUBDOMAIN must be one DNS label");
  }

  const oauthDbPath = (env.OAUTH_DB_PATH as string).trim();
  if (!isAbsolute(oauthDbPath)) {
    throw new Error("OAUTH_DB_PATH must be an absolute path");
  }

  return {
    ...readNetworkConfig(env),
    publicBaseUrl,
    zendeskSubdomain,
    zendeskOAuthClientId: (env.ZENDESK_OAUTH_CLIENT_ID as string).trim(),
    zendeskOAuthClientSecret: env.ZENDESK_OAUTH_CLIENT_SECRET as string,
    oauthEncryptionKey: readEncryptionKey(env.OAUTH_ENCRYPTION_KEY as string),
    oauthDbPath,
    zendeskCallbackUrl: new URL("/oauth/callback", publicBaseUrl),
  };
}

export function readHttpConfig(env: Environment = process.env): HttpConfig {
  if (isBlank(env.MCP_BEARER_TOKEN)) {
    throw new Error("Missing required environment variable: MCP_BEARER_TOKEN");
  }

  return {
    bearerToken: env.MCP_BEARER_TOKEN as string,
    ...readNetworkConfig(env),
  };
}
