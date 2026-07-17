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

const ZENDESK_KEYS = [
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_EMAIL",
  "ZENDESK_API_KEY",
] as const;

function isBlank(value: string | undefined): boolean {
  return value === undefined || value.trim() === "";
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
    bearerToken: env.MCP_BEARER_TOKEN as string,
    allowedHosts,
  };
}
