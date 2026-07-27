#!/usr/bin/env node
import "dotenv/config";
import { pathToFileURL } from "node:url";

import {
  readHttpOAuthConfig,
  type Environment,
  type HttpOAuthConfig,
} from "./config.js";
import { SecretCipher } from "./internal-auth/crypto.js";
import { InternalAuthStore } from "./internal-auth/store.js";
import {
  ZendeskOAuthClient,
  type ZendeskOAuthGateway,
} from "./internal-auth/zendesk-oauth.js";

const USAGE = [
  "Usage:",
  "  npm run admin -- create --label <label>",
  "  npm run admin -- reauthorize --user <uuid>",
  "  npm run admin -- list",
  "  npm run admin -- revoke --user <uuid> [--upstream]",
  "  npm run admin -- reset --user <uuid> --upstream",
  "  npm run admin -- backup --output <absolute-path>",
].join("\n");

type AdminDependencies = {
  env?: Environment;
  openStore?: typeof InternalAuthStore.open;
  createOAuth?: (config: HttpOAuthConfig) => ZendeskOAuthGateway;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
};

type ParsedCommand =
  | { kind: "create"; label: string }
  | { kind: "reauthorize"; userId: string }
  | { kind: "list" }
  | { kind: "revoke"; userId: string; upstream: boolean }
  | { kind: "reset"; userId: string }
  | { kind: "backup"; output: string };

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

function parseCommand(argv: string[]): ParsedCommand | undefined {
  const [command, ...args] = argv;
  if (
    command === "create" &&
    args.length === 2 &&
    args[0] === "--label" &&
    args[1].length > 0
  ) {
    return { kind: "create", label: args[1] };
  }
  if (command === "list" && args.length === 0) return { kind: "list" };
  if (
    command === "reauthorize" &&
    args.length === 2 &&
    args[0] === "--user" &&
    isUuid(args[1])
  ) {
    return { kind: "reauthorize", userId: args[1] };
  }
  if (
    command === "revoke" &&
    (args.length === 2 || args.length === 3) &&
    args[0] === "--user" &&
    isUuid(args[1]) &&
    (args.length === 2 || args[2] === "--upstream")
  ) {
    return {
      kind: "revoke",
      userId: args[1],
      upstream: args.length === 3,
    };
  }
  if (
    command === "reset" &&
    args.length === 3 &&
    args[0] === "--user" &&
    isUuid(args[1]) &&
    args[2] === "--upstream"
  ) {
    return { kind: "reset", userId: args[1] };
  }
  if (
    command === "backup" &&
    args.length === 2 &&
    args[0] === "--output" &&
    args[1].length > 0
  ) {
    return { kind: "backup", output: args[1] };
  }
  return undefined;
}

function defaultOAuth(config: HttpOAuthConfig): ZendeskOAuthGateway {
  return new ZendeskOAuthClient({
    subdomain: config.zendeskSubdomain,
    clientId: config.zendeskOAuthClientId,
    clientSecret: config.zendeskOAuthClientSecret,
    callbackUrl: config.zendeskCallbackUrl,
    timeoutMs: 10_000,
  });
}

export async function runAdmin(
  argv: string[],
  dependencies: AdminDependencies = {},
): Promise<number> {
  const stdout = dependencies.stdout ?? console.log;
  const stderr = dependencies.stderr ?? console.error;
  const command = parseCommand(argv);
  if (!command) {
    stderr(USAGE);
    return 2;
  }

  let store: InternalAuthStore | undefined;
  try {
    const config = readHttpOAuthConfig(dependencies.env);
    store = (dependencies.openStore ?? InternalAuthStore.open)({
      path: config.oauthDbPath,
      cipher: new SecretCipher(config.oauthEncryptionKey),
      subdomain: config.zendeskSubdomain,
      clientId: config.zendeskOAuthClientId,
    });

    if (command.kind === "create") {
      const created = store.createPendingUser(command.label);
      const link = new URL("/oauth/link", config.publicBaseUrl);
      link.searchParams.set("invitation", created.invitation);
      stdout(`user_id: ${created.userId}`);
      stdout(`mcp_bearer: ${created.bearer}`);
      stdout(`link_url: ${link.href}`);
      stdout(`expires_at: ${created.expiresAt}`);
      stdout("warning: The MCP bearer is shown once; transfer it securely.");
      return 0;
    }

    if (command.kind === "reauthorize") {
      const created = store.createReauthorization(command.userId);
      const link = new URL("/oauth/link", config.publicBaseUrl);
      link.searchParams.set("invitation", created.invitation);
      stdout(`user_id: ${command.userId}`);
      stdout(`link_url: ${link.href}`);
      stdout(`expires_at: ${created.expiresAt}`);
      return 0;
    }

    if (command.kind === "list") {
      stdout(JSON.stringify(store.inspectUsers(), null, 2));
      return 0;
    }

    if (command.kind === "backup") {
      await store.backup(command.output);
      stdout(`backup: ${command.output}`);
      return 0;
    }

    const localResult =
      command.kind === "reset"
        ? store.resetUser(command.userId)
        : store.revokeUser(command.userId);
    if (localResult.kind === "not_found") {
      stderr("Administration command failed");
      return 1;
    }
    stdout(`local: ${localResult.kind}`);
    const attemptUpstream =
      command.kind === "reset" || command.upstream;
    if (!attemptUpstream) {
      stdout("upstream: not_attempted");
      return 0;
    }
    if (!("capturedGrant" in localResult) || !localResult.capturedGrant) {
      stdout("upstream: unavailable");
      return 0;
    }
    try {
      const oauth = (dependencies.createOAuth ?? defaultOAuth)(config);
      await oauth.revokeCurrent(localResult.capturedGrant.accessToken);
      stdout("upstream: succeeded");
    } catch {
      stdout("upstream: failed");
    }
    return 0;
  } catch {
    stderr("Administration command failed");
    return 1;
  } finally {
    try {
      store?.close();
    } catch {
      // The command outcome is already fixed and no secret may be emitted.
    }
  }
}

const invokedPath = process.argv[1]
  ? pathToFileURL(process.argv[1]).href
  : undefined;
if (invokedPath === import.meta.url) {
  runAdmin(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      console.error("Administration command failed");
      process.exitCode = 1;
    });
}
