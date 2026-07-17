import { chmod, lstat, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

import {
  readOAuthAdminConfig,
  type Environment,
} from "../config.js";
import { openSqliteOAuthStore } from "./sqlite-store.js";
import { TokenCipher } from "./token-cipher.js";

const BACKUP_DIRECTORY = "/data/backups";
const DECIMAL_ID = /^\d+$/;
const FAMILY_ID = /^[A-Za-z0-9_-]{16,}$/;

export type AdminIo = {
  stdout(message: string): void;
  stderr(message: string): void;
};

class UsageError extends Error {}

type ParsedCommand =
  | { kind: "sessions"; zendeskUserId: string }
  | { kind: "revoke-family"; familyId: string; confirmed: boolean }
  | { kind: "disconnect-user"; zendeskUserId: string; confirmed: boolean }
  | { kind: "backup"; destination: string };

type AdminRuntime = {
  backupDirectory: string;
};

const defaultRuntime: AdminRuntime = { backupDirectory: BACKUP_DIRECTORY };

function escapeControls(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, "?");
}

function safeJson(value: unknown): string {
  return escapeControls(JSON.stringify(value));
}

function parseOptions(argv: string[]): Map<string, string | true> {
  const options = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (!option?.startsWith("--") || option.includes("=")) throw new UsageError();
    if (options.has(option)) throw new UsageError();
    if (option === "--confirm") {
      options.set(option, true);
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new UsageError();
    options.set(option, value);
    index += 1;
  }
  return options;
}

function requireOnly(
  options: Map<string, string | true>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((name) => !options.has(name)) ||
    [...options.keys()].some((name) => !allowed.has(name))
  ) {
    throw new UsageError();
  }
}

function stringOption(options: Map<string, string | true>, name: string): string {
  const value = options.get(name);
  if (typeof value !== "string") throw new UsageError();
  return value;
}

function parseCommand(argv: string[]): ParsedCommand {
  const [command, ...rawOptions] = argv;
  if (command === undefined || command.startsWith("--")) throw new UsageError();
  const options = parseOptions(rawOptions);

  if (command === "sessions") {
    requireOnly(options, ["--zendesk-user-id"]);
    const zendeskUserId = stringOption(options, "--zendesk-user-id");
    if (!DECIMAL_ID.test(zendeskUserId)) throw new UsageError();
    return { kind: command, zendeskUserId };
  }
  if (command === "revoke-family") {
    requireOnly(options, ["--family-id"], ["--confirm"]);
    const familyId = stringOption(options, "--family-id");
    const confirmed = options.get("--confirm") === true;
    if (!FAMILY_ID.test(familyId)) throw new UsageError();
    return { kind: command, familyId, confirmed };
  }
  if (command === "disconnect-user") {
    requireOnly(options, ["--zendesk-user-id"], ["--confirm"]);
    const zendeskUserId = stringOption(options, "--zendesk-user-id");
    const confirmed = options.get("--confirm") === true;
    if (!DECIMAL_ID.test(zendeskUserId)) throw new UsageError();
    return { kind: command, zendeskUserId, confirmed };
  }
  if (command === "backup") {
    requireOnly(options, ["--destination"]);
    const destination = stringOption(options, "--destination");
    if (!validBackupDestination(destination)) throw new UsageError();
    return { kind: command, destination };
  }
  throw new UsageError();
}

function validBackupDestination(destination: string): boolean {
  if (!isAbsolute(destination) || resolve(destination) !== destination) return false;
  return dirname(destination) === BACKUP_DIRECTORY;
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function prepareBackup(
  destination: string,
  runtime: AdminRuntime,
): Promise<string> {
  const physicalDestination = runtime.backupDirectory === BACKUP_DIRECTORY
    ? destination
    : join(runtime.backupDirectory, relative(BACKUP_DIRECTORY, destination));
  await mkdir(runtime.backupDirectory, { recursive: true, mode: 0o700 });
  const backupDirectory = await lstat(runtime.backupDirectory);
  if (!backupDirectory.isDirectory() || backupDirectory.isSymbolicLink()) {
    throw new Error("backup directory unavailable");
  }
  await chmod(runtime.backupDirectory, 0o700);
  if (await pathExists(physicalDestination)) throw new UsageError();
  return physicalDestination;
}

const defaultIo: AdminIo = {
  stdout: (message) => console.log(message),
  stderr: (message) => console.error(message),
};

export function runOAuthAdmin(
  argv: string[],
  env?: Environment,
  io?: AdminIo,
): Promise<number>;
export async function runOAuthAdmin(
  argv: string[],
  env: Environment = process.env,
  io: AdminIo = defaultIo,
  runtime: AdminRuntime = defaultRuntime,
): Promise<number> {
  let command: ParsedCommand;
  let backupDestination: string | undefined;
  try {
    command = parseCommand(argv);
    if (command.kind === "backup") {
      backupDestination = await prepareBackup(command.destination, runtime);
    }
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr("Invalid OAuth administration command.");
      return 2;
    }
    io.stderr("OAuth administration failed.");
    return 1;
  }

  if (command.kind === "revoke-family") {
    io.stdout(safeJson({ command: command.kind, familyId: command.familyId }));
    if (!command.confirmed) {
      io.stderr("Literal --confirm is required.");
      return 2;
    }
  }
  if (command.kind === "disconnect-user") {
    io.stdout(safeJson({
      command: command.kind,
      zendeskUserId: command.zendeskUserId,
    }));
    if (!command.confirmed) {
      io.stderr("Literal --confirm is required.");
      return 2;
    }
  }

  let store;
  try {
    const config = readOAuthAdminConfig(env);
    store = openSqliteOAuthStore({
      path: config.oauthDbPath,
      cipher: new TokenCipher(config.oauthEncryptionKey),
    });
    const now = Math.floor(Date.now() / 1000);

    if (command.kind === "sessions") {
      for (const session of store.listSessions(
        config.zendeskSubdomain,
        command.zendeskUserId,
        now,
      )) {
        io.stdout(safeJson({
          ...session,
          clientName:
            session.clientName === null ? null : escapeControls(session.clientName),
        }));
      }
      return 0;
    }
    if (command.kind === "revoke-family") {
      const result = store.revokeFamilyById(command.familyId, now);
      if (result.kind === "not_found") {
        io.stderr("OAuth token family was not found.");
        return 1;
      }
      io.stdout(result.kind === "revoked" ? "OAuth token family revoked." : "OAuth token family was already revoked.");
      return 0;
    }
    if (command.kind === "disconnect-user") {
      const result = store.disconnectUser(
        config.zendeskSubdomain,
        command.zendeskUserId,
        now,
      );
      if (result.kind === "not_found") {
        io.stderr("OAuth principal was not found.");
        return 1;
      }
      io.stdout(result.kind === "disconnected" ? "OAuth principal disconnected." : "OAuth principal was already disconnected.");
      return 0;
    }

    if (backupDestination === undefined) throw new Error("backup destination unavailable");
    await store.backup(backupDestination);
    io.stdout("OAuth backup created.");
    return 0;
  } catch {
    io.stderr("OAuth administration failed.");
    return 1;
  } finally {
    if (store !== undefined) {
      try {
        store.close();
      } catch {
        io.stderr("OAuth administration failed.");
        return 1;
      }
    }
  }
}
