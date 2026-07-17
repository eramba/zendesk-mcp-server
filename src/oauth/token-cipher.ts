import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

export type EncryptedValue = {
  version: 1;
  nonce: string;
  ciphertext: string;
  tag: string;
};

type BaseCipherContext = {
  rowId: string;
  expiresAt: number;
};

export type CipherContext =
  | (BaseCipherContext & {
      kind: "key_check";
    })
  | (BaseCipherContext & {
      kind: "login";
      subdomain: string;
      clientId: string;
      browserNonceHash: string;
      redirectDigest: string;
      resourceDigest: string;
    })
  | (BaseCipherContext & {
      kind: "zendesk_credential" | "disconnect_outbox";
      subdomain: string;
      principalId: string;
      credentialVersion: number;
      principalEpoch: number;
    })
  | (BaseCipherContext & {
      kind: "staged_grant";
      purpose: "login" | "refresh";
      subdomain: string;
      expectedPrincipalId: string | null;
      expectedCredentialVersion: number | null;
      expectedPrincipalEpoch: number | null;
    })
  | (BaseCipherContext & {
      kind: "mcp_refresh_retry";
      familyId: string;
      clientId: string;
      resource: string;
      scopes: string;
      generation: number;
    });

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonical(item)]),
    );
  }
  return value;
}

function aad(context: CipherContext): Buffer {
  return Buffer.from(JSON.stringify(canonical(context)), "utf8");
}

function decodeCanonicalBase64url(value: string, field: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error(`${field} must be canonical base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new Error(`${field} must be canonical base64url`);
  }
  return decoded;
}

export function randomOpaque(bytes = 32): string {
  if (!Number.isSafeInteger(bytes) || bytes < 32) {
    throw new Error("opaque values require at least 32 random bytes");
  }
  return randomBytes(bytes).toString("base64url");
}

export function hashOpaque(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

export function digestBinding(value: string): string {
  return hashOpaque(value);
}

export class TokenCipher {
  readonly #key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) throw new Error("TokenCipher key must be exactly 32 bytes");
    this.#key = Buffer.from(key);
  }

  encrypt(plaintext: string, context: CipherContext): EncryptedValue {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#key, nonce);
    cipher.setAAD(aad(context));
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    return {
      version: 1,
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
  }

  decrypt(envelope: EncryptedValue, context: CipherContext): string {
    if (envelope.version !== 1) throw new Error("Unsupported encrypted value version");
    const nonce = decodeCanonicalBase64url(envelope.nonce, "nonce");
    if (nonce.length !== 12) throw new Error("nonce must decode to exactly 12 bytes");
    const tag = decodeCanonicalBase64url(envelope.tag, "tag");
    if (tag.length !== 16) throw new Error("tag must decode to exactly 16 bytes");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.#key,
      nonce,
    );
    decipher.setAAD(aad(context));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(decodeCanonicalBase64url(envelope.ciphertext, "ciphertext")),
      decipher.final(),
    ]).toString("utf8");
  }
}
