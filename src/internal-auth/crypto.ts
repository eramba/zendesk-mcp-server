import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

type EncryptedEnvelope = {
  version: 1;
  nonce: string;
  ciphertext: string;
  tag: string;
};

function decodeCanonicalBase64url(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("invalid encoding");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new Error("invalid encoding");
  }
  return decoded;
}

function parseEnvelope(value: string): {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
} {
  const parsed: unknown = JSON.parse(value);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    (parsed as Partial<EncryptedEnvelope>).version !== 1
  ) {
    throw new Error("invalid envelope");
  }

  const envelope = parsed as Partial<EncryptedEnvelope>;
  const nonce = decodeCanonicalBase64url(envelope.nonce);
  const ciphertext = decodeCanonicalBase64url(envelope.ciphertext);
  const tag = decodeCanonicalBase64url(envelope.tag);
  if (nonce.length !== 12 || tag.length !== 16) {
    throw new Error("invalid envelope");
  }
  return { nonce, ciphertext, tag };
}

export function randomOpaque(prefix = ""): string {
  return `${prefix}${randomBytes(32).toString("base64url")}`;
}

export function hashOpaque(value: string): string {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("base64url");
}

export class SecretCipher {
  readonly #key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) {
      throw new Error("SecretCipher key must be exactly 32 bytes");
    }
    this.#key = Buffer.from(key);
  }

  encrypt(plaintext: string, associatedData: string): string {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#key, nonce);
    cipher.setAAD(Buffer.from(associatedData, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const envelope: EncryptedEnvelope = {
      version: 1,
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
    return JSON.stringify(envelope);
  }

  decrypt(envelopeJson: string, associatedData: string): string {
    try {
      const envelope = parseEnvelope(envelopeJson);
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.#key,
        envelope.nonce,
      );
      decipher.setAAD(Buffer.from(associatedData, "utf8"));
      decipher.setAuthTag(envelope.tag);
      return Buffer.concat([
        decipher.update(envelope.ciphertext),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Unable to decrypt stored credential");
    }
  }
}
