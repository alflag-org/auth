import type { SecretVersion } from "./config";

const encoder = new TextEncoder();

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index += 1) difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  return difference === 0;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  const normalized = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(normalized);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomString(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return encodeBase64Url(new Uint8Array(digest));
}

async function hmacKey(secret: SecretVersion, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", encoder.encode(secret.value), { name: "HMAC", hash: "SHA-256" }, false, usages);
}

async function hmac(value: string, secret: SecretVersion): Promise<Uint8Array> {
  const key = await hmacKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return new Uint8Array(signature);
}

async function verifyHmac(value: string, secret: SecretVersion, signature: Uint8Array): Promise<boolean> {
  const key = await hmacKey(secret, ["verify"]);
  const fixedSignature = new ArrayBuffer(signature.byteLength);
  new Uint8Array(fixedSignature).set(signature);
  return crypto.subtle.verify("HMAC", key, fixedSignature, encoder.encode(value));
}

export async function signVersionedValue(payload: string, secret: SecretVersion): Promise<string> {
  const version = String(secret.version);
  const encoded = encodeBase64Url(encoder.encode(payload));
  const signature = encodeBase64Url(await hmac(`${version}.${encoded}`, secret));
  return `${version}.${encoded}.${signature}`;
}

export async function verifyVersionedValue(value: string, secrets: SecretVersion[]): Promise<string | null> {
  const parts = value.split(".");
  if (parts.length !== 3) return null;
  const [versionText, encoded, signature] = parts;
  const version = Number(versionText);
  const secret = secrets.find((candidate) => candidate.version === version);
  if (!secret || !encoded || !signature) return null;
  let supplied: Uint8Array;
  try {
    supplied = decodeBase64Url(signature);
  } catch {
    return null;
  }
  if (!(await verifyHmac(`${versionText}.${encoded}`, secret, supplied))) return null;
  try {
    return new TextDecoder().decode(decodeBase64Url(encoded));
  } catch {
    return null;
  }
}
