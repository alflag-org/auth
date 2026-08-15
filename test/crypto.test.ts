import { describe, expect, it } from "vitest";
import { decodeBase64Url, signVersionedValue, verifyVersionedValue } from "../src/crypto";

const secret = { version: 1, value: "crypto-test-secret-1234567890abcdef" } as const;

describe("versioned HMAC values", () => {
  it("rejects truncated, extended, and malformed signatures", async () => {
    const signed = await signVersionedValue("payload", secret);
    const [version, encoded, signature] = signed.split(".");
    if (!version || !encoded || !signature) throw new Error("test signature was malformed");
    expect(await verifyVersionedValue(signed, [secret])).toBe("payload");
    expect(await verifyVersionedValue(`${version}.${encoded}.${signature.slice(1)}`, [secret])).toBeNull();
    expect(await verifyVersionedValue(`${version}.${encoded}.${signature}A`, [secret])).toBeNull();
    expect(await verifyVersionedValue(`${version}.${encoded}.%%%`, [secret])).toBeNull();
    expect(decodeBase64Url(signature).byteLength).toBe(32);
  });
});
