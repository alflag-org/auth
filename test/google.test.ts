import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import { createLocalJWKSet, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { getRuntimeConfig } from "../src/config";
import { verifyGoogleIdentityToken } from "../src/google";

async function token(
  overrides: Record<string, unknown> = {},
  options: { issuer?: string; audience?: string } = {},
): Promise<{ value: string; key: CryptoKey }> {
  const pair = await generateKeyPair("RS256");
  const value = await new SignJWT({
    sub: "google-sub-123",
    email: "user@example.com",
    email_verified: true,
    name: "Workspace User",
    hd: "example.com",
    nonce: "nonce-google",
    ...overrides,
  })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(options.issuer ?? "https://accounts.google.com")
    .setAudience(options.audience ?? "test-google-client")
    .setIssuedAt(typeof overrides.iat === "number" ? overrides.iat : undefined)
    .setExpirationTime("5m")
    .sign(pair.privateKey);
  return { value, key: pair.publicKey };
}

describe("Google Workspace identity validation", () => {
  it("accepts a signed Workspace identity and rejects provider/account claim deviations", async () => {
    const config = getRuntimeConfig(env);
    const valid = await token();
    const jwks = createLocalJWKSet({ keys: [await exportJWK(valid.key)] });
    await expect(verifyGoogleIdentityToken(valid.value, "nonce-google", config, jwks)).resolves.toBeUndefined();
    const legacyIssuer = await token({}, { issuer: "accounts.google.com" });
    await expect(
      verifyGoogleIdentityToken(
        legacyIssuer.value,
        "nonce-google",
        config,
        createLocalJWKSet({ keys: [await exportJWK(legacyIssuer.key)] }),
      ),
    ).resolves.toBeUndefined();

    const rejected: Array<{
      name: string;
      overrides: Record<string, unknown>;
      options?: { issuer?: string; audience?: string };
    }> = [
      { name: "personal account", overrides: { email: "user@gmail.com", hd: "gmail.com" } },
      { name: "missing hosted domain", overrides: { hd: undefined } },
      { name: "mismatched hosted domain", overrides: { hd: "other.example" } },
      { name: "wrong issuer", overrides: {}, options: { issuer: "https://evil.example" } },
      { name: "wrong audience", overrides: {}, options: { audience: "another-client" } },
      { name: "wrong nonce", overrides: { nonce: "another-nonce" } },
      { name: "future issued-at", overrides: { iat: Math.floor(Date.now() / 1000) + 60 } },
    ];
    for (const testCase of rejected) {
      const candidate = await token(testCase.overrides, testCase.options);
      if (testCase.name === "future issued-at") {
        expect(decodeJwt(candidate.value).iat).toBe(testCase.overrides.iat);
      }
      const candidateJWK = createLocalJWKSet({ keys: [await exportJWK(candidate.key)] });
      await expect(
        verifyGoogleIdentityToken(candidate.value, "nonce-google", config, candidateJWK),
        testCase.name,
      ).rejects.toThrow();
    }
    const missingIssuedAtPair = await generateKeyPair("RS256");
    const missingIssuedAt = await new SignJWT({
      sub: "google-sub-123",
      email: "user@example.com",
      email_verified: true,
      name: "Workspace User",
      hd: "example.com",
      nonce: "nonce-google",
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer("https://accounts.google.com")
      .setAudience("test-google-client")
      .setExpirationTime("5m")
      .sign(missingIssuedAtPair.privateKey);
    await expect(
      verifyGoogleIdentityToken(
        missingIssuedAt,
        "nonce-google",
        config,
        createLocalJWKSet({ keys: [await exportJWK(missingIssuedAtPair.publicKey)] }),
      ),
    ).rejects.toThrow();

    const expiredPair = await generateKeyPair("RS256");
    const expiredWithKnownKey = await new SignJWT({
      sub: "google-sub-123",
      email: "user@example.com",
      email_verified: true,
      name: "Workspace User",
      hd: "example.com",
      nonce: "nonce-google",
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer("https://accounts.google.com")
      .setAudience("test-google-client")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1)
      .sign(expiredPair.privateKey);
    await expect(
      verifyGoogleIdentityToken(
        expiredWithKnownKey,
        "nonce-google",
        config,
        createLocalJWKSet({ keys: [await exportJWK(expiredPair.publicKey)] }),
      ),
    ).rejects.toThrow();
    const differentKey = await generateKeyPair("RS256");
    await expect(
      verifyGoogleIdentityToken(
        valid.value,
        "nonce-google",
        config,
        createLocalJWKSet({ keys: [await exportJWK(differentKey.publicKey)] }),
      ),
    ).rejects.toThrow();
  });
});
