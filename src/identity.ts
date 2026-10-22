import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import type { GoogleSsoProfile } from "./core.js";

/**
 * The gate's signed identity header: who signed in, as a short-lived ES256
 * JWT the gate adds to every request it proxies for a signed-in browser. An
 * app behind the gate checks it with the gate's public key, so it doesn't
 * have to trust that a request came through the gate: one that went around
 * it (from elsewhere on the private network) has no valid header.
 *
 * Plain JWT, so any language's JWT library can check it: algorithm ES256,
 * issuer "google-sso-gate", audience the app's external origin.
 */

export const IDENTITY_HEADER = "x-gate-identity";
export const IDENTITY_ISSUER = "google-sso-gate";
const TTL_SECONDS = 60;
const DEFAULT_LEEWAY_SECONDS = 30;

interface IdentityClaims {
  iss: string;
  aud: string;
  sub: string;
  email: string;
  name?: string;
  hd?: string;
  iat: number;
  exp: number;
}

function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

/** An EC P-256 key pair as PEM, for GATE_SIGNING_KEY (private) and the apps (public). */
export function generateIdentityKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function assertP256(key: KeyObject, what: string): KeyObject {
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error(`${what} must be an EC P-256 key (google-sso-gate keygen makes one).`);
  }
  return key;
}

export function createIdentitySigner(privateKeyPem: string): {
  publicKey: string;
  sign(profile: GoogleSsoProfile, audience: string): string;
} {
  const key = assertP256(createPrivateKey(privateKeyPem), "The signing key");
  return {
    publicKey: createPublicKey(key).export({ type: "spki", format: "pem" }).toString(),
    sign(profile, audience) {
      const now = Math.floor(Date.now() / 1000);
      const claims: IdentityClaims = {
        iss: IDENTITY_ISSUER,
        aud: audience,
        sub: profile.email,
        email: profile.email,
        name: profile.name,
        hd: profile.hostedDomain,
        iat: now,
        exp: now + TTL_SECONDS,
      };
      const input = `${b64url(JSON.stringify({ alg: "ES256", typ: "JWT" }))}.${b64url(JSON.stringify(claims))}`;
      const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
      return `${input}.${b64url(signature)}`;
    },
  };
}

export interface VerifyIdentityOptions {
  /** The gate's public key (PEM). */
  publicKey: string | KeyObject;
  /** This app's external origin, e.g. "https://sitemap-test.tail127ff5.ts.net". */
  audience: string;
  /** Allowed clock difference in seconds. Default 30. */
  leewaySeconds?: number;
}

/**
 * The signed-in user from a request's X-Gate-Identity header, or null when
 * it's missing, forged, expired, or meant for another app.
 */
export function verifyGateIdentity(header: string | string[] | undefined, opts: VerifyIdentityOptions): GoogleSsoProfile | null {
  if (typeof header !== "string") return null;
  const parts = header.split(".");
  if (parts.length !== 3) return null;
  // Outside the try: a wrong key is a setup error, not a forged header.
  const key = assertP256(typeof opts.publicKey === "string" ? createPublicKey(opts.publicKey) : opts.publicKey, "The public key");
  try {
    const jwtHeader = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    if (jwtHeader.alg !== "ES256") return null;
    const signature = Buffer.from(parts[2], "base64url");
    if (!verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), { key, dsaEncoding: "ieee-p1363" }, signature)) return null;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as Partial<IdentityClaims>;
    const now = Math.floor(Date.now() / 1000);
    const leeway = opts.leewaySeconds ?? DEFAULT_LEEWAY_SECONDS;
    if (
      claims.iss !== IDENTITY_ISSUER ||
      claims.aud !== new URL(opts.audience).origin ||
      typeof claims.email !== "string" ||
      typeof claims.exp !== "number" ||
      typeof claims.iat !== "number" ||
      claims.exp + leeway < now ||
      claims.iat - leeway > now
    ) {
      return null;
    }
    return { email: claims.email, name: claims.name, hostedDomain: claims.hd };
  } catch {
    return null;
  }
}
