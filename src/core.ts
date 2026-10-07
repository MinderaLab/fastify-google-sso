import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { CodeChallengeMethod, OAuth2Client } from "google-auth-library";

/**
 * The framework-neutral half of this package: the whole Google login flow
 * (state + PKCE, code exchange, ID-token verification, isAllowed) and the
 * signed session cookie, expressed as plain functions over a Cookie request
 * header and Set-Cookie response header values. The Fastify plugin
 * (index.ts) is a thin wrapper around this; a service on Node's own http
 * module, or any other framework, can use it directly. Nothing here imports
 * Fastify.
 */

/**
 * The verified identity of whoever just logged in — everything isAllowed
 * needs to decide whether they're let in, and what a session hands back
 * afterward.
 */
export interface GoogleSsoProfile {
  email: string;
  name?: string;
  picture?: string;
  /** The Google Workspace domain, present only for a Workspace account (not a personal @gmail.com one). */
  hostedDomain?: string;
}

export interface GoogleSsoCoreOptions {
  /** OAuth 2.0 Client ID from Google Cloud Console (APIs & Services → Credentials). */
  clientId: string;
  /** OAuth 2.0 Client secret from the same place. */
  clientSecret: string;
  /**
   * The exact callback URL registered for this client in Google Cloud
   * Console, e.g. "https://admin.example.com/auth/google/callback". Must
   * match byte-for-byte (scheme, host, path) or Google rejects the request
   * before your app ever sees it.
   */
  callbackUri: string;
  /**
   * Secret used to sign the session cookie. Generate with e.g.
   * `openssl rand -hex 32`. Rotating it invalidates every existing session
   * (a deliberate, low-cost way to force everyone to log in again).
   */
  sessionSecret: string;
  /**
   * Decides who's actually allowed in once Google has verified their
   * identity — logging in with Google only proves *who* someone is, not
   * that they should have access. Typical implementation: check
   * profile.hostedDomain === "yourcompany.com", profile.email against an
   * explicit allowlist, or Google Group membership via googleGroupChecker.
   * If it throws, the login is refused with a 503 and no session is set.
   */
  isAllowed: (profile: GoogleSsoProfile) => boolean | Promise<boolean>;
  /** Session cookie name. Default "google_sso_session". */
  cookieName?: string;
  /** Session lifetime in seconds. Default 43200 (12 hours). */
  sessionTtlSeconds?: number;
  /** Where to send the browser after a successful login. Default "/". */
  successRedirect?: string;
  /**
   * Google's own `prompt` OAuth parameter. Default "select_account": always
   * show the account chooser, even if the browser already has an active
   * Google session. Without this, logging out of *this app* (which only
   * clears its own session cookie — no third-party app can log a browser
   * out of Google itself) can silently re-authenticate the same account on
   * the very next visit, since Google approves the request without asking —
   * logout then looks like it did nothing, even though it worked correctly.
   * "consent" is more aggressive still (re-shows the scope consent screen
   * too); "none" restores the original silent-reauth behavior.
   */
  prompt?: "none" | "consent" | "select_account";
  /**
   * SameSite attribute of the session cookie. Default "lax". "strict" keeps
   * the cookie off every request another site starts, including a link
   * someone follows into the app. The short-lived login-state cookie is
   * always Lax, since it must come back on Google's redirect to the callback.
   */
  sameSite?: "lax" | "strict";
}

/** Per-request cookie attributes. */
export interface CookieContext {
  /** Whether to mark cookies Secure — true when the browser reached the app over https. */
  secure: boolean;
}

export type CallbackResult =
  | {
      ok: true;
      profile: GoogleSsoProfile;
      /** successRedirect: where to send the browser now. */
      redirect: string;
      /** Set-Cookie header values to send: the session, and clearing the login-state cookie. */
      setCookies: string[];
    }
  | {
      ok: false;
      /** HTTP status to answer with: 400, 401, 403, 502 or 503. */
      status: number;
      /** A short plain-text message for the browser. */
      message: string;
      /** For your logs: why, in a word or two. */
      reason: string;
      /** For your logs: the underlying error, when there was one. */
      error?: unknown;
      /** Set-Cookie header values to send (clears the login-state cookie). */
      setCookies: string[];
    };

export interface GoogleSsoCore {
  /** Starts a login: redirect the browser to url, sending setCookies along. */
  startLogin(ctx: CookieContext): Promise<{ url: string; setCookies: string[] }>;
  /**
   * Finishes a login on the callback route. query is the callback request's
   * query string; cookieHeader its Cookie header.
   */
  handleCallback(query: URLSearchParams, cookieHeader: string | undefined, ctx: CookieContext): Promise<CallbackResult>;
  /** The logged-in profile from a request's Cookie header, or null for none, an invalid one or an expired one. */
  readSession(cookieHeader: string | undefined): GoogleSsoProfile | null;
  /** Set-Cookie header values that log the browser out. */
  logoutCookies(ctx: CookieContext): string[];
}

interface SessionPayload extends GoogleSsoProfile {
  /** Unix seconds. */
  exp: number;
}

interface LoginState {
  state: string;
  verifier: string;
  /** Unix seconds. */
  exp: number;
}

const DEFAULT_COOKIE_NAME = "google_sso_session";
const DEFAULT_TTL_SECONDS = 12 * 60 * 60;
const DEFAULT_PROMPT = "select_account";
const LOGIN_STATE_TTL_SECONDS = 10 * 60;
// openid+email+profile: the minimum needed to get an id_token back with a
// verified email and (for a Workspace account) its hd claim.
const SCOPES = ["openid", "email", "profile"];

// The session is signed with sessionSecret alone, independent of any cookie
// secret a host app has of its own, so sessionSecret is always what decides
// whether a session is genuine.
function sign(value: string, secret: string): string {
  const mac = createHmac("sha256", secret).update(value).digest("base64url");
  return `${value}.${mac}`;
}

function unsign(signedValue: string, secret: string): string | null {
  const separatorIndex = signedValue.lastIndexOf(".");
  if (separatorIndex === -1) return null;
  const value = signedValue.slice(0, separatorIndex);
  const mac = signedValue.slice(separatorIndex + 1);
  const expectedMac = createHmac("sha256", secret).update(value).digest("base64url");
  const macBuffer = Buffer.from(mac);
  const expectedBuffer = Buffer.from(expectedMac);
  if (macBuffer.length !== expectedBuffer.length || !timingSafeEqual(macBuffer, expectedBuffer)) return null;
  return value;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function getCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    if (part.slice(0, i).trim() !== name) continue;
    const raw = part.slice(i + 1).trim();
    // Values are written URI-encoded (as @fastify/cookie, which 1.x used,
    // wrote them), but a raw value is accepted too.
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  return null;
}

function serializeCookie(
  name: string,
  value: string,
  attrs: { maxAge: number; sameSite: "Lax" | "Strict"; secure: boolean }
): string {
  return (
    `${name}=${encodeURIComponent(value)}; Max-Age=${attrs.maxAge}; Path=/; HttpOnly; SameSite=${attrs.sameSite}` +
    (attrs.secure ? "; Secure" : "")
  );
}

function readSigned<T>(cookieHeader: string | undefined, name: string, secret: string): T | null {
  const raw = getCookie(cookieHeader, name);
  if (!raw) return null;
  const value = unsign(raw, secret);
  if (value === null) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

export function createGoogleSsoCore(opts: GoogleSsoCoreOptions): GoogleSsoCore {
  const cookieName = opts.cookieName ?? DEFAULT_COOKIE_NAME;
  const stateCookieName = `${cookieName}_login`;
  const ttlSeconds = opts.sessionTtlSeconds ?? DEFAULT_TTL_SECONDS;
  const successRedirect = opts.successRedirect ?? "/";
  const sameSite = opts.sameSite === "strict" ? "Strict" : "Lax";
  const client = new OAuth2Client({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    redirectUri: opts.callbackUri,
  });

  function clearStateCookie(ctx: CookieContext): string {
    return serializeCookie(stateCookieName, "", { maxAge: 0, sameSite: "Lax", secure: ctx.secure });
  }

  function failure(
    status: number,
    message: string,
    reason: string,
    ctx: CookieContext,
    error?: unknown
  ): CallbackResult {
    return { ok: false, status, message, reason, error, setCookies: [clearStateCookie(ctx)] };
  }

  return {
    async startLogin(ctx) {
      const state = randomBytes(16).toString("base64url");
      const { codeVerifier, codeChallenge } = await client.generateCodeVerifierAsync();
      const url = client.generateAuthUrl({
        scope: SCOPES,
        state,
        prompt: opts.prompt ?? DEFAULT_PROMPT,
        code_challenge: codeChallenge,
        code_challenge_method: CodeChallengeMethod.S256,
      });
      const payload: LoginState = {
        state,
        verifier: codeVerifier,
        exp: Math.floor(Date.now() / 1000) + LOGIN_STATE_TTL_SECONDS,
      };
      const cookie = serializeCookie(stateCookieName, sign(JSON.stringify(payload), opts.sessionSecret), {
        maxAge: LOGIN_STATE_TTL_SECONDS,
        sameSite: "Lax",
        secure: ctx.secure,
      });
      return { url, setCookies: [cookie] };
    },

    async handleCallback(query, cookieHeader, ctx) {
      const googleError = query.get("error");
      if (googleError) {
        return failure(401, "Login was cancelled or refused by Google.", `google: ${googleError}`, ctx);
      }
      const loginState = readSigned<LoginState>(cookieHeader, stateCookieName, opts.sessionSecret);
      const state = query.get("state");
      const code = query.get("code");
      if (
        !loginState ||
        typeof loginState.state !== "string" ||
        typeof loginState.verifier !== "string" ||
        typeof loginState.exp !== "number" ||
        loginState.exp < Date.now() / 1000 ||
        !state ||
        !safeEqual(state, loginState.state) ||
        !code
      ) {
        return failure(400, "Login expired or was started elsewhere. Please try again.", "invalid login state", ctx);
      }

      let idToken: string | null | undefined;
      try {
        const { tokens } = await client.getToken({ code, codeVerifier: loginState.verifier });
        idToken = tokens.id_token;
      } catch (err) {
        return failure(401, "Login failed.", "token exchange failed", ctx, err);
      }
      if (!idToken) {
        return failure(502, "Google did not return an ID token.", "no id token", ctx);
      }

      let payload;
      try {
        const ticket = await client.verifyIdToken({ idToken, audience: opts.clientId });
        payload = ticket.getPayload();
      } catch (err) {
        return failure(401, "Could not verify Google login.", "id token verification failed", ctx, err);
      }
      if (!payload?.email || !payload.email_verified) {
        return failure(401, "Your Google account has no verified email address.", "no verified email", ctx);
      }

      const profile: GoogleSsoProfile = {
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
        hostedDomain: payload.hd,
      };
      let allowed: boolean;
      try {
        allowed = await opts.isAllowed(profile);
      } catch (err) {
        // E.g. a group-membership lookup that Google couldn't answer. Fail
        // closed: no session, and a 503 rather than a 403, since this isn't
        // the user being refused — it's us not being able to decide.
        return failure(503, "Could not check your access right now. Please try again later.", "isAllowed threw", ctx, err);
      }
      if (!allowed) {
        return failure(403, `${profile.email} is not allowed to access this application.`, "rejected by isAllowed", ctx);
      }

      const session: SessionPayload = { ...profile, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
      const sessionCookie = serializeCookie(cookieName, sign(JSON.stringify(session), opts.sessionSecret), {
        maxAge: ttlSeconds,
        sameSite,
        secure: ctx.secure,
      });
      return { ok: true, profile, redirect: successRedirect, setCookies: [sessionCookie, clearStateCookie(ctx)] };
    },

    readSession(cookieHeader) {
      const payload = readSigned<SessionPayload>(cookieHeader, cookieName, opts.sessionSecret);
      if (
        !payload ||
        typeof payload.exp !== "number" ||
        payload.exp < Date.now() / 1000 ||
        typeof payload.email !== "string"
      ) {
        return null;
      }
      const { exp, ...profile } = payload;
      return profile;
    },

    logoutCookies(ctx) {
      return [serializeCookie(cookieName, "", { maxAge: 0, sameSite, secure: ctx.secure })];
    },
  };
}

export { googleGroupChecker } from "./groups.js";
export type { GoogleGroupChecker, GoogleGroupCheckerOptions, ServiceAccountKey } from "./groups.js";
