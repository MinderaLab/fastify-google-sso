import { createHmac, timingSafeEqual } from "node:crypto";
import fp from "fastify-plugin";
import fastifyOauth2 from "@fastify/oauth2";
import fastifyCookie from "@fastify/cookie";
import { OAuth2Client } from "google-auth-library";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

/**
 * The verified identity of whoever just logged in — everything isAllowed
 * needs to decide whether they're let in, and everything a protected route
 * gets back afterward via request.googleSsoUser.
 */
export interface GoogleSsoProfile {
  email: string;
  name?: string;
  picture?: string;
  /** The Google Workspace domain, present only for a Workspace account (not a personal @gmail.com one). */
  hostedDomain?: string;
}

export interface GoogleSsoOptions {
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
   * profile.hostedDomain === "yourcompany.com", or profile.email against an
   * explicit allowlist.
   */
  isAllowed: (profile: GoogleSsoProfile) => boolean | Promise<boolean>;
  /** Base path for this plugin's own routes (login/callback/logout). Default "/auth/google". */
  basePath?: string;
  /**
   * What to put in a browser-facing redirect Location header instead of
   * basePath, when they need to differ. Only matters behind a reverse proxy
   * that strips a path prefix before forwarding to this app (e.g. Tailscale
   * Serve's --set-path) — the app itself still only ever sees and registers
   * routes at the un-prefixed basePath (that's what actually arrives), but a
   * redirect Location header is resolved by the *browser* against the
   * external, still-prefixed URL, so it needs the full external prefix or it
   * 404s against the proxy layer instead of reaching this app. E.g. basePath
   * "/auth/google" + externalBasePath "/sitemap/auth/google" when this app
   * is reachable externally as https://host/sitemap/... Defaults to basePath
   * (no proxy prefix — the common case).
   */
  externalBasePath?: string;
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
}

interface SessionPayload extends GoogleSsoProfile {
  /** Unix seconds. */
  exp: number;
}

declare module "fastify" {
  interface FastifyRequest {
    /** Set by requireGoogleSession once a request's session cookie has been verified. */
    googleSsoUser?: GoogleSsoProfile;
  }
  interface FastifyInstance {
    /**
     * preHandler for any route that should require a logged-in, allowed
     * Google account. On a missing/invalid/expired session, redirects the
     * browser to this plugin's login route instead of returning a 401 —
     * these are human-facing pages, not an API a script calls.
     */
    requireGoogleSession(request: FastifyRequest, reply: FastifyReply): Promise<void>;
  }
}

const DEFAULT_BASE_PATH = "/auth/google";
const DEFAULT_COOKIE_NAME = "google_sso_session";
const DEFAULT_TTL_SECONDS = 12 * 60 * 60;
const DEFAULT_PROMPT = "select_account";
const OAUTH2_DECORATOR_NAME = "googleSsoOAuth2";

// Independent of @fastify/cookie's own signed-cookie feature, deliberately:
// @fastify/oauth2 requires *some* registration of @fastify/cookie to exist,
// but a host app may well have already registered it itself (with its own,
// unrelated secret) for its own purposes — registering it a second time
// throws (Fastify won't let the same fixed decorator name, e.g. setCookie,
// get added twice), and even if it didn't, sharing that secret would mean
// sessionSecret silently isn't what actually signs this cookie. Signing our
// own value with our own secret sidesteps both problems entirely.
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

async function googleSsoPlugin(fastify: FastifyInstance, opts: GoogleSsoOptions): Promise<void> {
  const basePath = opts.basePath ?? DEFAULT_BASE_PATH;
  const externalBasePath = opts.externalBasePath ?? basePath;
  const cookieName = opts.cookieName ?? DEFAULT_COOKIE_NAME;
  const ttlSeconds = opts.sessionTtlSeconds ?? DEFAULT_TTL_SECONDS;
  const successRedirect = opts.successRedirect ?? "/";

  if (!fastify.hasPlugin("@fastify/cookie")) {
    await fastify.register(fastifyCookie);
  }
  await fastify.register(fastifyOauth2, {
    name: OAUTH2_DECORATOR_NAME,
    // openid+email+profile: the minimum needed to get an id_token back with
    // a verified email and (for a Workspace account) its hd claim.
    scope: ["openid", "email", "profile"],
    credentials: {
      client: { id: opts.clientId, secret: opts.clientSecret },
      // Same as @fastify/oauth2's own GOOGLE_CONFIGURATION constant — inlined
      // rather than referenced, since that constant's static-property type
      // doesn't survive this package's CJS/ESM interop under NodeNext. These
      // are Google's well-known, stable OAuth2 endpoints.
      auth: {
        authorizeHost: "https://accounts.google.com",
        authorizePath: "/o/oauth2/v2/auth",
        tokenHost: "https://www.googleapis.com",
        tokenPath: "/oauth2/v4/token",
      },
    },
    startRedirectPath: `${basePath}/login`,
    callbackUri: opts.callbackUri,
    // Passed straight through to Google's authorize URL as extra query
    // params (see "prompt" above for why this matters for logout).
    callbackUriParams: { prompt: opts.prompt ?? DEFAULT_PROMPT },
  });

  const verifier = new OAuth2Client(opts.clientId);

  function setSession(reply: FastifyReply, profile: GoogleSsoProfile): void {
    const payload: SessionPayload = { ...profile, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
    reply.setCookie(cookieName, sign(JSON.stringify(payload), opts.sessionSecret), {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      // Same pattern as sitemap-service's own admin-key cookie: computed per
      // request rather than a fixed option, so local http:// dev still works
      // without a config flag, while a real https:// deployment gets Secure.
      secure: reply.request.protocol === "https",
      maxAge: ttlSeconds,
    });
  }

  function readSession(request: FastifyRequest): GoogleSsoProfile | null {
    const raw = request.cookies[cookieName];
    if (!raw) return null;
    const value = unsign(raw, opts.sessionSecret);
    if (value === null) return null;
    let payload: SessionPayload;
    try {
      payload = JSON.parse(value) as SessionPayload;
    } catch {
      return null;
    }
    if (typeof payload.exp !== "number" || payload.exp < Date.now() / 1000 || typeof payload.email !== "string") {
      return null;
    }
    const { exp, ...profile } = payload;
    return profile;
  }

  fastify.get(`${basePath}/callback`, async (request, reply) => {
    let idToken: string | undefined;
    try {
      // @fastify/oauth2 decorates the instance with whatever name you gave it
      // (fastify.googleSsoOAuth2 here) — its own type declarations only
      // recognise names starting with the literal "oauth2" (not this
      // plugin's convention, and not even its own README example's naming),
      // so this reaches past that rather than renaming around a type quirk.
      const oauth2 = (fastify as unknown as Record<string, unknown>)[OAUTH2_DECORATOR_NAME] as {
        getAccessTokenFromAuthorizationCodeFlow(req: FastifyRequest): Promise<{ token: { id_token?: string } }>;
      };
      const { token } = await oauth2.getAccessTokenFromAuthorizationCodeFlow(request);
      idToken = token.id_token;
    } catch (err) {
      request.log.warn({ err }, "google-sso: token exchange failed");
      return reply.code(401).type("text/plain").send("Login failed.");
    }
    if (!idToken) {
      return reply.code(502).type("text/plain").send("Google did not return an ID token.");
    }

    let payload;
    try {
      const ticket = await verifier.verifyIdToken({ idToken, audience: opts.clientId });
      payload = ticket.getPayload();
    } catch (err) {
      request.log.warn({ err }, "google-sso: ID token verification failed");
      return reply.code(401).type("text/plain").send("Could not verify Google login.");
    }
    if (!payload?.email || !payload.email_verified) {
      return reply.code(401).type("text/plain").send("Your Google account has no verified email address.");
    }

    const profile: GoogleSsoProfile = { email: payload.email, name: payload.name, picture: payload.picture, hostedDomain: payload.hd };
    const allowed = await opts.isAllowed(profile);
    if (!allowed) {
      request.log.info({ email: profile.email }, "google-sso: login rejected by isAllowed");
      return reply.code(403).type("text/plain").send(`${profile.email} is not allowed to access this application.`);
    }

    setSession(reply, profile);
    return reply.redirect(successRedirect);
  });

  fastify.get(`${basePath}/logout`, async (request, reply) => {
    reply.clearCookie(cookieName, { path: "/" });
    return reply.redirect(successRedirect);
  });

  fastify.decorate("requireGoogleSession", async function requireGoogleSession(request: FastifyRequest, reply: FastifyReply) {
    const profile = readSession(request);
    if (profile) {
      request.googleSsoUser = profile;
      return;
    }
    return reply.redirect(`${externalBasePath}/login`);
  });
}

export default fp(googleSsoPlugin, { name: "fastify-google-sso", fastify: "5.x" });
