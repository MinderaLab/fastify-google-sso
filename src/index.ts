import fp from "fastify-plugin";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createGoogleSsoCore, type GoogleSsoCoreOptions, type GoogleSsoProfile } from "./core.js";
import { renderLandingPage, renderPopupResult, type LandingPageOptions } from "./pages.js";

export { createGoogleSsoCore, googleGroupChecker, renderLandingPage, renderPopupResult } from "./core.js";
export type {
  CallbackResult,
  CookieContext,
  GoogleGroupChecker,
  GoogleGroupCheckerOptions,
  GoogleSsoCore,
  GoogleSsoCoreOptions,
  GoogleSsoProfile,
  LandingPageOptions,
  ServiceAccountKey,
} from "./core.js";

export interface GoogleSsoOptions extends GoogleSsoCoreOptions {
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
  /**
   * A sign-in page at basePath itself, whose "Sign in with Google" button
   * runs the login in a popup window. requireGoogleSession sends logged-out
   * browsers there. Pass { title, description } to word it for your app, or
   * false to go straight to Google instead. Default true.
   */
  landingPage?: boolean | LandingPageOptions;
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
     * browser to this plugin's landing page (or straight to its login route,
     * with landingPage: false) instead of returning a 401 —
     * these are human-facing pages, not an API a script calls.
     */
    requireGoogleSession(request: FastifyRequest, reply: FastifyReply): Promise<void>;
  }
}

const DEFAULT_BASE_PATH = "/auth/google";

async function googleSsoPlugin(fastify: FastifyInstance, opts: GoogleSsoOptions): Promise<void> {
  const basePath = opts.basePath ?? DEFAULT_BASE_PATH;
  const externalBasePath = opts.externalBasePath ?? basePath;
  const successRedirect = opts.successRedirect ?? "/";
  const landingPage = opts.landingPage ?? true;
  const core = createGoogleSsoCore(opts);

  // Computed per request rather than a fixed option, so local http:// dev
  // still works without a config flag, while a real https:// deployment
  // gets Secure cookies.
  const cookieContext = (request: FastifyRequest) => ({ secure: request.protocol === "https" });

  if (landingPage) {
    const html = renderLandingPage(`${externalBasePath}/login`, landingPage === true ? {} : landingPage);
    fastify.get(basePath, async (request, reply) => {
      if (core.readSession(request.headers.cookie)) return reply.redirect(successRedirect);
      return reply.header("cache-control", "no-store").type("text/html; charset=utf-8").send(html);
    });
  }

  fastify.get(`${basePath}/login`, async (request, reply) => {
    const popup = (request.query as Record<string, unknown>).popup === "1";
    const { url, setCookies } = await core.startLogin(cookieContext(request), { popup });
    return reply.header("set-cookie", setCookies).redirect(url);
  });

  fastify.get(`${basePath}/callback`, async (request, reply) => {
    const query = new URLSearchParams(request.url.split("?")[1] ?? "");
    const result = await core.handleCallback(query, request.headers.cookie, cookieContext(request));
    reply.header("set-cookie", result.setCookies);
    if (!result.ok) {
      const log = { err: result.error, reason: result.reason };
      if (result.status >= 500) request.log.error(log, "google-sso: login failed");
      else request.log.info(log, "google-sso: login refused");
    }
    if (result.popup) {
      return reply
        .code(result.ok ? 200 : result.status)
        .header("cache-control", "no-store")
        .type("text/html; charset=utf-8")
        .send(renderPopupResult(result));
    }
    if (result.ok) return reply.redirect(result.redirect);
    return reply.code(result.status).type("text/plain").send(result.message);
  });

  fastify.get(`${basePath}/logout`, async (request, reply) => {
    return reply.header("set-cookie", core.logoutCookies(cookieContext(request))).redirect(successRedirect);
  });

  fastify.decorate("requireGoogleSession", async function requireGoogleSession(request: FastifyRequest, reply: FastifyReply) {
    const profile = core.readSession(request.headers.cookie);
    if (profile) {
      request.googleSsoUser = profile;
      return;
    }
    return reply.redirect(landingPage ? externalBasePath : `${externalBasePath}/login`);
  });
}

export default fp(googleSsoPlugin, { name: "fastify-google-sso", fastify: "5.x" });
