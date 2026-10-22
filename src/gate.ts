import { createHmac } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { createGoogleSsoCore, type CookieContext, type GoogleSsoCore } from "./core.js";
import { googleGroupChecker, type ServiceAccountKey } from "./groups.js";
import { renderLandingPage, renderPopupResult } from "./pages.js";

/**
 * A Google SSO gate: a small reverse proxy that puts the whole login flow in
 * front of an app that has none of its own, whatever language it's written
 * in. Each route listens on its own local port, in front of one app on one
 * external origin — typically a Tailscale Serve handler pointed at
 * http://127.0.0.1:<port> instead of at the app. Browsers without a session
 * get the landing page; with one, requests are proxied to the app unchanged
 * apart from the gate's own cookies, which are stripped.
 *
 * Every path is gated except the route's `public` ones, which go straight
 * through: an app's machine-facing API, which keeps checking its own API
 * keys. With `passApiKeys`, so does any request that carries an API key.
 */

export interface GateRoute {
  /** Local port to listen on, e.g. 9001. Each route has its own. */
  listen: number;
  /** The external origin browsers use, e.g. "https://sitemap-test.tail127ff5.ts.net". */
  origin: string;
  /** Where allowed requests go, e.g. "http://sitemap-test:10000". */
  target: string;
  /** Admit only members of this Google Group (needs serviceAccountKey). Default: the whole allowedDomain. */
  group?: string;
  /**
   * Path prefixes passed through without a login. One ending in "/" matches
   * everything under it ("/v1/"); otherwise the path itself and everything
   * under it ("/mcp" matches "/mcp" and "/mcp/x", not "/mcpx").
   */
  public?: string[];
  /**
   * Pass requests that carry an API key (an "Authorization: Bearer" or
   * "X-API-Key" header) through without a login, for an app whose scripts
   * send a key on the same paths its pages use. The app must then check that
   * key on every path, and refuse a request whose key is wrong: anyone can
   * send the header. Default false.
   */
  passApiKeys?: boolean;
  /** Heading on the landing page. Default "Sign in". */
  title?: string;
}

export interface GateOptions {
  clientId: string;
  clientSecret: string;
  /** Signs the gate's sessions; each route signs with its own key derived from this. */
  sessionSecret: string;
  /** Only Google Workspace accounts of this domain get in, e.g. "kuutra.com". */
  allowedDomain: string;
  /** Needed when any route has a group. */
  serviceAccountKey?: ServiceAccountKey;
  routes: GateRoute[];
  /** Address to listen on. Default "127.0.0.1": the gate must only be reachable through the proxy in front of it. */
  host?: string;
  /** Default sessionTtlSeconds of the core (12h). */
  sessionTtlSeconds?: number;
  log?: (message: string) => void;
}

export interface Gate {
  close(): Promise<void>;
}

export const GATE_BASE_PATH = "/_gate/auth/google";
const COOKIE_NAME = "kuutra_gate";
const RETURN_COOKIE = `${COOKIE_NAME}_return`;
const RETURN_TTL_SECONDS = 10 * 60;

// Connection-level headers, which a proxy must not forward.
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export function isPublicPath(path: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) =>
    prefix.endsWith("/") ? path.startsWith(prefix) : path === prefix || path.startsWith(`${prefix}/`)
  );
}

/**
 * The request's path and query, with "." and ".." segments (also as %2e)
 * resolved, so a public prefix can't be climbed out of; null for an
 * absolute-form or otherwise unusable request target.
 */
export function normalizeTarget(rawUrl: string | undefined): { path: string; search: string } | null {
  if (!rawUrl || !rawUrl.startsWith("/")) return null;
  try {
    const url = new URL(rawUrl, "http://gate.invalid");
    if (url.host !== "gate.invalid") return null;
    return { path: url.pathname, search: url.search };
  } catch {
    return null;
  }
}

function getCookie(cookieHeader: string | undefined, name: string): string | null {
  for (const part of (cookieHeader ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i !== -1 && part.slice(0, i).trim() === name) {
      try {
        return decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

// The Cookie header without the gate's own cookies, so the app never sees them.
function withoutGateCookies(cookieHeader: string | string[] | undefined): string | undefined {
  if (typeof cookieHeader !== "string") return undefined;
  const kept = cookieHeader
    .split(";")
    .filter((part) => !part.trim().startsWith(`${COOKIE_NAME}`))
    .join(";")
    .trim();
  return kept === "" ? undefined : kept;
}

// A same-origin path to return to after login; anything else falls back to "/".
function safeReturnPath(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  return value;
}

function send(res: http.ServerResponse, status: number, headers: http.OutgoingHttpHeaders, body = ""): void {
  res.writeHead(status, { "cache-control": "no-store", ...headers });
  res.end(body);
}

function hasApiKey(req: http.IncomingMessage): boolean {
  return /^Bearer\s+\S/i.test(req.headers.authorization ?? "") || Boolean(req.headers["x-api-key"]);
}

function wantsHtml(req: http.IncomingMessage): boolean {
  return (req.method === "GET" || req.method === "HEAD") && (req.headers.accept ?? "").includes("text/html");
}

function createRouteHandler(route: GateRoute, core: GoogleSsoCore, log: (message: string) => void) {
  const target = new URL(route.target);
  const client = target.protocol === "https:" ? https : http;
  const agent = new client.Agent({ keepAlive: true });
  const publicPaths = route.public ?? [];
  const ctx: CookieContext = { secure: route.origin.startsWith("https:") };
  const secureAttr = ctx.secure ? "; Secure" : "";
  const landingHtml = renderLandingPage(`${GATE_BASE_PATH}/login`, { title: route.title, description: "Sign in with your Google account." });

  const returnCookie = (path: string, maxAge: number) =>
    `${RETURN_COOKIE}=${encodeURIComponent(path)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${secureAttr}`;

  function proxy(req: http.IncomingMessage, res: http.ServerResponse, pathAndQuery: string): void {
    const headers: http.OutgoingHttpHeaders = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(name)) headers[name] = value;
    }
    const cookie = withoutGateCookies(req.headers.cookie);
    if (cookie === undefined) delete headers.cookie;
    else headers.cookie = cookie;

    const upstream = client.request(
      { protocol: target.protocol, hostname: target.hostname, port: target.port, method: req.method, path: pathAndQuery, headers, agent },
      (upRes) => {
        const resHeaders: http.OutgoingHttpHeaders = {};
        for (const [name, value] of Object.entries(upRes.headers)) {
          if (!HOP_BY_HOP.has(name)) resHeaders[name] = value;
        }
        res.writeHead(upRes.statusCode ?? 502, resHeaders);
        upRes.pipe(res);
      }
    );
    upstream.on("error", (err) => {
      log(`gate ${route.origin}: upstream ${route.target} failed: ${err.message}`);
      if (!res.headersSent) send(res, 502, { "content-type": "text/plain" }, "The app is not reachable right now.");
      else res.destroy();
    });
    // The browser went away mid-response: stop the upstream request too.
    res.on("close", () => {
      if (!res.writableFinished) upstream.destroy();
    });
    req.pipe(upstream);
  }

  return async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const parsed = normalizeTarget(req.url);
    if (!parsed) return send(res, 400, { "content-type": "text/plain" }, "Bad request.");
    const { path, search } = parsed;

    if (path === GATE_BASE_PATH) {
      if (core.readSession(req.headers.cookie)) return send(res, 302, { location: "/" });
      return send(res, 200, { "content-type": "text/html; charset=utf-8" }, landingHtml);
    }
    if (path === `${GATE_BASE_PATH}/login`) {
      const popup = new URLSearchParams(search).get("popup") === "1";
      const { url, setCookies } = await core.startLogin(ctx, { popup });
      return send(res, 302, { location: url, "set-cookie": setCookies });
    }
    if (path === `${GATE_BASE_PATH}/callback`) {
      const result = await core.handleCallback(new URLSearchParams(search), req.headers.cookie, ctx);
      const setCookies = [...result.setCookies, returnCookie("", 0)];
      if (result.ok) {
        log(`gate ${route.origin}: ${result.profile.email} signed in`);
      } else {
        log(`gate ${route.origin}: login refused (${result.reason})${result.error ? `: ${String(result.error)}` : ""}`);
      }
      const finished = result.ok ? { ...result, redirect: safeReturnPath(getCookie(req.headers.cookie, RETURN_COOKIE)) } : result;
      if (finished.popup) {
        return send(
          res,
          finished.ok ? 200 : finished.status,
          { "content-type": "text/html; charset=utf-8", "set-cookie": setCookies },
          renderPopupResult(finished)
        );
      }
      if (finished.ok) return send(res, 302, { location: finished.redirect, "set-cookie": setCookies });
      return send(res, finished.status, { "content-type": "text/plain", "set-cookie": setCookies }, finished.message);
    }
    if (path === `${GATE_BASE_PATH}/logout`) {
      return send(res, 302, { location: GATE_BASE_PATH, "set-cookie": core.logoutCookies(ctx) });
    }

    const pathAndQuery = `${path}${search}`;
    if (
      isPublicPath(path, publicPaths) ||
      (route.passApiKeys === true && hasApiKey(req)) ||
      core.readSession(req.headers.cookie)
    ) {
      return proxy(req, res, pathAndQuery);
    }
    if (wantsHtml(req)) {
      return send(res, 302, { location: GATE_BASE_PATH, "set-cookie": returnCookie(pathAndQuery, RETURN_TTL_SECONDS) });
    }
    return send(res, 401, { "content-type": "text/plain" }, "Sign in first.");
  };
}

export async function startGate(opts: GateOptions): Promise<Gate> {
  const host = opts.host ?? "127.0.0.1";
  const log = opts.log ?? ((message) => console.log(message));
  if (!opts.allowedDomain) throw new Error("gate: allowedDomain is required.");
  if (opts.routes.some((route) => route.group) && !opts.serviceAccountKey) {
    throw new Error("gate: a route has a group, so serviceAccountKey is required.");
  }
  const groups = opts.serviceAccountKey ? googleGroupChecker({ serviceAccountKey: opts.serviceAccountKey }) : null;

  const servers: http.Server[] = [];
  for (const route of opts.routes) {
    const origin = new URL(route.origin).origin;
    new URL(route.target);
    const core = createGoogleSsoCore({
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      callbackUri: `${origin}${GATE_BASE_PATH}/callback`,
      // Per-origin key: a session from one gated app is no good on another
      // that admits a different group.
      sessionSecret: createHmac("sha256", opts.sessionSecret).update(`gate-session:${origin}`).digest("hex"),
      cookieName: COOKIE_NAME,
      sessionTtlSeconds: opts.sessionTtlSeconds,
      successRedirect: "/",
      isAllowed: async (profile) =>
        profile.hostedDomain === opts.allowedDomain &&
        (!route.group || (await groups!.isMember(profile.email, route.group))),
    });
    const handle = createRouteHandler({ ...route, origin }, core, log);
    const server = http.createServer((req, res) => {
      handle(req, res).catch((err) => {
        log(`gate ${origin}: ${String(err)}`);
        if (!res.headersSent) send(res, 500, { "content-type": "text/plain" }, "Internal error.");
        else res.destroy();
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(route.listen, host, () => resolve());
    });
    servers.push(server);
    log(`gate: ${origin} on ${host}:${route.listen} -> ${route.target}` + (route.group ? ` (group ${route.group})` : ""));
  }

  return {
    async close() {
      await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    },
  };
}
