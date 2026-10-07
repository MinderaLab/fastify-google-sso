import { createHmac, generateKeyPairSync } from "node:crypto";
import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import { OAuth2Client } from "google-auth-library";
import googleSso, { googleGroupChecker } from "../dist/index.js";
import { createGoogleSsoCore } from "../dist/core.js";

const SESSION_SECRET = "test-secret-1234567890-abcdef-ghijkl";
const CLIENT_ID = "fake-client-id.apps.googleusercontent.com";
const results = [];
function check(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log((pass ? "PASS" : "FAIL") + " - " + name + (detail ? " (" + detail + ")" : ""));
}

// Mirrors the plugin's own sign() exactly, to construct test cookies without
// needing a real Google login.
function sign(value, secret) {
  const mac = createHmac("sha256", secret).update(value).digest("base64url");
  return `${value}.${mac}`;
}

// --- App 1: verify registration + login redirect + unauthenticated gating ---
const app1 = Fastify();
await app1.register(googleSso, {
  clientId: CLIENT_ID,
  clientSecret: "fake-secret",
  callbackUri: "http://localhost:3000/auth/google/callback",
  sessionSecret: SESSION_SECRET,
  isAllowed: (profile) => profile.hostedDomain === "kuutra.com",
});
app1.get("/admin", { preHandler: app1.requireGoogleSession }, async (request) => {
  return { user: request.googleSsoUser };
});

const loginRes = await app1.inject({ method: "GET", url: "/auth/google/login" });
check("1. GET /auth/google/login redirects (302)", loginRes.statusCode === 302);
const loc = loginRes.headers.location || "";
check("2. redirect goes to accounts.google.com", loc.startsWith("https://accounts.google.com/o/oauth2/v2/auth"), loc.slice(0, 60));
check("3. redirect includes our client_id", loc.includes(encodeURIComponent(CLIENT_ID)) || loc.includes(CLIENT_ID));
check("4. redirect requests openid scope", loc.includes("openid"));
check("4b. redirect defaults to prompt=select_account (forces the account chooser, so a post-logout re-login is visibly fresh rather than silently auto-approved)", loc.includes("prompt=select_account"));

const noCookieRes = await app1.inject({ method: "GET", url: "/admin" });
check("5. protected route with no cookie redirects (302)", noCookieRes.statusCode === 302);
check("6. redirects to the login route", noCookieRes.headers.location === "/auth/google/login");

// --- App 2: does the SAME app already use @fastify/cookie itself for something
// unrelated, with its OWN secret? This is the exact scenario that broke before
// the fix — registering our plugin on top must not throw, and must still sign
// our session with OUR OWN sessionSecret, not the host's unrelated one. ---
const app2 = Fastify();
await app2.register(fastifyCookie, { secret: "the-hosts-own-unrelated-secret" });
await app2.register(googleSso, {
  clientId: CLIENT_ID,
  clientSecret: "fake-secret",
  callbackUri: "http://localhost:3000/auth/google/callback",
  sessionSecret: SESSION_SECRET,
  isAllowed: (profile) => profile.hostedDomain === "kuutra.com",
});
app2.get("/admin", { preHandler: app2.requireGoogleSession }, async (request) => {
  return { user: request.googleSsoUser };
});
await app2.ready();
check("7. registering alongside a host app's own @fastify/cookie doesn't throw", true);

const validPayload = { email: "alice@kuutra.com", name: "Alice", hostedDomain: "kuutra.com", exp: Math.floor(Date.now() / 1000) + 3600 };
const validSigned = sign(JSON.stringify(validPayload), SESSION_SECRET);

const okRes = await app2.inject({ method: "GET", url: "/admin", headers: { cookie: "google_sso_session=" + validSigned } });
check("8. valid signed session cookie is accepted (200)", okRes.statusCode === 200);
check("9. request.googleSsoUser populated correctly", JSON.parse(okRes.body).user?.email === "alice@kuutra.com");

const expiredPayload = { ...validPayload, exp: Math.floor(Date.now() / 1000) - 10 };
const expiredSigned = sign(JSON.stringify(expiredPayload), SESSION_SECRET);
const expiredRes = await app2.inject({ method: "GET", url: "/admin", headers: { cookie: "google_sso_session=" + expiredSigned } });
check("10. expired session is rejected (redirects, not 200)", expiredRes.statusCode === 302);

const tamperedRes = await app2.inject({ method: "GET", url: "/admin", headers: { cookie: "google_sso_session=" + validSigned + "tampered" } });
check("11. tampered/corrupted cookie is rejected", tamperedRes.statusCode === 302);

const wrongSecretSigned = sign(JSON.stringify(validPayload), "a-totally-different-secret-xxxxxxxxxx");
const wrongSecretRes = await app2.inject({ method: "GET", url: "/admin", headers: { cookie: "google_sso_session=" + wrongSecretSigned } });
check("12. cookie signed with a different secret is rejected (proves it's NOT using the host's own cookie secret)", wrongSecretRes.statusCode === 302);

// If our plugin had (incorrectly) used app2's own @fastify/cookie secret
// ("the-hosts-own-unrelated-secret") instead of sessionSecret, THIS cookie
// would wrongly be accepted.
const hostSecretSigned = sign(JSON.stringify(validPayload), "the-hosts-own-unrelated-secret");
const hostSecretRes = await app2.inject({ method: "GET", url: "/admin", headers: { cookie: "google_sso_session=" + hostSecretSigned } });
check("13. cookie signed with the HOST's own cookie secret is rejected too (sessionSecret is authoritative)", hostSecretRes.statusCode === 302);

const logoutRes = await app2.inject({ method: "GET", url: "/auth/google/logout", headers: { cookie: "google_sso_session=" + validSigned } });
check("14. logout clears the cookie", [].concat(logoutRes.headers["set-cookie"] || []).some((c) => c.startsWith("google_sso_session=;")));

// --- App 3: behind a reverse proxy that strips a path prefix (e.g. Tailscale
// Serve --set-path=/sitemap) — the exact scenario that broke the dashboard
// earlier this session. basePath stays unprefixed (that's what this app
// actually receives after the proxy strips it); externalBasePath carries the
// prefix a browser-facing redirect needs. ---
const app3 = Fastify();
await app3.register(googleSso, {
  clientId: CLIENT_ID,
  clientSecret: "fake-secret",
  callbackUri: "https://kuutraprod.tail127ff5.ts.net/sitemap/auth/google/callback",
  sessionSecret: SESSION_SECRET,
  basePath: "/auth/google",
  externalBasePath: "/sitemap/auth/google",
  successRedirect: "/sitemap/admin/dashboard",
  isAllowed: (profile) => profile.hostedDomain === "kuutra.com",
});
app3.get("/admin/dashboard", { preHandler: app3.requireGoogleSession }, async () => "ok");

const noCookieRes3 = await app3.inject({ method: "GET", url: "/admin/dashboard" });
check("15. behind a stripped prefix, the login redirect carries externalBasePath", noCookieRes3.headers.location === "/sitemap/auth/google/login");

const validSigned3 = sign(JSON.stringify(validPayload), SESSION_SECRET);
const logoutRes3 = await app3.inject({ method: "GET", url: "/auth/google/logout", headers: { cookie: "google_sso_session=" + validSigned3 } });
check("16. successRedirect after logout also carries the external prefix", logoutRes3.headers.location === "/sitemap/admin/dashboard");

// --- App 4: prompt is overridable, not hardcoded ---
const app4 = Fastify();
await app4.register(googleSso, {
  clientId: CLIENT_ID,
  clientSecret: "fake-secret",
  callbackUri: "http://localhost:3000/auth/google/callback",
  sessionSecret: SESSION_SECRET,
  prompt: "none",
  isAllowed: () => true,
});
const loginRes4 = await app4.inject({ method: "GET", url: "/auth/google/login" });
check("17. prompt is overridable (prompt: \"none\" here, not the select_account default)", (loginRes4.headers.location || "").includes("prompt=none"));

// --- googleGroupChecker: stub fetch so the whole path runs — service-account token exchange, then the Admin SDK
// hasMember call — without a real Google account. ---
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const fakeKey = {
  client_email: "sso-groups-reader@example.iam.gserviceaccount.com",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};
const directoryCalls = [];
let directoryStatus = 200;
// gaxios (google-auth-library's HTTP layer) uses window.fetch when a window
// exists and its own bundled node-fetch otherwise — so the stub goes there.
globalThis.window = { fetch: async (input, init) => {
  const url = typeof input === "string" ? input : input.url ?? String(input);
  if (url.startsWith("https://oauth2.googleapis.com/token") || url.startsWith("https://www.googleapis.com/oauth2/v4/token")) {
    return new Response(JSON.stringify({ access_token: "fake-access-token", expires_in: 3600, token_type: "Bearer" }), {
      headers: { "content-type": "application/json" },
    });
  }
  if (url.startsWith("https://admin.googleapis.com/admin/directory/v1/groups/")) {
    const headers = new Headers(init?.headers);
    directoryCalls.push({ url, authorization: headers.get("authorization") });
    if (directoryStatus !== 200) {
      return new Response(JSON.stringify({ error: { code: directoryStatus, message: "Not Authorized to access this resource/api" } }), {
        status: directoryStatus,
        headers: { "content-type": "application/json" },
      });
    }
    const isMember = decodeURIComponent(url.split("/hasMember/")[1]) === "alice@kuutra.com";
    return new Response(JSON.stringify({ isMember }), { headers: { "content-type": "application/json" } });
  }
  throw new Error("unexpected fetch in test: " + url);
} };
try {
  const groups = googleGroupChecker({ serviceAccountKey: fakeKey });
  check("18. group member is reported as a member", (await groups.isMember("alice@kuutra.com", "sitemap_access@kuutra.com")) === true);
  check("19. non-member is reported as not a member", (await groups.isMember("bob@kuutra.com", "sitemap_access@kuutra.com")) === false);
  check(
    "20. calls hasMember for the right group and user",
    directoryCalls[0]?.url === "https://admin.googleapis.com/admin/directory/v1/groups/sitemap_access%40kuutra.com/hasMember/alice%40kuutra.com",
    directoryCalls[0]?.url
  );
  check("21. authenticates as the service account", directoryCalls[0]?.authorization === "Bearer fake-access-token");

  directoryStatus = 403;
  let threw = false;
  try {
    await groups.isMember("alice@kuutra.com", "sitemap_access@kuutra.com");
  } catch {
    threw = true;
  }
  check("22. a Google API error throws instead of quietly returning false", threw);
} finally {
  delete globalThis.window;
}

// --- The framework-neutral core, callback included. google-auth-library's own
// token exchange and ID-token verification are stubbed on its prototype (the
// same module instance core.js uses): what's tested is this package's logic
// around them — state, PKCE, cookies, isAllowed — not Google's library. ---
const tokenCalls = [];
let idTokenPayload = { email: "alice@kuutra.com", email_verified: true, hd: "kuutra.com", name: "Alice" };
const realGetToken = OAuth2Client.prototype.getToken;
const realVerify = OAuth2Client.prototype.verifyIdToken;
OAuth2Client.prototype.getToken = async function (options) {
  tokenCalls.push(options);
  return { tokens: { id_token: "fake-id-token" } };
};
OAuth2Client.prototype.verifyIdToken = async function ({ idToken }) {
  if (idToken !== "fake-id-token") throw new Error("unexpected id token");
  return { getPayload: () => idTokenPayload };
};

// The Cookie header a browser would send back: name=value of each Set-Cookie
const cookieHeader = (setCookies) => setCookies.map((c) => c.split(";")[0]).join("; ");
const queryOf = (url) => new URL(url).searchParams;

try {
  let allowedEmails = ["alice@kuutra.com"];
  let isAllowedThrows = false;
  const core = createGoogleSsoCore({
    clientId: CLIENT_ID,
    clientSecret: "fake-secret",
    callbackUri: "https://kv.example/auth/google/callback",
    sessionSecret: SESSION_SECRET,
    cookieName: "kv_session",
    successRedirect: "/auth/google/done",
    sameSite: "strict",
    isAllowed: async (profile) => {
      if (isAllowedThrows) throw new Error("groups lookup failed");
      return allowedEmails.includes(profile.email);
    },
  });
  const ctx = { secure: true };

  const start = await core.startLogin(ctx);
  const authQuery = queryOf(start.url);
  check("23. core login URL carries state, an S256 PKCE challenge and the callback", Boolean(authQuery.get("state")) &&
    authQuery.get("code_challenge_method") === "S256" && Boolean(authQuery.get("code_challenge")) &&
    authQuery.get("redirect_uri") === "https://kv.example/auth/google/callback");
  check("24. login-state cookie is HttpOnly, Lax and Secure", /^kv_session_login=.*HttpOnly; SameSite=Lax; Secure$/.test(start.setCookies[0]), start.setCookies[0]);

  const callbackQuery = new URLSearchParams({ code: "the-code", state: authQuery.get("state") });
  const ok = await core.handleCallback(callbackQuery, cookieHeader(start.setCookies), ctx);
  check("25. a valid callback succeeds and redirects to successRedirect", ok.ok === true && ok.redirect === "/auth/google/done");
  check("26. the code is exchanged with the PKCE verifier from the login cookie", tokenCalls[0]?.code === "the-code" && typeof tokenCalls[0]?.codeVerifier === "string" && tokenCalls[0].codeVerifier.length >= 43);
  const sessionSetCookie = ok.setCookies?.find((c) => c.startsWith("kv_session="));
  check("27. the session cookie honours sameSite: strict", /HttpOnly; SameSite=Strict; Secure$/.test(sessionSetCookie || ""), sessionSetCookie);
  check("28. the login-state cookie is cleared", Boolean(ok.setCookies?.some((c) => c.startsWith("kv_session_login=;") && c.includes("Max-Age=0"))));
  const profile = core.readSession(cookieHeader([sessionSetCookie]));
  check("29. readSession returns the profile from that cookie", profile?.email === "alice@kuutra.com" && profile?.hostedDomain === "kuutra.com");
  check("30. readSession ignores the login-state cookie and other cookies", core.readSession("kv_session_login=x; other=1") === null);

  const wrongState = await core.handleCallback(new URLSearchParams({ code: "c", state: "not-the-state" }), cookieHeader(start.setCookies), ctx);
  check("31. a state that doesn't match the login cookie is refused (400)", wrongState.ok === false && wrongState.status === 400);
  const noCookie = await core.handleCallback(callbackQuery, undefined, ctx);
  check("32. a callback without the login cookie is refused (400)", noCookie.ok === false && noCookie.status === 400);
  const cancelled = await core.handleCallback(new URLSearchParams({ error: "access_denied" }), cookieHeader(start.setCookies), ctx);
  check("33. Google's error=access_denied is refused (401)", cancelled.ok === false && cancelled.status === 401);

  allowedEmails = [];
  const refused = await core.handleCallback(callbackQuery, cookieHeader(start.setCookies), ctx);
  check("34. isAllowed false gives 403 and no session", refused.ok === false && refused.status === 403 && !refused.setCookies.some((c) => c.startsWith("kv_session=")));
  isAllowedThrows = true;
  const threw = await core.handleCallback(callbackQuery, cookieHeader(start.setCookies), ctx);
  check("35. isAllowed throwing gives 503 and no session", threw.ok === false && threw.status === 503 && !threw.setCookies.some((c) => c.startsWith("kv_session=")));
  isAllowedThrows = false;
  allowedEmails = ["alice@kuutra.com"];

  idTokenPayload = { email: "alice@kuutra.com", email_verified: false };
  const unverified = await core.handleCallback(callbackQuery, cookieHeader(start.setCookies), ctx);
  check("36. an unverified email is refused (401)", unverified.ok === false && unverified.status === 401);
  idTokenPayload = { email: "alice@kuutra.com", email_verified: true, hd: "kuutra.com", name: "Alice" };

  const logout = core.logoutCookies({ secure: false });
  check("37. logoutCookies expires the session cookie", logout.length === 1 && logout[0].startsWith("kv_session=;") && logout[0].includes("Max-Age=0") && !logout[0].includes("Secure"));

  // The Fastify plugin end to end through the same core
  const app5 = Fastify();
  await app5.register(googleSso, {
    clientId: CLIENT_ID,
    clientSecret: "fake-secret",
    callbackUri: "http://localhost:3000/auth/google/callback",
    sessionSecret: SESSION_SECRET,
    successRedirect: "/admin",
    isAllowed: (p) => p.hostedDomain === "kuutra.com",
  });
  app5.get("/admin", { preHandler: app5.requireGoogleSession }, async (request) => ({ user: request.googleSsoUser }));
  const login5 = await app5.inject({ method: "GET", url: "/auth/google/login" });
  const loginCookies5 = [].concat(login5.headers["set-cookie"] || []);
  const state5 = queryOf(login5.headers.location).get("state");
  const cb5 = await app5.inject({
    method: "GET",
    url: "/auth/google/callback?code=c5&state=" + encodeURIComponent(state5),
    headers: { cookie: cookieHeader(loginCookies5) },
  });
  const cbCookies5 = [].concat(cb5.headers["set-cookie"] || []);
  check("38. Fastify callback logs in and redirects to successRedirect", cb5.statusCode === 302 && cb5.headers.location === "/admin", String(cb5.statusCode));
  const admin5 = await app5.inject({ method: "GET", url: "/admin", headers: { cookie: cookieHeader(cbCookies5.filter((c) => c.startsWith("google_sso_session="))) } });
  check("39. the session it set opens a protected route", admin5.statusCode === 200 && JSON.parse(admin5.body).user?.email === "alice@kuutra.com");
  const bad5 = await app5.inject({ method: "GET", url: "/auth/google/callback?code=c5&state=wrong", headers: { cookie: cookieHeader(loginCookies5) } });
  check("40. Fastify callback with a bad state answers 400", bad5.statusCode === 400);
} finally {
  OAuth2Client.prototype.getToken = realGetToken;
  OAuth2Client.prototype.verifyIdToken = realVerify;
}

const failed = results.filter((r) => !r.pass);
console.log("\n" + (results.length - failed.length) + "/" + results.length + " passed");
process.exit(failed.length > 0 ? 1 : 0);
