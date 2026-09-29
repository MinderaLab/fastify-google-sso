import { createHmac } from "node:crypto";
import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import googleSso from "../dist/index.js";

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
check("14. logout clears the cookie", (logoutRes.headers["set-cookie"] || "").includes("google_sso_session=;"));

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

const failed = results.filter((r) => !r.pass);
console.log("\n" + (results.length - failed.length) + "/" + results.length + " passed");
process.exit(failed.length > 0 ? 1 : 0);
