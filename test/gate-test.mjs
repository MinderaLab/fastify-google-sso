import { createHmac } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { startGate } from "../dist/gate.js";

const SESSION_SECRET = "gate-test-secret-1234567890-abcdef";
const ORIGIN = "https://sitemap-test.example.ts.net";
const OTHER_ORIGIN = "https://other-test.example.ts.net";
const results = [];
function check(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log((pass ? "PASS" : "FAIL") + " - " + name + (detail ? " (" + detail + ")" : ""));
}

// Mirrors core's sign() and the gate's per-origin key, to build session
// cookies without a real Google login.
function sign(value, secret) {
  return `${value}.${createHmac("sha256", secret).update(value).digest("base64url")}`;
}
function sessionCookie(origin, email = "henkka@kuutra.com") {
  const key = createHmac("sha256", SESSION_SECRET).update(`gate-session:${origin}`).digest("hex");
  const payload = JSON.stringify({ email, hostedDomain: "kuutra.com", exp: Math.floor(Date.now() / 1000) + 3600 });
  return `kuutra_gate=${encodeURIComponent(sign(payload, key))}`;
}

// The "app": echoes what reached it.
const upstream = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    res.writeHead(200, { "content-type": "application/json", "set-cookie": "app=1; Path=/" });
    res.end(JSON.stringify({ method: req.method, url: req.url, cookie: req.headers.cookie ?? null, body }));
  });
});
await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
const upstreamPort = upstream.address().port;

const gate = await startGate({
  clientId: "fake-client-id.apps.googleusercontent.com",
  clientSecret: "fake-secret",
  sessionSecret: SESSION_SECRET,
  allowedDomain: "kuutra.com",
  routes: [
    { listen: 19101, origin: ORIGIN, target: `http://127.0.0.1:${upstreamPort}`, public: ["/v1/", "/mcp", "/healthz"] },
    { listen: 19102, origin: OTHER_ORIGIN, target: "http://127.0.0.1:1" },
    { listen: 19104, origin: "https://keys-test.example.ts.net", target: `http://127.0.0.1:${upstreamPort}`, passApiKeys: true },
  ],
  log: () => {},
});

function request(path, { port = 19101, method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
// http.request resolves dot segments itself, so send these over a raw socket.
function rawRequest(target) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(19101, "127.0.0.1", () => {
      socket.write(`GET ${target} HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\nConnection: close\r\n\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => (data += chunk));
    socket.on("end", () => resolve({ status: Number(data.split(" ")[1]), raw: data }));
    socket.on("error", reject);
  });
}
const html = { accept: "text/html,application/xhtml+xml" };

let res = await request("/admin/dashboard?x=1", { headers: html });
check("1. logged-out page view redirects to the landing page", res.status === 302 && res.headers.location === "/_gate/auth/google");
check(
  "2. ...remembering where it was going",
  (res.headers["set-cookie"] ?? []).some((c) => c.startsWith("kuutra_gate_return=%2Fadmin%2Fdashboard%3Fx%3D1"))
);

res = await request("/admin/customers", { method: "POST", headers: { "content-type": "application/json" } });
check("3. logged-out non-page request gets 401", res.status === 401);

res = await request("/_gate/auth/google", { headers: html });
check("4. landing page is served", res.status === 200 && res.body.includes("Sign in with Google"));

res = await request("/_gate/auth/google/login");
const google = new URL(res.headers.location ?? "http://none");
check("5. login redirects to Google", res.status === 302 && google.hostname === "accounts.google.com");
check(
  "6. ...with the gate's own callback URI",
  google.searchParams.get("redirect_uri") === `${ORIGIN}/_gate/auth/google/callback`,
  google.searchParams.get("redirect_uri")
);

res = await request("/v1/sitemap/example.com", { headers: { authorization: "Bearer k", cookie: "kuutra_gate=junk; app=1" } });
let echoed = JSON.parse(res.body || "{}");
check("7. public path passes through without a login", res.status === 200 && echoed.url === "/v1/sitemap/example.com");
check("8. gate cookies are stripped, app cookies kept", echoed.cookie === "app=1", echoed.cookie);

res = await request("/mcp", { method: "POST", body: '{"jsonrpc":"2.0"}', headers: { "content-type": "application/json" } });
echoed = JSON.parse(res.body || "{}");
check("9. /mcp is public, and a POST body reaches the app", res.status === 200 && echoed.body === '{"jsonrpc":"2.0"}');

res = await request("/mcpx", { headers: html });
check("10. /mcpx is not covered by /mcp", res.status === 302);

res = await rawRequest("/v1/../admin/dashboard");
check("11. /v1/../admin is gated", res.status === 302, String(res.status));
res = await rawRequest("/v1/%2e%2e/admin/dashboard");
check("12. /v1/%2e%2e/admin is gated", res.status === 302, String(res.status));
res = await rawRequest("http://evil.example/v1/x");
check("13. absolute-form request target is refused", res.status === 400, String(res.status));

res = await request("/admin/dashboard", { headers: { ...html, cookie: `${sessionCookie(ORIGIN)}; app=1` } });
echoed = JSON.parse(res.body || "{}");
check("14. valid session is proxied to the app", res.status === 200 && echoed.url === "/admin/dashboard");
check("15. ...without the gate's cookie", echoed.cookie === "app=1", echoed.cookie);
check("16. app's Set-Cookie comes back", (res.headers["set-cookie"] ?? []).includes("app=1; Path=/"));

res = await request("/admin/dashboard", { headers: { ...html, cookie: sessionCookie(OTHER_ORIGIN) } });
check("17. session from another gated app is refused", res.status === 302);

res = await request("/", { port: 19102, headers: { ...html, cookie: sessionCookie(OTHER_ORIGIN) } });
check("18. unreachable app gives 502", res.status === 502);

res = await request("/_gate/auth/google/logout");
check(
  "19. logout clears the session",
  res.status === 302 && (res.headers["set-cookie"] ?? []).some((c) => c.startsWith("kuutra_gate=;") && c.includes("Max-Age=0"))
);

res = await request("/api/runs", { headers: { authorization: "Bearer k" } });
check("20. a Bearer key is gated without passApiKeys", res.status === 401);
res = await request("/api/runs", { port: 19104, headers: { authorization: "Bearer k" } });
check("21. passApiKeys passes a Bearer key through", res.status === 200 && JSON.parse(res.body).url === "/api/runs");
res = await request("/api/runs", { port: 19104, headers: { "x-api-key": "k" } });
check("22. ...and an X-API-Key", res.status === 200);
res = await request("/api/runs", { port: 19104, headers: { authorization: "Basic abc", ...html } });
check("23. ...but nothing else", res.status === 302);

let refused = false;
try {
  await startGate({
    clientId: "x", clientSecret: "x", sessionSecret: "x", allowedDomain: "kuutra.com",
    routes: [{ listen: 19103, origin: ORIGIN, target: "http://127.0.0.1:1", group: "g@kuutra.com" }],
  });
} catch {
  refused = true;
}
check("24. a group without a service account key refuses to start", refused);

await gate.close();
upstream.close();
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
