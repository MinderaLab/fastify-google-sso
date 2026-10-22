# fastify-google-sso

A drop-in Fastify plugin that gates a service's human-facing pages (an admin
dashboard, an internal tool — anything a person opens in a browser) behind
"Sign in with Google," restricted to a Google Workspace domain, an
explicit email allowlist, or Google Group membership. Services that don't use
Fastify can use its framework-neutral core instead (see "Without Fastify"
below), and apps in any language can sit behind its standalone gate (see "The
gate"). It's deliberately narrow: it does the OAuth2 login
dance, verifies the ID token, checks your allow policy, and sets a signed
session cookie. It does **not** try to be a general auth system — the
machine-facing API of whatever service you add it to should keep using its
own API keys; this is for the pages a human opens, not what another service
or an LLM caller hits.

## Install

No package registry — install directly from this repo:

```bash
npm install git+https://github.com/MinderaLab/fastify-google-sso.git
```

Pin to a tag or commit once you've settled on a version you trust, rather
than tracking a moving branch:

```json
"fastify-google-sso": "git+https://github.com/MinderaLab/fastify-google-sso.git#v1.4.0"
```

The Fastify plugin needs `fastify` ^5 (an optional peer dependency, already
in your app). The core (`fastify-google-sso/core`) doesn't need Fastify at
all.

## One-time Google Cloud setup

You need an OAuth 2.0 Client ID — this is an account-level step in Google
Cloud Console, not something this package can do for you:

1. In [Google Cloud Console](https://console.cloud.google.com/), pick or
   create a project.
2. **APIs & Services → OAuth consent screen** — set it up (internal, if
   you're restricting to your own Workspace domain; external + verification
   only if you need accounts outside it).
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**,
   type "Web application."
4. **Authorized redirect URIs**: add the exact URL your service will use for
   `callbackUri` below (e.g. `https://admin.example.com/auth/google/callback`).
   Must match byte-for-byte — scheme, host, path, no trailing slash
   mismatch — or Google rejects the request before your app sees it.
5. Copy the generated **Client ID** and **Client secret** into your service's
   own env vars (this package never sees Google Cloud Console itself).

## Usage

```ts
import Fastify from "fastify";
import googleSso from "fastify-google-sso";

const app = Fastify();

await app.register(googleSso, {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackUri: "https://admin.example.com/auth/google/callback",
  sessionSecret: process.env.GOOGLE_SSO_SESSION_SECRET!, // openssl rand -hex 32
  isAllowed: (profile) => profile.hostedDomain === "kuutra.com",
});

// Any route that should require a logged-in, allowed Google account:
app.get("/admin/dashboard", { preHandler: app.requireGoogleSession }, async (request) => {
  return `Hello, ${request.googleSsoUser!.email}`;
});
```

That's it — the plugin registers its own routes under `basePath` (default
`/auth/google`): the landing page at `basePath` itself, `/login` (start the
flow), `/callback` (Google redirects here), `/logout` (clears the session).
Visiting a route with `requireGoogleSession` while logged out redirects to
the landing page — not a 401 — since this is for a human in a browser, not a
script.

## The landing page

By default, `basePath` serves a small sign-in page with Kuutra's logo and colors, and a
"Sign in with Google" button. The button opens the Google login in a popup
window. When the popup finishes, it tells the landing page and closes, and
the landing page moves on to `successRedirect`. If the login is refused, the
landing page shows why. A browser that's already logged in goes straight to
`successRedirect`.

```ts
await app.register(googleSso, {
  // ...
  landingPage: { title: "Sitemap admin", description: "Sign in with your Kuutra Google account." },
});
```

- **Popups blocked, or JavaScript off**: the button is a plain link to
  `/login`, so the login falls back to the normal full-page redirect flow.
- **The popup reports back** over a same-origin `BroadcastChannel` and
  `window.opener.postMessage`. If neither reaches the landing page, the popup
  carries on to `successRedirect` itself.
- **Inline script and style**: if your app sends a Content-Security-Policy,
  it has to allow them on `basePath` and `/callback`, or the button falls back
  to the full-page flow and a popup won't close itself.
- **Turn it off** with `landingPage: false`. Logged-out browsers then go
  straight to `/login`, as before.

## Options

| Option | Required | Default | Notes |
| --- | --- | --- | --- |
| `clientId` | yes | — | From Google Cloud Console. |
| `clientSecret` | yes | — | From Google Cloud Console. |
| `callbackUri` | yes | — | Must exactly match an authorized redirect URI. |
| `sessionSecret` | yes | — | Signs the session cookie. `openssl rand -hex 32`. Rotating it logs everyone out. |
| `isAllowed` | yes | — | `(profile) => boolean \| Promise<boolean>`. Authorization, not authentication — see below. If it throws, the login is refused with a 503. |
| `basePath` | no | `/auth/google` | Where this plugin's own routes live. |
| `externalBasePath` | no | same as `basePath` | Set this if you're behind a reverse proxy that strips a path prefix before forwarding here — see below. |
| `cookieName` | no | `google_sso_session` | |
| `sessionTtlSeconds` | no | `43200` (12h) | |
| `successRedirect` | no | `/` | Where the browser lands after a successful login. |
| `sameSite` | no | `lax` | The session cookie's `SameSite`. `"strict"` also keeps it off links followed into the app from other sites. |
| `landingPage` | no | `true` | The sign-in page at `basePath` (see above). `{ title, description }` words it for your app; `false` turns it off. |
| `prompt` | no | `select_account` | Google's own OAuth `prompt` param. The default forces the account chooser every time, even with an already-active Google session — see "Why logout needs this" below. `"consent"` also re-shows the scope consent screen; `"none"` restores silent re-auth. |

`isAllowed` receives a `GoogleSsoProfile`: `{ email, name?, picture?,
hostedDomain? }`. `hostedDomain` (Google's `hd` claim) is set only for a
Google Workspace account — it's absent for a personal `@gmail.com` one.
Restricting to a Workspace domain (`profile.hostedDomain === "kuutra.com"`)
is usually simpler to maintain than an explicit email list, since it doesn't
need updating as people join or leave; use an explicit list instead if you
need named individuals outside that domain too.

## Restricting access to Google Group members

Signing in only proves who someone is. To let in only members of a
Workspace group (e.g. `sitemap_access@kuutra.com`), use `googleGroupChecker`
inside `isAllowed`:

```ts
import googleSso, { googleGroupChecker } from "fastify-google-sso";

const groups = googleGroupChecker({
  serviceAccountKey: JSON.parse(process.env.GOOGLE_SSO_SERVICE_ACCOUNT_KEY!),
});

await app.register(googleSso, {
  // ...
  isAllowed: async (profile) =>
    profile.hostedDomain === "kuutra.com" &&
    (await groups.isMember(profile.email, "sitemap_access@kuutra.com")),
});
```

It calls the Admin SDK Directory API's `members.hasMember`, which also
counts members of nested groups. One-time setup:

1. In the Google Cloud project, enable the **Admin SDK API**.
2. Create a service account (no project roles needed) and download a JSON
   key for it.
3. In the Workspace Admin console, **Account → Admin roles → Groups Reader →
   Assign service accounts**, and add the service account's email. The
   service account then reads groups as itself: no domain-wide delegation.

One service account can serve any number of apps, each checking its own
group.

- **Fails closed.** If Google can't answer (missing role, mistyped group,
  outage), `isMember` throws. The plugin then refuses the login with a 503
  and logs the error. It doesn't create a session.
- **Checked at login only.** Removing someone from the group doesn't end a
  session they already have. It lasts up to `sessionTtlSeconds` (12h by
  default), so lower that if access must be revoked faster.

## Without Fastify

`fastify-google-sso/core` runs the same flow as plain functions over a
`Cookie` request header and `Set-Cookie` response values, so any Node server
can mount it. It takes the same options as the plugin, except `basePath` and
`externalBasePath`, because you choose the routes yourself. From CommonJS,
`require()` it (Node 20.19+ or 22.12+ can `require` an ES module).

```js
const http = require("node:http");
const { createGoogleSsoCore } = require("fastify-google-sso/core");

const sso = createGoogleSsoCore({
  clientId, clientSecret, sessionSecret,
  callbackUri: "https://app.example/auth/google/callback",
  isAllowed: (profile) => profile.hostedDomain === "kuutra.com",
});

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const ctx = { secure: true }; // whether the browser came in over https

  if (url.pathname === "/auth/google/login") {
    const { url: to, setCookies } = await sso.startLogin(ctx);
    res.writeHead(302, { Location: to, "Set-Cookie": setCookies });
    return res.end();
  }
  if (url.pathname === "/auth/google/callback") {
    const result = await sso.handleCallback(url.searchParams, req.headers.cookie, ctx);
    if (result.ok) {
      res.writeHead(302, { Location: result.redirect, "Set-Cookie": result.setCookies });
    } else {
      console.warn("login refused:", result.reason, result.error ?? "");
      res.writeHead(result.status, { "Content-Type": "text/plain", "Set-Cookie": result.setCookies });
      res.write(result.message);
    }
    return res.end();
  }

  const user = sso.readSession(req.headers.cookie); // the profile, or null
  // ...
});
```

`sso.logoutCookies(ctx)` returns the `Set-Cookie` values that log the
browser out.

For the popup landing page, serve `renderLandingPage(loginUrl, { title })`
as HTML, start the login with `sso.startLogin(ctx, { popup: true })` when the
login URL has `?popup=1`, and on the callback answer a result with
`result.popup` set with `renderPopupResult(result)` as HTML (status 200, or
`result.status` when refused) instead of redirecting.

## The gate: for apps in any language

`google-sso-gate` is a small reverse proxy that runs the whole login in
front of an app that has no Google SSO of its own: Python, Next.js, anything.
Each route listens on its own local port, in front of one app on one external
origin. Point the proxy you already have (e.g. Tailscale Serve) at the gate
instead of at the app:

```
browser ──► Tailscale Serve (https://sitemap-test.<tailnet>.ts.net)
            ──► gate on 127.0.0.1:9001 ── no session → landing page → Google
            ──► http://sitemap-test:10000
```

```bash
npm install -g git+https://github.com/MinderaLab/fastify-google-sso.git#v1.5.0

GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
GATE_SESSION_SECRET=$(openssl rand -hex 32) \
GATE_ALLOWED_DOMAIN=kuutra.com \
GOOGLE_SSO_SERVICE_ACCOUNT_KEY="$(cat key.json)" \
GATE_ROUTES='[{"listen":9001,"origin":"https://sitemap-test.tail127ff5.ts.net",
  "target":"http://sitemap-test:10000","group":"sitemap_access@kuutra.com",
  "public":["/v1/","/mcp","/healthz"],"title":"Sitemap"}]' \
google-sso-gate
```

From Node, `startGate()` from `fastify-google-sso/gate` takes the same
settings as an object.

- **Its own routes** are under `/_gate/auth/google`, and its cookie is
  `kuutra_gate`. Neither collides with an app that still runs this plugin
  itself. Each route's callback is `<origin>/_gate/auth/google/callback`;
  add it to the OAuth client's Authorized redirect URIs.
- **Every path needs a login except `public`**, which goes straight through
  for the app's machine-facing API to check its own API keys. A prefix ending
  in `/` covers everything under it; `/mcp` covers `/mcp` and `/mcp/...`, not
  `/mcpx`. `.` and `..` segments (also as `%2e`) are resolved first, and the
  app gets the resolved path.
- **`"passApiKeys": true`** also passes through any request with an
  `Authorization: Bearer` or `X-API-Key` header, for an app whose scripts
  send a key on the same paths as its pages. Anyone can send that header, so
  the app must check the key on every path and refuse a wrong one, never
  treating it as a signed-in browser.
- **Who gets in**: Workspace accounts of `GATE_ALLOWED_DOMAIN`, and members
  of the route's `group` when it has one (checked at login, as above). Each
  route signs sessions with its own key, so a session from one gated app is
  no good on another.
- **Logged out**: a page view goes to the landing page and comes back to the
  page it asked for after the login; anything else gets a 401.
  `/_gate/auth/google/logout` signs out.
- **It listens on 127.0.0.1 only.** Anything that can reach the app directly,
  around the gate, isn't asked to log in, so have the app check the identity
  header (below).
- **The app sees the request unchanged**, minus the gate's cookies and any
  `X-Gate-Identity` the client sent. WebSocket upgrades aren't proxied.

### Who signed in: the X-Gate-Identity header

With `GATE_SIGNING_KEY` set, every request the gate proxies for a signed-in
browser carries `X-Gate-Identity`: a JWT signed with ES256, issuer
`google-sso-gate`, audience the app's origin, valid for 60 seconds, with
`email`, `name` and `hd` (the Workspace domain). The app checks it with the
gate's public key, so a request that went around the gate, which has no valid
header, gets nothing. Requests passed through for `public` paths or
`passApiKeys` carry it only if the browser is signed in too.

`google-sso-gate keygen` prints a new key pair: the private key goes in the
gate's `GATE_SIGNING_KEY` (multi-line, or one line with `\n`s), the public key
in each app. The gate also logs its public key when it starts.

Each app then decides per request:

1. **An API key header** (`Authorization: Bearer`, `X-API-Key`): check the
   key, and answer 401 when it's wrong. Never fall back to anything else.
2. **Otherwise a valid `X-Gate-Identity`**: the user is signed in.
3. **Otherwise** answer 401, except for the route's `public` paths.

Node, with `fastify-google-sso/identity` (no other dependencies):

```ts
import { verifyGateIdentity } from "fastify-google-sso/identity";

const user = verifyGateIdentity(request.headers["x-gate-identity"], {
  publicKey: process.env.GATE_PUBLIC_KEY!,
  audience: "https://sitemap-test.tail127ff5.ts.net",
}); // { email, name, hostedDomain } or null
```

Python, with `PyJWT[crypto]`:

```python
import jwt

def gate_user(request):
    token = request.headers.get("X-Gate-Identity")
    if not token:
        return None
    try:
        return jwt.decode(token, GATE_PUBLIC_KEY, algorithms=["ES256"], issuer="google-sso-gate",
                          audience="https://seocrew-test.tail127ff5.ts.net", leeway=30)
    except jwt.PyJWTError:
        return None
```

Pin `algorithms=["ES256"]` in any library, so a token can't pick its own.

## What this does and doesn't handle

- **Session storage**: a signed, `HttpOnly`, `SameSite=Lax` (or `Strict`) cookie holding
  the verified profile + an expiry — no server-side session store. Fine for
  an admin tool's traffic; not built for a consumer-facing product's scale.
- **Not encrypted, only signed**: the cookie's payload (email, name,
  picture, Workspace domain) is readable by anyone who has the cookie, just
  tamper-proof. Don't put anything more sensitive than that in a future
  version's payload without encrypting it.
- **Coexists with your own `@fastify/cookie` usage**: the plugin reads and
  writes its cookies itself, so it doesn't register `@fastify/cookie` and
  never uses its secret. The session cookie is always signed with your own
  `sessionSecret`.
- **No "return to the page you wanted" redirect after login** — you always
  land on `successRedirect`. A reasonable v2 addition if you need it; left
  out for now to avoid the open-redirect footgun of doing it carelessly.
- **CSRF protection on the login flow itself**: a random `state` and a PKCE
  verifier go into a signed, 10-minute `<cookieName>_login` cookie, and the
  callback refuses anything that doesn't match it. Nothing extra is needed
  from you there. Protecting your own state-changing routes is still your job.
- **Why logout needs `prompt`**: logging out only clears *this app's own*
  session cookie — no third-party app can remotely log a browser out of
  Google itself, by design. Without `prompt=select_account` (the default),
  a browser with an already-active Google session would silently get a
  fresh, valid session back the next time it's challenged to log in — no
  interaction, no visible sign anything happened — so logout would look
  broken even though it worked correctly. The account chooser screen is
  what makes a fresh login visibly fresh.

## Behind a reverse proxy that strips a path prefix

If this app is reached through something like Tailscale Serve's
`--set-path=/sitemap` — the proxy strips `/sitemap` before forwarding, so
the app itself only ever sees and registers un-prefixed paths — set
`externalBasePath` to the full external prefix:

```ts
await app.register(googleSso, {
  // ...
  basePath: "/auth/google",              // unprefixed — what this app actually receives
  externalBasePath: "/sitemap/auth/google", // what the browser actually needs in the URL
  successRedirect: "/sitemap/admin/dashboard",
});
```

Without this, `requireGoogleSession`'s "please log in" redirect sends the
browser to `/auth/google/login` — resolved by the browser against the
external origin, missing the proxy's prefix — which 404s against the proxy
layer itself, never reaching this app. `callbackUri` still needs to be the
*full* external URL (scheme + host + prefixed path, exactly matching what's
registered in Google Cloud Console) — `externalBasePath` is path-only, since
a `Location` header is always resolved relative to the current origin.
