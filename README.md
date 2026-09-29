# fastify-google-sso

A drop-in Fastify plugin that gates a service's human-facing pages (an admin
dashboard, an internal tool — anything a person opens in a browser) behind
"Sign in with Google," restricted to a Google Workspace domain or an
explicit email allowlist. It's deliberately narrow: it does the OAuth2 login
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
"fastify-google-sso": "git+https://github.com/MinderaLab/fastify-google-sso.git#v1.0.0"
```

Requires `fastify` ^5 as a peer dependency (already in your app).

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
`/auth/google`): `/login` (start the flow), `/callback` (Google redirects
here), `/logout` (clears the session). Visiting a route with
`requireGoogleSession` while logged out redirects to `/login` — not a 401 —
since this is for a human in a browser, not a script.

## Options

| Option | Required | Default | Notes |
| --- | --- | --- | --- |
| `clientId` | yes | — | From Google Cloud Console. |
| `clientSecret` | yes | — | From Google Cloud Console. |
| `callbackUri` | yes | — | Must exactly match an authorized redirect URI. |
| `sessionSecret` | yes | — | Signs the session cookie. `openssl rand -hex 32`. Rotating it logs everyone out. |
| `isAllowed` | yes | — | `(profile) => boolean \| Promise<boolean>`. Authorization, not authentication — see below. |
| `basePath` | no | `/auth/google` | Where this plugin's own routes live. |
| `externalBasePath` | no | same as `basePath` | Set this if you're behind a reverse proxy that strips a path prefix before forwarding here — see below. |
| `cookieName` | no | `google_sso_session` | |
| `sessionTtlSeconds` | no | `43200` (12h) | |
| `successRedirect` | no | `/` | Where the browser lands after a successful login. |

`isAllowed` receives a `GoogleSsoProfile`: `{ email, name?, picture?,
hostedDomain? }`. `hostedDomain` (Google's `hd` claim) is set only for a
Google Workspace account — it's absent for a personal `@gmail.com` one.
Restricting to a Workspace domain (`profile.hostedDomain === "kuutra.com"`)
is usually simpler to maintain than an explicit email list, since it doesn't
need updating as people join or leave; use an explicit list instead if you
need named individuals outside that domain too.

## What this does and doesn't handle

- **Session storage**: a signed, `HttpOnly`, `SameSite=Lax` cookie holding
  the verified profile + an expiry — no server-side session store. Fine for
  an admin tool's traffic; not built for a consumer-facing product's scale.
- **Not encrypted, only signed**: the cookie's payload (email, name,
  picture, Workspace domain) is readable by anyone who has the cookie, just
  tamper-proof. Don't put anything more sensitive than that in a future
  version's payload without encrypting it.
- **Coexists with your own `@fastify/cookie` usage**: if your app already
  registers `@fastify/cookie` for something unrelated, this plugin detects
  that and doesn't re-register it (which Fastify doesn't allow) or borrow
  its secret — the session cookie is always signed with your own
  `sessionSecret`, independently.
- **No "return to the page you wanted" redirect after login** — you always
  land on `successRedirect`. A reasonable v2 addition if you need it; left
  out for now to avoid the open-redirect footgun of doing it carelessly.
- **`@fastify/oauth2` handles CSRF protection** on the OAuth flow itself
  (the `state`/PKCE dance) — nothing extra needed from you there.

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
