import { readFileSync } from "node:fs";
import type { CallbackResult } from "./core.js";

/**
 * The two small HTML pages behind the popup login: a landing page with a
 * "Sign in with Google" button that opens the login flow in a popup, and the
 * page the popup lands on at the callback, which tells the landing page how
 * the login went and closes itself. Plain strings, no framework, so the
 * core's users can serve them too.
 *
 * The popup reports back over a BroadcastChannel and window.opener (both
 * same-origin only). The channel is there because Google's sign-in pages may
 * cut the popup's link to its opener; when neither reaches the landing page,
 * the popup finishes the login in its own window instead.
 */

export interface LandingPageOptions {
  /** Heading on the page, and its <title>. Default "Sign in". */
  title?: string;
  /** A line under the heading, e.g. what the app is. Default none. */
  description?: string;
}

const CHANNEL = "fastify-google-sso";

// Inlined, so the page needs no route of its own for it (or a proxy prefix).
const LOGO_DATA_URI = `data:image/png;base64,${readFileSync(new URL("../static/kuutra_logo.png", import.meta.url)).toString("base64")}`;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// JSON safe to put inside a <script> element.
function scriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

// Kuutra's palette (kuutra.com): deep green, yellow accent, pale greens.
const STYLES = `
:root {
  --bg: #e7f6ea;
  --card: #ffffff;
  --text: #2f6544;
  --muted: #637069;
  --accent: #ffe393;
  --accent-hover: #ffda6e;
  --accent-text: #2f6544;
  --border: rgba(30, 55, 40, 0.2);
  --error: #e66d32;
  --error-bg: #ffd6c4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #09110c;
    --card: #1e3728;
    --text: #f7eeda;
    --muted: #b5c2ba;
    --border: rgba(255, 255, 255, 0.2);
    --error-bg: rgba(230, 109, 50, 0.18);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  background: var(--bg);
  color: var(--text);
  font-family: "Urbanist", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.5;
}
main {
  width: 100%;
  max-width: 400px;
  padding: 40px 32px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 20px;
  text-align: center;
}
.logo { display: block; width: 180px; max-width: 70%; height: auto; margin: 0 auto 28px; }
@media (prefers-color-scheme: dark) {
  .logo { filter: invert(1) brightness(0.95); }
}
h1 { margin: 0 0 8px; font-size: 28px; font-weight: 700; letter-spacing: -0.01em; }
p { margin: 0 0 24px; color: var(--muted); }
.signin {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  width: 100%;
  padding: 14px 20px;
  border: 0;
  border-radius: 999px;
  background: var(--accent);
  color: var(--accent-text);
  font: inherit;
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
}
.signin:hover { background: var(--accent-hover); }
.signin:focus-visible { outline: 3px solid var(--text); outline-offset: 3px; }
.signin svg { flex: none; padding: 3px; background: #fff; border-radius: 50%; box-sizing: content-box; }
.error {
  margin: 0 0 20px;
  padding: 12px 14px;
  border-left: 4px solid var(--error);
  border-radius: 8px;
  background: var(--error-bg);
  color: var(--text);
  text-align: left;
}
.error[hidden] { display: none; }
`;

const GOOGLE_G = `<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`;

function page(title: string, body: string, script: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>${STYLES}</style>
</head>
<body>
${body}
<script>${script}</script>
</body>
</html>
`;
}

/**
 * The landing page: a "Sign in with Google" button that opens loginUrl (with
 * ?popup=1) in a popup. Once the popup reports a successful login, the page
 * moves on to the redirect the popup hands back; a refused login shows its
 * message here. With JavaScript off or popups blocked, the button is a plain
 * link to loginUrl, the ordinary full-page flow.
 */
export function renderLandingPage(loginUrl: string, opts: LandingPageOptions = {}): string {
  const title = opts.title ?? "Sign in";
  const description = opts.description ? `<p>${escapeHtml(opts.description)}</p>` : "";
  const body = `<main>
<img class="logo" src="${LOGO_DATA_URI}" alt="Kuutra" width="180" height="45">
<h1>${escapeHtml(title)}</h1>
${description}
<div class="error" role="alert" hidden></div>
<a class="signin" href="${escapeHtml(loginUrl)}">${GOOGLE_G}<span>Sign in with Google</span></a>
</main>`;
  const script = `(function () {
  var loginUrl = ${scriptJson(loginUrl)};
  var button = document.querySelector(".signin");
  var errorBox = document.querySelector(".error");
  var popup = null;
  function onResult(msg) {
    if (!msg || msg.source !== ${scriptJson(CHANNEL)}) return;
    if (popup && !popup.closed) popup.close();
    if (msg.ok) { location.replace(msg.redirect); return; }
    errorBox.textContent = msg.message;
    errorBox.hidden = false;
  }
  window.addEventListener("message", function (e) {
    if (e.origin === location.origin) onResult(e.data);
  });
  if (window.BroadcastChannel) {
    new BroadcastChannel(${scriptJson(CHANNEL)}).onmessage = function (e) { onResult(e.data); };
  }
  button.addEventListener("click", function (e) {
    var w = 500, h = 640;
    var left = window.screenX + Math.max(0, (window.outerWidth - w) / 2);
    var top = window.screenY + Math.max(0, (window.outerHeight - h) / 2);
    var url = loginUrl + (loginUrl.indexOf("?") === -1 ? "?" : "&") + "popup=1";
    popup = window.open(url, "google-sso", "popup,width=" + w + ",height=" + h + ",left=" + left + ",top=" + top);
    if (!popup) return; // blocked: let the link do a full-page login
    e.preventDefault();
    errorBox.hidden = true;
    popup.focus();
  });
})();`;
  return page(title, body, script);
}

/**
 * The page a popup login ends on, at the callback: it hands the result to the
 * landing page and closes. Serve it with the result's setCookies, and with
 * result.status when the login was refused.
 */
export function renderPopupResult(result: CallbackResult): string {
  const msg = result.ok
    ? { source: CHANNEL, ok: true, redirect: result.redirect }
    : { source: CHANNEL, ok: false, message: result.message };
  const body = result.ok
    ? `<main><h1>Signed in</h1><p>You can close this window.</p></main>`
    : `<main><h1>Sign-in failed</h1><div class="error" role="alert">${escapeHtml(result.message)}</div></main>`;
  const script = `(function () {
  var msg = ${scriptJson(msg)};
  var told = false;
  try {
    if (window.BroadcastChannel) { new BroadcastChannel(msg.source).postMessage(msg); told = true; }
  } catch (e) {}
  try {
    if (window.opener && !window.opener.closed) { window.opener.postMessage(msg, location.origin); told = true; }
  } catch (e) {}
  if (told) window.close();
  // Still open: nothing was listening, or the browser kept the window. A
  // successful login then carries on here; a failure stays on screen.
  if (msg.ok) setTimeout(function () { location.replace(msg.redirect); }, told ? 500 : 0);
})();`;
  return page(result.ok ? "Signed in" : "Sign-in failed", body, script);
}
