#!/usr/bin/env node
import { startGate, type GateRoute } from "./gate.js";

/**
 * Runs the gate from environment variables:
 *
 *   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET   the OAuth client
 *   GATE_SESSION_SECRET                      openssl rand -hex 32
 *   GATE_ALLOWED_DOMAIN                      e.g. kuutra.com
 *   GOOGLE_SSO_SERVICE_ACCOUNT_KEY           the JSON key, when a route has a group
 *   GATE_ROUTES                              a JSON array of routes (see GateRoute)
 */

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set.`);
  return value;
}

try {
  const routes = JSON.parse(required("GATE_ROUTES")) as GateRoute[];
  if (!Array.isArray(routes) || routes.length === 0) throw new Error("GATE_ROUTES must be a non-empty JSON array.");
  const key = process.env.GOOGLE_SSO_SERVICE_ACCOUNT_KEY;
  await startGate({
    clientId: required("GOOGLE_CLIENT_ID"),
    clientSecret: required("GOOGLE_CLIENT_SECRET"),
    sessionSecret: required("GATE_SESSION_SECRET"),
    allowedDomain: required("GATE_ALLOWED_DOMAIN"),
    serviceAccountKey: key ? JSON.parse(key) : undefined,
    routes,
  });
} catch (err) {
  console.error(`gate: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
