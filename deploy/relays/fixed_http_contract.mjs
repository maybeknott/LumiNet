export const FIXED_HTTP_CONTRACT_VERSION = 1;
export const DEFAULT_MAX_RELAY_HOPS = 2;
export const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

const HOP_BY_HOP_HEADERS = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "host",
  "content-length", "forwarded", "via", "x-forwarded-for",
  "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto",
  "x-real-ip", "x-relay-hop", "x-fwd-hop", "x-luminet-relay-hop",
  "authorization", "cookie",
]);

export function relayError(code, status, requestId = "") {
  return new Response(JSON.stringify({
    v: FIXED_HTTP_CONTRACT_VERSION,
    error: { code, retryable: status >= 500, request_id: requestId },
  }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

export function requestId(request) {
  return request.headers.get("x-request-id") || crypto.randomUUID();
}

export function hopCount(headers) {
  const values = ["x-luminet-relay-hop", "x-relay-hop", "x-fwd-hop"]
    .map((name) => Number.parseInt(headers.get(name) || "0", 10));
  return Math.max(0, ...values.filter(Number.isFinite));
}

export function rejectHop(request, maxHops = DEFAULT_MAX_RELAY_HOPS) {
  return hopCount(request.headers) >= maxHops
    ? relayError("loop_detected", 508, requestId(request))
    : null;
}

export function sanitizedHeaders(input) {
  const source = input instanceof Headers ? input : new Headers(input);
  const output = new Headers();
  for (const [name, value] of source) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || lower.startsWith("x-vercel-")) continue;
    output.set(name, value);
  }
  return output;
}

export function authorized(request, env, allowQuery = true) {
  const expected = env.RELAY_AUTH_KEY || env.AUTH_KEY || "";
  // Fail closed: an unconfigured relay must refuse tunneling traffic instead
  // of operating as an open proxy. Operators must set RELAY_AUTH_KEY.
  if (!expected) return false;
  const bearer = request.headers.get("authorization");
  const header = request.headers.get("x-gsa-auth-key");
  const query = allowQuery ? new URL(request.url).searchParams.get("key") : null;
  return bearer === `Bearer ${expected}` || header === expected || query === expected;
}

export function fixedTarget(base, requestPath) {
  const target = new URL(base);
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    throw new Error("unsupported target scheme");
  }
  const suffix = new URL(
    requestPath.startsWith("/") ? requestPath : `/${requestPath}`,
    "https://relay.invalid",
  );
  target.pathname = `${target.pathname.replace(/\/$/, "")}${suffix.pathname}`;
  target.search = suffix.search;
  return target;
}
