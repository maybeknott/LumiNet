/**
 * LumiNet Vercel Edge Relay
 *
 * Implements high-throughput edge proxying and multi-path micro-dispersal
 * chunk routing on Vercel Edge Functions.
 * Adheres to fixed_http_contract.mjs invariants.
 */

import {
  authorized,
  hopCount,
  rejectHop,
  relayError,
  requestId,
  sanitizedHeaders,
  DEFAULT_MAX_BODY_BYTES,
} from "./fixed_http_contract.mjs";

export const config = {
  runtime: "edge",
};

export default async function handler(request) {
  const reqId = requestId(request);

  // 1. Authorization check
  if (!authorized(request, process.env)) {
    return relayError("unauthorized", 401, reqId);
  }

  // 2. Loop detection
  const loopError = rejectHop(request);
  if (loopError) {
    return loopError;
  }
  const relayHop = String(hopCount(request.headers) + 1);

  // 3. Health check route
  const url = new URL(request.url);
  if (url.pathname === "/health" || url.pathname === "/api/health") {
    return new Response(JSON.stringify({ status: "healthy", runner: "vercel_edge", timestamp: Date.now() }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  // 4. Handle Dispersal MicroFrame or Direct Proxy Request
  if (request.method === "POST" && request.headers.get("content-type")?.includes("application/json")) {
    try {
      const frame = await request.json();
      if (frame.session_id && frame.target && frame.data) {
        // Handle micro-dispersal frame forwarding
        const targetUrl = frame.target.startsWith("http") ? frame.target : `https://${frame.target}`;
        const binaryData = typeof frame.data === "string" ? Buffer.from(frame.data, "base64") : new Uint8Array(frame.data);

        const upstreamResp = await fetch(targetUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-LumiNet-Session": frame.session_id,
            "X-LumiNet-Seq": String(frame.seq || 0),
            "X-LumiNet-Relay-Hop": relayHop,
          },
          body: binaryData,
        });

        const respData = await upstreamResp.arrayBuffer();
        const responseFrame = {
          session_id: frame.session_id,
          seq: frame.seq,
          data: Array.from(new Uint8Array(respData)),
        };

        return new Response(JSON.stringify(responseFrame), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
    } catch {
      // Fall through to standard proxying if not a JSON frame
    }
  }

  // 5. Standard Forwarding Relay
  const targetHost = request.headers.get("x-target-host") || process.env.UPSTREAM_TARGET;
  if (!targetHost) {
    return relayError("missing_target", 400, reqId);
  }

  const outboundUrl = new URL(url.pathname + url.search, `https://${targetHost}`);
  const headers = sanitizedHeaders(request.headers);
  headers.set("x-luminet-relay-hop", relayHop);

  try {
    const upstream = await fetch(outboundUrl.toString(), {
      method: request.method,
      headers,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
      redirect: "manual",
    });

    const respHeaders = sanitizedHeaders(upstream.headers);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: respHeaders,
    });
  } catch (err) {
    return relayError("upstream_unavailable", 502, reqId);
  }
}
