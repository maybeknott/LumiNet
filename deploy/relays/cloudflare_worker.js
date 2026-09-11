// ============================================================================
// LumiNet Serverless Cloudflare Worker Relay
// ============================================================================
//
// This script acts as a serverless bridge between the LumiNet Client
// and the LumiNet EvasionRelayServer, deployed at the Cloudflare edge.
//
// How to deploy:
// 1. Go to Cloudflare Dashboard -> Workers & Pages.
// 2. Create a new Worker.
// 3. Paste this code.
// 4. Configure AUTH_KEY and RELAY_URL environment variables or edit CONFIG below.
// 5. Deploy.

import {
  DEFAULT_MAX_BODY_BYTES,
  FIXED_HTTP_CONTRACT_VERSION,
  authorized,
  hopCount,
  rejectHop,
  relayError,
  requestId,
} from "./fixed_http_contract.mjs";

const CONFIG = {
  // RELAY_URL and DOH_UPSTREAM are placeholders that operators must replace.
  // There is deliberately no default AUTH_KEY: the tunnel path fails closed
  // until env.AUTH_KEY is configured.
  RELAY_URL: "https://your-evasion-relay-server.com/tunnel",
  DOH_UPSTREAM: "https://cloudflare-dns.com/dns-query"
};

export default {
  async fetch(request, env, ctx) {
    const requestIdValue = requestId(request);
    const loopResponse = rejectHop(request, Number(env.RELAY_MAX_HOPS || 2));
    if (loopResponse) return loopResponse;
    const authKey = env.AUTH_KEY || "";
    const relayUrl = env.RELAY_URL || CONFIG.RELAY_URL;
    const dohUpstream = env.DOH_UPSTREAM || CONFIG.DOH_UPSTREAM;

    const url = new URL(request.url);

    // 1. Handle DoH Caching Proxy Endpoint (POST to GET Cache Conversion - from Batch 5 doh-cache-worker)
    if (url.pathname === "/dns-query") {
      if (request.method === "GET") {
        const dnsParam = url.searchParams.get("dns");
        if (!dnsParam) {
          return new Response("Missing 'dns' query parameter", { status: 400 });
        }

        const targetUrl = `${dohUpstream}?dns=${dnsParam}`;
        const dohResponse = await fetch(targetUrl, {
          method: "GET",
          headers: {
            "Accept": "application/dns-message"
          },
          cf: { cacheEverything: true, cacheTtl: 300 }
        });

        const responseHeaders = new Headers(dohResponse.headers);
        responseHeaders.set("Access-Control-Allow-Origin", "*");

        return new Response(dohResponse.body, {
          status: dohResponse.status,
          headers: responseHeaders
        });
      } else if (request.method === "POST") {
        try {
          const bodyBuffer = await request.arrayBuffer();
          const base64url = arrayBufferToBase64Url(bodyBuffer);
          const targetUrl = `${dohUpstream}?dns=${base64url}`;

          const dohResponse = await fetch(targetUrl, {
            method: "GET",
            headers: {
              "Accept": "application/dns-message"
            },
            cf: { cacheEverything: true, cacheTtl: 300 }
          });

          const responseHeaders = new Headers(dohResponse.headers);
          responseHeaders.set("Access-Control-Allow-Origin", "*");

          return new Response(dohResponse.body, {
            status: dohResponse.status,
            headers: responseHeaders
          });
        } catch (error) {
          return new Response("Failed to proxy DoH query: " + error.message, { status: 500 });
        }
      }
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 2. Handle GET health check
    if (request.method === "GET") {
      return new Response(JSON.stringify({
        status: "ok",
        service: "LumiNet Cloudflare Worker Relay",
        version: "1.1.0",
        features: ["tunnel", "doh-caching"]
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    if (request.method !== "POST") {
      return relayError("invalid_request", 405, requestIdValue);
    }

    // 3. Verify Authentication for Tunneling
    if (!authorized(request, { ...env, AUTH_KEY: authKey })) {
      return relayError("unauthorized", 401, requestIdValue);
    }

    // 4. Forward Payload to EvasionRelayServer
    try {
      const requestBody = await request.arrayBuffer();
      if (requestBody.byteLength > Number(env.MAX_BODY_BYTES || DEFAULT_MAX_BODY_BYTES)) {
        return relayError("body_too_large", 413, requestIdValue);
      }

      const forwardResponse = await fetch(relayUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-LumiNet-Relay-Hop": String(hopCount(request.headers) + 1),
          "X-LumiNet-Relay-Contract": String(FIXED_HTTP_CONTRACT_VERSION),
          "X-Request-ID": requestIdValue,
          "X-GSA-Auth-Key": authKey
        },
        body: requestBody
      });

      const responseBody = await forwardResponse.text();

      return new Response(responseBody, {
        status: forwardResponse.status,
        headers: {
          "Content-Type": "application/json",
          "X-LumiNet-CF-Worker": "processed"
        }
      });
    } catch (error) {
      return relayError("upstream_failure", 502, requestIdValue);
    }
  }
};

// Helper to convert array buffer to base64url format
function arrayBufferToBase64Url(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
