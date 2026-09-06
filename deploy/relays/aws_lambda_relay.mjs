/**
 * LumiNet AWS Lambda Relay
 *
 * Implements serverless edge relaying and micro-frame routing on AWS Lambda
 * with API Gateway / Function URL support.
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

export const handler = async (event) => {
  const headers = new Headers(event.headers || {});
  const method = event.requestContext?.http?.method || event.httpMethod || "GET";
  const rawPath = event.rawPath || event.path || "/";
  const queryString = event.rawQueryString ? `?${event.rawQueryString}` : "";
  const reqId = headers.get("x-request-id") || `aws-${Date.now()}`;

  // 1. Health check (public diagnostic endpoint)
  if (rawPath === "/health") {
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "healthy", runner: "aws_lambda", timestamp: Date.now() }),
    };
  }

  // 2. Authorization — the relay must never forward without a configured
  //    key (authorized() fails closed when no key is configured).
  if (!authorized(new Request(`https://relay.local${rawPath}${queryString}`, { headers }), process.env)) {
    return {
      statusCode: 401,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "unauthorized", request_id: reqId }),
    };
  }

  // 3. Loop detection — reject requests that have already traversed the
  //    maximum number of relay hops.
  if (rejectHop(new Request(`https://relay.local${rawPath}${queryString}`, { headers }))) {
    return {
      statusCode: 508,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "loop_detected", request_id: reqId }),
    };
  }

  // 4. Body size cap.
  if (event.body && Buffer.byteLength(event.isBase64Encoded
      ? Buffer.from(event.body, "base64")
      : event.body) > DEFAULT_MAX_BODY_BYTES) {
    return {
      statusCode: 413,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "body_too_large", request_id: reqId }),
    };
  }

  const relayHop = String(hopCount(headers) + 1);

  // 5. Micro-frame Dispersal
  if (method === "POST" && event.body) {
    try {
      const parsedBody = event.isBase64Encoded
        ? JSON.parse(Buffer.from(event.body, "base64").toString("utf-8"))
        : JSON.parse(event.body);

      if (parsedBody.session_id && parsedBody.target && parsedBody.data) {
        const targetUrl = parsedBody.target.startsWith("http")
          ? parsedBody.target
          : `https://${parsedBody.target}`;

        const binaryData = typeof parsedBody.data === "string"
          ? Buffer.from(parsedBody.data, "base64")
          : new Uint8Array(parsedBody.data);

        const upstream = await fetch(targetUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-LumiNet-Session": parsedBody.session_id,
            "X-LumiNet-Seq": String(parsedBody.seq || 0),
            "X-LumiNet-Relay-Hop": relayHop,
          },
          body: binaryData,
        });

        const respBuf = await upstream.arrayBuffer();
        const outFrame = {
          session_id: parsedBody.session_id,
          seq: parsedBody.seq,
          data: Array.from(new Uint8Array(respBuf)),
        };

        return {
          statusCode: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify(outFrame),
        };
      }
    } catch {
      // Fall through to standard proxying
    }
  }

  // 6. Fallback direct target forwarding
  const targetHost = headers.get("x-target-host") || process.env.UPSTREAM_TARGET;
  if (!targetHost) {
    return {
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "missing target host", request_id: reqId }),
    };
  }

  try {
    const outboundUrl = `https://${targetHost}${rawPath}${queryString}`;
    const cleanHeaders = sanitizedHeaders(headers);
    cleanHeaders.set("x-luminet-relay-hop", relayHop);

    const reqBody = event.body
      ? event.isBase64Encoded
        ? Buffer.from(event.body, "base64")
        : event.body
      : undefined;

    const resp = await fetch(outboundUrl, {
      method,
      headers: cleanHeaders,
      body: method !== "GET" && method !== "HEAD" ? reqBody : undefined,
    });

    const respData = await resp.arrayBuffer();
    const respHeaders = {};
    for (const [k, v] of resp.headers.entries()) {
      respHeaders[k.toLowerCase()] = v;
    }

    return {
      statusCode: resp.status,
      headers: respHeaders,
      isBase64Encoded: true,
      body: Buffer.from(respData).toString("base64"),
    };
  } catch (err) {
    return {
      statusCode: 502,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "upstream connection failure", detail: err.message }),
    };
  }
};
