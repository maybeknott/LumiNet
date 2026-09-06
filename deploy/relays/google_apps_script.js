// ============================================================================
// LumiNet Serverless Google Apps Script Relay
// ============================================================================
//
// This script acts as a serverless bridge between the LumiNet Client (GsaTunnelConn)
// and the LumiNet EvasionRelayServer.
//
// How to deploy:
// 1. Go to https://script.google.com/
// 2. Create a new project.
// 3. Paste this code.
// 4. Update the CONFIG variables below.
// 5. Click "Deploy" -> "New deployment" -> Select "Web app".
// 6. Execute as: "Me", Who has access: "Anyone".
// 7. Copy the Web App URL and use it in LumiNet client configuration.

var CONFIG = {
  // Authentication key to authorize requests. Must match the client's CovertGsaKey.
  // No default is provided: the relay fails closed until the operator sets a key.
  AUTH_KEY: "",

  // The actual URL of your LumiNet EvasionRelayServer /tunnel endpoint.
  // Note: GsaTunnelConn routes stateful TCP sessions through this relay.
  RELAY_URL: "https://your-evasion-relay-server.com/tunnel",

  // Maximum relay hops before a request is rejected as a forwarding loop.
  MAX_RELAY_HOPS: 2
};

function doPost(e) {
  try {
    // 1. Verify Authentication
    var clientAuth = e.parameter.key || getHeader(e, "X-GSA-Auth-Key");
    if (!clientAuth && e.postData && e.postData.contents) {
      // Fallback check inside payload if headers are stripped by edge proxies
      try {
        var tempPayload = JSON.parse(e.postData.contents);
        if (tempPayload.auth_key) {
          clientAuth = tempPayload.auth_key;
        }
      } catch (ex) {}
    }

    // Fail closed: refuse to tunnel until the operator configures a real key.
    if (!CONFIG.AUTH_KEY || clientAuth !== CONFIG.AUTH_KEY) {
      return ContentService.createTextOutput(JSON.stringify({
        error: "Unauthorized: Invalid or missing X-GSA-Auth-Key"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Reject requests that already traversed the maximum relay hops.
    var inboundHop = parseInt(getHeader(e, "X-LumiNet-Relay-Hop") || "0", 10);
    if (!isFinite(inboundHop) || inboundHop < 0 || inboundHop >= CONFIG.MAX_RELAY_HOPS) {
      return ContentService.createTextOutput(JSON.stringify({
        error: "loop_detected",
        request_id: getHeader(e, "X-Request-ID") || ""
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // 2. Extract client payload
    var requestBody = e.postData.contents;

    // 3. Forward to EvasionRelayServer
    var options = {
      method: "post",
      contentType: "application/json",
      payload: requestBody,
      headers: {
        "X-LumiNet-Relay-Hop": String(inboundHop + 1),
        "X-GSA-Auth-Key": CONFIG.AUTH_KEY
      },
      muteHttpExceptions: true
    };

    var response = UrlFetchApp.fetch(CONFIG.RELAY_URL, options);
    var responseCode = response.getResponseCode();
    var responseBody = response.getContentText();

    // 4. Return response to LumiNet client
    return ContentService.createTextOutput(responseBody)
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      error: "Relay Internal Error: " + error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  // Diagnostic health check
  return ContentService.createTextOutput(JSON.stringify({
    status: "ok",
    service: "LumiNet GSA Serverless Relay",
    version: "1.0.0"
  })).setMimeType(ContentService.MimeType.JSON);
}

function getHeader(e, headerName) {
  if (!e.headers) return null;
  var key = headerName.toLowerCase();
  for (var h in e.headers) {
    if (h.toLowerCase() === key) {
      return e.headers[h];
    }
  }
  return null;
}
