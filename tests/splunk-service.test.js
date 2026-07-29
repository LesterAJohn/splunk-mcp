import assert from "node:assert/strict";
import test from "node:test";

import { SplunkServiceClient } from "../src/services/splunkService.js";

function withFetchStub(handler) {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = handler;
  return () => {
    globalThis.fetch = previousFetch;
  };
}

function okResponse({ body = { ok: true }, contentType = "application/json", status = 200 } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        if (String(name).toLowerCase() === "content-type") {
          return contentType;
        }
        return null;
      }
    },
    async text() {
      return typeof body === "string" ? body : JSON.stringify(body);
    }
  };
}

test("enterprise request requires /services and sends Splunk auth header", async () => {
  let seenHeaders;
  const restoreFetch = withFetchStub(async (_url, init) => {
    seenHeaders = init.headers;
    return okResponse();
  });

  try {
    const client = new SplunkServiceClient({ timeoutMs: 1000 });
    const response = await client.request({
      baseUrl: "https://splunk.example.com:8089",
      method: "GET",
      path: "/services/server/info",
      query: { output_mode: "json" },
      authMode: "splunk",
      authSecret: { sessionKey: "splunk-session" }
    });

    assert.equal(response.apiFamily, "enterprise");
    assert.equal(response.path, "/services/server/info");
    assert.equal(seenHeaders.Authorization, "Splunk splunk-session");
  } finally {
    restoreFetch();
  }
});

test("soar request requires /rest and sends ph-auth-token header", async () => {
  let seenHeaders;
  const restoreFetch = withFetchStub(async (_url, init) => {
    seenHeaders = init.headers;
    return okResponse({ body: { count: 0, data: [] } });
  });

  try {
    const client = new SplunkServiceClient({ timeoutMs: 1000 });
    const response = await client.request({
      baseUrl: "https://soar.example.com",
      apiFamily: "soar",
      method: "GET",
      path: "/rest/container",
      query: { page_size: 1 },
      authMode: "phantom",
      authSecret: { phAuthToken: "phantom-token" }
    });

    assert.equal(response.apiFamily, "soar");
    assert.equal(response.path, "/rest/container");
    assert.equal(seenHeaders["ph-auth-token"], "phantom-token");
  } finally {
    restoreFetch();
  }
});

test("enterprise request rejects non-services paths", async () => {
  const client = new SplunkServiceClient({ timeoutMs: 1000 });

  await assert.rejects(
    () =>
      client.request({
        baseUrl: "https://splunk.example.com:8089",
        apiFamily: "enterprise",
        method: "GET",
        path: "/rest/container",
        authMode: "none"
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.match(error.message, /must start with \/services/i);
      return true;
    }
  );
});

test("soar request rejects non-rest paths", async () => {
  const client = new SplunkServiceClient({ timeoutMs: 1000 });

  await assert.rejects(
    () =>
      client.request({
        baseUrl: "https://soar.example.com",
        apiFamily: "soar",
        method: "GET",
        path: "/services/server/info",
        authMode: "none"
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.match(error.message, /must start with \/rest/i);
      return true;
    }
  );
});
