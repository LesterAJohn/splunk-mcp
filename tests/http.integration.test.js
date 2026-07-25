import assert from "node:assert/strict";
import test from "node:test";

import { createHttpMcpServer } from "../src/http/server.js";
import { createMcpServer } from "../src/mcp/server.js";

function createDependencies() {
  const splunkClient = {
    getConnectionInfo() {
      return { timeoutMs: 30000, verifyTls: false };
    },
    async request(payload) {
      return {
        status: 200,
        method: payload.method,
        path: payload.path,
        data: { ok: true }
      };
    }
  };

  const configStore = {
    async getConfigWithFallback(key, userId) {
      return {
        source: "none",
        resolvedUserId: userId,
        row: null,
        key
      };
    }
  };

  const vaultService = {
    async getSecret() {
      return { sessionKey: "splunk-session" };
    },
    async setSecret() {
      return { ok: true };
    }
  };

  return { splunkClient, configStore, vaultService };
}

function createTestServer() {
  const deps = createDependencies();
  return createHttpMcpServer({
    host: "127.0.0.1",
    port: 0,
    mcpPath: "/mcp",
    healthPath: "/healthz",
    authMode: "token",
    authTokens: ["test-token"],
    trustedProxy: false,
    allowedOrigins: [],
    allowedIps: [],
    maxBodyBytes: 1024 * 1024,
    rateLimitWindowMs: 60_000,
    rateLimitMaxRequests: 60,
    createMcpServer: () =>
      createMcpServer({
        name: "splunk-mcp",
        version: "0.1.0",
        splunkClient: deps.splunkClient,
        configStore: deps.configStore,
        vaultService: deps.vaultService,
        runtimeEnv: {
          appName: "splunk",
          config: { defaultUserId: "default" },
          splunk: { defaultEnvironment: "default", defaultBaseUrl: "https://127.0.0.1:8089", authMode: "splunk" }
        }
      })
  });
}

function initializeRequestPayload() {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: {
        name: "test-client",
        version: "1.0.0"
      }
    }
  };
}

test("unauthorized HTTP request is rejected", async () => {
  const server = createTestServer();
  await server.start();

  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");

    const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(initializeRequestPayload())
    });

    assert.equal(response.status, 401);
  } finally {
    await server.close();
  }
});

test("authorized HTTP MCP initialize call succeeds", async () => {
  const server = createTestServer();
  await server.start();

  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");

    const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-token"
      },
      body: JSON.stringify(initializeRequestPayload())
    });

    assert.equal(response.status, 200);
  } finally {
    await server.close();
  }
});

test("health endpoint reports HTTP MCP status", async () => {
  const server = createTestServer();
  await server.start();

  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");

    const response = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(response.status, 200);

    const payload = await response.json();
    assert.equal(payload.ok, true);
    assert.equal(payload.status, 200);
    assert.equal(payload.transport, "http");
    assert.equal(payload.path, "/mcp");
  } finally {
    await server.close();
  }
});
