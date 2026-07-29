import assert from "node:assert/strict";
import test from "node:test";

import { createMcpServer } from "../src/mcp/server.js";

function setEnv(updates) {
  const previous = {};
  for (const [key, value] of Object.entries(updates)) {
    previous[key] = process.env[key];
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }

  return () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  };
}

function createDependencies() {
  const calls = {
    request: 0,
    setConfig: 0,
    setSecret: 0
  };

  const secrets = new Map();

  const splunkClient = {
    getConnectionInfo() {
      return { timeoutMs: 30000, verifyTls: false };
    },
    async request(payload) {
      calls.request += 1;
      return {
        status: 200,
        method: payload.method,
        path: payload.path,
        apiFamily: payload.apiFamily,
        query: payload.query,
        body: payload.body,
        bodyFormat: payload.bodyFormat,
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
    },
    async setConfig() {
      calls.setConfig += 1;
      return { ok: true };
    }
  };

  const vaultService = {
    async getSecret(path) {
      if (secrets.has(path)) {
        return secrets.get(path);
      }
      return { sessionKey: "splunk-session" };
    },
    async setSecret(path, payload) {
      calls.setSecret += 1;
      secrets.set(path, payload);
      return { ok: true };
    }
  };

  return { splunkClient, configStore, vaultService, calls, secrets };
}

async function invokeTool(server, name, args = {}) {
  const registeredTools = server._registeredTools;
  assert.ok(registeredTools[name], `Expected tool ${name} to be registered`);
  const result = await registeredTools[name].handler(args);
  const payload = JSON.parse(result.content[0].text);
  return { result, payload };
}

test("splunk_connection_info returns ok", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });

  try {
    const deps = createDependencies();
    const server = createMcpServer({
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
    });

    const { payload } = await invokeTool(server, "splunk_connection_info");

    assert.equal(payload.ok, true);
    assert.equal(payload.status, 200);
    assert.equal(payload.data.server.name, "splunk-mcp");
    assert.ok(payload.data.endpointCatalog.totalCount > 0);
  } finally {
    restoreEnv();
  }
});

test("mutating tools require authorizationKey when admin key is configured", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "super-secret" });

  try {
    const deps = createDependencies();
    const server = createMcpServer({
      name: "splunk-mcp",
      version: "0.1.0",
      splunkClient: deps.splunkClient,
      configStore: deps.configStore,
      vaultService: deps.vaultService,
      runtimeEnv: {
        appName: "splunk",
        adminAuthKey: "super-secret",
        config: { defaultUserId: "default" },
        splunk: { defaultEnvironment: "default", defaultBaseUrl: "https://127.0.0.1:8089", authMode: "splunk" }
      }
    });

    const unauthorized = await invokeTool(server, "splunk_search_job_create", {
      search: "search index=_internal | head 1"
    });
    assert.equal(unauthorized.result.isError, true);
    assert.equal(unauthorized.payload.status, 401);

    const authorized = await invokeTool(server, "splunk_search_job_create", {
      search: "search index=_internal | head 1",
      authorizationKey: "super-secret"
    });
    assert.equal(authorized.payload.ok, true);

    const genericUnauthorized = await invokeTool(server, "splunk_api_request", {
      method: "POST",
      path: "/services/search/jobs",
      body: { search: "search index=_internal | head 1" }
    });
    assert.equal(genericUnauthorized.result.isError, true);
    assert.equal(genericUnauthorized.payload.status, 401);

    const genericAuthorized = await invokeTool(server, "splunk_api_request", {
      method: "POST",
      path: "/services/search/jobs",
      body: { search: "search index=_internal | head 1" },
      authorizationKey: "super-secret"
    });
    assert.equal(genericAuthorized.payload.ok, true);
    assert.equal(deps.calls.request, 2);
  } finally {
    restoreEnv();
  }
});

test("token tools support multi-user update and deactivation flow", async () => {
  const deps = createDependencies();
  const server = createMcpServer({
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
  });

  const upsert = await invokeTool(server, "mcp_token_upsert", {
    targetUserId: "analyst-a",
    token: "token-abc",
    scopes: ["mcp:invoke"]
  });

  assert.equal(upsert.payload.ok, true);
  assert.equal(upsert.payload.data.userId, "analyst-a");

  const listed = await invokeTool(server, "mcp_token_list", {
    targetUserId: "analyst-a"
  });

  assert.equal(listed.payload.ok, true);
  assert.equal(listed.payload.data.tokenCount, 1);

  const tokenHash = listed.payload.data.tokens[0].tokenHash;
  const deactivate = await invokeTool(server, "mcp_token_deactivate", {
    targetUserId: "analyst-a",
    tokenHash
  });

  assert.equal(deactivate.payload.ok, true);
  assert.equal(deactivate.payload.data.deactivated, true);
});

test("mcp_tool_discovery returns guidance for all MCP tools", async () => {
  const deps = createDependencies();
  const server = createMcpServer({
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
  });

  const { payload } = await invokeTool(server, "mcp_tool_discovery", {});

  assert.equal(payload.ok, true);
  assert.equal(payload.status, 200);
  assert.ok(payload.data.totalTools >= 19);
  assert.equal(payload.data.returnedTools, payload.data.totalTools);

  const toolNames = payload.data.tools.map((entry) => entry.name);
  assert.ok(toolNames.includes("splunk_connection_info"));
  assert.ok(toolNames.includes("splunk_api_request"));
  assert.ok(toolNames.includes("splunk_soar_api_request"));
  assert.ok(toolNames.includes("splunk_soar_container_get"));
  assert.ok(toolNames.includes("splunk_soar_container_find_by_source"));
  assert.ok(toolNames.includes("splunk_soar_container_create"));
  assert.ok(toolNames.includes("splunk_soar_artifact_create"));
  assert.ok(toolNames.includes("mcp_token_upsert"));

  const searchFiltered = await invokeTool(server, "mcp_tool_discovery", {
    intent: "search",
    includeSchemas: false,
    includeExamples: false
  });

  assert.equal(searchFiltered.payload.ok, true);
  assert.ok(searchFiltered.payload.data.returnedTools > 0);
  assert.ok(searchFiltered.payload.data.tools.every((entry) => entry.intents.includes("search")));
  assert.ok(searchFiltered.payload.data.tools.every((entry) => entry.schema === undefined));
  assert.ok(searchFiltered.payload.data.tools.every((entry) => entry.examples === undefined));

  const querySuggestionFiltered = await invokeTool(server, "mcp_tool_discovery", {
    intent: "query-suggestion",
    includeSchemas: false,
    includeExamples: false
  });

  assert.equal(querySuggestionFiltered.payload.ok, true);
  assert.ok(querySuggestionFiltered.payload.data.returnedTools >= payload.data.totalTools);
  assert.ok(
    querySuggestionFiltered.payload.data.tools.every((entry) => entry.intents.includes("query-suggestion"))
  );
});

test("SOAR tools use /rest product family", async () => {
  const deps = createDependencies();
  const server = createMcpServer({
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
  });

  const genericSoar = await invokeTool(server, "splunk_api_request", {
    product: "soar",
    method: "GET",
    path: "/rest/container/1"
  });
  assert.equal(genericSoar.payload.ok, true);
  assert.equal(genericSoar.payload.data.response.apiFamily, "soar");

  const dedicatedSoar = await invokeTool(server, "splunk_soar_api_request", {
    method: "GET",
    path: "/rest/container/1"
  });
  assert.equal(dedicatedSoar.payload.ok, true);
  assert.equal(dedicatedSoar.payload.data.response.apiFamily, "soar");

  const containerGet = await invokeTool(server, "splunk_soar_container_get", {
    containerId: 42
  });
  assert.equal(containerGet.payload.ok, true);
  assert.equal(containerGet.payload.data.response.path, "/rest/container/42");

  const containerFind = await invokeTool(server, "splunk_soar_container_find_by_source", {
    sourceDataIdentifier: "12387",
    pageSize: 1
  });
  assert.equal(containerFind.payload.ok, true);
  assert.equal(containerFind.payload.data.response.path, "/rest/container");
  assert.equal(containerFind.payload.data.response.query._filter_source_data_identifier, '"12387"');
  assert.equal(containerFind.payload.data.response.query.page_size, 1);

  const containerCreate = await invokeTool(server, "splunk_soar_container_create", {
    name: "new container",
    label: "events",
    runAutomation: false
  });
  assert.equal(containerCreate.payload.ok, true);
  assert.equal(containerCreate.payload.data.response.path, "/rest/container");
  assert.equal(containerCreate.payload.data.response.bodyFormat, "json");
  assert.equal(containerCreate.payload.data.response.body.run_automation, false);

  const artifactCreate = await invokeTool(server, "splunk_soar_artifact_create", {
    containerId: 42,
    label: "event",
    cef: { sourceAddress: "1.2.3.4" }
  });
  assert.equal(artifactCreate.payload.ok, true);
  assert.equal(artifactCreate.payload.data.response.path, "/rest/artifact");
  assert.equal(artifactCreate.payload.data.response.body.container_id, 42);
  assert.equal(artifactCreate.payload.data.response.body.label, "event");
});
