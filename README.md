# splunk-mcp

Splunk Enterprise REST API MCP server built from the skeleton pattern, with:
- Multi-user scoping for all token and environment operations
- Persistent secrets in Vault
- Persistent non-secret configuration in Postgres
- Stdio and HTTP MCP transports
- Admin-gated mutating operations via MCP_ADMIN_AUTH_KEY
- Dedicated Splunk tools plus a full-coverage generic API tool

## What This Repository Implements

This repository is the Splunk-specific implementation of the original skeleton architecture.
It is not a generic template.

Key guarantees:
- User tokens are multi-user and user-scoped in Vault.
- Secret material is never stored in Postgres.
- Splunk environment configuration is persisted per user in Postgres.
- Mutating operations are authorization-key gated when MCP_ADMIN_AUTH_KEY is configured.

## Architecture

Runtime components:
- src/index.js: starts stdio MCP transport
- src/http/index.js: starts HTTP MCP transport
- src/mcp/server.js: MCP tool registry and policy enforcement
- src/services/splunkService.js: Splunk REST HTTP client
- src/services/vault.js: Vault read/write and retry queue
- src/services/configStore.js: Postgres config store
- src/http/server.js: HTTP MCP server with token/OAuth2 auth and rate limiting
- src/http/vaultTokenAuth.js: Vault-backed bearer token verifier
- src/http/oauth2.js: OAuth2 introspection verifier
- src/data/splunk-api-catalog.json: extracted Splunk 10.4 endpoint catalog

Persistence model:
- Vault stores:
  - Splunk auth secrets per app/user/environment
  - MCP HTTP token index per app/user
- Postgres stores:
  - Non-secret environment config per app/user
  - Runtime knobs and defaults

## Multi-User Scope Model

Scope is app + user.

- Postgres table: <app>_config
- Postgres primary key: (user_id, key)
- Vault token index path: <app>/users/<user>/http/auth/token-index
- Vault Splunk auth secret path (default):
  - <app>/users/<user>/splunk/environments/<environment>/auth

User fallback behavior:
- Config reads can fall back to default user when user-scoped key is missing.
- Token index operations are always explicitly user-scoped.

## Splunk API Coverage

Coverage approach:
- MCP-native query suggestion and schema discovery via mcp_tool_discovery
- Dedicated tools for common operations (health, context, search jobs, saved searches, indexes, users)
- Generic splunk_api_request for full path/method coverage
- Bundled endpoint catalog derived from Splunk Enterprise REST API Reference 10.4

Catalog size in this repository:
- 427 endpoint path patterns in src/data/splunk-api-catalog.json
- Human-readable grouped report in docs/splunk-api-catalog.md

## Environment Variables

See .env.example for complete settings.

Core variables:
- APP_NAME
- MCP_SERVER_NAME
- MCP_ADMIN_AUTH_KEY
- MCP_TRANSPORT_MODE

Splunk defaults:
- SPLUNK_DEFAULT_ENVIRONMENT
- SPLUNK_BASE_URL
- SPLUNK_AUTH_MODE
- SPLUNK_NAMESPACE_OWNER
- SPLUNK_NAMESPACE_APP
- SPLUNK_ENVIRONMENT_CONFIG_PREFIX

Persistence:
- POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
- VAULT_ADDR, VAULT_TOKEN, VAULT_KV_MOUNT

HTTP auth:
- MCP_HTTP_AUTH_MODE: token | oauth2 | both
- MCP_HTTP_TOKEN_SOURCE: static | vault | both
- MCP_HTTP_AUTH_TOKENS
- MCP_HTTP_VAULT_TOKEN_INDEX_PATH
- MCP_HTTP_OAUTH2_INTROSPECTION_URL

## Run Locally

1) Install dependencies

npm ci

2) Start local Postgres + Vault + HTTP MCP

docker compose up -d

3) Start stdio MCP server

npm run start:stdio

4) Start HTTP MCP server

npm run start:http

Health endpoint (HTTP mode):
- GET http://127.0.0.1:3000/healthz

## Tool Catalog

All tools return JSON text in MCP content format.
Success shape:
- { ok: true, status: 200, data: ... }

Error shape:
- { ok: false, status: <http-like-code>, error: "..." }

Mutating tools require authorizationKey when MCP_ADMIN_AUTH_KEY is set.

### mcp_tool_discovery
- When to use: discover all MCP tools, query recommendations, and parameter schema hints.
- Do not use: if you already know the exact tool and parameters to call.
- Risk: read-only, low.
- Parameters:
  - toolName (optional substring filter)
  - intent (optional intent filter, such as query-suggestion, search, environment, token-management)
  - includeSchemas (optional boolean, default true)
  - includeExamples (optional boolean, default true)
- Response: tool metadata with use/don't-use guidance, prerequisites/follow-ups, suggested queries, and schema hints.
- Example:
  - {"name":"mcp_tool_discovery","arguments":{"intent":"query-suggestion"}}
  - {"name":"mcp_tool_discovery","arguments":{"intent":"search","includeSchemas":true}}

### splunk_connection_info
- When to use: inspect runtime, default scope, and catalog stats.
- Do not use: for live Splunk data.
- Risk: read-only, low.
- Prerequisites: none.
- Response: server metadata + Splunk defaults + endpoint catalog counts.
- Example:
  - {"name":"splunk_connection_info","arguments":{}}

### splunk_scope_info
- When to use: confirm app/user scope mapping for Vault/Postgres.
- Do not use: for Splunk endpoint calls.
- Risk: read-only, low.
- Prerequisites: none.
- Response: normalized scope model.
- Example:
  - {"name":"splunk_scope_info","arguments":{"userId":"analyst-a"}}

### splunk_list_endpoints
- When to use: discover Splunk path patterns before generic calls.
- Do not use: for endpoint liveness.
- Risk: read-only, low.
- Prerequisites: none.
- Parameters: category, prefix, limit (1-500), offset (>=0).
- Response: paginated endpoint list from bundled catalog.
- Example:
  - {"name":"splunk_list_endpoints","arguments":{"prefix":"/services/search"}}

### splunk_environment_get
- When to use: fetch resolved user/environment config.
- Do not use: to read secrets.
- Risk: read-only, low.
- Prerequisites: splunk_scope_info.
- Response: baseUrl/authMode/namespace/authSecretPath.
- Example:
  - {"name":"splunk_environment_get","arguments":{"environment":"prod"}}

### splunk_environment_set
- When to use: persist non-secret environment settings in Postgres.
- Do not use: to store tokens/passwords.
- Risk: mutating, medium.
- Permissions: authorizationKey may be required.
- Failure conditions: invalid auth key, Postgres errors.
- Follow-up: splunk_auth_secret_set.
- Example:
  - {"name":"splunk_environment_set","arguments":{"environment":"prod","baseUrl":"https://splunk.example.com:8089","authMode":"splunk","authorizationKey":"<key>"}}

### splunk_auth_secret_set
- When to use: write or rotate Splunk credentials in Vault.
- Do not use: for non-secret config.
- Risk: mutating, high.
- Permissions: authorizationKey may be required.
- Parameter constraints: provide at least one credential field.
- Failure conditions: missing credentials, Vault errors.
- Follow-up: splunk_health_check.
- Example:
  - {"name":"splunk_auth_secret_set","arguments":{"environment":"prod","sessionKey":"<session-key>","authorizationKey":"<key>"}}

### splunk_auth_secret_metadata
- When to use: confirm secret existence/shape without exposing values.
- Do not use: to rotate credentials.
- Risk: read-only, medium.
- Response: path + field names + redacted secret.
- Example:
  - {"name":"splunk_auth_secret_metadata","arguments":{"environment":"prod"}}

### mcp_token_upsert
- When to use: create/update user-scoped MCP bearer token metadata.
- Do not use: when only listing tokens.
- Risk: mutating, high.
- Permissions: authorizationKey may be required.
- Prerequisites: token consumers should already trust Vault token index source.
- Response: token hash + user + index path.
- Example:
  - {"name":"mcp_token_upsert","arguments":{"targetUserId":"default","token":"<opaque-token>","authorizationKey":"<key>"}}

### mcp_token_list
- When to use: inspect per-user token metadata inventory.
- Do not use: token creation or deactivation.
- Risk: read-only, medium.
- Response: token hashes + redacted metadata.
- Example:
  - {"name":"mcp_token_list","arguments":{"targetUserId":"default"}}

### mcp_token_deactivate
- When to use: disable one token by tokenHash or token value.
- Do not use: for rotation to new value.
- Risk: mutating, high.
- Permissions: authorizationKey may be required.
- Safety warning: can immediately block HTTP MCP clients.
- Example:
  - {"name":"mcp_token_deactivate","arguments":{"targetUserId":"default","tokenHash":"<sha256>","authorizationKey":"<key>"}}

### splunk_health_check
- When to use: verify authenticated connectivity via /services/server/info.
- Do not use: deep subsystem diagnostics.
- Risk: read-only, low.
- Response: scope + upstream response payload.
- Example:
  - {"name":"splunk_health_check","arguments":{"environment":"prod"}}

### splunk_search_job_create
- When to use: dispatch a Splunk search job.
- Do not use: static metadata retrieval.
- Risk: mutating, medium.
- Permissions: authorizationKey may be required and Splunk role must allow dispatch.
- Follow-up: splunk_search_job_status, splunk_search_job_results.
- Example:
  - {"name":"splunk_search_job_create","arguments":{"search":"search index=_internal | head 10","authorizationKey":"<key>"}}

### splunk_search_job_status
- When to use: inspect status for a search SID.
- Do not use: to retrieve result rows.
- Risk: read-only, low.
- Example:
  - {"name":"splunk_search_job_status","arguments":{"sid":"<sid>"}}

### splunk_search_job_results
- When to use: fetch rows from search SID results endpoint.
- Do not use: to cancel jobs.
- Risk: read-only, medium.
- Parameter constraints: count 1..10000, offset >=0.
- Example:
  - {"name":"splunk_search_job_results","arguments":{"sid":"<sid>","count":100}}

### splunk_search_job_cancel
- When to use: cancel a running search job.
- Do not use: when job has already completed.
- Risk: mutating, high.
- Safety warning: destructive operation on in-flight job execution.
- Example:
  - {"name":"splunk_search_job_cancel","arguments":{"sid":"<sid>","authorizationKey":"<key>"}}

### splunk_saved_searches_list
- When to use: list saved searches in namespace.
- Do not use: ad-hoc search dispatch.
- Risk: read-only, low.
- Parameters: owner/app optional, count/offset optional.
- Example:
  - {"name":"splunk_saved_searches_list","arguments":{"owner":"-","app":"search"}}

### splunk_indexes_list
- When to use: list Splunk indexes.
- Do not use: search execution.
- Risk: read-only, low.
- Example:
  - {"name":"splunk_indexes_list","arguments":{}}

### splunk_users_list
- When to use: list Splunk user accounts.
- Do not use: token-index operations.
- Risk: read-only, medium.
- Example:
  - {"name":"splunk_users_list","arguments":{}}

### splunk_api_request
- When to use: invoke any Splunk REST path for full coverage.
- Do not use: if a dedicated tool already fits.
- Risk: mixed, high for mutating paths.
- Permissions: authorizationKey required for mutating methods when admin key is set.
- Parameter constraints:
  - path must start with /services or /servicesNS
  - bodyFormat: json | form | raw
- Common failures: invalid path, auth failure, upstream 4xx/5xx.
- Safety warnings: destructive operations may impact cluster state/data.
- Example:
  - {"name":"splunk_api_request","arguments":{"method":"GET","path":"/services/server/info","query":{"output_mode":"json"}}}

## Security Notes

- Keep MCP_ALLOW_SENSITIVE_OUTPUT=false in production.
- Use MCP_ADMIN_AUTH_KEY for all mutating operations.
- Prefer Vault token source for HTTP auth validation.
- Store only secret references in Postgres.
- Rotate Vault and Splunk credentials regularly.

## Testing

Run all tests:

npm test

Current suite includes:
- MCP tool integration tests
- HTTP auth and transport tests
- Vault token index behavior tests
- Vault production script tests
- Agent/runtime configuration tests

## Git and Publishing

This repository is intended to be pushed as:
- https://github.com/LesterAJohn/splunk-mcp

Do not push changes to:
- https://github.com/LesterAJohn/skeleton-mcp

