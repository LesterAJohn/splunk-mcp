# Splunk MCP Maintenance Playbook

Use this checklist when extending splunk-mcp.

## 1. Capability Definition

- Define whether the request is read-only, mutating, or high-risk.
- Define required Splunk endpoint path(s) and auth expectations.
- Define whether a dedicated tool is needed or splunk_api_request is sufficient.

## 2. Security and Scope

- Keep multi-user scope as app + user.
- Keep secrets in Vault only.
- Keep non-secret config in Postgres only.
- Keep mutating tools behind authorizationKey when MCP_ADMIN_AUTH_KEY is set.

## 3. Implementation

- Update env parsing in src/config/env.js when new config is introduced.
- Update src/services/splunkService.js for client-level behavior.
- Register/refine tools in src/mcp/server.js with explicit tool metadata.
- Wire runtime dependencies in src/index.js and src/http/index.js.

## 4. HTTP Auth

- Preserve token/oauth2/both auth modes.
- Preserve Vault token verifier compatibility.
- Preserve rate limits, body limits, and auth failure behavior.

## 5. Persistence

- Vault paths must remain user-scoped.
- Postgres config keys must remain user-scoped with default-user fallback where intended.
- Keep App-only external deployment mode documentation for external Vault and Postgres services.

## 6. Validation

- Add tests under tests/ for happy path + auth failures + edge cases.
- Run npm test and resolve regressions.
- Update README.md and changelog in the same change.
