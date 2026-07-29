# Changelog

## Unreleased

- Migrated repository identity from skeleton-mcp to splunk-mcp.
- Implemented Splunk Enterprise REST API MCP tooling with dedicated operations and a generic full-coverage request tool.
- Added bundled Splunk 10.4 endpoint catalog in src/data/splunk-api-catalog.json.
- Enforced multi-user token-index operations in Vault paths scoped by app/user.
- Kept secrets persistent in Vault and configuration persistent in Postgres.
- Added MCP tools for token upsert/list/deactivate and admin-key support for mutating tools.
- Rewrote solution documentation for Splunk-specific operations.
- Added/updated integration tests for Splunk tool behavior and HTTP transport auth.
- Added Splunk SOAR (Phantom) support with product-aware request validation (`/rest`), `phantom` auth mode (`ph-auth-token`), and a dedicated `splunk_soar_api_request` tool.
- Added dedicated SOAR convenience tools: `splunk_soar_container_get`, `splunk_soar_container_create`, and `splunk_soar_artifact_create`.
- Added `splunk_soar_container_find_by_source` for source_data_identifier dedupe lookups before container creation.
