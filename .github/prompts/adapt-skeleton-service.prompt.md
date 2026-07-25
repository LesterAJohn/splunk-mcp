---
mode: agent
tools: ["codebase", "editFiles", "search", "testFailure"]
description: "Implement Splunk MCP feature changes in this repository with tests and documentation updates."
---

Use the Splunk MCP Maintainer agent for repository updates.

Capture this request spec:
- Feature summary
- Read-only or mutating
- Splunk endpoint paths and methods
- User-scope and persistence implications
- Security/auth implications
- Expected response shape
- Tests required

Execution requirements:
1. Keep multi-user behavior.
2. Keep secrets in Vault and configuration in Postgres.
3. Keep mutating tools guarded by authorizationKey when MCP_ADMIN_AUTH_KEY is set.
4. Preserve HTTP auth/rate/body safeguards.
5. Update README.md and CHANGELOG.md.
6. Run npm test.
7. Summarize changed files and verification results.

If the request introduces new external service assumptions, ensure docs still include the App-only external deployment mode for external Vault and Postgres services.
