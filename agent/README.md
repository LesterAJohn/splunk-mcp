# Agent Structure

This directory stores implementation playbooks for maintaining splunk-mcp.

## Contents

- playbooks/service-onboarding.md: Splunk MCP maintenance and extension checklist.
- templates/service-spec.md: Structured input for proposing additional Splunk tool capabilities.
- .github/prompts/adapt-skeleton-service.prompt.md: Prompt workflow for repository updates.

## Usage Focus

Use these assets when you need to:
- Add or refine Splunk REST tools.
- Preserve multi-user scope behavior.
- Preserve Vault-secret and Postgres-config persistence boundaries.
- Maintain App-only external deployment mode for external Vault and Postgres services.
- Keep tests and docs aligned with runtime behavior.
