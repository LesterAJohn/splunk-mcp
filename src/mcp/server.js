import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import endpointCatalog from "../data/splunk-api-catalog.json" with { type: "json" };
import {
  createVaultTokenEntry,
  getVaultUserTokenIndexPath,
  mergeVaultTokenIndex,
  normalizeAppName,
  normalizeUserIdForPath,
  sha256Hex
} from "../config/vaultAuthTokenIndex.js";
import { redactObject } from "../services/security.js";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const HIGH_RISK_PATH_HINTS = ["/delete", "/remove", "/disable", "/revoke", "/decommission", "/maintenance"];
const SPLUNK_PRODUCTS = new Set(["enterprise", "soar"]);
const SPLUNK_AUTH_MODES = ["splunk", "bearer", "basic", "phantom", "none"];

const TOOL_DISCOVERY_CATALOG = [
  {
    name: "splunk_connection_info",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["onboarding", "connection", "discovery", "query-suggestion"],
    whenToUse: "Inspect runtime defaults, scope model, and endpoint catalog counts.",
    doNotUse: "You need live data from a Splunk endpoint.",
    prerequisites: [],
    followUps: ["splunk_scope_info", "splunk_environment_get"],
    recommendedQueries: ["Show MCP and Splunk runtime defaults", "What environment and scope defaults are active?"],
    schema: { required: [], properties: {} },
    examples: [{ name: "splunk_connection_info", arguments: {} }]
  },
  {
    name: "splunk_scope_info",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["onboarding", "scope", "tenanting", "query-suggestion"],
    whenToUse: "Validate app/user scoping across Postgres and Vault paths.",
    doNotUse: "You need a Splunk API response.",
    prerequisites: [],
    followUps: ["splunk_environment_get"],
    recommendedQueries: ["Show scope model for user analyst-a"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1, description: "Optional target user id." }
      }
    },
    examples: [{ name: "splunk_scope_info", arguments: { userId: "analyst-a" } }]
  },
  {
    name: "splunk_list_endpoints",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["discovery", "api-exploration", "schema", "query-suggestion"],
    whenToUse: "Discover candidate Splunk REST paths before invoking generic API calls.",
    doNotUse: "You already know the exact path and need execution.",
    prerequisites: ["splunk_connection_info"],
    followUps: ["splunk_api_request"],
    recommendedQueries: ["List search-related endpoints", "Show endpoints under /services/search"],
    schema: {
      required: [],
      properties: {
        category: { type: "string", minLength: 1 },
        prefix: { type: "string", minLength: 1 },
        limit: { type: "integer", minimum: 1, maximum: 500, default: 100 },
        offset: { type: "integer", minimum: 0, default: 0 }
      }
    },
    examples: [{ name: "splunk_list_endpoints", arguments: { prefix: "/services/search" } }]
  },
  {
    name: "splunk_environment_get",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["environment", "configuration", "connection", "query-suggestion"],
    whenToUse: "Resolve effective Splunk config for user/environment including auth secret path.",
    doNotUse: "You need to read secret values.",
    prerequisites: ["splunk_scope_info"],
    followUps: ["splunk_auth_secret_set", "splunk_health_check"],
    recommendedQueries: ["Get prod environment config", "What auth mode is configured for default user?"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "splunk_environment_get", arguments: { environment: "prod" } }]
  },
  {
    name: "splunk_environment_set",
    category: "mutating",
    risk: "medium",
    mutating: true,
    intents: ["environment", "configuration", "setup", "query-suggestion"],
    whenToUse: "Persist non-secret Splunk environment settings for a user in Postgres.",
    doNotUse: "You need to persist credentials or tokens.",
    prerequisites: ["splunk_environment_get"],
    followUps: ["splunk_auth_secret_set"],
    recommendedQueries: ["Set prod base URL and auth mode", "Update namespace defaults for search app"],
    schema: {
      required: ["environment"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        product: { type: "string", enum: ["enterprise", "soar"] },
        baseUrl: { type: "string", format: "uri" },
        authMode: { type: "string", enum: ["splunk", "bearer", "basic", "phantom", "none"] },
        namespaceOwner: { type: "string", minLength: 1 },
        namespaceApp: { type: "string", minLength: 1 },
        authSecretPath: { type: "string", minLength: 1 },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [
      {
        name: "splunk_environment_set",
        arguments: { environment: "prod", baseUrl: "https://splunk.example.com:8089", authMode: "splunk" }
      }
    ]
  },
  {
    name: "splunk_auth_secret_set",
    category: "mutating",
    risk: "high",
    mutating: true,
    intents: ["credentials", "security", "rotation", "query-suggestion"],
    whenToUse: "Create or rotate Splunk auth credentials in Vault.",
    doNotUse: "You only need non-secret environment config.",
    prerequisites: ["splunk_environment_get"],
    followUps: ["splunk_health_check", "splunk_auth_secret_metadata"],
    recommendedQueries: ["Rotate prod session key", "Set bearer token secret for dev"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        path: { type: "string", minLength: 1 },
        authMode: { type: "string", enum: ["splunk", "bearer", "basic", "phantom", "none"] },
        token: { type: "string", minLength: 1, sensitive: true },
        phAuthToken: { type: "string", minLength: 1, sensitive: true },
        sessionKey: { type: "string", minLength: 1, sensitive: true },
        username: { type: "string", minLength: 1, sensitive: true },
        password: { type: "string", sensitive: true },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      },
      constraints: ["At least one credential field is required: token | sessionKey | username | password"]
    },
    examples: [{ name: "splunk_auth_secret_set", arguments: { environment: "prod", sessionKey: "<session-key>" } }]
  },
  {
    name: "splunk_auth_secret_metadata",
    category: "read-only",
    risk: "medium",
    mutating: false,
    intents: ["credentials", "security", "verification", "query-suggestion"],
    whenToUse: "Check secret existence and fields without exposing plaintext values.",
    doNotUse: "You need to update credentials.",
    prerequisites: ["splunk_environment_get"],
    followUps: ["splunk_auth_secret_set", "splunk_health_check"],
    recommendedQueries: ["Verify prod auth secret exists", "Show auth secret metadata fields"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        path: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "splunk_auth_secret_metadata", arguments: { environment: "prod" } }]
  },
  {
    name: "mcp_token_upsert",
    category: "mutating",
    risk: "high",
    mutating: true,
    intents: ["http-auth", "token-management", "security", "query-suggestion"],
    whenToUse: "Create or update per-user bearer token index entries for HTTP MCP auth.",
    doNotUse: "You only need read-only token inventory.",
    prerequisites: ["splunk_scope_info"],
    followUps: ["mcp_token_list", "mcp_token_deactivate"],
    recommendedQueries: ["Add bearer token for analyst-a", "Rotate token metadata for default user"],
    schema: {
      required: ["token"],
      properties: {
        targetUserId: { type: "string", minLength: 1 },
        token: { type: "string", minLength: 1, sensitive: true },
        tokenId: { type: "string", minLength: 1 },
        scopes: { oneOf: [{ type: "string", minLength: 1 }, { type: "array", items: { type: "string", minLength: 1 } }] },
        audience: { oneOf: [{ type: "string", minLength: 1 }, { type: "array", items: { type: "string", minLength: 1 } }] },
        expiresAt: { type: "string", description: "Unix epoch seconds or ISO timestamp." },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [{ name: "mcp_token_upsert", arguments: { targetUserId: "default", token: "<opaque-token>" } }]
  },
  {
    name: "mcp_token_list",
    category: "read-only",
    risk: "medium",
    mutating: false,
    intents: ["http-auth", "token-management", "security", "query-suggestion"],
    whenToUse: "List per-user token metadata from Vault token index.",
    doNotUse: "You need to create or deactivate a token.",
    prerequisites: ["splunk_scope_info"],
    followUps: ["mcp_token_upsert", "mcp_token_deactivate"],
    recommendedQueries: ["List token hashes for analyst-a", "Show HTTP token inventory"],
    schema: {
      required: [],
      properties: {
        targetUserId: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "mcp_token_list", arguments: { targetUserId: "default" } }]
  },
  {
    name: "mcp_token_deactivate",
    category: "mutating",
    risk: "high",
    mutating: true,
    intents: ["http-auth", "token-management", "security", "query-suggestion"],
    whenToUse: "Disable a token entry by hash or plaintext token value.",
    doNotUse: "You want to rotate to a new token in the same step.",
    prerequisites: ["mcp_token_list"],
    followUps: ["mcp_token_upsert"],
    recommendedQueries: ["Deactivate compromised token hash", "Disable token for default user"],
    schema: {
      required: [],
      properties: {
        targetUserId: { type: "string", minLength: 1 },
        tokenHash: { type: "string", minLength: 1 },
        token: { type: "string", minLength: 1, sensitive: true },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      },
      constraints: ["Provide either tokenHash or token."]
    },
    examples: [{ name: "mcp_token_deactivate", arguments: { tokenHash: "<sha256>", targetUserId: "default" } }]
  },
  {
    name: "splunk_health_check",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["connection", "verification", "health", "query-suggestion"],
    whenToUse: "Validate authenticated connectivity for the configured product (Enterprise or SOAR).",
    doNotUse: "You need deep diagnostics or custom endpoint data.",
    prerequisites: ["splunk_environment_get", "splunk_auth_secret_set"],
    followUps: ["splunk_search_job_create", "splunk_api_request"],
    recommendedQueries: ["Run connectivity check for prod"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "splunk_health_check", arguments: { environment: "prod" } }]
  },
  {
    name: "splunk_search_job_create",
    category: "mutating",
    risk: "medium",
    mutating: true,
    intents: ["search", "analytics", "jobs", "query-suggestion"],
    whenToUse: "Dispatch a search job to Splunk.",
    doNotUse: "You only need endpoint metadata or saved-search inventory.",
    prerequisites: ["splunk_health_check"],
    followUps: ["splunk_search_job_status", "splunk_search_job_results", "splunk_search_job_cancel"],
    recommendedQueries: ["Create search job for _internal logs", "Dispatch ad-hoc SPL query"],
    schema: {
      required: ["search"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        search: { type: "string", minLength: 1 },
        exec_mode: { type: "string", minLength: 1 },
        earliest_time: { type: "string", minLength: 1 },
        latest_time: { type: "string", minLength: 1 },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [{ name: "splunk_search_job_create", arguments: { search: "search index=_internal | head 10" } }]
  },
  {
    name: "splunk_search_job_status",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["search", "analytics", "jobs", "query-suggestion"],
    whenToUse: "Poll or inspect status for a SID returned by search job creation.",
    doNotUse: "You need result rows.",
    prerequisites: ["splunk_search_job_create"],
    followUps: ["splunk_search_job_results", "splunk_search_job_cancel"],
    recommendedQueries: ["Check status for SID"],
    schema: {
      required: ["sid"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        sid: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "splunk_search_job_status", arguments: { sid: "<sid>" } }]
  },
  {
    name: "splunk_search_job_results",
    category: "read-only",
    risk: "medium",
    mutating: false,
    intents: ["search", "analytics", "jobs", "query-suggestion"],
    whenToUse: "Retrieve paginated result rows for a completed or running SID.",
    doNotUse: "You need to cancel a job.",
    prerequisites: ["splunk_search_job_create"],
    followUps: ["splunk_search_job_cancel"],
    recommendedQueries: ["Fetch top 100 rows for SID", "Paginate search results"],
    schema: {
      required: ["sid"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        sid: { type: "string", minLength: 1 },
        count: { type: "integer", minimum: 1, maximum: 10000 },
        offset: { type: "integer", minimum: 0 }
      }
    },
    examples: [{ name: "splunk_search_job_results", arguments: { sid: "<sid>", count: 100 } }]
  },
  {
    name: "splunk_search_job_cancel",
    category: "mutating",
    risk: "high",
    mutating: true,
    intents: ["search", "analytics", "jobs", "query-suggestion"],
    whenToUse: "Cancel an in-flight search job.",
    doNotUse: "The job already completed and results are available.",
    prerequisites: ["splunk_search_job_status"],
    followUps: [],
    recommendedQueries: ["Cancel SID <sid>"],
    schema: {
      required: ["sid"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        sid: { type: "string", minLength: 1 },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [{ name: "splunk_search_job_cancel", arguments: { sid: "<sid>" } }]
  },
  {
    name: "splunk_saved_searches_list",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["search", "metadata", "saved-searches", "query-suggestion"],
    whenToUse: "List saved searches for a namespace.",
    doNotUse: "You need ad-hoc search execution.",
    prerequisites: ["splunk_health_check"],
    followUps: ["splunk_search_job_create", "splunk_api_request"],
    recommendedQueries: ["List saved searches for app search", "Enumerate saved searches in namespace"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        owner: { type: "string", minLength: 1 },
        app: { type: "string", minLength: 1 },
        count: { type: "integer", minimum: 1, maximum: 5000 },
        offset: { type: "integer", minimum: 0 }
      }
    },
    examples: [{ name: "splunk_saved_searches_list", arguments: { owner: "-", app: "search" } }]
  },
  {
    name: "splunk_indexes_list",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["metadata", "indexes", "inventory", "query-suggestion"],
    whenToUse: "List available Splunk indexes.",
    doNotUse: "You need user accounts or search jobs.",
    prerequisites: ["splunk_health_check"],
    followUps: ["splunk_search_job_create"],
    recommendedQueries: ["List all indexes"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "splunk_indexes_list", arguments: {} }]
  },
  {
    name: "splunk_users_list",
    category: "read-only",
    risk: "medium",
    mutating: false,
    intents: ["metadata", "users", "inventory", "query-suggestion"],
    whenToUse: "List Splunk user accounts.",
    doNotUse: "You need token index operations.",
    prerequisites: ["splunk_health_check"],
    followUps: ["splunk_api_request"],
    recommendedQueries: ["List Splunk users"],
    schema: {
      required: [],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 }
      }
    },
    examples: [{ name: "splunk_users_list", arguments: {} }]
  },
  {
    name: "splunk_api_request",
    category: "read-write",
    risk: "high",
    mutating: true,
    intents: ["generic", "advanced", "fallback", "query-suggestion"],
    whenToUse: "Invoke arbitrary Splunk Enterprise REST paths when no dedicated tool exists.",
    doNotUse: "A dedicated tool already fits your task.",
    prerequisites: ["splunk_list_endpoints", "splunk_environment_get", "splunk_auth_secret_set"],
    followUps: ["splunk_search_job_status", "splunk_search_job_results"],
    recommendedQueries: ["Call server info endpoint", "Run custom GET against /servicesNS path"],
    schema: {
      required: ["method", "path"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        product: { type: "string", enum: ["enterprise", "soar"], description: "Overrides environment product for this request." },
        method: { type: "string", minLength: 1 },
        path: {
          type: "string",
          minLength: 1,
          description: "Enterprise: /services or /servicesNS. SOAR: /rest."
        },
        query: { type: "object", additionalProperties: true },
        body: { type: "any" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        bodyFormat: { type: "string", enum: ["json", "form", "raw"] },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [
      {
        name: "splunk_api_request",
        arguments: { method: "GET", path: "/services/server/info", query: { output_mode: "json" } }
      }
    ]
  },
  {
    name: "splunk_soar_api_request",
    category: "read-write",
    risk: "high",
    mutating: true,
    intents: ["soar", "phantom", "generic", "advanced", "query-suggestion"],
    whenToUse: "Invoke Splunk SOAR (Phantom) REST paths such as /rest/container and /rest/artifact.",
    doNotUse: "You need Splunk Enterprise /services endpoints.",
    prerequisites: ["splunk_environment_set", "splunk_auth_secret_set"],
    followUps: ["splunk_auth_secret_metadata"],
    recommendedQueries: ["Get one container", "Create a container with run_automation=false"],
    schema: {
      required: ["method", "path"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        method: { type: "string", minLength: 1 },
        path: { type: "string", minLength: 1, description: "Must start with /rest." },
        query: { type: "object", additionalProperties: true },
        body: { type: "any" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        bodyFormat: { type: "string", enum: ["json", "form", "raw"] },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [
      {
        name: "splunk_soar_api_request",
        arguments: { method: "GET", path: "/rest/container/1" }
      }
    ]
  },
  {
    name: "splunk_soar_container_get",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["soar", "phantom", "containers", "query-suggestion"],
    whenToUse: "Retrieve one SOAR/Phantom container by id.",
    doNotUse: "You need to create or update records.",
    prerequisites: ["splunk_environment_set", "splunk_auth_secret_set"],
    followUps: ["splunk_soar_artifact_create"],
    recommendedQueries: ["Get container 12345", "Inspect incident container details"],
    schema: {
      required: ["containerId"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        containerId: { oneOf: [{ type: "integer", minimum: 1 }, { type: "string", minLength: 1 }] }
      }
    },
    examples: [{ name: "splunk_soar_container_get", arguments: { containerId: 1 } }]
  },
  {
    name: "splunk_soar_container_find_by_source",
    category: "read-only",
    risk: "low",
    mutating: false,
    intents: ["soar", "phantom", "containers", "dedupe", "query-suggestion"],
    whenToUse: "Find existing SOAR/Phantom containers by source_data_identifier for deduplication workflows.",
    doNotUse: "You already know the exact container id.",
    prerequisites: ["splunk_environment_set", "splunk_auth_secret_set"],
    followUps: ["splunk_soar_container_get", "splunk_soar_artifact_create"],
    recommendedQueries: ["Find incident by source_data_identifier", "Check if indicator id already exists"],
    schema: {
      required: ["sourceDataIdentifier"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        sourceDataIdentifier: { type: "string", minLength: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 200 },
        page: { type: "integer", minimum: 0 }
      }
    },
    examples: [
      {
        name: "splunk_soar_container_find_by_source",
        arguments: { sourceDataIdentifier: "12387", pageSize: 1 }
      }
    ]
  },
  {
    name: "splunk_soar_container_create",
    category: "mutating",
    risk: "high",
    mutating: true,
    intents: ["soar", "phantom", "containers", "ingest", "query-suggestion"],
    whenToUse: "Create a SOAR/Phantom container (incident).",
    doNotUse: "You only need to read existing records.",
    prerequisites: ["splunk_environment_set", "splunk_auth_secret_set"],
    followUps: ["splunk_soar_artifact_create", "splunk_soar_container_get"],
    recommendedQueries: ["Create a container for suspicious login", "Create container with run_automation false"],
    schema: {
      required: ["name", "label"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        name: { type: "string", minLength: 1 },
        label: { type: "string", minLength: 1 },
        description: { type: "string" },
        severity: { type: "string", enum: ["low", "medium", "high"] },
        sensitivity: { type: "string", enum: ["white", "green", "amber", "red"] },
        sourceDataIdentifier: { type: "string", minLength: 1 },
        runAutomation: { type: "boolean" },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [
      {
        name: "splunk_soar_container_create",
        arguments: { name: "new container", label: "events", description: "Created from MCP" }
      }
    ]
  },
  {
    name: "splunk_soar_artifact_create",
    category: "mutating",
    risk: "high",
    mutating: true,
    intents: ["soar", "phantom", "artifacts", "ingest", "query-suggestion"],
    whenToUse: "Create a SOAR/Phantom artifact linked to a container.",
    doNotUse: "You need to create a container first.",
    prerequisites: ["splunk_soar_container_create"],
    followUps: ["splunk_soar_container_get"],
    recommendedQueries: ["Attach IOC artifact to container", "Add CEF/data artifact fields"],
    schema: {
      required: ["containerId", "label"],
      properties: {
        userId: { type: "string", minLength: 1 },
        environment: { type: "string", minLength: 1 },
        containerId: { oneOf: [{ type: "integer", minimum: 1 }, { type: "string", minLength: 1 }] },
        label: { type: "string", minLength: 1 },
        name: { type: "string", minLength: 1 },
        sourceDataIdentifier: { type: "string", minLength: 1 },
        severity: { type: "string", enum: ["low", "medium", "high"] },
        runAutomation: { type: "boolean" },
        cef: { type: "object", additionalProperties: true },
        data: { type: "object", additionalProperties: true },
        authorizationKey: { type: "string", minLength: 1, sensitive: true }
      }
    },
    examples: [
      {
        name: "splunk_soar_artifact_create",
        arguments: { containerId: 1, label: "event", cef: { sourceAddress: "1.2.3.4" } }
      }
    ]
  }
];

function normalizeMethod(method) {
  return String(method ?? "GET").trim().toUpperCase();
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/";
  }

  return raw.startsWith("/") ? raw : `/${raw}`;
}

function normalizeSplunkProduct(product) {
  const normalized = String(product ?? "enterprise").trim().toLowerCase() || "enterprise";
  if (!SPLUNK_PRODUCTS.has(normalized)) {
    const error = new Error(`Invalid Splunk product: ${product}`);
    error.status = 400;
    throw error;
  }
  return normalized;
}

function toolSpecDescription({
  purpose,
  doNotUse,
  category,
  risk,
  permissions,
  envBehavior,
  params,
  responseShape,
  failures,
  prerequisites,
  followUps,
  warnings,
  examples
}) {
  return [
    `Use when: ${purpose}`,
    `Do not use when: ${doNotUse}`,
    `Category: ${category}`,
    `Risk: ${risk}`,
    `Required permissions and prerequisites: ${permissions}`,
    `Environment-selection behavior: ${envBehavior}`,
    `Parameter formats and constraints: ${params}`,
    `Expected response shape: ${responseShape}`,
    `Common failure conditions: ${failures}`,
    `Recommended prerequisite tools: ${prerequisites}`,
    `Recommended follow-up tools: ${followUps}`,
    `Safety warnings for destructive operations: ${warnings}`,
    `Short valid invocation examples: ${examples}`
  ].join("\n");
}

function parseOptionalExpiresAt(value) {
  const raw = String(value ?? "").trim();
  if (!raw) {
    return "";
  }

  if (/^\d+$/.test(raw)) {
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) {
      throw new Error(`Invalid expiresAt value: ${raw}`);
    }
    return new Date(parsed * 1000).toISOString();
  }

  const parsed = Date.parse(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid expiresAt value: ${raw}`);
  }

  return new Date(parsed).toISOString();
}

function isHighRiskSplunkPath(path) {
  const normalized = normalizePath(path).toLowerCase();
  return HIGH_RISK_PATH_HINTS.some((hint) => normalized.includes(hint));
}

function buildToolDiscoveryResponse({ toolName, intent, includeSchemas = true, includeExamples = true } = {}) {
  const normalizedToolName = String(toolName ?? "").trim().toLowerCase();
  const normalizedIntent = String(intent ?? "").trim().toLowerCase();

  let tools = TOOL_DISCOVERY_CATALOG;

  if (normalizedToolName) {
    tools = tools.filter((entry) => String(entry.name).toLowerCase().includes(normalizedToolName));
  }

  if (normalizedIntent) {
    tools = tools.filter((entry) =>
      Array.isArray(entry.intents) && entry.intents.some((label) => String(label).toLowerCase().includes(normalizedIntent))
    );
  }

  const byIntent = TOOL_DISCOVERY_CATALOG.reduce((acc, entry) => {
    for (const label of entry.intents ?? []) {
      acc[label] = (acc[label] ?? 0) + 1;
    }
    return acc;
  }, {});

  const normalizedTools = tools.map((entry) => ({
    name: entry.name,
    category: entry.category,
    risk: entry.risk,
    mutating: entry.mutating,
    intents: entry.intents,
    whenToUse: entry.whenToUse,
    doNotUse: entry.doNotUse,
    prerequisites: entry.prerequisites,
    followUps: entry.followUps,
    recommendedQueries: entry.recommendedQueries,
    ...(includeSchemas ? { schema: entry.schema } : {}),
    ...(includeExamples ? { examples: entry.examples } : {})
  }));

  return {
    ok: true,
    status: 200,
    data: {
      totalTools: TOOL_DISCOVERY_CATALOG.length,
      returnedTools: normalizedTools.length,
      filters: {
        toolName: normalizedToolName || null,
        intent: normalizedIntent || null,
        includeSchemas: Boolean(includeSchemas),
        includeExamples: Boolean(includeExamples)
      },
      intentIndex: Object.entries(byIntent)
        .map(([label, count]) => ({ intent: label, toolCount: count }))
        .sort((a, b) => a.intent.localeCompare(b.intent)),
      recommendationGuide: {
        onboardingSequence: ["splunk_connection_info", "splunk_scope_info", "splunk_environment_get", "splunk_health_check"],
        safeQueryPreference:
          "Filter by intent=query-suggestion for broad recommendations. Prefer dedicated tools first; use splunk_api_request only for uncovered endpoints.",
        mutationSafety: "Any mutating tool may require authorizationKey when MCP_ADMIN_AUTH_KEY is configured."
      },
      tools: normalizedTools
    }
  };
}

export function createMcpServer({ name, version, splunkClient, configStore, vaultService, runtimeEnv }) {
  const server = new McpServer({ name, version });

  const adminAuthKey = runtimeEnv?.adminAuthKey ?? process.env.MCP_ADMIN_AUTH_KEY ?? "";
  const appName = normalizeAppName(runtimeEnv?.appName ?? process.env.APP_NAME ?? "skeleton");
  const defaultUserId =
    String(runtimeEnv?.config?.defaultUserId ?? process.env.MCP_CONFIG_DEFAULT_USER_ID ?? "default").trim() ||
    "default";
  const allowSensitiveOutput = Boolean(runtimeEnv?.allowSensitiveOutput ?? false);
  const splunkDefaultEnvironment = String(runtimeEnv?.splunk?.defaultEnvironment ?? "default").trim() || "default";
  const splunkDefaultBaseUrl = String(runtimeEnv?.splunk?.defaultBaseUrl ?? "https://127.0.0.1:8089").trim();
  const splunkDefaultProduct = normalizeSplunkProduct(runtimeEnv?.splunk?.defaultProduct ?? "enterprise");
  const splunkDefaultAuthMode = String(runtimeEnv?.splunk?.authMode ?? "splunk").trim().toLowerCase();
  const splunkNamespaceOwner = String(runtimeEnv?.splunk?.namespaceOwner ?? "-").trim() || "-";
  const splunkNamespaceApp = String(runtimeEnv?.splunk?.namespaceApp ?? "-").trim() || "-";
  const splunkEnvironmentConfigPrefix =
    String(runtimeEnv?.splunk?.environmentConfigPrefix ?? "splunk.environment").trim() || "splunk.environment";

  const catalog = Array.isArray(endpointCatalog) ? endpointCatalog : [];

  function resolveUserId(userId) {
    return String(userId ?? defaultUserId).trim() || defaultUserId;
  }

  function getScopeModel(userId = defaultUserId) {
    const resolvedUserId = resolveUserId(userId);
    return {
      appName,
      userId: resolvedUserId,
      userIdPathSegment: normalizeUserIdForPath(resolvedUserId),
      postgres: {
        tableName: `${appName}_config`,
        primaryKey: ["user_id", "key"],
        scope: "app_and_user"
      },
      vault: {
        tokenIndexPath: getVaultUserTokenIndexPath(appName, resolvedUserId),
        splunkSecretBasePath: `${appName}/users/${normalizeUserIdForPath(resolvedUserId)}/splunk`,
        scope: "app_and_user"
      }
    };
  }

  function getDefaultAuthSecretPath(userId, environment) {
    return `${appName}/users/${normalizeUserIdForPath(userId)}/splunk/environments/${normalizeUserIdForPath(
      environment
    )}/auth`;
  }

  async function resolveSplunkEnvironmentConfig({ userId, environment }) {
    const effectiveUserId = resolveUserId(userId);
    const effectiveEnvironment = String(environment ?? splunkDefaultEnvironment).trim() || splunkDefaultEnvironment;
    const key = `${splunkEnvironmentConfigPrefix}.${effectiveEnvironment}`;

    const fallback = configStore
      ? await configStore.getConfigWithFallback(key, effectiveUserId)
      : { row: null, source: "none", resolvedUserId: effectiveUserId };
    const dbValue = fallback?.row?.value && typeof fallback.row.value === "object" ? fallback.row.value : {};

    return {
      userId: effectiveUserId,
      environment: effectiveEnvironment,
      configSource: fallback.source,
      product: normalizeSplunkProduct(dbValue.product ?? splunkDefaultProduct),
      baseUrl: String(dbValue.baseUrl ?? splunkDefaultBaseUrl).trim() || splunkDefaultBaseUrl,
      authMode: String(dbValue.authMode ?? splunkDefaultAuthMode).trim().toLowerCase() || splunkDefaultAuthMode,
      namespaceOwner: String(dbValue.namespaceOwner ?? splunkNamespaceOwner).trim() || splunkNamespaceOwner,
      namespaceApp: String(dbValue.namespaceApp ?? splunkNamespaceApp).trim() || splunkNamespaceApp,
      authSecretPath:
        String(dbValue.authSecretPath ?? "").trim() || getDefaultAuthSecretPath(effectiveUserId, effectiveEnvironment)
    };
  }

  async function resolveSplunkAuthSecret(authSecretPath) {
    if (!vaultService) {
      return {};
    }

    const secret = await vaultService.getSecret(authSecretPath).catch((error) => {
      if (String(error?.message ?? "").includes("404")) {
        return null;
      }
      throw error;
    });

    return secret && typeof secret === "object" ? secret : {};
  }

  async function invokeSplunkRequest({ userId, environment, product, method, path, query, body, headers, bodyFormat }) {
    const envConfig = await resolveSplunkEnvironmentConfig({ userId, environment });
    const authSecret = await resolveSplunkAuthSecret(envConfig.authSecretPath);
    const effectiveProduct = product ? normalizeSplunkProduct(product) : envConfig.product;

    return {
      scope: {
        userId: envConfig.userId,
        environment: envConfig.environment,
        configSource: envConfig.configSource,
        product: effectiveProduct,
        baseUrl: envConfig.baseUrl,
        authMode: envConfig.authMode,
        authSecretPath: envConfig.authSecretPath,
        namespaceOwner: envConfig.namespaceOwner,
        namespaceApp: envConfig.namespaceApp
      },
      response: await splunkClient.request({
        baseUrl: envConfig.baseUrl,
        method,
        path,
        query,
        body,
        headers,
        authMode: envConfig.authMode,
        authSecret,
        bodyFormat,
        apiFamily: effectiveProduct
      })
    };
  }

  function asText(value) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(value, null, 2)
        }
      ]
    };
  }

  function classifyToolError(error) {
    const status = Number(error?.status ?? error?.statusCode ?? 500);
    return {
      ok: false,
      status: Number.isFinite(status) ? status : 500,
      error: error instanceof Error ? error.message : String(error)
    };
  }

  function withErrorHandling(handler) {
    return async (args) => {
      try {
        return asText(await handler(args));
      } catch (error) {
        return {
          ...asText(classifyToolError(error)),
          isError: true
        };
      }
    };
  }

  function assertAuthorized(authorizationKey) {
    if (!adminAuthKey) {
      return;
    }

    if (!authorizationKey || authorizationKey !== adminAuthKey) {
      const unauthorized = new Error("Unauthorized: invalid authorizationKey for mutating API operation");
      unauthorized.status = 401;
      throw unauthorized;
    }
  }

  server.tool(
    "splunk_connection_info",
    toolSpecDescription({
      purpose: "you need runtime defaults and persistence details.",
      doNotUse: "you only need endpoint execution.",
      category: "read-only",
      risk: "low",
      permissions: "none",
      envBehavior: "reports default app/user scope and Splunk environment defaults.",
      params: "none",
      responseShape: "{ ok, status, data: { server, splunkDefaults, endpointCatalog } }",
      failures: "500 runtime metadata errors.",
      prerequisites: "none",
      followUps: "splunk_scope_info, splunk_environment_get",
      warnings: "none",
      examples: "{\"name\":\"splunk_connection_info\",\"arguments\":{}}"
    }),
    {},
    withErrorHandling(async () => ({
      ok: true,
      status: 200,
      data: {
        server: {
          name,
          version,
          adminAuthConfigured: Boolean(adminAuthKey),
          scopeModel: getScopeModel()
        },
        splunkDefaults: {
          environment: splunkDefaultEnvironment,
          product: splunkDefaultProduct,
          baseUrl: splunkDefaultBaseUrl,
          authMode: splunkDefaultAuthMode,
          namespaceOwner: splunkNamespaceOwner,
          namespaceApp: splunkNamespaceApp
        },
        endpointCatalog: {
          totalCount: catalog.length,
          categories: Object.entries(
            catalog.reduce((acc, entry) => {
              const key = String(entry.category ?? "unknown");
              acc[key] = (acc[key] ?? 0) + 1;
              return acc;
            }, {})
          )
            .map(([category, count]) => ({ category, count }))
            .sort((a, b) => b.count - a.count)
        }
      }
    }))
  );

  server.tool(
    "mcp_tool_discovery",
    toolSpecDescription({
      purpose: "you need query suggestions and input schema discovery across all MCP tools.",
      doNotUse: "you already know exactly which tool and parameters to call.",
      category: "read-only",
      risk: "low",
      permissions: "none",
      envBehavior: "returns static recommendations aligned to this MCP tool catalog.",
      params: "toolName/intent optional filters; includeSchemas/includeExamples optional booleans.",
      responseShape: "{ ok, status, data: { tools[], intentIndex[], recommendationGuide } }",
      failures: "none expected; invalid filters return empty tools array.",
      prerequisites: "none",
      followUps: "any recommended tool listed in tools[].",
      warnings: "schema hints are guidance and may evolve with future releases.",
      examples:
        '{"name":"mcp_tool_discovery","arguments":{}} | {"name":"mcp_tool_discovery","arguments":{"intent":"search","includeSchemas":true}}'
    }),
    {
      toolName: z.string().min(1).optional(),
      intent: z.string().min(1).optional(),
      includeSchemas: z.boolean().optional(),
      includeExamples: z.boolean().optional()
    },
    withErrorHandling(async ({ toolName, intent, includeSchemas = true, includeExamples = true }) =>
      buildToolDiscoveryResponse({ toolName, intent, includeSchemas, includeExamples })
    )
  );

  server.tool(
    "splunk_scope_info",
    toolSpecDescription({
      purpose: "you need app/user scope details for Postgres and Vault.",
      doNotUse: "you need live Splunk data.",
      category: "read-only",
      risk: "low",
      permissions: "none",
      envBehavior: "defaults userId from MCP_CONFIG_DEFAULT_USER_ID.",
      params: "userId optional string.",
      responseShape: "{ ok, status, data: scopeModel }",
      failures: "500 normalization issues.",
      prerequisites: "none",
      followUps: "splunk_environment_get",
      warnings: "none",
      examples: "{\"name\":\"splunk_scope_info\",\"arguments\":{\"userId\":\"analyst-a\"}}"
    }),
    { userId: z.string().min(1).optional() },
    withErrorHandling(async ({ userId }) => ({ ok: true, status: 200, data: getScopeModel(userId) }))
  );

  server.tool(
    "splunk_list_endpoints",
    toolSpecDescription({
      purpose: "you need endpoint catalog discovery from bundled Splunk 10.4 reference.",
      doNotUse: "you already know exact path and want execution.",
      category: "read-only",
      risk: "low",
      permissions: "none",
      envBehavior: "static catalog; no remote call.",
      params: "category/prefix optional, limit 1..500, offset >=0.",
      responseShape: "{ ok, status, data: { total, returned, nextOffset, endpoints[] } }",
      failures: "400 invalid pagination.",
      prerequisites: "splunk_connection_info",
      followUps: "splunk_api_request",
      warnings: "catalog is path-oriented; method specifics may vary.",
      examples: "{\"name\":\"splunk_list_endpoints\",\"arguments\":{\"prefix\":\"/services/search\"}}"
    }),
    {
      category: z.string().min(1).optional(),
      prefix: z.string().min(1).optional(),
      limit: z.number().int().min(1).max(500).optional(),
      offset: z.number().int().min(0).optional()
    },
    withErrorHandling(async ({ category, prefix, limit = 100, offset = 0 }) => {
      const normalizedCategory = String(category ?? "").trim().toLowerCase();
      const normalizedPrefix = prefix ? normalizePath(prefix).toLowerCase() : "";

      const filtered = catalog.filter((entry) => {
        const matchesCategory = normalizedCategory ? String(entry.category).toLowerCase() === normalizedCategory : true;
        const matchesPrefix = normalizedPrefix ? String(entry.path).toLowerCase().startsWith(normalizedPrefix) : true;
        return matchesCategory && matchesPrefix;
      });

      const slice = filtered.slice(offset, offset + limit);
      return {
        ok: true,
        status: 200,
        data: {
          total: filtered.length,
          returned: slice.length,
          nextOffset: offset + slice.length < filtered.length ? offset + slice.length : null,
          endpoints: slice
        }
      };
    })
  );

  server.tool(
    "splunk_environment_get",
    toolSpecDescription({
      purpose: "you need resolved environment config for one user/environment.",
      doNotUse: "you need secret values.",
      category: "read-only",
      risk: "low",
      permissions: "none",
      envBehavior: "reads user-scoped Postgres config with default-user fallback.",
      params: "userId/environment optional.",
      responseShape: "{ ok, status, data: { userId, environment, product, baseUrl, authMode, authSecretPath } }",
      failures: "500 config parsing errors.",
      prerequisites: "splunk_scope_info",
      followUps: "splunk_auth_secret_set, splunk_api_request",
      warnings: "secret contents are not returned.",
      examples: "{\"name\":\"splunk_environment_get\",\"arguments\":{\"environment\":\"prod\"}}"
    }),
    { userId: z.string().min(1).optional(), environment: z.string().min(1).optional() },
    withErrorHandling(async ({ userId, environment }) => ({
      ok: true,
      status: 200,
      data: await resolveSplunkEnvironmentConfig({ userId, environment })
    }))
  );

  server.tool(
    "splunk_environment_set",
    toolSpecDescription({
      purpose: "you need to persist user-scoped Splunk environment settings in Postgres.",
      doNotUse: "you need to store secrets.",
      category: "mutating",
      risk: "medium",
      permissions: "authorizationKey when MCP_ADMIN_AUTH_KEY is enabled.",
      envBehavior: "writes {prefix}.{environment} per user.",
      params: "environment required; userId/product/baseUrl/authMode/namespace/authSecretPath optional.",
      responseShape: "{ ok, status, data: row }",
      failures: "401 unauthorized, 5xx Postgres errors.",
      prerequisites: "splunk_environment_get",
      followUps: "splunk_auth_secret_set",
      warnings: "bad values can break all Splunk tool calls for that scope.",
      examples: "{\"name\":\"splunk_environment_set\",\"arguments\":{\"environment\":\"prod\",\"baseUrl\":\"https://splunk.example.com:8089\"}}"
    }),
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1),
      product: z.enum(["enterprise", "soar"]).optional(),
      baseUrl: z.string().url().optional(),
      authMode: z.enum(SPLUNK_AUTH_MODES).optional(),
      namespaceOwner: z.string().min(1).optional(),
      namespaceApp: z.string().min(1).optional(),
      authSecretPath: z.string().min(1).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async (args) => {
      assertAuthorized(args.authorizationKey);
      if (!configStore) {
        const error = new Error("Postgres config store is not configured");
        error.status = 500;
        throw error;
      }

      const row = await configStore.setConfig(
        `${splunkEnvironmentConfigPrefix}.${String(args.environment).trim()}`,
        {
          ...(args.product ? { product: normalizeSplunkProduct(args.product) } : {}),
          ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
          ...(args.authMode ? { authMode: args.authMode } : {}),
          ...(args.namespaceOwner ? { namespaceOwner: args.namespaceOwner } : {}),
          ...(args.namespaceApp ? { namespaceApp: args.namespaceApp } : {}),
          ...(args.authSecretPath ? { authSecretPath: args.authSecretPath } : {})
        },
        resolveUserId(args.userId)
      );

      return { ok: true, status: 200, data: row };
    })
  );

  server.tool(
    "splunk_auth_secret_set",
    toolSpecDescription({
      purpose: "you need to persist/rotate Splunk credentials in Vault.",
      doNotUse: "you need only non-secret configuration.",
      category: "mutating",
      risk: "high",
      permissions: "authorizationKey when MCP_ADMIN_AUTH_KEY is enabled.",
      envBehavior: "writes to user/environment Vault path, defaulting to app-scoped path.",
      params: "userId/environment optional; path optional; token/phAuthToken/sessionKey/username/password optional (at least one required).",
      responseShape: "{ ok, status, data: { path, updatedAt } }",
      failures: "401 unauthorized, 400 empty payload, 5xx Vault errors.",
      prerequisites: "splunk_environment_get",
      followUps: "splunk_health_check",
      warnings: "do not pass secrets into Postgres config tools.",
      examples: "{\"name\":\"splunk_auth_secret_set\",\"arguments\":{\"environment\":\"prod\",\"sessionKey\":\"<key>\"}}"
    }),
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      path: z.string().min(1).optional(),
      authMode: z.enum(SPLUNK_AUTH_MODES).optional(),
      token: z.string().min(1).optional(),
      phAuthToken: z.string().min(1).optional(),
      sessionKey: z.string().min(1).optional(),
      username: z.string().min(1).optional(),
      password: z.string().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ userId, environment, path, authMode, token, phAuthToken, sessionKey, username, password, authorizationKey }) => {
      assertAuthorized(authorizationKey);
      if (!vaultService) {
        const error = new Error("Vault service is not configured");
        error.status = 500;
        throw error;
      }

      const resolved = await resolveSplunkEnvironmentConfig({ userId, environment });
      const secretPath = String(path ?? "").trim() || resolved.authSecretPath;
      const payload = {
        ...(authMode ? { authMode } : {}),
        ...(token ? { token } : {}),
        ...(phAuthToken ? { phAuthToken } : {}),
        ...(sessionKey ? { sessionKey } : {}),
        ...(username ? { username } : {}),
        ...(password !== undefined ? { password } : {}),
        updatedAt: new Date().toISOString(),
        updatedBy: resolveUserId(userId)
      };

      if (!["token", "phAuthToken", "sessionKey", "username", "password"].some((key) => key in payload)) {
        const error = new Error("At least one credential field must be provided");
        error.status = 400;
        throw error;
      }

      await vaultService.setSecret(secretPath, payload);
      return { ok: true, status: 200, data: { path: secretPath, updatedAt: payload.updatedAt } };
    })
  );

  server.tool(
    "splunk_auth_secret_metadata",
    toolSpecDescription({
      purpose: "you need metadata presence checks for Vault auth secrets.",
      doNotUse: "you need to mutate secrets.",
      category: "read-only",
      risk: "medium",
      permissions: "Vault read access from runtime token.",
      envBehavior: "resolves path using user/environment config when path omitted.",
      params: "userId/environment/path optional.",
      responseShape: "{ ok, status, data: { path, exists, fields, redactedSecret } }",
      failures: "5xx Vault errors.",
      prerequisites: "splunk_environment_get",
      followUps: "splunk_auth_secret_set",
      warnings: "values are redacted unless MCP_ALLOW_SENSITIVE_OUTPUT=true.",
      examples: "{\"name\":\"splunk_auth_secret_metadata\",\"arguments\":{\"environment\":\"prod\"}}"
    }),
    { userId: z.string().min(1).optional(), environment: z.string().min(1).optional(), path: z.string().min(1).optional() },
    withErrorHandling(async ({ userId, environment, path }) => {
      const resolved = await resolveSplunkEnvironmentConfig({ userId, environment });
      const secretPath = String(path ?? "").trim() || resolved.authSecretPath;
      const secret = await resolveSplunkAuthSecret(secretPath);
      return {
        ok: true,
        status: 200,
        data: {
          path: secretPath,
          exists: Object.keys(secret).length > 0,
          fields: Object.keys(secret),
          redactedSecret: redactObject(secret, allowSensitiveOutput)
        }
      };
    })
  );

  server.tool(
    "mcp_token_upsert",
    toolSpecDescription({
      purpose: "you need to create/update multi-user token-index entries for HTTP auth.",
      doNotUse: "you only need to list token metadata.",
      category: "mutating",
      risk: "high",
      permissions: "authorizationKey when MCP_ADMIN_AUTH_KEY is enabled.",
      envBehavior: "writes to app/users/<user>/http/auth/token-index in Vault.",
      params: "targetUserId optional; token required; tokenId/scopes/audience/expiresAt optional.",
      responseShape: "{ ok, status, data: { userId, tokenHash, tokenId, indexPath } }",
      failures: "401 unauthorized, 400 invalid expiresAt, 5xx Vault errors.",
      prerequisites: "splunk_scope_info",
      followUps: "mcp_token_list, mcp_token_deactivate",
      warnings: "plaintext token input is sensitive.",
      examples: "{\"name\":\"mcp_token_upsert\",\"arguments\":{\"targetUserId\":\"default\",\"token\":\"<token>\"}}"
    }),
    {
      targetUserId: z.string().min(1).optional(),
      token: z.string().min(1),
      tokenId: z.string().min(1).optional(),
      scopes: z.union([z.string().min(1), z.array(z.string().min(1))]).optional(),
      audience: z.union([z.string().min(1), z.array(z.string().min(1))]).optional(),
      expiresAt: z.string().min(1).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ targetUserId, token, tokenId, scopes, audience, expiresAt, authorizationKey }) => {
      assertAuthorized(authorizationKey);
      const userId = resolveUserId(targetUserId);
      const indexPath = getVaultUserTokenIndexPath(appName, userId);
      const existingPayload = await vaultService.getSecret(indexPath).catch((error) => {
        if (String(error?.message ?? "").includes("404")) {
          return null;
        }
        throw error;
      });

      const { tokenHash, entry } = createVaultTokenEntry({
        userId,
        token,
        tokenId,
        scopes,
        audience,
        expiresAt: parseOptionalExpiresAt(expiresAt) || undefined
      });

      await vaultService.setSecret(
        indexPath,
        mergeVaultTokenIndex(existingPayload, {
          userId,
          tokenHash,
          entry
        })
      );

      return {
        ok: true,
        status: 200,
        data: {
          userId,
          tokenHash,
          tokenId: entry.tokenId,
          indexPath
        }
      };
    })
  );

  server.tool(
    "mcp_token_list",
    toolSpecDescription({
      purpose: "you need token inventory metadata for one user index.",
      doNotUse: "you need to add/deactivate tokens.",
      category: "read-only",
      risk: "medium",
      permissions: "Vault read access via runtime.",
      envBehavior: "reads per-user Vault token index.",
      params: "targetUserId optional.",
      responseShape: "{ ok, status, data: { indexPath, tokenCount, tokens[] } }",
      failures: "5xx Vault errors.",
      prerequisites: "splunk_scope_info",
      followUps: "mcp_token_upsert",
      warnings: "token values are not recoverable; only hashes + metadata are returned.",
      examples: "{\"name\":\"mcp_token_list\",\"arguments\":{\"targetUserId\":\"default\"}}"
    }),
    { targetUserId: z.string().min(1).optional() },
    withErrorHandling(async ({ targetUserId }) => {
      const userId = resolveUserId(targetUserId);
      const indexPath = getVaultUserTokenIndexPath(appName, userId);
      const payload = await vaultService.getSecret(indexPath).catch((error) => {
        if (String(error?.message ?? "").includes("404")) {
          return {};
        }
        throw error;
      });
      const tokenMap = payload?.tokens && typeof payload.tokens === "object" ? payload.tokens : {};
      const tokens = Object.entries(tokenMap).map(([tokenHash, entry]) => ({
        tokenHash,
        ...(entry && typeof entry === "object" ? redactObject(entry, allowSensitiveOutput) : {})
      }));
      return { ok: true, status: 200, data: { indexPath, tokenCount: tokens.length, tokens } };
    })
  );

  server.tool(
    "mcp_token_deactivate",
    toolSpecDescription({
      purpose: "you need to disable a token entry by hash or raw token.",
      doNotUse: "you need to create a replacement token.",
      category: "mutating",
      risk: "high",
      permissions: "authorizationKey when MCP_ADMIN_AUTH_KEY is enabled.",
      envBehavior: "updates per-user Vault token index.",
      params: "targetUserId optional; tokenHash or token required.",
      responseShape: "{ ok, status, data: { tokenHash, deactivated } }",
      failures: "401 unauthorized, 404 token hash not found.",
      prerequisites: "mcp_token_list",
      followUps: "mcp_token_upsert",
      warnings: "deactivation can immediately block HTTP MCP access.",
      examples: "{\"name\":\"mcp_token_deactivate\",\"arguments\":{\"tokenHash\":\"abc...\",\"authorizationKey\":\"<key>\"}}"
    }),
    {
      targetUserId: z.string().min(1).optional(),
      tokenHash: z.string().min(1).optional(),
      token: z.string().min(1).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ targetUserId, tokenHash, token, authorizationKey }) => {
      assertAuthorized(authorizationKey);
      const userId = resolveUserId(targetUserId);
      const indexPath = getVaultUserTokenIndexPath(appName, userId);
      const payload = (await vaultService.getSecret(indexPath)) ?? {};
      const resolvedTokenHash = String(tokenHash ?? "").trim() || sha256Hex(String(token ?? "").trim());
      if (!resolvedTokenHash) {
        const error = new Error("Either tokenHash or token must be provided");
        error.status = 400;
        throw error;
      }

      if (!payload.tokens || typeof payload.tokens !== "object" || !payload.tokens[resolvedTokenHash]) {
        const error = new Error("Token hash not found in index");
        error.status = 404;
        throw error;
      }

      payload.tokens[resolvedTokenHash] = {
        ...payload.tokens[resolvedTokenHash],
        active: false,
        deactivatedAt: new Date().toISOString()
      };

      await vaultService.setSecret(indexPath, payload);
      return { ok: true, status: 200, data: { tokenHash: resolvedTokenHash, deactivated: true } };
    })
  );

  server.tool(
    "splunk_health_check",
    "GET product-specific health endpoint using resolved user/environment auth.",
    { userId: z.string().min(1).optional(), environment: z.string().min(1).optional() },
    withErrorHandling(async ({ userId, environment }) => {
      const resolved = await resolveSplunkEnvironmentConfig({ userId, environment });
      const isSoar = resolved.product === "soar";
      return {
        ok: true,
        status: 200,
        data: await invokeSplunkRequest({
          userId,
          environment,
          product: resolved.product,
          method: "GET",
          path: isSoar ? "/rest/container" : "/services/server/info",
          query: isSoar ? { page_size: 1 } : { output_mode: "json" }
        })
      };
    })
  );

  server.tool(
    "splunk_search_job_create",
    "POST /services/search/jobs to dispatch search.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      search: z.string().min(1),
      exec_mode: z.string().min(1).optional(),
      earliest_time: z.string().min(1).optional(),
      latest_time: z.string().min(1).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ authorizationKey, ...args }) => {
      assertAuthorized(authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await invokeSplunkRequest({
          userId: args.userId,
          environment: args.environment,
          method: "POST",
          path: "/services/search/jobs",
          body: {
            search: args.search,
            exec_mode: args.exec_mode,
            earliest_time: args.earliest_time,
            latest_time: args.latest_time,
            output_mode: "json"
          },
          bodyFormat: "form"
        })
      };
    })
  );

  server.tool(
    "splunk_search_job_status",
    "GET /services/search/jobs/{sid}.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      sid: z.string().min(1)
    },
    withErrorHandling(async ({ userId, environment, sid }) => ({
      ok: true,
      status: 200,
      data: await invokeSplunkRequest({
        userId,
        environment,
        method: "GET",
        path: `/services/search/jobs/${encodeURIComponent(sid)}`,
        query: { output_mode: "json" }
      })
    }))
  );

  server.tool(
    "splunk_search_job_results",
    "GET /services/search/jobs/{sid}/results.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      sid: z.string().min(1),
      count: z.number().int().min(1).max(10000).optional(),
      offset: z.number().int().min(0).optional()
    },
    withErrorHandling(async ({ userId, environment, sid, count, offset }) => ({
      ok: true,
      status: 200,
      data: await invokeSplunkRequest({
        userId,
        environment,
        method: "GET",
        path: `/services/search/jobs/${encodeURIComponent(sid)}/results`,
        query: {
          output_mode: "json",
          ...(count ? { count } : {}),
          ...(offset !== undefined ? { offset } : {})
        }
      })
    }))
  );

  server.tool(
    "splunk_search_job_cancel",
    "POST /services/search/jobs/{sid}/control with action=cancel.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      sid: z.string().min(1),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ userId, environment, sid, authorizationKey }) => {
      assertAuthorized(authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await invokeSplunkRequest({
          userId,
          environment,
          method: "POST",
          path: `/services/search/jobs/${encodeURIComponent(sid)}/control`,
          body: { action: "cancel", output_mode: "json" },
          bodyFormat: "form"
        })
      };
    })
  );

  server.tool(
    "splunk_saved_searches_list",
    "GET /servicesNS/{owner}/{app}/saved/searches.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      owner: z.string().min(1).optional(),
      app: z.string().min(1).optional(),
      count: z.number().int().min(1).max(5000).optional(),
      offset: z.number().int().min(0).optional()
    },
    withErrorHandling(async ({ userId, environment, owner, app, count, offset }) => {
      const resolved = await resolveSplunkEnvironmentConfig({ userId, environment });
      return {
        ok: true,
        status: 200,
        data: await invokeSplunkRequest({
          userId,
          environment,
          method: "GET",
          path: `/servicesNS/${encodeURIComponent(owner ?? resolved.namespaceOwner)}/${encodeURIComponent(app ?? resolved.namespaceApp)}/saved/searches`,
          query: {
            output_mode: "json",
            ...(count ? { count } : {}),
            ...(offset !== undefined ? { offset } : {})
          }
        })
      };
    })
  );

  server.tool(
    "splunk_indexes_list",
    "GET /services/data/indexes.",
    { userId: z.string().min(1).optional(), environment: z.string().min(1).optional() },
    withErrorHandling(async ({ userId, environment }) => ({
      ok: true,
      status: 200,
      data: await invokeSplunkRequest({
        userId,
        environment,
        method: "GET",
        path: "/services/data/indexes",
        query: { output_mode: "json" }
      })
    }))
  );

  server.tool(
    "splunk_users_list",
    "GET /services/authentication/users.",
    { userId: z.string().min(1).optional(), environment: z.string().min(1).optional() },
    withErrorHandling(async ({ userId, environment }) => ({
      ok: true,
      status: 200,
      data: await invokeSplunkRequest({
        userId,
        environment,
        method: "GET",
        path: "/services/authentication/users",
        query: { output_mode: "json" }
      })
    }))
  );

  server.tool(
    "splunk_api_request",
    toolSpecDescription({
      purpose: "you need full Splunk REST coverage beyond dedicated tools, including Enterprise and SOAR request families.",
      doNotUse: "a dedicated tool already matches your use case and is safer.",
      category: "read-write",
      risk: "high",
      permissions: "mutating calls require authorizationKey when MCP_ADMIN_AUTH_KEY is set.",
      envBehavior: "reads user/environment config from Postgres and auth secret from Vault.",
      params: "method/path required; product override optional; query/body/headers optional; bodyFormat json|form|raw.",
      responseShape: "{ ok, status, data: { scope, response, requestRisk } }",
      failures: "400 invalid path, 401 unauthorized, 4xx/5xx upstream failures.",
      prerequisites: "splunk_environment_get, splunk_auth_secret_set",
      followUps: "splunk_search_job_status, splunk_list_endpoints",
      warnings: "destructive endpoints can impact Splunk data and topology.",
      examples:
        "{\"name\":\"splunk_api_request\",\"arguments\":{\"method\":\"GET\",\"path\":\"/services/server/info\"}} | {\"name\":\"splunk_api_request\",\"arguments\":{\"product\":\"soar\",\"method\":\"GET\",\"path\":\"/rest/container/1\"}}"
    }),
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      product: z.enum(["enterprise", "soar"]).optional(),
      method: z.string().min(1),
      path: z.string().min(1),
      query: z
        .record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))]))
        .optional(),
      body: z.unknown().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      bodyFormat: z.enum(["json", "form", "raw"]).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ userId, environment, product, method, path, query, body, headers, bodyFormat, authorizationKey }) => {
      const normalizedMethod = normalizeMethod(method);
      const normalizedPath = normalizePath(path);

      if (MUTATING_METHODS.has(normalizedMethod)) {
        assertAuthorized(authorizationKey);
      }

      return {
        ok: true,
        status: 200,
        data: {
          ...(await invokeSplunkRequest({
            userId,
            environment,
            product,
            method: normalizedMethod,
            path: normalizedPath,
            query,
            body,
            headers,
            bodyFormat
          })),
          requestRisk: isHighRiskSplunkPath(normalizedPath) ? "high" : MUTATING_METHODS.has(normalizedMethod) ? "medium" : "low"
        }
      };
    })
  );

  server.tool(
    "splunk_soar_api_request",
    toolSpecDescription({
      purpose: "you need Splunk SOAR (Phantom) API coverage using /rest endpoints.",
      doNotUse: "you need Splunk Enterprise /services endpoints.",
      category: "read-write",
      risk: "high",
      permissions: "mutating calls require authorizationKey when MCP_ADMIN_AUTH_KEY is set.",
      envBehavior: "forces product=soar while still resolving baseUrl/auth secret from user/environment config.",
      params: "method/path required; path must start with /rest; query/body/headers optional; bodyFormat json|form|raw.",
      responseShape: "{ ok, status, data: { scope, response, requestRisk } }",
      failures: "400 invalid path, 401 unauthorized, 4xx/5xx upstream failures.",
      prerequisites: "splunk_environment_set (product=soar), splunk_auth_secret_set",
      followUps: "splunk_auth_secret_metadata",
      warnings: "destructive endpoints can mutate incidents/artifacts and orchestration state.",
      examples: "{\"name\":\"splunk_soar_api_request\",\"arguments\":{\"method\":\"GET\",\"path\":\"/rest/container/1\"}}"
    }),
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      method: z.string().min(1),
      path: z.string().min(1),
      query: z
        .record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))]))
        .optional(),
      body: z.unknown().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      bodyFormat: z.enum(["json", "form", "raw"]).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({ userId, environment, method, path, query, body, headers, bodyFormat, authorizationKey }) => {
      const normalizedMethod = normalizeMethod(method);
      const normalizedPath = normalizePath(path);

      if (MUTATING_METHODS.has(normalizedMethod)) {
        assertAuthorized(authorizationKey);
      }

      return {
        ok: true,
        status: 200,
        data: {
          ...(await invokeSplunkRequest({
            userId,
            environment,
            product: "soar",
            method: normalizedMethod,
            path: normalizedPath,
            query,
            body,
            headers,
            bodyFormat
          })),
          requestRisk: isHighRiskSplunkPath(normalizedPath) ? "high" : MUTATING_METHODS.has(normalizedMethod) ? "medium" : "low"
        }
      };
    })
  );

  server.tool(
    "splunk_soar_container_get",
    "GET /rest/container/{containerId} for SOAR/Phantom.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      containerId: z.union([z.number().int().min(1), z.string().min(1)])
    },
    withErrorHandling(async ({ userId, environment, containerId }) => ({
      ok: true,
      status: 200,
      data: await invokeSplunkRequest({
        userId,
        environment,
        product: "soar",
        method: "GET",
        path: `/rest/container/${encodeURIComponent(String(containerId))}`
      })
    }))
  );

  server.tool(
    "splunk_soar_container_find_by_source",
    "GET /rest/container filtered by source_data_identifier for SOAR/Phantom dedupe lookups.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      sourceDataIdentifier: z.string().min(1),
      pageSize: z.number().int().min(1).max(200).optional(),
      page: z.number().int().min(0).optional()
    },
    withErrorHandling(async ({ userId, environment, sourceDataIdentifier, pageSize = 1, page = 0 }) => ({
      ok: true,
      status: 200,
      data: await invokeSplunkRequest({
        userId,
        environment,
        product: "soar",
        method: "GET",
        path: "/rest/container",
        query: {
          _filter_source_data_identifier: `"${sourceDataIdentifier}"`,
          page_size: pageSize,
          page
        }
      })
    }))
  );

  server.tool(
    "splunk_soar_container_create",
    "POST /rest/container for SOAR/Phantom container creation.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      name: z.string().min(1),
      label: z.string().min(1),
      description: z.string().optional(),
      severity: z.enum(["low", "medium", "high"]).optional(),
      sensitivity: z.enum(["white", "green", "amber", "red"]).optional(),
      sourceDataIdentifier: z.string().min(1).optional(),
      runAutomation: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({
      userId,
      environment,
      name,
      label,
      description,
      severity,
      sensitivity,
      sourceDataIdentifier,
      runAutomation,
      authorizationKey
    }) => {
      assertAuthorized(authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await invokeSplunkRequest({
          userId,
          environment,
          product: "soar",
          method: "POST",
          path: "/rest/container",
          body: {
            name,
            label,
            ...(description !== undefined ? { description } : {}),
            ...(severity !== undefined ? { severity } : {}),
            ...(sensitivity !== undefined ? { sensitivity } : {}),
            ...(sourceDataIdentifier !== undefined ? { source_data_identifier: sourceDataIdentifier } : {}),
            ...(runAutomation !== undefined ? { run_automation: runAutomation } : {})
          },
          bodyFormat: "json"
        })
      };
    })
  );

  server.tool(
    "splunk_soar_artifact_create",
    "POST /rest/artifact for SOAR/Phantom artifact creation.",
    {
      userId: z.string().min(1).optional(),
      environment: z.string().min(1).optional(),
      containerId: z.union([z.number().int().min(1), z.string().regex(/^\d+$/)]),
      label: z.string().min(1),
      name: z.string().min(1).optional(),
      sourceDataIdentifier: z.string().min(1).optional(),
      severity: z.enum(["low", "medium", "high"]).optional(),
      runAutomation: z.boolean().optional(),
      cef: z.record(z.string(), z.unknown()).optional(),
      data: z.record(z.string(), z.unknown()).optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(async ({
      userId,
      environment,
      containerId,
      label,
      name,
      sourceDataIdentifier,
      severity,
      runAutomation,
      cef,
      data,
      authorizationKey
    }) => {
      assertAuthorized(authorizationKey);
      const normalizedContainerId = Number(containerId);
      if (!Number.isInteger(normalizedContainerId) || normalizedContainerId < 1) {
        const error = new Error("containerId must be a positive integer");
        error.status = 400;
        throw error;
      }
      return {
        ok: true,
        status: 200,
        data: await invokeSplunkRequest({
          userId,
          environment,
          product: "soar",
          method: "POST",
          path: "/rest/artifact",
          body: {
            container_id: normalizedContainerId,
            label,
            ...(name !== undefined ? { name } : {}),
            ...(sourceDataIdentifier !== undefined ? { source_data_identifier: sourceDataIdentifier } : {}),
            ...(severity !== undefined ? { severity } : {}),
            ...(runAutomation !== undefined ? { run_automation: runAutomation } : {}),
            ...(cef !== undefined ? { cef } : {}),
            ...(data !== undefined ? { data } : {})
          },
          bodyFormat: "json"
        })
      };
    })
  );

  return server;
}
