import dotenv from "dotenv";

dotenv.config();

const TRANSPORT_MODES = new Set(["stdio", "http", "both"]);
const HTTP_AUTH_MODES = new Set(["token", "oauth2", "both"]);
const HTTP_TOKEN_SOURCES = new Set(["static", "vault", "both"]);
const SPLUNK_AUTH_MODES = new Set(["splunk", "bearer", "basic", "phantom", "none"]);
const SPLUNK_PRODUCTS = new Set(["enterprise", "soar"]);

function enumValue(name, fallback, allowedValues) {
  const value = String(process.env[name] ?? fallback).toLowerCase();
  if (!allowedValues.has(value)) {
    throw new Error(
      `Environment variable ${name} must be one of: ${Array.from(allowedValues).join(", ")}`
    );
  }
  return value;
}

function required(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function positiveNumber(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Environment variable ${name} must be a non-negative number`);
  }
  return value;
}

function portNumber(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Environment variable ${name} must be an integer between 1 and 65535`);
  }
  return value;
}

function parseCsv(name, fallback = "") {
  return String(process.env[name] ?? fallback)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function optionalNumber(name, fallback) {
  const raw = process.env[name] ?? fallback;
  if (raw === undefined || raw === "") {
    return undefined;
  }

  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Environment variable ${name} must be a number`);
  }

  return parsed;
}

function booleanValue(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }

  const value = String(raw).toLowerCase();
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }

  throw new Error(`Environment variable ${name} must be either true or false`);
}

function normalizeAppName(value, fallback = "skeleton") {
  return String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-") || fallback;
}

const transportMode = enumValue("MCP_TRANSPORT_MODE", "stdio", TRANSPORT_MODES);
const httpAuthMode = enumValue("MCP_HTTP_AUTH_MODE", "token", HTTP_AUTH_MODES);
const httpTokenSource = enumValue("MCP_HTTP_TOKEN_SOURCE", "vault", HTTP_TOKEN_SOURCES);
const splunkDefaultProduct = enumValue("SPLUNK_PRODUCT", "enterprise", SPLUNK_PRODUCTS);
const splunkAuthMode = enumValue("SPLUNK_AUTH_MODE", "splunk", SPLUNK_AUTH_MODES);
const appName = normalizeAppName(process.env.APP_NAME, "skeleton");

export const env = {
  appName,
  mcpServerName: process.env.MCP_SERVER_NAME ?? `${appName}-mcp`,
  mcpServerVersion: process.env.MCP_SERVER_VERSION ?? "0.1.0",
  adminAuthKey: process.env.MCP_ADMIN_AUTH_KEY ?? "",
  allowSensitiveOutput: booleanValue("MCP_ALLOW_SENSITIVE_OUTPUT", false),
  config: {
    defaultUserId: required("MCP_CONFIG_DEFAULT_USER_ID", "default"),
    tokenRotationDefaultIntervalMs: positiveNumber("MCP_TOKEN_ROTATION_DEFAULT_INTERVAL_MS", "86400000"),
    tokenRotationUserIntervalConfigKey: required(
      "MCP_TOKEN_ROTATION_USER_INTERVAL_CONFIG_KEY",
      "token.rotation.intervalMs"
    ),
    vaultAgent: {
      authModeConfigKey: required("MCP_VAULT_AGENT_AUTH_MODE_CONFIG_KEY", "vault.agent.auth.mode"),
      tokenFilePathConfigKey: required(
        "MCP_VAULT_AGENT_TOKEN_FILE_PATH_CONFIG_KEY",
        "vault.agent.tokenFilePath"
      ),
      listenerAddrConfigKey: required("MCP_VAULT_AGENT_LISTENER_ADDR_CONFIG_KEY", "vault.agent.listener.addr")
    }
  },
  postgres: {
    host: required("POSTGRES_HOST", "127.0.0.1"),
    port: portNumber("POSTGRES_PORT", "5432"),
    database: required("POSTGRES_DB", "mcp_config"),
    user: required("POSTGRES_USER", "mcp_user"),
    password: required("POSTGRES_PASSWORD", "mcp_password"),
    ssl: booleanValue("POSTGRES_SSL", false) ? { rejectUnauthorized: false } : undefined
  },
  vault: {
    endpoint: required("VAULT_ADDR", "http://127.0.0.1:8200"),
    token: process.env.VAULT_TOKEN ?? "",
    agentEnabled: booleanValue("VAULT_AGENT_ENABLED", false),
    agentAuthMode: required("VAULT_AGENT_AUTH_MODE", "file").toLowerCase(),
    agentTokenFilePath: process.env.VAULT_AGENT_TOKEN_FILE_PATH ?? "/tmp/vault-agent-token",
    agentListenerEnabled: booleanValue("VAULT_AGENT_LISTENER_ENABLED", false),
    agentListenerAddr: process.env.VAULT_AGENT_LISTENER_ADDR ?? "http://127.0.0.1:8100",
    kvMount: required("VAULT_KV_MOUNT", "secret"),
    writeRetryAttempts: positiveNumber("VAULT_WRITE_RETRY_ATTEMPTS", "3"),
    writeRetryBaseDelayMs: positiveNumber("VAULT_WRITE_RETRY_BASE_DELAY_MS", "200"),
    writeRetryMaxDelayMs: positiveNumber("VAULT_WRITE_RETRY_MAX_DELAY_MS", "2000")
  },
  splunk: {
    defaultEnvironment: required("SPLUNK_DEFAULT_ENVIRONMENT", "default"),
    defaultProduct: splunkDefaultProduct,
    defaultBaseUrl: required("SPLUNK_BASE_URL", "https://127.0.0.1:8089"),
    timeoutMs: positiveNumber("SPLUNK_TIMEOUT_MS", "30000"),
    authMode: splunkAuthMode,
    namespaceOwner: required("SPLUNK_NAMESPACE_OWNER", "-") || "-",
    namespaceApp: required("SPLUNK_NAMESPACE_APP", "-") || "-",
    authSecretPathConfigKey: required(
      "SPLUNK_AUTH_SECRET_PATH_CONFIG_KEY",
      "splunk.auth.secretPath"
    ),
    environmentConfigPrefix: required(
      "SPLUNK_ENVIRONMENT_CONFIG_PREFIX",
      "splunk.environment"
    ),
    verifyTls: booleanValue("SPLUNK_VERIFY_TLS", false)
  },
  transport: {
    mode: transportMode,
    http: {
      host: required("MCP_HTTP_HOST", "127.0.0.1"),
      port: portNumber("MCP_HTTP_PORT", "3000"),
      mcpPath: required("MCP_HTTP_PATH", "/mcp"),
      healthPath: required("MCP_HTTP_HEALTH_PATH", "/healthz"),
      authMode: httpAuthMode,
      tokenSource: httpTokenSource,
      authTokens: parseCsv("MCP_HTTP_AUTH_TOKENS", "replace-me-token"),
      vaultTokenIndexPath: required("MCP_HTTP_VAULT_TOKEN_INDEX_PATH", `${appName}/http/auth/token-index`),
      vaultTokenDefaultUserId: required("MCP_HTTP_VAULT_TOKEN_DEFAULT_USER_ID", "default"),
      vaultTokenRequiredScopes: parseCsv("MCP_HTTP_VAULT_TOKEN_REQUIRED_SCOPES", "mcp:invoke"),
      vaultTokenRequiredAudience: process.env.MCP_HTTP_VAULT_TOKEN_REQUIRED_AUDIENCE ?? "",
      vaultTokenCacheTtlMs: positiveNumber("MCP_HTTP_VAULT_TOKEN_CACHE_TTL_MS", "30000"),
      oauth2IntrospectionUrl: process.env.MCP_HTTP_OAUTH2_INTROSPECTION_URL ?? "",
      oauth2ClientId: process.env.MCP_HTTP_OAUTH2_CLIENT_ID ?? "",
      oauth2ClientSecret: process.env.MCP_HTTP_OAUTH2_CLIENT_SECRET ?? "",
      oauth2RequiredScopes: parseCsv("MCP_HTTP_OAUTH2_REQUIRED_SCOPES", ""),
      oauth2RequiredAudience: process.env.MCP_HTTP_OAUTH2_REQUIRED_AUDIENCE ?? "",
      oauth2TimeoutMs: positiveNumber("MCP_HTTP_OAUTH2_TIMEOUT_MS", "5000"),
      oauth2CacheTtlMs: positiveNumber("MCP_HTTP_OAUTH2_CACHE_TTL_MS", "30000"),
      trustedProxy: booleanValue("MCP_HTTP_TRUST_PROXY", false),
      allowedOrigins: parseCsv("MCP_HTTP_ALLOWED_ORIGINS", ""),
      allowedIps: parseCsv("MCP_HTTP_ALLOWED_IPS", ""),
      maxBodyBytes: positiveNumber("MCP_HTTP_MAX_BODY_BYTES", "1048576"),
      rateLimitWindowMs: positiveNumber("MCP_HTTP_RATE_LIMIT_WINDOW_MS", "60000"),
      rateLimitMaxRequests: positiveNumber("MCP_HTTP_RATE_LIMIT_MAX_REQUESTS", "60"),
      tls: {
        enabled: booleanValue("MCP_HTTP_TLS_ENABLED", false),
        certPath: process.env.MCP_HTTP_TLS_CERT_PATH ?? "",
        keyPath: process.env.MCP_HTTP_TLS_KEY_PATH ?? ""
      }
    }
  },
  tracing: {
    enabled: booleanValue("MCP_TRACE_ENABLED", false),
    requestSampleRate: optionalNumber("MCP_TRACE_REQUEST_SAMPLE_RATE", "1")
  }
};
