import { env } from "../config/env.js";
import { createHttpMcpServer } from "./server.js";
import { createMcpServer } from "../mcp/server.js";
import { ConfigStore } from "../services/configStore.js";
import { SplunkServiceClient } from "../services/splunkService.js";
import { VaultService } from "../services/vault.js";
import { createOAuth2IntrospectionVerifier } from "./oauth2.js";
import { createVaultTokenVerifier } from "./vaultTokenAuth.js";

async function main() {
  if (env.transport.http.tls.enabled) {
    throw new Error(
      "MCP_HTTP_TLS_ENABLED=true is not supported in this process mode. Terminate TLS at a reverse proxy/load balancer."
    );
  }

  const configStore = new ConfigStore(env.postgres, {
    appName: env.appName,
    defaultUserId: env.config.defaultUserId
  });

  const vaultService = new VaultService({
    endpoint: env.vault.endpoint,
    token: env.vault.token,
    agentEnabled: env.vault.agentEnabled,
    agentAuthMode: env.vault.agentAuthMode,
    agentTokenFilePath: env.vault.agentTokenFilePath,
    agentListenerEnabled: env.vault.agentListenerEnabled,
    agentListenerAddr: env.vault.agentListenerAddr,
    kvMount: env.vault.kvMount,
    writeRetryAttempts: env.vault.writeRetryAttempts,
    writeRetryBaseDelayMs: env.vault.writeRetryBaseDelayMs,
    writeRetryMaxDelayMs: env.vault.writeRetryMaxDelayMs
  });

  const splunkClient = new SplunkServiceClient({
    timeoutMs: env.splunk.timeoutMs,
    verifyTls: env.splunk.verifyTls
  });

  const tokenVerifier =
    env.transport.http.tokenSource === "vault" || env.transport.http.tokenSource === "both"
      ? createVaultTokenVerifier({
          vaultService,
          indexPath: env.transport.http.vaultTokenIndexPath,
          defaultUserId: env.transport.http.vaultTokenDefaultUserId,
          requiredScopes: env.transport.http.vaultTokenRequiredScopes,
          requiredAudience: env.transport.http.vaultTokenRequiredAudience,
          cacheTtlMs: env.transport.http.vaultTokenCacheTtlMs
        })
      : undefined;

  const oauth2Verifier =
    env.transport.http.authMode === "oauth2" || env.transport.http.authMode === "both"
      ? createOAuth2IntrospectionVerifier({
          introspectionUrl: env.transport.http.oauth2IntrospectionUrl,
          clientId: env.transport.http.oauth2ClientId,
          clientSecret: env.transport.http.oauth2ClientSecret,
          requiredScopes: env.transport.http.oauth2RequiredScopes,
          requiredAudience: env.transport.http.oauth2RequiredAudience,
          timeoutMs: env.transport.http.oauth2TimeoutMs,
          cacheTtlMs: env.transport.http.oauth2CacheTtlMs
        })
      : undefined;

  const httpServer = createHttpMcpServer({
    host: env.transport.http.host,
    port: env.transport.http.port,
    mcpPath: env.transport.http.mcpPath,
    healthPath: env.transport.http.healthPath,
    authMode: env.transport.http.authMode,
    authTokens: env.transport.http.authTokens,
    tokenVerifier,
    oauth2Verifier,
    trustedProxy: env.transport.http.trustedProxy,
    allowedOrigins: env.transport.http.allowedOrigins,
    allowedIps: env.transport.http.allowedIps,
    maxBodyBytes: env.transport.http.maxBodyBytes,
    rateLimitWindowMs: env.transport.http.rateLimitWindowMs,
    rateLimitMaxRequests: env.transport.http.rateLimitMaxRequests,
    createMcpServer: () =>
      createMcpServer({
        name: env.mcpServerName,
        version: env.mcpServerVersion,
        splunkClient,
        configStore,
        vaultService,
        runtimeEnv: env
      })
  });

  await httpServer.start();

  console.log(
    `HTTP MCP server listening on http://${httpServer.host}:${httpServer.port}${httpServer.mcpPath}`
  );

  const shutdown = async () => {
    await Promise.allSettled([httpServer.close(), configStore.close()]);
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("HTTP MCP server failed to start", error);
  process.exit(1);
});
