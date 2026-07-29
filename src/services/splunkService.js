const DEFAULT_TIMEOUT_MS = 30000;
const API_FAMILIES = new Set(["enterprise", "soar"]);

function normalizeMethod(method) {
  return String(method ?? "GET").trim().toUpperCase();
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/services";
  }

  return raw.startsWith("/") ? raw : `/${raw}`;
}

function joinUrl(baseUrl, path, query) {
  const normalizedPath = normalizePath(path);
  const url = new URL(normalizedPath, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);

  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          url.searchParams.append(key, String(entry));
        }
        continue;
      }

      url.searchParams.set(key, String(value));
    }
  }

  return url;
}

function parseResponseBody(contentType, text) {
  if (!text) {
    return null;
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  return text;
}

function asFormBody(payload) {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(payload ?? {})) {
    if (value === undefined || value === null) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        params.append(key, String(item));
      }
      continue;
    }

    params.append(key, String(value));
  }

  return params.toString();
}

function buildAuthHeaders(authMode, secret) {
  const normalized = String(authMode ?? "none").toLowerCase();
  const source = secret && typeof secret === "object" ? secret : {};

  if (normalized === "none") {
    return {};
  }

  if (normalized === "bearer") {
    const token = String(source.token ?? "").trim();
    if (!token) {
      throw new Error("Missing bearer token in Vault auth secret");
    }
    return { Authorization: `Bearer ${token}` };
  }

  if (normalized === "splunk") {
    const sessionKey = String(source.sessionKey ?? source.token ?? "").trim();
    if (!sessionKey) {
      throw new Error("Missing Splunk session key/token in Vault auth secret");
    }
    return { Authorization: `Splunk ${sessionKey}` };
  }

  if (normalized === "basic") {
    const username = String(source.username ?? "").trim();
    const password = String(source.password ?? "");
    if (!username) {
      throw new Error("Missing basic username in Vault auth secret");
    }

    const credential = Buffer.from(`${username}:${password}`).toString("base64");
    return { Authorization: `Basic ${credential}` };
  }

  if (normalized === "phantom") {
    const token = String(source.phAuthToken ?? source.token ?? "").trim();
    if (!token) {
      throw new Error("Missing Phantom auth token in Vault auth secret");
    }
    return { "ph-auth-token": token };
  }

  throw new Error(`Unsupported Splunk auth mode: ${authMode}`);
}

function normalizeApiFamily(apiFamily) {
  const normalized = String(apiFamily ?? "enterprise").trim().toLowerCase();
  if (!API_FAMILIES.has(normalized)) {
    const error = new Error(`Unsupported API family: ${apiFamily}`);
    error.status = 400;
    throw error;
  }
  return normalized;
}

function assertValidPathForApiFamily(path, apiFamily) {
  if (apiFamily === "enterprise") {
    if (!path.startsWith("/services") && !path.startsWith("/servicesNS")) {
      const error = new Error("Splunk REST path must start with /services or /servicesNS");
      error.status = 400;
      throw error;
    }
    return;
  }

  if (!path.startsWith("/rest")) {
    const error = new Error("Splunk SOAR (Phantom) REST path must start with /rest");
    error.status = 400;
    throw error;
  }
}

export class SplunkServiceClient {
  constructor({ timeoutMs = DEFAULT_TIMEOUT_MS, verifyTls = false } = {}) {
    this.timeoutMs = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_TIMEOUT_MS;
    this.verifyTls = Boolean(verifyTls);
  }

  getConnectionInfo() {
    return {
      timeoutMs: this.timeoutMs,
      verifyTls: this.verifyTls
    };
  }

  async request({
    baseUrl,
    method = "GET",
    path = "/services",
    query,
    body,
    headers = {},
    authMode = "none",
    authSecret,
    bodyFormat = "form",
    apiFamily = "enterprise"
  }) {
    const upperMethod = normalizeMethod(method);
    const normalizedPath = normalizePath(path);
    const normalizedApiFamily = normalizeApiFamily(apiFamily);

    assertValidPathForApiFamily(normalizedPath, normalizedApiFamily);

    const url = joinUrl(baseUrl, normalizedPath, query);
    const requestHeaders = {
      Accept: "application/json, text/plain, text/xml, application/xml",
      ...headers
    };

    Object.assign(requestHeaders, buildAuthHeaders(authMode, authSecret));

    let payload;
    if (body !== undefined && body !== null && !["GET", "HEAD"].includes(upperMethod)) {
      if (typeof body === "string") {
        payload = body;
      } else if (bodyFormat === "json") {
        payload = JSON.stringify(body);
        if (!requestHeaders["Content-Type"] && !requestHeaders["content-type"]) {
          requestHeaders["Content-Type"] = "application/json";
        }
      } else {
        payload = asFormBody(body);
        if (!requestHeaders["Content-Type"] && !requestHeaders["content-type"]) {
          requestHeaders["Content-Type"] = "application/x-www-form-urlencoded";
        }
      }
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: upperMethod,
        headers: requestHeaders,
        body: payload,
        signal: controller.signal
      });

      const text = await response.text();
      const contentType = String(response.headers.get("content-type") ?? "");
      const parsed = parseResponseBody(contentType, text);

      if (!response.ok) {
        const error = new Error(`Splunk request failed: ${upperMethod} ${url.pathname} -> ${response.status}`);
        error.status = response.status;
        error.response = parsed;
        throw error;
      }

      return {
        method: upperMethod,
        apiFamily: normalizedApiFamily,
        path: url.pathname,
        url: url.toString(),
        status: response.status,
        contentType,
        data: parsed
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
