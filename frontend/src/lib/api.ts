export type Principal = {
  tenant_id: string;
  user_id: string;
  email?: string;
  role?: string;
};

export type AuditEvent = {
  id: number;
  actor: string;
  action: string;
  resource: string;
  result: string;
  tenant_id: string;
  at: string;
};

type TokenPair = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
};

type APIErrorPayload = {
  error?: {
    code?: string;
    message?: string;
  };
};

const accessTokenKey = "portal_access_token";
const refreshTokenKey = "portal_refresh_token";
const apiBaseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") || "";

export function setSession(pair: TokenPair) {
  localStorage.setItem(accessTokenKey, pair.access_token);
  localStorage.setItem(refreshTokenKey, pair.refresh_token);
}

export function clearSession() {
  localStorage.removeItem(accessTokenKey);
  localStorage.removeItem(refreshTokenKey);
}

export function getToken() {
  return localStorage.getItem(accessTokenKey) ?? "";
}

function getRefreshToken() {
  return localStorage.getItem(refreshTokenKey) ?? "";
}

async function readError(res: Response): Promise<Error> {
  const text = await res.text();
  if (!text) {
    return new Error(res.statusText || "request failed");
  }
  try {
    const json = JSON.parse(text) as APIErrorPayload;
    if (json.error?.message) {
      return new Error(json.error.message);
    }
  } catch {
    // ignore
  }
  return new Error(text);
}

async function tryRefreshToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return false;
  }

  const res = await fetch(`${apiBaseURL}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken })
  });
  if (!res.ok) {
    clearSession();
    return false;
  }

  const payload = (await res.json()) as TokenPair;
  setSession(payload);
  return true;
}

async function apiFetch<T>(path: string, init?: RequestInit, retry = true): Promise<T> {
  const headers = new Headers(init?.headers ?? {});
  const token = getToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (!headers.has("Content-Type") && init?.body) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401 && retry) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      return apiFetch<T>(path, init, false);
    }
  }
  if (!res.ok) {
    throw await readError(res);
  }
  return (await res.json()) as T;
}

export async function register(input: { email: string; password: string; display_name?: string }) {
  return apiFetch<{ user_id: string; tenant_id: string }>(`${apiBaseURL}/api/v1/auth/register`, {
    method: "POST",
    body: JSON.stringify(input)
  });
}

export async function verifyEmail(email: string, code: string) {
  return apiFetch<{ verified: boolean }>(`${apiBaseURL}/api/v1/auth/verify-email`, {
    method: "POST",
    body: JSON.stringify({ email, code })
  });
}

export async function login(email: string, password: string) {
  const pair = await apiFetch<TokenPair>(`${apiBaseURL}/api/v1/auth/login`, {
    method: "POST",
    body: JSON.stringify({ email, password })
  });
  setSession(pair);
  return pair;
}

export async function logout() {
  const refreshToken = getRefreshToken();
  if (refreshToken) {
    await apiFetch<{ ok: boolean }>(`${apiBaseURL}/api/v1/auth/logout`, {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken })
    });
  }
  clearSession();
}

export async function forgotPassword(email: string) {
  return apiFetch<{ ok: boolean }>(`${apiBaseURL}/api/v1/auth/password/forgot`, {
    method: "POST",
    body: JSON.stringify({ email })
  });
}

export async function resetPassword(token: string, newPassword: string) {
  return apiFetch<{ ok: boolean }>(`${apiBaseURL}/api/v1/auth/password/reset`, {
    method: "POST",
    body: JSON.stringify({ token, new_password: newPassword })
  });
}

export async function changePassword(oldPassword: string, newPassword: string) {
  return apiFetch<{ ok: boolean }>(`${apiBaseURL}/api/v1/auth/password/change`, {
    method: "POST",
    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
  });
}

export function getMe() {
  return apiFetch<Principal>(`${apiBaseURL}/api/v1/me`);
}

export function listMembers(tenantID: string) {
  return apiFetch<{ items: Principal[] }>(`${apiBaseURL}/api/v1/tenants/${tenantID}/members`);
}

export function checkPermission(payload: { subject: string; relation: string; object: string }) {
  return apiFetch<{ allowed: boolean }>(`${apiBaseURL}/api/v1/permissions/check`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function writeRelationships(tuples: Array<{ subject: string; relation: string; object: string }>) {
  return apiFetch<{ written: number }>(`${apiBaseURL}/api/v1/policies/relationships`, {
    method: "POST",
    body: JSON.stringify({ tuples })
  });
}

export function listAudit(action?: string) {
  const q = action ? `?action=${encodeURIComponent(action)}` : "";
  return apiFetch<{ items: AuditEvent[] }>(`${apiBaseURL}/api/v1/audit/events${q}`);
}
