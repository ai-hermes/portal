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

const tokenKey = "portal_access_token";
const apiBaseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") || "";

export function setToken(token: string) {
  localStorage.setItem(tokenKey, token);
}

export function getToken() {
  return localStorage.getItem(tokenKey) ?? "";
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const headers = new Headers(init?.headers ?? {});
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (!headers.has("Content-Type") && init?.body) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return (await res.json()) as T;
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

export async function startLogin(tenantID: string, redirectURI: string) {
  return apiFetch<{ auth_url: string; state: string }>(`${apiBaseURL}/api/v1/auth/login/start`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantID, redirect_uri: redirectURI })
  });
}

export async function exchangeCallback(code: string, state: string) {
  return apiFetch<{ access_token: string }>(
    `${apiBaseURL}/api/v1/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`
  );
}
