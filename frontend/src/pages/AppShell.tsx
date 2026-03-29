import { useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { getMe, getToken, logout, type Principal } from "../lib/api";
import { AuditPage } from "./AuditPage";
import { LiteLLMCreditsPage } from "./LiteLLMCreditsPage";
import { MembersPage } from "./MembersPage";
import { PolicyPage } from "./PolicyPage";

export function AppShell() {
  const [me, setMe] = useState<Principal | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    getMe().then(setMe).catch(() => setMe(null));
  }, []);

  if (!getToken()) {
    return <Navigate to="/login" replace />;
  }

  async function onLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col p-4">
      <header className="mb-4 rounded-xl border border-border bg-card p-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold">AI-Hermes 4A Console</h1>
          <button onClick={onLogout} className="text-sm text-slate-600 hover:underline">
            Logout
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          {me?.email || "unknown user"} · {me?.tenant_id || "unknown tenant"} · {me?.role || "unknown role"}
        </p>
        <nav className="mt-3 flex gap-4 text-sm text-slate-700">
          <Link to="/app">Members</Link>
          <Link to="/app/policy">Policy</Link>
          <Link to="/app/audit">Audit</Link>
          <Link to="/app/litellm-credits">LiteLLM Credits</Link>
        </nav>
      </header>
      <Routes>
        <Route path="/" element={<MembersPage />} />
        <Route path="/policy" element={<PolicyPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/litellm-credits" element={<LiteLLMCreditsPage />} />
      </Routes>
    </div>
  );
}
