import { Link, Navigate, Route, Routes } from "react-router-dom";
import { getToken } from "../lib/api";
import { AuditPage } from "./AuditPage";
import { MembersPage } from "./MembersPage";
import { PolicyPage } from "./PolicyPage";

export function AppShell() {
  if (!getToken()) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col p-4">
      <header className="mb-4 rounded-xl border border-border bg-card p-4">
        <h1 className="text-lg font-semibold">AI-Hermas 4A Console</h1>
        <nav className="mt-3 flex gap-4 text-sm text-slate-700">
          <Link to="/app">Members</Link>
          <Link to="/app/policy">Policy</Link>
          <Link to="/app/audit">Audit</Link>
        </nav>
      </header>
      <Routes>
        <Route path="/" element={<MembersPage />} />
        <Route path="/policy" element={<PolicyPage />} />
        <Route path="/audit" element={<AuditPage />} />
      </Routes>
    </div>
  );
}
