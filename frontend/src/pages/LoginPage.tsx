import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { exchangeCallback, setToken, startLogin } from "../lib/api";

export function LoginPage() {
  const [tenantID, setTenantID] = useState("tenant-acme");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function onLogin() {
    try {
      setLoading(true);
      setError("");
      const redirectURI = `${window.location.origin}/login`;
      const { auth_url } = await startLogin(tenantID, redirectURI);
      const url = new URL(auth_url);
      const code = url.searchParams.get("code") || "demo-code";
      const state = url.searchParams.get("state") || "state-demo";
      const callback = await exchangeCallback(code, state);
      setToken(callback.access_token);
      navigate("/app");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-slate-100 to-slate-50 p-4">
      <Card className="w-full max-w-md space-y-4">
        <h1 className="text-xl font-semibold">AI-Hermes Portal Login</h1>
        <p className="text-sm text-slate-600">OIDC bridge for tenant-scoped access.</p>
        <Input value={tenantID} onChange={(e) => setTenantID(e.currentTarget.value)} />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button onClick={onLogin} disabled={loading} className="w-full">
          {loading ? "Signing in..." : "Sign in"}
        </Button>
      </Card>
    </div>
  );
}
