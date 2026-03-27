import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { login } from "../lib/api";

export function LoginPage() {
  const [account, setAccount] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function onLogin() {
    try {
      setLoading(true);
      setError("");
      await login(account, password);
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
        <Input placeholder="Email or phone" value={account} onChange={(e) => setAccount(e.currentTarget.value)} />
        <Input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button onClick={onLogin} disabled={loading} className="w-full">
          {loading ? "Signing in..." : "Sign in"}
        </Button>
        <div className="flex justify-between text-sm text-slate-600">
          <Link to="/register" className="hover:underline">
            Create account
          </Link>
          <Link to="/forgot-password" className="hover:underline">
            Forgot password
          </Link>
        </div>
      </Card>
    </div>
  );
}
