import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { register } from "../lib/api";

export function RegisterPage() {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function onRegister() {
    try {
      setLoading(true);
      setError("");
      await register({ email, password, display_name: displayName });
      navigate(`/verify-email?email=${encodeURIComponent(email)}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-slate-100 to-slate-50 p-4">
      <Card className="w-full max-w-md space-y-4">
        <h1 className="text-xl font-semibold">Create Account</h1>
        <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
        <Input
          placeholder="Display Name (optional)"
          value={displayName}
          onChange={(e) => setDisplayName(e.currentTarget.value)}
        />
        <Input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
        />
        <p className="text-xs text-slate-500">Password must be at least 8 chars and include letters + digits.</p>
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button onClick={onRegister} disabled={loading} className="w-full">
          {loading ? "Creating..." : "Create account"}
        </Button>
        <Link to="/login" className="text-sm text-slate-600 hover:underline">
          Back to login
        </Link>
      </Card>
    </div>
  );
}
