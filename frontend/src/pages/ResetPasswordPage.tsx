import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { resetPassword } from "../lib/api";

export function ResetPasswordPage() {
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function onSubmit() {
    try {
      setLoading(true);
      setError("");
      await resetPassword(token, newPassword);
      navigate("/login");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-slate-100 to-slate-50 p-4">
      <Card className="w-full max-w-md space-y-4">
        <h1 className="text-xl font-semibold">Reset Password</h1>
        <Input placeholder="Reset token" value={token} onChange={(e) => setToken(e.currentTarget.value)} />
        <Input
          placeholder="New password"
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.currentTarget.value)}
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button onClick={onSubmit} disabled={loading} className="w-full">
          {loading ? "Resetting..." : "Reset password"}
        </Button>
        <Link to="/login" className="text-sm text-slate-600 hover:underline">
          Back to login
        </Link>
      </Card>
    </div>
  );
}
