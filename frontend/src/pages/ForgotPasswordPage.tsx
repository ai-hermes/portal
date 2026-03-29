import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { forgotPassword } from "../lib/api";

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  async function onSubmit() {
    try {
      setLoading(true);
      setError("");
      await forgotPassword(email);
      setDone(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-slate-100 to-slate-50 p-4">
      <Card className="w-full max-w-md space-y-4">
        <h1 className="text-xl font-semibold">Forgot Password</h1>
        <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
        {error && <p className="text-sm text-red-600">{error}</p>}
        {done && <p className="text-sm text-emerald-700">If the account exists, reset instructions were sent.</p>}
        <Button onClick={onSubmit} disabled={loading} className="w-full">
          {loading ? "Submitting..." : "Send reset token"}
        </Button>
        <div className="flex justify-between text-sm text-slate-600">
          <Link to="/reset-password" className="hover:underline">
            I have a token
          </Link>
          <Link to="/login" className="hover:underline">
            Back to login
          </Link>
        </div>
      </Card>
    </div>
  );
}
