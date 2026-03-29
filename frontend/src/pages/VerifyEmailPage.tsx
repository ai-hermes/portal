import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { verifyEmail } from "../lib/api";

export function VerifyEmailPage() {
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const location = useLocation();
  const navigate = useNavigate();

  const email = useMemo(() => {
    const q = new URLSearchParams(location.search);
    return q.get("email") ?? "";
  }, [location.search]);

  async function onVerify() {
    try {
      setLoading(true);
      setError("");
      await verifyEmail(email, code);
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
        <h1 className="text-xl font-semibold">Verify Email</h1>
        <Input value={email} disabled />
        <Input placeholder="6-digit code" value={code} onChange={(e) => setCode(e.currentTarget.value)} />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button onClick={onVerify} disabled={loading || !email} className="w-full">
          {loading ? "Verifying..." : "Verify"}
        </Button>
        <Link to="/login" className="text-sm text-slate-600 hover:underline">
          Back to login
        </Link>
      </Card>
    </div>
  );
}
