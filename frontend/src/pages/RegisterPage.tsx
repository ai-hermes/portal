import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { register, registerByPhone, sendRegisterSMSCode } from "../lib/api";

export function RegisterPage() {
  const [mode, setMode] = useState<"email" | "phone">("phone");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [sendingCode, setSendingCode] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    if (cooldown <= 0) {
      return;
    }
    const timer = window.setInterval(() => {
      setCooldown((value) => {
        if (value <= 1) {
          window.clearInterval(timer);
          return 0;
        }
        return value - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [cooldown]);

  async function onSendCode() {
    try {
      setSendingCode(true);
      setError("");
      await sendRegisterSMSCode(phone);
      setCooldown(60);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSendingCode(false);
    }
  }

  async function onRegister() {
    try {
      setLoading(true);
      setError("");
      if (mode === "email") {
        await register({ email, password, display_name: displayName });
        navigate(`/verify-email?email=${encodeURIComponent(email)}`);
        return;
      }
      await registerByPhone({ phone, code, password, display_name: displayName });
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
        <h1 className="text-xl font-semibold">Create Account</h1>
        <div className="grid grid-cols-2 gap-2">
          <Button
            onClick={() => setMode("phone")}
            className={`w-full ${mode === "phone" ? "" : "bg-slate-200 text-slate-700 hover:bg-slate-300"}`}
          >
            Phone
          </Button>
          <Button
            onClick={() => setMode("email")}
            className={`w-full ${mode === "email" ? "" : "bg-slate-200 text-slate-700 hover:bg-slate-300"}`}
          >
            Email
          </Button>
        </div>
        {mode === "email" ? (
          <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
        ) : (
          <div className="space-y-2">
            <Input placeholder="Phone (11 digits)" value={phone} onChange={(e) => setPhone(e.currentTarget.value)} />
            <div className="flex gap-2">
              <Input placeholder="6-digit code" value={code} onChange={(e) => setCode(e.currentTarget.value)} />
              <Button onClick={onSendCode} disabled={sendingCode || cooldown > 0} className="whitespace-nowrap">
                {cooldown > 0 ? `${cooldown}s` : sendingCode ? "Sending..." : "Send code"}
              </Button>
            </div>
          </div>
        )}
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
          {loading ? "Creating..." : mode === "phone" ? "Create with phone" : "Create with email"}
        </Button>
        <Link to="/login" className="text-sm text-slate-600 hover:underline">
          Back to login
        </Link>
      </Card>
    </div>
  );
}
