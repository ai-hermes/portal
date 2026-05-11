import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { forgotPassword, resetPasswordByPhone, sendPasswordResetSMSCode } from "../lib/api";

type ResetMode = "phone" | "email";

export function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<ResetMode>("phone");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [sendingCode, setSendingCode] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = window.setInterval(() => setCooldown((value) => (value > 0 ? value - 1 : 0)), 1000);
    return () => window.clearInterval(timer);
  }, [cooldown]);

  const canSendCode = useMemo(() => /^1\d{10}$/.test(phone.trim()) && cooldown === 0 && !sendingCode, [phone, cooldown, sendingCode]);

  async function onSendCode() {
    if (!canSendCode) return;
    try {
      setSendingCode(true);
      setError("");
      await sendPasswordResetSMSCode(phone.trim());
      setCooldown(60);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSendingCode(false);
    }
  }

  async function onSubmit() {
    try {
      setLoading(true);
      setError("");
      if (mode === "email") {
        await forgotPassword(email.trim());
      } else {
        await resetPasswordByPhone(phone.trim(), code.trim(), newPassword);
        window.setTimeout(() => navigate("/login"), 1200);
      }
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
        <h1 className="text-xl font-semibold">Reset Password</h1>
        <div className="grid grid-cols-2 rounded-md border border-border bg-slate-50 p-1 text-sm">
          <button
            type="button"
            className={`rounded px-3 py-1.5 ${mode === "phone" ? "bg-white font-semibold shadow-sm" : "text-slate-600"}`}
            onClick={() => {
              setMode("phone");
              setError("");
              setDone(false);
            }}
          >
            Phone
          </button>
          <button
            type="button"
            className={`rounded px-3 py-1.5 ${mode === "email" ? "bg-white font-semibold shadow-sm" : "text-slate-600"}`}
            onClick={() => {
              setMode("email");
              setError("");
              setDone(false);
            }}
          >
            Email
          </button>
        </div>
        {mode === "phone" ? (
          <>
            <Input placeholder="Phone number" value={phone} onChange={(e) => setPhone(e.currentTarget.value)} />
            <div className="flex gap-2">
              <Input placeholder="SMS code" value={code} onChange={(e) => setCode(e.currentTarget.value)} />
              <Button type="button" onClick={onSendCode} disabled={!canSendCode} className="whitespace-nowrap">
                {cooldown > 0 ? `${cooldown}s` : sendingCode ? "Sending..." : "Send code"}
              </Button>
            </div>
            <Input
              placeholder="New password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.currentTarget.value)}
            />
          </>
        ) : (
          <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
        )}
        {error && <p className="text-sm text-red-600">{error}</p>}
        {done && (
          <p className="text-sm text-emerald-700">
            {mode === "phone"
              ? "Password reset successfully. Redirecting to login..."
              : "If the account exists, reset instructions were sent."}
          </p>
        )}
        <Button onClick={onSubmit} disabled={loading} className="w-full">
          {loading ? "Submitting..." : mode === "phone" ? "Reset password" : "Send reset token"}
        </Button>
        <div className="flex justify-between text-sm text-slate-600">
          <Link to="/reset-password" className="hover:underline">
            I have an email token
          </Link>
          <Link to="/login" className="hover:underline">
            Back to login
          </Link>
        </div>
      </Card>
    </div>
  );
}
