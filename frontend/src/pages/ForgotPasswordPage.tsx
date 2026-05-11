import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Button, Card, Input } from "../components/ui";
import { resetPasswordByPhone, sendPasswordResetSMSCode } from "../lib/api";

export function ForgotPasswordPage() {
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
      await resetPasswordByPhone(phone.trim(), code.trim(), newPassword);
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
        {error && <p className="text-sm text-red-600">{error}</p>}
        {done && <p className="text-sm text-emerald-700">Password reset successfully. You can sign in now.</p>}
        <Button onClick={onSubmit} disabled={loading} className="w-full">
          {loading ? "Resetting..." : "Reset password"}
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
