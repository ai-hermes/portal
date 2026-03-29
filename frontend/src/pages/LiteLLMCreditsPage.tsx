import { useMemo, useState } from "react";
import { Button, Card, Input } from "../components/ui";
import { adjustLiteLLMCredit, getLiteLLMCredit, listLiteLLMCreditEvents, type LiteLLMCreditEvent, type LiteLLMCreditSnapshot } from "../lib/api";

export function LiteLLMCreditsPage() {
  const [tenantID, setTenantID] = useState("");
  const [userID, setUserID] = useState("");
  const [mode, setMode] = useState<"set" | "delta">("delta");
  const [amount, setAmount] = useState("0");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(false);
  const [snapshot, setSnapshot] = useState<LiteLLMCreditSnapshot | null>(null);
  const [events, setEvents] = useState<LiteLLMCreditEvent[]>([]);
  const [error, setError] = useState("");

  const parsedAmount = useMemo(() => Number(amount), [amount]);

  async function onQuery() {
    setLoading(true);
    setError("");
    try {
      const res = await getLiteLLMCredit(tenantID.trim(), userID.trim());
      setSnapshot(res);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function onAdjust() {
    if (!Number.isFinite(parsedAmount)) {
      setError("Amount must be a valid number");
      return;
    }
    if (!reason.trim()) {
      setError("Reason is required");
      return;
    }

    setLoading(true);
    setError("");
    try {
      const res = await adjustLiteLLMCredit({
        tenant_id: tenantID.trim(),
        user_id: userID.trim(),
        mode,
        amount: parsedAmount,
        reason: reason.trim()
      });
      setSnapshot(res);
      const history = await listLiteLLMCreditEvents(10, 0);
      setEvents(history.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function onLoadEvents() {
    setLoading(true);
    setError("");
    try {
      const history = await listLiteLLMCreditEvents(20, 0);
      setEvents(history.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <h2 className="mb-3 text-base font-semibold">LiteLLM Credit Admin</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="Tenant ID" value={tenantID} onChange={(e) => setTenantID(e.currentTarget.value)} />
          <Input placeholder="User ID" value={userID} onChange={(e) => setUserID(e.currentTarget.value)} />
          <div>
            <label className="mb-1 block text-xs text-slate-600">Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.currentTarget.value as "set" | "delta")}
              className="w-full rounded-md border border-border bg-white px-3 py-2 text-sm outline-none ring-primary focus:ring-2"
            >
              <option value="delta">delta</option>
              <option value="set">set</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-600">Amount</label>
            <Input value={amount} onChange={(e) => setAmount(e.currentTarget.value)} />
          </div>
        </div>
        <div className="mt-3">
          <Input placeholder="Reason (required)" value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button disabled={loading || !tenantID.trim() || !userID.trim()} onClick={onQuery}>Query Credit</Button>
          <Button disabled={loading || !tenantID.trim() || !userID.trim()} onClick={onAdjust}>Adjust Credit</Button>
          <Button disabled={loading} onClick={onLoadEvents}>Load Events</Button>
        </div>
        {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
      </Card>

      {snapshot && (
        <Card>
          <h3 className="mb-3 text-sm font-semibold">Current Snapshot</h3>
          <div className="grid gap-2 text-sm md:grid-cols-2">
            <p>Tenant: {snapshot.tenant_id}</p>
            <p>User: {snapshot.user_id}</p>
            <p>Total Budget: {snapshot.budget_total}</p>
            <p>Spend Used: {snapshot.spend_used}</p>
            <p>Budget Remaining: {snapshot.budget_remaining}</p>
            <p>Unit: {snapshot.unit}</p>
          </div>
        </Card>
      )}

      <Card>
        <h3 className="mb-3 text-sm font-semibold">Recent Events</h3>
        {events.length === 0 ? (
          <p className="text-sm text-slate-500">No events loaded.</p>
        ) : (
          <div className="space-y-2">
            {events.map((event) => (
              <div key={event.id} className="rounded border border-border p-3 text-sm">
                <p>
                  {event.created_at} · {event.result} · {event.mode} {event.amount}
                </p>
                <p>
                  {event.tenant_id}/{event.user_id} · before {event.before_budget} {"->"} after {event.after_budget}
                </p>
                <p>reason: {event.reason}</p>
                {event.error_message && <p className="text-red-600">error: {event.error_message}</p>}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
