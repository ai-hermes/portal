import { useEffect, useState } from "react";
import { Button, Card, Input } from "../components/ui";
import {
  adjustLiteLLMCredit,
  getMe,
  getLiteLLMAccess,
  getLiteLLMCredit,
  getLiteLLMMyCredit,
  listLiteLLMCreditEvents,
  listLiteLLMMyRecentCalls,
  listLiteLLMRecentCalls,
  type LiteLLMCreditEvent,
  type LiteLLMCreditSnapshot,
  type LiteLLMRecentCall
} from "../lib/api";

export function LiteLLMCreditsPage() {
  const [tenantID, setTenantID] = useState("");
  const [userID, setUserID] = useState("");
  const [mode, setMode] = useState<"set" | "delta">("delta");
  const [amount, setAmount] = useState("0");
  const [reason, setReason] = useState("");
  const [canManage, setCanManage] = useState(false);
  const [loading, setLoading] = useState(false);
  const [snapshot, setSnapshot] = useState<LiteLLMCreditSnapshot | null>(null);
  const [events, setEvents] = useState<LiteLLMCreditEvent[]>([]);
  const [recentCalls, setRecentCalls] = useState<LiteLLMRecentCall[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    getMe()
      .then((me) => {
        if (!tenantID && me.tenant_id) {
          setTenantID(me.tenant_id);
        }
        if (!userID && me.user_id) {
          setUserID(me.user_id);
        }
      })
      .catch(() => {
        // ignore
      });
  }, [tenantID, userID]);

  useEffect(() => {
    getLiteLLMAccess()
      .then((res) => setCanManage(Boolean(res.can_manage)))
      .catch(() => setCanManage(false));
  }, []);

  async function onQuery() {
    setLoading(true);
    setError("");
    try {
      const res = canManage
        ? await getLiteLLMCredit(tenantID.trim(), userID.trim())
        : await getLiteLLMMyCredit();
      setSnapshot(res);
      setTenantID(res.tenant_id || tenantID.trim());
      setUserID(res.user_id || userID.trim());
      const calls = canManage
        ? await listLiteLLMRecentCalls(res.tenant_id || tenantID.trim(), res.user_id || userID.trim(), 20)
        : await listLiteLLMMyRecentCalls(20);
      setRecentCalls(calls.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function onLoadEvents() {
    if (!canManage) {
      setError("Current account is not allowed to view LiteLLM admin events.");
      return;
    }
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

  async function onLoadRecentCalls() {
    setLoading(true);
    setError("");
    try {
      const calls = canManage
        ? await listLiteLLMRecentCalls(tenantID.trim(), userID.trim(), 20)
        : await listLiteLLMMyRecentCalls(20);
      setRecentCalls(calls.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function onCopyAPIKey() {
    if (!snapshot?.api_key) {
      return;
    }
    try {
      await navigator.clipboard.writeText(snapshot.api_key);
    } catch {
      setError("Failed to copy API key");
    }
  }

  async function onAdjust() {
    if (!canManage) {
      setError("Current account is not allowed to adjust LiteLLM credits.");
      return;
    }
    const parsedAmount = Number(amount);
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
      const tenant = tenantID.trim();
      const user = userID.trim();
      const res = await adjustLiteLLMCredit({
        tenant_id: tenant,
        user_id: user,
        mode,
        amount: parsedAmount,
        reason: reason.trim()
      });
      setSnapshot(res);
      const calls = await listLiteLLMRecentCalls(tenant, user, 20);
      setRecentCalls(calls.items);
      const history = await listLiteLLMCreditEvents(20, 0);
      setEvents(history.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function maskKey(value?: string) {
    if (!value) {
      return "-";
    }
    if (value.length <= 10) {
      return value;
    }
    return `${value.slice(0, 6)}***${value.slice(-4)}`;
  }

  function formatNumber(value?: number) {
    if (typeof value !== "number" || Number.isNaN(value)) {
      return "-";
    }
    return value.toLocaleString(undefined, { maximumFractionDigits: 6 });
  }

  function formatTime(value?: string) {
    if (!value) {
      return "-";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  }

  return (
    <div className="space-y-4">
      <Card>
        <h2 className="mb-3 text-base font-semibold">LiteLLM Credit Admin</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="Tenant ID" value={tenantID} readOnly />
          <Input placeholder="User ID" value={userID} readOnly />
          {canManage && (
            <>
              <div>
                <label className="mb-1 block text-xs text-slate-600">Adjustment Mode</label>
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
                <Input type="number" step="0.000001" value={amount} onChange={(e) => setAmount(e.currentTarget.value)} />
              </div>
            </>
          )}
        </div>
        {canManage ? (
          <div className="mt-3">
            <Input placeholder="Reason (required)" value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
          </div>
        ) : (
          <p className="mt-2 text-xs text-slate-500">Only authorized users can view Adjustment Mode and Amount.</p>
        )}
        <div className="mt-4 flex flex-wrap gap-2">
          <Button disabled={loading || !tenantID.trim() || !userID.trim()} onClick={onQuery}>Query Credit</Button>
          {canManage && <Button disabled={loading || !tenantID.trim() || !userID.trim()} onClick={onAdjust}>Adjust Credit</Button>}
          {canManage && <Button disabled={loading} onClick={onLoadEvents}>Load Events</Button>}
          {canManage && <Button disabled={loading || !tenantID.trim() || !userID.trim()} onClick={onLoadRecentCalls}>Load Recent Calls</Button>}
        </div>
        {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
      </Card>

      {snapshot && (
        <Card>
          <h3 className="mb-3 text-sm font-semibold">Current Snapshot</h3>
          <div className="grid gap-2 text-sm md:grid-cols-2">
            <p>Tenant: {snapshot.tenant_id}</p>
            <p>User: {snapshot.user_id}</p>
            <p>LiteLLM Key: {snapshot.key_alias || "-"}</p>
            <p>LiteLLM User: {snapshot.litellm_user_id || "-"}</p>
            <p>
              API Key: {maskKey(snapshot.api_key)}{" "}
              <button className="text-xs text-slate-600 underline" onClick={onCopyAPIKey} type="button">
                Copy
              </button>
            </p>
            <p>Quota Total: {formatNumber(snapshot.budget_total)}</p>
            <p>Quota Used: {formatNumber(snapshot.spend_used)}</p>
            <p>Quota Remaining: {formatNumber(snapshot.budget_remaining)}</p>
            <p>Unit: {snapshot.unit}</p>
          </div>
        </Card>
      )}

      <Card>
        <h3 className="mb-3 text-sm font-semibold">Recent LLM Calls</h3>
        {recentCalls.length === 0 ? (
          <p className="text-sm text-slate-500">No recent calls loaded.</p>
        ) : (
          <div className="space-y-2">
            {recentCalls.map((call, idx) => (
              <div key={`${call.at}-${idx}`} className="rounded border border-border p-3 text-sm">
                <p>{formatTime(call.at)} · {call.model || "unknown-model"}</p>
                <p>
                  Prompt: {formatNumber(call.prompt_tokens)} · Completion: {formatNumber(call.completion_tokens)} · Total: {formatNumber(call.total_tokens)}
                </p>
                <p>Cost: {formatNumber(call.cost)}</p>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <h3 className="mb-3 text-sm font-semibold">Recent Events</h3>
        {events.length === 0 ? (
          <p className="text-sm text-slate-500">No events loaded.</p>
        ) : (
          <div className="space-y-2">
            {events.map((event) => (
              <div key={event.id} className="rounded border border-border p-3 text-sm">
                <p>
                  {formatTime(event.created_at)} · {event.result} · {event.mode} {formatNumber(event.amount)}
                </p>
                <p>
                  {event.tenant_id}/{event.user_id} · before {formatNumber(event.before_budget)} {"->"} after {formatNumber(event.after_budget)}
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
