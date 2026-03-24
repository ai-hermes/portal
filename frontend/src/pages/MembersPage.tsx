import { useEffect, useState } from "react";
import { Card } from "../components/ui";
import { listMembers, type Principal } from "../lib/api";

export function MembersPage() {
  const [items, setItems] = useState<Principal[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    listMembers("tenant-acme")
      .then((res) => setItems(res.items))
      .catch((e) => setError((e as Error).message));
  }, []);

  return (
    <Card>
      <h2 className="mb-3 text-base font-semibold">Tenant Members</h2>
      {error && <p className="mb-2 text-sm text-red-600">{error}</p>}
      <div className="space-y-2 text-sm">
        {items.map((m) => (
          <div key={m.user_id} className="rounded border border-border p-3">
            <p className="font-medium">{m.user_id}</p>
            <p className="text-slate-600">{m.email}</p>
            <p className="text-xs uppercase text-slate-500">{m.role}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}
