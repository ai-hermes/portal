import { useEffect, useState } from "react";
import { Button, Card, Input } from "../components/ui";
import { listAudit, type AuditEvent } from "../lib/api";

export function AuditPage() {
  const [action, setAction] = useState("");
  const [items, setItems] = useState<AuditEvent[]>([]);

  async function load() {
    const result = await listAudit(action || undefined);
    setItems(result.items);
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <Card>
      <div className="mb-3 flex gap-2">
        <Input placeholder="filter action" value={action} onChange={(e) => setAction(e.currentTarget.value)} />
        <Button onClick={load}>Search</Button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="p-2">ID</th>
              <th className="p-2">Actor</th>
              <th className="p-2">Action</th>
              <th className="p-2">Resource</th>
              <th className="p-2">Result</th>
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.id} className="border-b border-border">
                <td className="p-2">{e.id}</td>
                <td className="p-2">{e.actor}</td>
                <td className="p-2">{e.action}</td>
                <td className="p-2">{e.resource}</td>
                <td className="p-2">{e.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
