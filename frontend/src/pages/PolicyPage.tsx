import { useState } from "react";
import { Button, Card, Input } from "../components/ui";
import { checkPermission, writeRelationships } from "../lib/api";

export function PolicyPage() {
  const [subject, setSubject] = useState("u-admin");
  const [relation, setRelation] = useState("viewer");
  const [object, setObject] = useState("project:alpha");
  const [message, setMessage] = useState("");

  async function onWrite() {
    const res = await writeRelationships([{ subject, relation, object }]);
    setMessage(`wrote ${res.written} relationship(s)`);
  }

  async function onCheck() {
    const res = await checkPermission({ subject, relation, object });
    setMessage(`allowed=${String(res.allowed)}`);
  }

  return (
    <Card className="space-y-3">
      <h2 className="text-base font-semibold">Authorization Tuples</h2>
      <Input value={subject} onChange={(e) => setSubject(e.currentTarget.value)} />
      <Input value={relation} onChange={(e) => setRelation(e.currentTarget.value)} />
      <Input value={object} onChange={(e) => setObject(e.currentTarget.value)} />
      <div className="flex gap-2">
        <Button onClick={onWrite}>Write</Button>
        <Button onClick={onCheck} className="bg-slate-800">
          Check
        </Button>
      </div>
      {message && <p className="text-sm text-slate-700">{message}</p>}
    </Card>
  );
}
