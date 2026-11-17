import { useState, type FormEvent } from "react";

type Entry = {
  id: string;
  path: string;
  patch: string;
  status: "pending" | "approved" | "consumed" | "declined" | "expired";
  expires_at: number;
};
type Queue = { session: string | null; entries: Entry[] };
const endpoint = "/api/testing-approvals";

export function TestingApprovals() {
  const [key, setKey] = useState("");
  const [queue, setQueue] = useState<Queue>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function sync(entry?: Entry, choice?: "approve" | "decline") {
    const headers = { Authorization: `Bearer ${key.trim()}` };
    setBusy(true);
    setError("");
    try {
      if (entry && choice) {
        const result = await fetch(`${endpoint}/${entry.id}/${choice}`, { method: "POST", headers });
        if (result.status === 409 || result.status === 404) {
          setError("This request has changed. Review the refreshed queue.");
        } else if (!result.ok) {
          throw new Error("The decision could not be saved. Refresh before trying again.");
        } else {
          const updated: Entry = await result.json();
          setQueue(current => current && {
            ...current,
            entries: current.entries.map(row => row.id === updated.id ? updated : row),
          });
        }
      }
      const result = await fetch(endpoint, { headers });
      if (result.status === 401) {
        setQueue(undefined);
        throw new Error("The approval key was rejected.");
      }
      if (!result.ok) throw new Error("The approval queue is unavailable.");
      setQueue(await result.json() as Queue);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The approval queue is unavailable.");
    } finally {
      setBusy(false);
    }
  }

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void sync();
  }

  return <section className="panel" aria-labelledby="approvals-heading">
    <div className="panel-heading approval-heading">
      <h2 id="approvals-heading">Testing approvals</h2>
      {queue && <button type="button" onClick={() => void sync()} disabled={busy}>Refresh</button>}
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {!queue && <form className="form-row" onSubmit={connect}>
      <label className="grow">Local approval key
        <input type="password" value={key} autoComplete="off" onChange={event => setKey(event.target.value)} required />
      </label>
      <button className="primary" disabled={busy} type="submit">Unlock queue</button>
    </form>}
    {queue && !queue.session && <p className="quiet">No Codex test chat selected.</p>}
    {queue?.session && <>
      <p className="quiet approval-session">Codex test session <code>{queue.session}</code></p>
      {!queue.entries.length && <p className="quiet">No edits waiting for review.</p>}
      {queue.entries.map(entry => <article className="approval-entry" key={entry.id}>
        <div className="panel-heading approval-heading">
          <h3><code>{entry.path}</code></h3>
          <span className="status" data-status={{
            pending: "flag", approved: "allow", consumed: "allow",
            declined: "block", expired: "expired",
          }[entry.status]}>{entry.status}</span>
        </div>
        {entry.patch && <pre className="approval-patch" tabIndex={0} aria-label={`Proposed patch for ${entry.path}`}>{entry.patch}</pre>}
        {(entry.status === "pending" || entry.status === "approved") &&
          <p className="quiet">Expires at {new Date(entry.expires_at * 1000).toLocaleTimeString()}.</p>}
        {entry.status === "pending" && <div className="form-row">
          <button type="button" className="primary" disabled={busy} onClick={() => void sync(entry, "approve")}>Approve once</button>
          <button type="button" disabled={busy} onClick={() => void sync(entry, "decline")}>Decline</button>
        </div>}
      </article>)}
    </>}
    {queue && <button type="button" className="text-button" disabled={busy} onClick={() => {
      setQueue(undefined);
      setKey("");
      setError("");
    }}>Lock queue</button>}
  </section>;
}
