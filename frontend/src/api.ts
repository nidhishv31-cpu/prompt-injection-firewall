export async function api<T>(path: string, body?: unknown, method = "POST"): Promise<T> {
  const response = await fetch(path, body === undefined ? {} : {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    const message = error?.detail ?? error?.response;
    throw new Error(typeof message === "string" ? message : `Request failed (${response.status}).`);
  }
  return response.json();
}

export type Reason = { layer: string; score: number; evidence: string; category: string | null };
export type Chat = {
  session_id: string;
  decision: string;
  risk: number;
  reasons: Reason[];
  response: string;
  normalized: string;
  latency_ms: number;
};
