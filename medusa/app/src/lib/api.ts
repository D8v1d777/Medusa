const getBaseUrl = (): string => {
  return (window as any).MEDUSA_API_URL || "http://127.0.0.1:17432";
};

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${getBaseUrl()}${path}`, init);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export const sessions = {
  list: () => api<Array<{ id: string; name: string }>>("/api/sessions"),
  create: (body: object) => api<{ id: string }>("/api/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }),
};
