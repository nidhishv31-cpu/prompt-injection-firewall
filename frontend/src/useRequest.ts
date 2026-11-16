import { useEffect, useState } from "react";
import { api } from "./api";

export function useData<T>(path: string, interval = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    let pending = false;
    async function refresh() {
      if (pending) return;
      pending = true;
      try {
        const value = await api<T>(path);
        if (active) {
          setData(value);
          setError("");
        }
      } catch (error) {
        if (active) setError(String(error));
      } finally {
        pending = false;
      }
    }
    void refresh();
    const timer = interval ? window.setInterval(refresh, interval) : undefined;
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [path, interval]);
  return { data, error };
}

export function useAction<T>(path: string, method = "POST") {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(body: unknown) {
    setBusy(true);
    setError("");
    try {
      const result = await api<T>(path, body, method);
      setData(result);
      return result;
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  }
  return { data, error, busy, submit };
}
