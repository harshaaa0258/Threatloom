"use client";

import { useEffect, useState } from "react";

const API = "https://threatloom.onrender.com";

type AlertRecord = {
  id: number;
  type: string;
  summary: string;
  severity: string;
  created_at: string;
  payload?: Record<string, unknown>;
};

function formatTimestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export default function AlertFeed() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [connection, setConnection] = useState<"loading" | "live" | "reconnecting" | "unavailable">("loading");

  useEffect(() => {
    let source: EventSource | undefined;
    let cancelled = false;

    const load = async () => {
      try {
        const response = await fetch(`${API}/alerts`);
        if (!response.ok) throw new Error("Could not load alerts.");
        const data = await response.json();
        if (cancelled) return;

        const initial = Array.isArray(data.alerts) ? (data.alerts as AlertRecord[]) : [];
        setAlerts(initial.slice(0, 50));
        const afterId = initial.reduce((max, alert) => Math.max(max, Number(alert.id) || 0), 0);
        source = new EventSource(`${API}/alerts/stream?after_id=${afterId}`);
        source.onopen = () => setConnection("live");
        source.onerror = () => setConnection("reconnecting");
        source.onmessage = (event) => {
          try {
            const incoming = JSON.parse(event.data) as AlertRecord;
            setAlerts((current) => {
              if (current.some((alert) => alert.id === incoming.id)) return current;
              return [incoming, ...current].sort((a, b) => b.id - a.id).slice(0, 50);
            });
          } catch {
            // Ignore malformed events and keep the live stream open.
          }
        };
      } catch {
        if (!cancelled) setConnection("unavailable");
      }
    };

    void load();
    return () => {
      cancelled = true;
      source?.close();
    };
  }, []);

  const connectionLabel = {
    loading: "Loading",
    live: "Live",
    reconnecting: "Reconnecting",
    unavailable: "Unavailable",
  }[connection];

  return (
    <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-xl font-semibold">Live Alert Feed</h3>
          <p className="mt-1 text-sm text-slate-400">High-risk analysis events from the threat monitoring service.</p>
        </div>
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${connection === "live" ? "border-emerald-700 text-emerald-300" : "border-slate-700 text-slate-400"}`}>
          {connectionLabel}
        </span>
      </div>

      {alerts.length === 0 ? (
        <p className="mt-5 rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
          {connection === "unavailable" ? "Alert service is currently unavailable." : "No alerts recorded yet."}
        </p>
      ) : (
        <div className="mt-5 max-h-80 space-y-2 overflow-y-auto">
          {alerts.map((alert) => (
            <article key={alert.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950 p-4">
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-200">{alert.summary}</p>
                <p className="mt-1 text-xs text-slate-500">{alert.type.replaceAll("_", " ")} · {formatTimestamp(alert.created_at)}</p>
              </div>
              <span className={`rounded-full px-2.5 py-1 text-xs font-bold uppercase ${alert.severity.toLowerCase() === "high" ? "bg-rose-950 text-rose-300" : "bg-amber-950 text-amber-300"}`}>
                {alert.severity}
              </span>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
