"use client";

import { useEffect, useRef, useState } from "react";

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
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission | "unsupported">("default");
  const seenAlertIds = useRef(new Set<number>());

  useEffect(() => {
    setNotificationPermission(
      "Notification" in window ? Notification.permission : "unsupported",
    );
  }, []);

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
        initial.forEach((alert) => seenAlertIds.current.add(Number(alert.id)));
        const afterId = initial.reduce((max, alert) => Math.max(max, Number(alert.id) || 0), 0);
        source = new EventSource(`${API}/alerts/stream?after_id=${afterId}`);
        source.onopen = () => setConnection("live");
        source.onerror = () => setConnection("reconnecting");
        source.onmessage = (event) => {
          try {
            const incoming = JSON.parse(event.data) as AlertRecord;
            const alertId = Number(incoming.id);
            if (!Number.isFinite(alertId) || seenAlertIds.current.has(alertId)) return;
            seenAlertIds.current.add(alertId);
            setAlerts((current) => [incoming, ...current].sort((a, b) => b.id - a.id).slice(0, 50));

            const severity = incoming.severity.toLowerCase();
            if (
              "Notification" in window &&
              Notification.permission === "granted" &&
              ["high", "critical"].includes(severity)
            ) {
              const notification = new Notification("MailCipherX-AI high-risk alert", {
                body: incoming.summary,
                tag: `mailcipherx-alert-${alertId}`,
              });
              notification.onclick = () => {
                window.focus();
                notification.close();
              };
            }
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

  const enableBrowserNotifications = async () => {
    if (!("Notification" in window)) {
      setNotificationPermission("unsupported");
      return;
    }
    try {
      setNotificationPermission(await Notification.requestPermission());
    } catch {
      setNotificationPermission("denied");
    }
  };

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
        <div className="flex flex-wrap items-center justify-end gap-2">
          {notificationPermission !== "unsupported" && notificationPermission !== "denied" && (
            <button
              type="button"
              onClick={enableBrowserNotifications}
              disabled={notificationPermission === "granted"}
              className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-blue-500 disabled:cursor-default disabled:opacity-70"
            >
              {notificationPermission === "granted" ? "Browser alerts on" : "Enable browser alerts"}
            </button>
          )}
          <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${connection === "live" ? "border-emerald-700 text-emerald-300" : "border-slate-700 text-slate-400"}`}>
            {connectionLabel}
          </span>
        </div>
      </div>
      {notificationPermission === "denied" && (
        <p className="mt-3 text-xs text-slate-500">Browser alerts are blocked in this browser's site settings.</p>
      )}

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
