"use client";

import { useEffect, useState } from "react";

const API = "https://threatloom.onrender.com";

type GmailMonitorStatus = {
  enabled: boolean;
  state: string;
  poll_interval_seconds: number;
  last_sync_at: string | null;
  last_error: string | null;
  processed_messages: number;
  skipped_messages: number;
  external_intel_enabled: boolean;
  new_mail_only: boolean;
  message_bodies_retained: boolean;
};

function formatTime(value: string | null) {
  if (!value) return "Not yet synced";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not yet synced" : date.toLocaleString();
}

function describeState(status: GmailMonitorStatus | null, error: string | null) {
  if (error) return "Monitor status is unavailable. Check that the analysis backend is online.";
  if (!status?.enabled || status.state === "not_configured") {
    return "Monitoring is off. Add the Gmail OAuth settings to the backend environment to enable it.";
  }
  if (status.state === "authorization_required") {
    return "Gmail authorization needs attention. Check the refresh token and consent settings.";
  }
  if (status.state === "service_unavailable") {
    return "Gmail could not be reached. The monitor will retry automatically.";
  }
  if (status.state === "analysis_error") {
    return "A new message could not be analyzed. The monitor will retry it.";
  }
  if (status.state === "monitoring_new_mail") {
    return "Connected. New Inbox messages are checked without marking them as read.";
  }
  return "Starting Gmail monitoring...";
}

export default function GmailMonitorPanel() {
  const [status, setStatus] = useState<GmailMonitorStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const response = await fetch(`${API}/gmail-monitor/status`, { cache: "no-store" });
        if (!response.ok) throw new Error("Could not load Gmail monitor status.");
        const data = (await response.json()) as GmailMonitorStatus;
        if (!cancelled) {
          setStatus(data);
          setError(null);
        }
      } catch {
        if (!cancelled) setError("unavailable");
      }
    };

    void load();
    const timer = window.setInterval(() => void load(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-xl font-semibold">Gmail / Google Workspace monitoring</h3>
          <p className="mt-1 text-sm text-slate-400">
            Read-only monitoring for new Inbox messages, with high-risk findings sent to the live alert feed.
          </p>
        </div>
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${status?.enabled && status.state === "monitoring_new_mail" ? "border-emerald-700 text-emerald-300" : "border-slate-700 text-slate-400"}`}>
          {status?.enabled ? status.state.replaceAll("_", " ") : "not configured"}
        </span>
      </div>

      <p className="mt-4 text-sm text-slate-300">{describeState(status, error)}</p>

      {status?.enabled && (
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-500">Check interval</p>
            <p className="mt-1 text-sm font-semibold text-slate-100">{status.poll_interval_seconds} seconds</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-500">New messages analyzed</p>
            <p className="mt-1 text-sm font-semibold text-slate-100">{status.processed_messages}</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-500">Last check</p>
            <p className="mt-1 text-sm font-semibold text-slate-100">{formatTime(status.last_sync_at)}</p>
          </div>
        </div>
      )}

      <p className="mt-4 text-xs leading-5 text-slate-500">
        The first connection sets a starting point; older mail is not backfilled. Message bodies and sender details are processed in memory and not saved by this monitor. Third-party reputation checks are off by default; enabling them sends extracted indicators to configured providers. SPF, DKIM, and DMARC still use DNS lookups.
      </p>
      {status?.last_error && (
        <p className="mt-2 text-xs text-amber-300">Monitor status: {status.last_error.replaceAll("_", " ")}</p>
      )}
      {!status && !error && <p className="mt-4 text-xs text-slate-500">Loading monitor status...</p>}
    </section>
  );
}
