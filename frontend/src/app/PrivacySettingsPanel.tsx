"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";

const API = "https://threatloom.onrender.com";

type PrivacySettings = {
  retention_days: number;
  mask_email_addresses: boolean;
  mask_ip_addresses: boolean;
};

export default function PrivacySettingsPanel() {
  const [settings, setSettings] = useState<PrivacySettings>({
    retention_days: 0,
    mask_email_addresses: false,
    mask_ip_addresses: false,
  });
  const [retentionDays, setRetentionDays] = useState("0");
  const [maskEmails, setMaskEmails] = useState(false);
  const [maskIps, setMaskIps] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const applySettings = (value: PrivacySettings) => {
    setSettings(value);
    setRetentionDays(String(value.retention_days));
    setMaskEmails(value.mask_email_addresses);
    setMaskIps(value.mask_ip_addresses);
  };

  const loadSettings = useCallback(async () => {
    try {
      const response = await fetch(`${API}/privacy/settings`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not load privacy settings.");
      applySettings(data);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load privacy settings.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchSettings = async () => {
      try {
        const response = await fetch(`${API}/privacy/settings`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not load privacy settings.");
        if (cancelled) return;
        applySettings(data);
        setError("");
      } catch (reason) {
        if (cancelled) return;
        setError(reason instanceof Error ? reason.message : "Could not load privacy settings.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void fetchSettings();
    return () => {
      cancelled = true;
    };
  }, []);

  const saveSettings = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const retention = Number(retentionDays);
    if (!Number.isInteger(retention) || retention < 0 || retention > 3650) {
      setError("Retention must be a whole number from 0 to 3650 days.");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API}/privacy/settings`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          retention_days: retention,
          mask_email_addresses: maskEmails,
          mask_ip_addresses: maskIps,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not save privacy settings.");
      applySettings(data);
      setNotice(`Privacy settings saved. Retention removed ${data.cleanup_deleted_count || 0} expired investigation(s).`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not save privacy settings.");
    } finally {
      setBusy(false);
    }
  };

  const runRetention = async () => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API}/privacy/retention/run`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not run retention cleanup.");
      setNotice(data.retention_days === 0
        ? "Automatic retention is disabled; no investigations were removed."
        : `Retention cleanup removed ${data.deleted_count} expired investigation(s).`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not run retention cleanup.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-xl font-semibold">Privacy and retention</h3>
          <p className="mt-1 text-sm text-slate-400">Choose how long saved investigations remain and which identifiers are masked in outputs.</p>
        </div>
        <button
          onClick={() => {
            setLoading(true);
            void loadSettings();
          }}
          disabled={loading || busy}
          className="rounded-lg border border-slate-700 px-3 py-2 text-xs hover:border-blue-500 disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {error && <p className="mt-4 rounded-lg border border-red-900/50 bg-red-950/20 p-3 text-sm text-red-300">{error}</p>}
      {notice && <p className="mt-4 rounded-lg border border-emerald-900/50 bg-emerald-950/20 p-3 text-sm text-emerald-300">{notice}</p>}

      <form onSubmit={saveSettings} className="mt-5 grid gap-4 lg:grid-cols-[1fr_1fr]">
        <label className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
          <span className="block text-sm font-semibold text-slate-200">Investigation retention</span>
          <span className="mt-1 block text-xs text-slate-500">0 keeps saved investigations until you delete them. Saving a shorter period immediately removes expired records.</span>
          <div className="mt-3 flex items-center gap-2">
            <input type="number" min={0} max={3650} step={1} value={retentionDays} onChange={(event) => setRetentionDays(event.target.value)} className="w-28 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <span className="text-sm text-slate-400">days</span>
          </div>
        </label>

        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
          <p className="text-sm font-semibold text-slate-200">Mask identifiers in results</p>
          <label className="flex items-center gap-3 text-sm text-slate-300">
            <input type="checkbox" checked={maskEmails} onChange={(event) => setMaskEmails(event.target.checked)} className="h-4 w-4 accent-blue-500" />
            Mask email local parts
          </label>
          <label className="flex items-center gap-3 text-sm text-slate-300">
            <input type="checkbox" checked={maskIps} onChange={(event) => setMaskIps(event.target.checked)} className="h-4 w-4 accent-blue-500" />
            Mask IP addresses
          </label>
          <p className="text-xs leading-5 text-slate-500">Masking applies to analysis responses, saved investigation views, cases, relationship graphs, and PDF reports. Verified source downloads remain byte-for-byte original.</p>
        </div>

        <div className="flex flex-wrap items-center gap-3 lg:col-span-2">
          <button type="submit" disabled={loading || busy} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold hover:bg-blue-500 disabled:opacity-50">{busy ? "Saving…" : "Save privacy settings"}</button>
          <button type="button" onClick={runRetention} disabled={loading || busy} className="rounded-lg border border-slate-700 px-4 py-2 text-sm hover:border-amber-500 disabled:opacity-50">Run retention cleanup now</button>
          {!loading && <span className="text-xs text-slate-500">Current policy: {settings.retention_days === 0 ? "no automatic expiry" : `${settings.retention_days} days`}</span>}
        </div>
      </form>

      <p className="mt-4 text-xs leading-5 text-slate-500">Expired source files are purged and the investigation is removed; its hash-only custody record remains for integrity history. Scheduled cleanup runs hourly.</p>
    </section>
  );
}
