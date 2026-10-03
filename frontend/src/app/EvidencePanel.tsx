"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";

const API = "https://threatloom.onrender.com";

type EvidenceEvent = {
  id: number;
  event_type: string;
  recorded_at?: string;
  actor?: string;
  notes?: string;
  source_sha256?: string;
  previous_hash?: string;
  record_hash?: string;
};

type EvidenceBundle = {
  source?: {
    sha256?: string;
    analysis_text_sha256?: string;
    byte_length?: number;
    artifact_status?: string;
    artifact_verified?: boolean | null;
  };
  events?: EvidenceEvent[];
  ledger_integrity?: {
    verified?: boolean;
    entry_count?: number;
    first_failed_entry_id?: number | null;
  };
  note?: string;
};

export default function EvidencePanel({ investigationId }: { investigationId: number | string }) {
  const [bundle, setBundle] = useState<EvidenceBundle | null>(null);
  const [eventType, setEventType] = useState("reviewed");
  const [actor, setActor] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const loadEvidence = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API}/investigations/${investigationId}/evidence`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not load evidence history.");
      setBundle(data);
      setError("");
    } catch (reason) {
      setBundle(null);
      setError(reason instanceof Error ? reason.message : "Could not load evidence history.");
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  const addEvent = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    try {
      const response = await fetch(`${API}/investigations/${investigationId}/evidence/events`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_type: eventType, actor, notes }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not record custody event.");
      setNotes("");
      await loadEvidence();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not record custody event.");
      setLoading(false);
    }
  };

  const downloadSource = async () => {
    try {
      const response = await fetch(`${API}/investigations/${investigationId}/evidence/source`);
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Could not download verified source evidence.");
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `investigation-${investigationId}.eml`;
      link.click();
      URL.revokeObjectURL(objectUrl);
      await loadEvidence();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not download source evidence.");
    }
  };

  const source = bundle?.source;
  const ledgerOk = bundle?.ledger_integrity?.verified === true;
  const artifactOk = source?.artifact_verified === true;

  return (
    <section className="mt-5 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h5 className="font-semibold text-slate-100">Evidence chain of custody</h5>
          <p className="mt-1 text-xs text-slate-400">Source hashes, preserved message integrity, and custody events.</p>
        </div>
        <button onClick={() => void loadEvidence()} disabled={loading} className="rounded-lg border border-slate-700 px-3 py-2 text-xs hover:border-blue-500 disabled:opacity-50">
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      {error && <p className="mt-3 rounded-lg border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-200">{error}</p>}
      {bundle && source && (
        <>
          <div className="mt-4 grid gap-3 text-xs md:grid-cols-2">
            <div className="rounded-lg border border-slate-800 p-3">
              <p className="text-slate-500">Submitted source SHA-256</p>
              <p className="mt-1 break-all font-mono text-slate-300">{source.sha256 || "Unavailable"}</p>
            </div>
            <div className="rounded-lg border border-slate-800 p-3">
              <p className="text-slate-500">Analyzed text SHA-256</p>
              <p className="mt-1 break-all font-mono text-slate-300">{source.analysis_text_sha256 || "Unavailable"}</p>
            </div>
            <div className="rounded-lg border border-slate-800 p-3 text-slate-300">
              Source size: {source.byte_length ?? "Unknown"} bytes · Artifact: {source.artifact_status || "Unknown"}
            </div>
            <div className={`rounded-lg border p-3 ${ledgerOk && (source.artifact_verified === null || artifactOk) ? "border-emerald-900/60 text-emerald-300" : "border-amber-900/60 text-amber-200"}`}>
              Ledger {ledgerOk ? "verified" : `integrity issue at entry ${bundle.ledger_integrity?.first_failed_entry_id ?? "unknown"}`} · {artifactOk ? "source verified" : source.artifact_verified === null ? "no retained source bytes" : "source integrity issue"}
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button onClick={() => void downloadSource()} disabled={!artifactOk || !ledgerOk || loading} className="rounded-lg bg-blue-600 px-3 py-2 text-xs font-semibold hover:bg-blue-500 disabled:opacity-40">
              Download verified .eml
            </button>
            <span className="text-xs text-slate-500">{bundle.ledger_integrity?.entry_count ?? 0} ledger event(s)</span>
          </div>

          <form onSubmit={addEvent} className="mt-4 grid gap-2 rounded-lg border border-slate-800 p-3 md:grid-cols-[150px_180px_1fr_auto]">
            <select value={eventType} onChange={(event) => setEventType(event.target.value)} className="rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-200">
              <option value="reviewed">Reviewed</option>
              <option value="transferred">Transferred</option>
              <option value="custody_note">Custody note</option>
            </select>
            <input required value={actor} onChange={(event) => setActor(event.target.value)} placeholder="Actor label" className="rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-200" />
            <input value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Optional note" className="rounded-md border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-200" />
            <button disabled={loading || !ledgerOk} className="rounded-md border border-slate-700 px-3 py-2 text-xs hover:border-blue-500 disabled:opacity-40">Record event</button>
          </form>
          <p className="mt-2 text-[11px] text-slate-500">{bundle.note}</p>

          <ol className="mt-4 max-h-72 space-y-2 overflow-y-auto">
            {[...(bundle.events || [])].reverse().map((item) => (
              <li key={item.id} className="rounded-lg border border-slate-800 p-3 text-xs">
                <div className="flex flex-wrap justify-between gap-2 text-slate-300">
                  <span className="font-semibold">#{item.id} · {item.event_type} · {item.actor || "Unknown actor"}</span>
                  <time>{item.recorded_at ? new Date(item.recorded_at).toLocaleString() : "Unknown time"}</time>
                </div>
                {item.notes && <p className="mt-2 text-slate-400">{item.notes}</p>}
                <p className="mt-2 break-all font-mono text-[10px] text-slate-600">Record hash: {item.record_hash || "Unavailable"}</p>
              </li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
