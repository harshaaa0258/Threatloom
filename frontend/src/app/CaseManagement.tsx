"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";

const API = "https://threatloom.onrender.com";

type CaseRecord = {
  id: number;
  title: string;
  description: string;
  status: "open" | "closed";
  tags: string[];
  investigation_count: number;
};

type InvestigationRecord = {
  id: number;
  sender?: string;
  subject?: string;
  created_at?: string;
  threat_score?: number;
  risk_level?: string;
  classification?: string;
};

type CaseDetails = {
  case: CaseRecord;
  investigations: InvestigationRecord[];
};

type CampaignSuggestion = {
  investigation_ids: number[];
  investigations: InvestigationRecord[];
  shared_indicators: Array<{ type: string; value: string; investigation_count: number }>;
  signal_strength: string;
  note: string;
};

export default function CaseManagement() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selected, setSelected] = useState<CaseDetails | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [caseSearch, setCaseSearch] = useState("");
  const [investigationSearch, setInvestigationSearch] = useState("");
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [campaignSuggestions, setCampaignSuggestions] = useState<CampaignSuggestion[]>([]);
  const [investigationId, setInvestigationId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const loadCases = useCallback(async (query: string) => {
    const response = await fetch(`${API}/cases?search=${encodeURIComponent(query)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Could not load cases.");
    setCases(Array.isArray(data.cases) ? data.cases : []);
  }, []);

  const loadCase = async (id: number) => {
    const response = await fetch(`${API}/cases/${id}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Could not load this case.");
    setSelected(data);
    setSelectedId(id);
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      loadCases(caseSearch).catch((reason) => setError(reason.message));
    }, 180);
    return () => window.clearTimeout(timer);
  }, [caseSearch, loadCases]);

  useEffect(() => {
    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch(
          `${API}/investigations?search=${encodeURIComponent(investigationSearch)}&limit=100`,
        );
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not search investigations.");
        setInvestigations(Array.isArray(data.investigations) ? data.investigations : []);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Could not search investigations.");
      }
    }, 180);
    return () => window.clearTimeout(timer);
  }, [investigationSearch]);

  useEffect(() => {
    let cancelled = false;
    const loadSuggestions = async () => {
      try {
        const response = await fetch(`${API}/campaigns/suggestions`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not load campaign suggestions.");
        if (!cancelled) {
          setCampaignSuggestions(
            Array.isArray(data.suggestions) ? data.suggestions : [],
          );
        }
      } catch (reason) {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : "Could not load campaign suggestions.");
        }
      }
    };
    void loadSuggestions();
    return () => {
      cancelled = true;
    };
  }, []);

  const createSuggestedCampaign = async (suggestion: CampaignSuggestion) => {
    setBusy(true);
    setError("");
    try {
      const first = suggestion.investigations[0];
      const title = `Campaign: ${first?.sender || first?.subject || `investigations ${suggestion.investigation_ids.join(", ")}`}`;
      const response = await fetch(`${API}/campaigns/from-suggestion`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          investigation_ids: suggestion.investigation_ids,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not create campaign case.");
      await Promise.all([
        loadCases(caseSearch),
        loadCase(data.case_id),
      ]);
      setCampaignSuggestions((current) =>
        current.filter((item) => item !== suggestion),
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create campaign case.");
    } finally {
      setBusy(false);
    }
  };

  const createCase = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`${API}/cases`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          description,
          tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not create case.");
      setTitle("");
      setDescription("");
      setTags("");
      await loadCases(caseSearch);
      await loadCase(data.case_id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create case.");
    } finally {
      setBusy(false);
    }
  };

  const updateStatus = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const response = await fetch(`${API}/cases/${selected.case.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: selected.case.status === "open" ? "closed" : "open" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not update case.");
      await Promise.all([loadCases(caseSearch), loadCase(selected.case.id)]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update case.");
    } finally {
      setBusy(false);
    }
  };

  const deleteCase = async () => {
    if (!selected || !window.confirm(`Delete case “${selected.case.title}”?`)) return;
    setBusy(true);
    try {
      const response = await fetch(`${API}/cases/${selected.case.id}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not delete case.");
      setSelected(null);
      setSelectedId(null);
      await loadCases(caseSearch);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not delete case.");
    } finally {
      setBusy(false);
    }
  };

  const addInvestigation = async () => {
    if (!selected || !investigationId) return;
    setBusy(true);
    try {
      const response = await fetch(
        `${API}/cases/${selected.case.id}/investigations/${investigationId}`,
        { method: "PUT" },
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not add investigation.");
      setInvestigationId("");
      await Promise.all([loadCases(caseSearch), loadCase(selected.case.id)]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not add investigation.");
    } finally {
      setBusy(false);
    }
  };

  const removeInvestigation = async (id: number) => {
    if (!selected) return;
    setBusy(true);
    try {
      const response = await fetch(
        `${API}/cases/${selected.case.id}/investigations/${id}`,
        { method: "DELETE" },
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not remove investigation.");
      await Promise.all([loadCases(caseSearch), loadCase(selected.case.id)]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not remove investigation.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-5">
        <h3 className="text-xl font-semibold">Campaign cases</h3>
        <p className="mt-1 text-sm text-slate-400">
          Group related investigations, search cases, and track review status.
        </p>
      </div>

      {error && <p className="mb-4 rounded-lg border border-red-900/50 bg-red-950/20 p-3 text-sm text-red-300">{error}</p>}

      <div className="mb-5 rounded-xl border border-blue-900/60 bg-blue-950/20 p-4">
        <h4 className="font-semibold text-blue-100">Suggested campaign clusters</h4>
        <p className="mt-1 text-xs text-slate-400">Suggestions use shared senders, public origin IPs, reply domains, and linked URL domains. Review each cluster before creating a case.</p>
        {campaignSuggestions.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No multi-investigation clusters found.</p>
        ) : (
          <div className="mt-3 space-y-3">
            {campaignSuggestions.map((suggestion) => (
              <div key={suggestion.investigation_ids.join("-")} className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-slate-100">{suggestion.investigation_ids.length} related investigations · {suggestion.shared_indicators.length} shared indicators · {suggestion.signal_strength.replaceAll("_", " ")}</p>
                    <p className="mt-1 text-xs text-slate-400">
                      {suggestion.shared_indicators.map((item) => `${item.type.replaceAll("_", " ")}: ${item.value} (${item.investigation_count})`).join(" · ")}
                    </p>
                    <p className="mt-1 text-[11px] text-slate-500">{suggestion.note}</p>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void createSuggestedCampaign(suggestion)}
                    className="rounded-lg border border-blue-800 px-3 py-2 text-xs font-semibold text-blue-200 hover:bg-blue-950 disabled:opacity-50"
                  >
                    Create campaign case
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <form onSubmit={createCase} className="grid gap-3 rounded-xl border border-slate-800 bg-slate-950/50 p-4 md:grid-cols-2">
        <input required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Case title" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="Tags, separated by commas" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        <input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Short case description" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm md:col-span-2" />
        <button disabled={busy} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold hover:bg-blue-500 disabled:opacity-50 md:col-span-2">
          {busy ? "Saving…" : "Create case"}
        </button>
      </form>

      <div className="mt-5 grid gap-5 lg:grid-cols-[minmax(240px,0.8fr)_minmax(0,1.5fr)]">
        <div>
          <input value={caseSearch} onChange={(event) => setCaseSearch(event.target.value)} placeholder="Search cases, descriptions, tags" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
          <div className="mt-3 max-h-[440px] space-y-2 overflow-y-auto">
            {cases.map((item) => (
              <button key={item.id} onClick={() => loadCase(item.id).catch((reason) => setError(reason.message))} className={`block w-full rounded-xl border p-3 text-left ${selectedId === item.id ? "border-blue-500 bg-blue-950/30" : "border-slate-800 bg-slate-950/50 hover:border-slate-600"}`}>
                <span className="flex items-center justify-between gap-2 font-medium text-slate-100"><span>{item.title}</span><span className="text-xs uppercase text-slate-400">{item.status}</span></span>
                <span className="mt-1 block text-xs text-slate-400">{item.investigation_count} investigation(s){item.tags.length ? ` · ${item.tags.join(", ")}` : ""}</span>
              </button>
            ))}
            {cases.length === 0 && <p className="py-4 text-sm text-slate-500">No matching cases.</p>}
          </div>
        </div>

        {selected ? (
          <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h4 className="text-lg font-semibold text-white">{selected.case.title}</h4>
                <p className="mt-1 text-sm text-slate-400">{selected.case.description || "No description"}</p>
                {selected.case.tags.length > 0 && <p className="mt-2 text-xs text-blue-300">Tags: {selected.case.tags.join(", ")}</p>}
              </div>
              <div className="flex gap-2">
                <button disabled={busy} onClick={updateStatus} className="rounded-lg border border-slate-700 px-3 py-2 text-xs hover:border-blue-500">Mark {selected.case.status === "open" ? "closed" : "open"}</button>
                <button disabled={busy} onClick={deleteCase} className="rounded-lg border border-red-900/70 px-3 py-2 text-xs text-red-300 hover:bg-red-950/50">Delete</button>
              </div>
            </div>

            <div className="mt-5 grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
              <input value={investigationSearch} onChange={(event) => setInvestigationSearch(event.target.value)} placeholder="Search sender, subject, IP…" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
              <select value={investigationId} onChange={(event) => setInvestigationId(event.target.value)} className="min-w-0 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                <option value="">Select investigation to add</option>
                {investigations.map((item) => <option key={item.id} value={item.id}>#{item.id} · {item.sender || "Unknown sender"} · {item.subject || "No subject"}</option>)}
              </select>
              <button disabled={busy || !investigationId} onClick={addInvestigation} className="rounded-lg bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700 disabled:opacity-50">Add</button>
            </div>

            <div className="mt-4 space-y-2">
              {selected.investigations.map((item) => (
                <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 p-3 text-sm">
                  <div className="min-w-0">
                    <p className="font-medium text-slate-200">#{item.id} · {item.subject || "No subject"}</p>
                    <p className="mt-1 break-all text-xs text-slate-400">{item.sender || "Unknown sender"} · {item.classification || item.risk_level || "Unclassified"} · score {item.threat_score ?? "--"}</p>
                  </div>
                  <button disabled={busy} onClick={() => removeInvestigation(item.id)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-red-500">Remove</button>
                </div>
              ))}
              {selected.investigations.length === 0 && <p className="py-3 text-sm text-slate-500">No investigations attached to this case yet.</p>}
            </div>
          </div>
        ) : (
          <div className="flex min-h-48 items-center justify-center rounded-xl border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">Create or select a case to group related investigations.</div>
        )}
      </div>
    </section>
  );
}
