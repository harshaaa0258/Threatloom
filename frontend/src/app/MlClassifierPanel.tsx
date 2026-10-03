"use client";

type ClassifierResult = {
  model?: string;
  classification?: string;
  confidence?: number;
  training_source?: string;
  training_samples?: number;
  class_counts?: Record<string, number>;
  training_warning?: string;
  confidence_note?: string;
};

type Props = { data: ClassifierResult | null };

export default function MlClassifierPanel({ data }: Props) {
  if (!data) return null;

  const counts = Object.entries(data.class_counts ?? {});
  const score = typeof data.confidence === "number" ? `${Math.round(data.confidence * 100)}%` : "Not available";

  return (
    <section className="mt-6 rounded-2xl border border-violet-900/50 bg-slate-900 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-xl font-semibold">Email ML Classifier</h3>
          <p className="mt-1 text-sm text-slate-400">{data.model || "Local classifier"}</p>
        </div>
        <span className="rounded-full border border-violet-800 bg-violet-950/40 px-3 py-1 text-xs font-semibold uppercase text-violet-300">
          {data.classification || "Unclassified"}
        </span>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-xs uppercase text-slate-500">Model score</p>
          <p className="mt-2 text-2xl font-bold text-white">{score}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-xs uppercase text-slate-500">Training source</p>
          <p className="mt-2 text-sm font-semibold text-slate-200">{data.training_source?.replaceAll("_", " ") || "Unknown"}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-xs uppercase text-slate-500">Training examples</p>
          <p className="mt-2 text-2xl font-bold text-white">{data.training_samples ?? 0}</p>
        </div>
      </div>

      {counts.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {counts.map(([label, count]) => (
            <span key={label} className="rounded-full border border-slate-800 bg-slate-950 px-3 py-1 text-xs text-slate-300">
              {label}: {count}
            </span>
          ))}
        </div>
      )}

      {data.training_warning && <p className="mt-4 text-sm text-amber-300">{data.training_warning}</p>}
      <p className="mt-4 text-xs text-slate-500">
        {data.confidence_note || "Model scores support triage and do not establish that a message is malicious."}
      </p>
    </section>
  );
}
