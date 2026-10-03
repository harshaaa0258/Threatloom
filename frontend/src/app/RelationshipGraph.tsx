"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type GraphNode = {
  id: string;
  type: "email" | "domain" | "ip";
  label: string;
  investigation_count: number;
  investigation_ids: number[];
};

type GraphEdge = {
  source: string;
  target: string;
  relation: string;
  investigation_count: number;
  investigation_ids: number[];
};

type GraphResponse = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: {
    investigations_analyzed: number;
    entities: number;
    relationships: number;
    repeated_entities: number;
    repeated_relationships: number;
  };
  note: string;
};

const backendUrl = "https://threatloom.onrender.com";
const columns: GraphNode["type"][] = ["email", "domain", "ip"];
const columnLabels: Record<GraphNode["type"], string> = {
  email: "Email identities",
  domain: "Domains",
  ip: "Public IPs",
};
const nodeColors: Record<GraphNode["type"], string> = {
  email: "#38bdf8",
  domain: "#a78bfa",
  ip: "#fb7185",
};

export default function RelationshipGraph() {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadGraph = useCallback(async () => {
    try {
      const response = await fetch(`${backendUrl}/investigations/graph?limit=300`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not load relationship data.");
      setError("");
      setGraph(data);
    } catch {
      setError("Relationship data is unavailable. Check that the analysis backend is online.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchGraph = async () => {
      try {
        const response = await fetch(`${backendUrl}/investigations/graph?limit=300`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not load relationship data.");
        if (cancelled) return;
        setError("");
        setGraph(data);
      } catch {
        if (cancelled) return;
        setError("Relationship data is unavailable. Check that the analysis backend is online.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void fetchGraph();
    return () => {
      cancelled = true;
    };
  }, []);

  const layout = useMemo(() => {
    const visibleNodes = columns.flatMap((type) =>
      (graph?.nodes ?? [])
        .filter((node) => node.type === type)
        .slice(0, 10)
        .map((node, index, group) => ({
          ...node,
          x: type === "email" ? 185 : type === "domain" ? 550 : 915,
          y: 88 + ((index + 1) * 470) / (group.length + 1),
        }))
    );
    const positions = new Map(visibleNodes.map((node) => [node.id, node]));
    const visibleEdges = (graph?.edges ?? [])
      .filter((edge) => positions.has(edge.source) && positions.has(edge.target))
      .slice(0, 60);
    return { nodes: visibleNodes, edges: visibleEdges, positions };
  }, [graph]);

  return (
    <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold">Cross-investigation relationship graph</h3>
          <p className="mt-1 max-w-3xl text-sm text-slate-400">
            See email identities, domains, and public IPs that appear together across saved analyses.
          </p>
        </div>
        <button
          onClick={() => {
            setLoading(true);
            setError("");
            void loadGraph();
          }}
          disabled={loading}
          className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold hover:border-blue-500 disabled:opacity-50"
        >
          {loading ? "Loading…" : "Refresh graph"}
        </button>
      </div>

      {error && (
        <p className="mt-4 rounded-lg border border-amber-900/50 bg-amber-950/20 p-3 text-sm text-amber-300">
          {error}
        </p>
      )}

      {graph && (
        <>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {[
              ["Analyses", graph.summary.investigations_analyzed],
              ["Entities", graph.summary.entities],
              ["Relationships", graph.summary.relationships],
              ["Repeated entities", graph.summary.repeated_entities],
              ["Repeated links", graph.summary.repeated_relationships],
            ].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
                <p className="mt-1 text-xl font-semibold text-slate-100">{value}</p>
              </div>
            ))}
          </div>

          {graph.nodes.length === 0 ? (
            <p className="mt-5 rounded-xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">
              Analyze emails to build a relationship graph from saved investigations.
            </p>
          ) : (
            <div className="mt-5 overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-2">
              <svg
                viewBox="0 0 1100 620"
                role="img"
                aria-label="Graph connecting email identities, domains, and public IP addresses found in saved investigations"
                className="min-w-[760px] w-full"
              >
                {columns.map((type) => (
                  <text
                    key={type}
                    x={type === "email" ? 185 : type === "domain" ? 550 : 915}
                    y="34"
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize="13"
                  >
                    {columnLabels[type]}
                  </text>
                ))}
                {layout.edges.map((edge) => {
                  const source = layout.positions.get(edge.source);
                  const target = layout.positions.get(edge.target);
                  if (!source || !target) return null;
                  return (
                    <line
                      key={`${edge.source}-${edge.target}-${edge.relation}`}
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke="#64748b"
                      strokeOpacity="0.42"
                      strokeWidth={Math.min(1 + edge.investigation_count, 4)}
                    >
                      <title>
                        {edge.relation.replaceAll("_", " ")} · {edge.investigation_count} investigation(s)
                      </title>
                    </line>
                  );
                })}
                {layout.nodes.map((node) => (
                  <g key={node.id}>
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r="8"
                      fill={nodeColors[node.type]}
                      stroke="#0f172a"
                      strokeWidth="3"
                    >
                      <title>
                        {node.label} · found in {node.investigation_count} investigation(s)
                      </title>
                    </circle>
                    <text
                      x={node.x + (node.type === "email" ? -16 : 16)}
                      y={node.y + 4}
                      textAnchor={node.type === "email" ? "end" : "start"}
                      fill="#e2e8f0"
                      fontSize="11"
                    >
                      {node.label.length > 30 ? `${node.label.slice(0, 27)}…` : node.label}
                    </text>
                    <text
                      x={node.x + (node.type === "email" ? -16 : 16)}
                      y={node.y + 18}
                      textAnchor={node.type === "email" ? "end" : "start"}
                      fill="#64748b"
                      fontSize="9"
                    >
                      {node.investigation_count} investigation(s)
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          )}
          <p className="mt-3 text-xs text-slate-500">{graph.note}</p>
          {layout.nodes.length < graph.nodes.length && (
            <p className="mt-1 text-xs text-slate-500">
              Showing the ten most frequently observed entities in each column.
            </p>
          )}
        </>
      )}
    </section>
  );
}
