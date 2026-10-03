"use client";

type InfrastructureIndicator = {
  type?: unknown;
  value?: unknown;
  severity?: unknown;
  confidence?: unknown;
  source?: unknown;
  reason?: unknown;
};

type Props = {
  data: unknown;
};

const indicatorTypes = new Set([
  "Tor exit node",
  "VPN / proxy infrastructure",
  "Cloud / hosted infrastructure",
  "Reported abusive IP",
  "Configured botnet C2 indicator",
  "Configured open relay indicator",
  "Verified phishing URL",
]);

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function formatStatus(value: unknown) {
  return typeof value === "string" ? value.replaceAll("_", " ") : "unknown";
}

export default function InfrastructurePanel({ data }: Props) {
  const intelligence = asRecord(data);
  const summary = asRecord(intelligence.infrastructure_summary);
  const threatSummary = asRecord(intelligence.summary);
  const sourceStatus = asRecord(intelligence.infrastructure_source_status);
  const threatSourceStatus = asRecord(intelligence.source_status);
  const indicators = Array.isArray(intelligence.indicators)
    ? (intelligence.indicators as InfrastructureIndicator[]).filter((indicator) =>
        indicatorTypes.has(String(indicator.type ?? ""))
      )
    : [];

  if (Object.keys(summary).length === 0 && Object.keys(sourceStatus).length === 0 && indicators.length === 0) {
    return null;
  }

  const metrics: Array<[string, unknown]> = [
    ["Tor exits", summary.tor_exit_ips],
    ["VPN / proxy", summary.vpn_or_proxy_ips],
    ["Hosted", summary.hosting_ips],
    ["Abuse reports", summary.abuse_reported_ips],
    ["Botnet C2", summary.botnet_c2_ips],
    ["Open relays", summary.open_relay_ips],
    ["PhishTank matches", threatSummary.phishtank_matches],
  ];

  return (
    <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h3 className="text-xl font-semibold">Infrastructure and threat-feed signals</h3>
      <p className="mt-1 text-sm text-slate-400">
        Provider, exit-node, and reputation-feed matches for email infrastructure and links.
      </p>

      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-7">
        {metrics.map(([label, value]) => (
          <div key={label} className="rounded-xl border border-slate-800 bg-slate-950 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
            <p className="mt-1 text-xl font-semibold text-slate-100">
              {typeof value === "number" ? value : 0}
            </p>
          </div>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-400">
        {[
          ["Tor Project", sourceStatus.tor_project_exit_list],
          ["AbuseIPDB", sourceStatus.abuseipdb],
          ["VirusTotal", threatSourceStatus.virustotal],
          ["PhishTank", threatSourceStatus.phishtank],
          ["Botnet C2 list", sourceStatus.botnet_c2_list],
          ["Open relay list", sourceStatus.open_relay_list],
        ].map(([label, value]) => (
          <span key={label} className="rounded-full border border-slate-800 bg-slate-950 px-3 py-1">
            {label}: {formatStatus(value)}
          </span>
        ))}
      </div>

      {indicators.length === 0 ? (
        <p className="mt-4 text-sm text-slate-400">No infrastructure indicators matched the checked sources.</p>
      ) : (
        <div className="mt-5 space-y-2">
          {indicators.map((indicator, index) => (
            <div
              key={`${String(indicator.type)}-${String(indicator.value)}-${index}`}
              className="rounded-lg border border-slate-800 bg-slate-950 p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-full bg-slate-800 px-2 py-1 text-xs font-semibold text-slate-300">
                  {String(indicator.type ?? "Indicator")}
                </span>
                <span className="rounded-full bg-slate-800 px-2 py-1 text-xs text-slate-400">
                  {String(indicator.severity ?? "Info")}
                </span>
                {indicator.confidence != null && (
                  <span className="rounded-full bg-slate-800 px-2 py-1 text-xs text-slate-400">
                    {String(indicator.confidence)} confidence
                  </span>
                )}
                <span className="break-all text-sm text-blue-400">
                  {String(indicator.value ?? "Unknown")}
                </span>
              </div>
              {indicator.source != null && (
                <p className="mt-2 text-xs text-slate-500">Source: {String(indicator.source)}</p>
              )}
              {indicator.reason != null && (
                <p className="mt-2 text-sm text-slate-400">{String(indicator.reason)}</p>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="mt-4 text-xs text-slate-500">
        VPN/proxy and hosting labels are contextual signals. Botnet C2 and open relay matching require operator-maintained IP lists.
      </p>
    </section>
  );
}
