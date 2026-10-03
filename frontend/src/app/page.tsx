"use client";
import dynamic from "next/dynamic";
import { useEffect, useState } from "react";
import RelationshipGraph from "./RelationshipGraph";
import InfrastructurePanel from "./InfrastructurePanel";
import CaseManagement from "./CaseManagement";
import EvidencePanel from "./EvidencePanel";
import PrivacySettingsPanel from "./PrivacySettingsPanel";
import AlertFeed from "./AlertFeed";
const MapView = dynamic(() => import("./MapView"), {
  ssr: false,
});
export default function Home() {
  const [backendStatus, setBackendStatus] = useState("Checking...");
  const [email, setEmail] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState("");
  const [headers, setHeaders] = useState<Record<string, string>>({});
  const [threatScore, setThreatScore] = useState<number | null>(null);
  const [scoreBreakdown, setScoreBreakdown] = useState<any[]>([]);
  const [classification, setClassification] = useState("");
  const [spf, setSpf] = useState<any>(null);
  const [dkim, setDkim] = useState<any>(null);
  const [dmarc, setDmarc] = useState<any>(null);   
  const [candidateOriginIp, setCandidateOriginIp] = useState("");
  const [ipIntelligence, setIpIntelligence] = useState<any>(null);
  const [ipLocations, setIpLocations] = useState<any[]>([]);
  const [ipReputation, setIpReputation] = useState<any[]>([]);
  const [findings, setFindings] = useState<string[]>([]);
  const [relayPath, setRelayPath] = useState<any[]>([]);
  const [ipAddresses, setIpAddresses] = useState<string[]>([]);
  const [urls, setUrls] = useState<string[]>([]);
  const [urlIntelligence, setUrlIntelligence] = useState<any[]>([]);
  const [domainIntelligence, setDomainIntelligence] = useState<any[]>([]); 
  const [attachments, setAttachments] = useState<any[]>([]);
  const [threatIntelligence, setThreatIntelligence] = useState<any>(null);
  const [nlpAnalysis, setNlpAnalysis] = useState<any>(null);
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedInvestigation, setSelectedInvestigation] = useState<any>(null);
  const [historyError, setHistoryError] = useState("");
useEffect(() => {
    fetch("https://threatloom.onrender.com/health")
      .then((response) => response.json())
      .then((data) => {
        setBackendStatus(data.status === "healthy" ? "Online" : "Offline");
      })
      .catch(() => {
        setBackendStatus("Offline");
      });
  }, []);

  useEffect(() => {
    loadInvestigations();
  }, []);

  const loadInvestigations = async () => {
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const response = await fetch("https://threatloom.onrender.com/investigations");
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Failed to load investigations.");
      setInvestigations(Array.isArray(data.investigations) ? data.investigations : []);
    } catch (error) {
      console.error("Investigation history failed:", error);
      setHistoryError("Could not load investigation history.");
    } finally {
      setHistoryLoading(false);
    }
  };

  const viewInvestigation = async (id: number) => {
    try {
      const response = await fetch(`https://threatloom.onrender.com/investigations/${id}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Failed to load investigation.");
      setSelectedInvestigation(data.investigation || data);
    } catch (error) {
      console.error("Investigation details failed:", error);
      setHistoryError("Could not load investigation details.");
    }
  };

  const analyzeEmail = async () => {
    if (selectedFile) {
      setNlpAnalysis(null);
      try{
  const formData = new FormData();
  formData.append("file", selectedFile);

  const response = await fetch("https://threatloom.onrender.com/upload", {
    method: "POST",
    body: formData,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "File upload failed");
  }

  setThreatScore(data.threat_score);
      setClassification(data.classification || "");

      const backendBreakdown = Array.isArray(data.score_breakdown)
        ? data.score_breakdown
        : [];

      const fallbackBreakdown = [
        ...(data.findings || []).some((f: string) =>
          f.toLowerCase().includes("reply-to domain differs")
        )
          ? [{ reason: "Reply-To domain mismatch", points: 25 }]
          : [],
        ...(data.findings || []).some((f: string) =>
          f.toLowerCase().includes("suspicious social-engineering language")
        )
          ? [{ reason: "Suspicious social-engineering language", points: 15 }]
          : [],
        ...(data.findings || []).some((f: string) =>
          f.toLowerCase().includes("credential request")
        )
          ? [{ reason: "Credential request", points: 20 }]
          : [],
        ...(data.findings || []).some((f: string) =>
          f.toLowerCase().includes("suspicious account/login url")
        )
          ? [{ reason: "Suspicious account/login URL", points: 15 }]
          : [],
        ...(data.findings || []).some((f: string) =>
          f.toLowerCase().includes("sender-domain impersonation")
        )
          ? [{ reason: "Possible sender-domain impersonation", points: 15 }]
          : [],
      ];

      setScoreBreakdown(
        backendBreakdown.length > 0 ? backendBreakdown : fallbackBreakdown
      );

      console.log(
        "Score Breakdown:",
        backendBreakdown.length > 0 ? backendBreakdown : fallbackBreakdown
      );

      setHeaders(data.headers || {});
  setSpf(data.spf || null);
  setDkim(data.dkim || null);
  setDmarc(data.dmarc || null);
  setCandidateOriginIp(data.candidate_origin_ip || "");
  setIpIntelligence(data.candidate_origin_intelligence || null);
  setIpLocations(data.ip_intelligence || []);
  setIpReputation(
  (data.ip_intelligence || []).map(
    (location: any) => location.reputation
  )
);
  setFindings(data.findings || []);
  setRelayPath(data.relay_path || []);
  setIpAddresses(data.ip_addresses || []);
  setUrls(
    Array.isArray(data.urls)
      ? data.urls.map((item: any) =>
          typeof item === "string" ? item : item?.url || String(item ?? "")
        )
      : []
  );
  setUrlIntelligence(data.url_intelligence || []);
  setDomainIntelligence(data.domain_intelligence || []);
  setAttachments(data.attachments || []);
  setThreatIntelligence(data.threat_intelligence || null);
  setNlpAnalysis(data.nlp_analysis || null);
setAnalysis(
  `Analysis complete. Threat Score: ${data.threat_score}`
);
      await loadInvestigations();

  } catch (error) {
    console.error("Upload analysis failed:", error);
    setAnalysis("File analysis failed. Please check that the backend is running.");
  }

  return;
}
    if (!email.trim()) {
      setAnalysis("Please paste an email first.");
      return;
    }
  
    setAnalysis("Analyzing email...");
    setNlpAnalysis(null);
  
    try {
      const response = await fetch("https://threatloom.onrender.com/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: email,
        }),
      });
      const data = await response.json();
      setThreatScore(data.threat_score);
      setClassification(data.classification || "");
      setScoreBreakdown(
        Array.isArray(data.score_breakdown) ? data.score_breakdown : []
      );
      setHeaders(data.headers || {});

setSpf(data.spf || null);
setDkim(data.dkim || null);
setDmarc(data.dmarc || null);
setCandidateOriginIp(data.candidate_origin_ip || "");
setIpIntelligence(data.candidate_origin_intelligence || null);
setFindings(data.findings || []);
setRelayPath(data.relay_path || []);
setIpAddresses(data.ip_addresses || []);
setUrls(data.urls || []);
setUrlIntelligence(data.url_intelligence || []);
       setDomainIntelligence(data.domain_intelligence || []);
       setThreatIntelligence(data.threat_intelligence || null);
setAnalysis(
  `Analysis complete. Threat Score: ${data.threat_score}`
);
      await loadInvestigations();
    } catch (error) {
      setAnalysis("Backend connection failed.");
    }
  };

  const dashboardStats = {
    total: investigations.length,
    low: investigations.filter((item) => String(item.risk_level || '').toLowerCase() === 'low').length,
    medium: investigations.filter((item) => String(item.risk_level || '').toLowerCase() === 'medium').length,
    high: investigations.filter((item) => String(item.risk_level || '').toLowerCase() === 'high').length,
    critical: investigations.filter((item) => String(item.risk_level || '').toLowerCase() === 'critical').length,
    phishing: investigations.filter((item) => String(item.classification || '').toLowerCase() === 'phishing').length,
    malicious: investigations.filter((item) => String(item.classification || '').toLowerCase().includes('malicious')).length,
    suspicious: investigations.filter((item) => String(item.classification || '').toLowerCase() === 'suspicious').length,
  };

  return (
    <main className="min-h-screen bg-slate-950 text-white">
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
          <div>
            <h1 className="text-2xl font-bold">🛡️ MailTrace AI</h1>
            <p className="text-sm text-slate-400">
              Email Threat Detection & Forensics Intelligence
            </p>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-slate-700 px-4 py-2">
            <span className="h-2.5 w-2.5 rounded-full bg-green-400" />
            <span className="text-sm">
              Backend: {backendStatus}
            </span>
          </div>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold">
            Email Security Dashboard
          </h2>

          <p className="mt-2 text-slate-400">
            Analyze suspicious emails and investigate potential threats.
          </p>
        </div>

        <section className="mb-6">
          <div className="mb-4">
            <h3 className="text-xl font-semibold">📊 Dashboard Statistics</h3>
            <p className="mt-1 text-sm text-slate-400">
              Live statistics from saved investigations.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Total Investigations" value={dashboardStats.total} />
            <StatCard label="🟢 Low Risk" value={dashboardStats.low} />
            <StatCard label="🟡 Medium Risk" value={dashboardStats.medium} />
            <StatCard label="🟠 High Risk" value={dashboardStats.high} />
            <StatCard label="🔴 Critical Risk" value={dashboardStats.critical} />
            <StatCard label="🎣 Phishing" value={dashboardStats.phishing} />
            <StatCard label="☠️ Malicious" value={dashboardStats.malicious} />
            <StatCard label="⚠️ Suspicious" value={dashboardStats.suspicious} />
          </div>
        </section>

        <div className="grid gap-6 lg:grid-cols-3">
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
            <h3 className="mb-2 text-xl font-semibold">
              📧 Analyze Email
            </h3>

            <p className="mb-4 text-sm text-slate-400">
              Paste the email content or headers below.
            </p>

            <textarea
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-64 w-full resize-none rounded-xl border border-slate-700 bg-slate-950 p-4 text-sm text-slate-200 outline-none focus:border-blue-500"
              placeholder="Paste email headers or email content here..."
            />
            <div className="mt-4 rounded-xl border border-dashed border-slate-700 bg-slate-950 p-4">
  <label className="block text-sm font-medium text-slate-300">
    📁 Upload .eml file
  </label>

  <input
    type="file"
    accept=".eml"
    onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
    className="mt-2 block w-full text-sm text-slate-400"
  />

  {selectedFile && (
    <p className="mt-2 text-sm text-green-400">
      Selected: {selectedFile.name}
    </p>
  )}
</div>

            <button
              onClick={analyzeEmail}
              className="mt-4 rounded-xl bg-blue-600 px-6 py-3 font-semibold hover:bg-blue-500"
            >
              🔍 Analyze Email
            </button>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
            <h3 className="text-xl font-semibold">
              ⚠️ Threat Score
            </h3>

            <div className="mt-8 text-center">
              <div
  className={`text-6xl font-bold ${
    threatScore === null
      ? "text-slate-400"
      : threatScore >= 75
      ? "text-red-400"
      : threatScore >= 50
      ? "text-orange-400"
      : threatScore >= 25
      ? "text-yellow-400"
      : "text-green-400"
  }`}
>
  {threatScore ?? "--"}
</div>

              {threatScore !== null && (
  <p className="mt-2 text-lg font-semibold">
    {threatScore >= 75
      ? "🔴 Critical Risk"
      : threatScore >= 50
      ? "🟠 High Risk"
      : threatScore >= 25
      ? "🟡 Medium Risk"
      : "🟢 Low Risk"}
  </p>
)}
{classification && (
  <p className="mt-2 text-lg font-semibold text-slate-200">
    Classification: {classification}
  </p>
)}

<p className="mt-3 text-slate-400">
  {analysis || "Waiting for analysis"}
</p>
            </div>
          </div>
        </div>

        {nlpAnalysis && (
          <section className="mt-6 rounded-2xl border border-blue-900/50 bg-slate-900 p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-xl font-semibold">
                  🧠 AI-Assisted NLP Threat Analysis
                </h3>
                <p className="mt-1 text-sm text-slate-400">
                  Explainable language-pattern analysis kept separate from the evidence score to avoid double-counting.
                </p>
              </div>
              <span className="rounded-full border border-blue-900/50 bg-blue-950/40 px-3 py-1 text-xs font-semibold text-blue-300">
                Local NLP Engine
              </span>
            </div>

            <div className="mt-5 grid gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-xs uppercase text-slate-500">Assessment</p>
                <p className="mt-2 text-lg font-semibold text-white">
                  {nlpAnalysis.assessment || "Not available"}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-xs uppercase text-slate-500">NLP Signal Score</p>
                <p className="mt-2 text-3xl font-bold text-blue-400">
                  {nlpAnalysis.signal_score ?? 0}<span className="text-base text-slate-500">/100</span>
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-xs uppercase text-slate-500">Primary Threat</p>
                <p className="mt-2 text-lg font-semibold text-white">
                  {nlpAnalysis.primary_threat || "No strong pattern detected"}
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-sm font-semibold text-white">Detected Categories</p>
                {nlpAnalysis.categories && Object.keys(nlpAnalysis.categories).length > 0 ? (
                  <div className="mt-3 space-y-2">
                    {Object.entries(nlpAnalysis.categories).map(([category, matches]: [string, any]) => (
                      <div
                        key={category}
                        className="rounded-lg border border-slate-800 bg-slate-900 p-3"
                      >
                        <p className="text-sm font-semibold capitalize text-slate-200">
                          {category.replaceAll("_", " ")}
                        </p>
                        <p className="mt-1 break-words text-sm text-slate-400">
                          {Array.isArray(matches)
                            ? matches
                                .map((item: any) =>
                                  typeof item === "string"
                                    ? item
                                    : item?.url || item?.value || JSON.stringify(item)
                                )
                                .join(", ")
                            : typeof matches === "object" && matches !== null
                            ? JSON.stringify(matches)
                            : String(matches)}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-sm text-slate-400">No NLP categories detected.</p>
                )}
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-sm font-semibold text-white">Context Signals</p>
                <div className="mt-3 space-y-3 text-sm text-slate-300">
                  <p>
                    <strong className="text-white">Brand Context:</strong>{" "}
                    {nlpAnalysis.brand_context || "None"}
                  </p>
                  <p>
                    <strong className="text-white">Reply-To Domain Mismatch:</strong>{" "}
                    {nlpAnalysis.reply_to_domain_mismatch ? "Yes" : "No"}
                  </p>
                  <p className="break-words">
                    <strong className="text-white">Suspicious URL Context:</strong>{" "}
                    {nlpAnalysis.suspicious_url_context || "None"}
                  </p>
                </div>
              </div>
            </div>

            {nlpAnalysis.note && (
              <p className="mt-4 text-xs text-yellow-400">
                ⚠️ {nlpAnalysis.note}
              </p>
            )}
          </section>
        )}

        <div className="mt-6 grid gap-6 md:grid-cols-3">
         <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
  <div className="flex items-center justify-between">
    <h3 className="text-lg font-semibold">
      🔐 SPF
    </h3>

    <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-400">
      {spf?.status || "Pending"}
    </span>
  </div>

  {spf ? (
    <div className="mt-4 space-y-2 text-sm text-slate-400">
      <p>
        <strong className="text-white">Status:</strong>{" "}
        {spf.status}
      </p>

      {spf.domain && (
        <p>
          <strong className="text-white">Domain:</strong>{" "}
          {spf.domain}
        </p>
      )}

      {spf.sending_ip && (
        <p>
          <strong className="text-white">Sending IP:</strong>{" "}
          {spf.sending_ip}
        </p>
      )}

      {spf.alignment && (
        <p>
          <strong className="text-white">Alignment:</strong>{" "}
          {spf.alignment}
        </p>
      )}

      {spf.explanation && (
        <p>{spf.explanation}</p>
      )}
    </div>
  ) : (
    <p className="mt-4 text-sm text-slate-400">
     SPF could not be evaluated because no sending IP was available.
    </p>
  )}
</div>

 <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
  <div className="flex items-center justify-between">
    <h3 className="text-lg font-semibold">
      🔑 DKIM
    </h3>

    <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-400">
      {dkim?.status || "Pending"}
    </span>
  </div>

  {dkim ? (
    <div className="mt-4 space-y-2 text-sm text-slate-400">
      <p>
        <strong className="text-white">Status:</strong>{" "}
        {dkim.status}
      </p>

      {dkim.domain && (
        <p>
          <strong className="text-white">Domain:</strong>{" "}
          {dkim.domain}
        </p>
      )}

      {dkim.selector && (
        <p>
          <strong className="text-white">Selector:</strong>{" "}
          {dkim.selector}
        </p>
      )}

      {dkim.alignment && (
        <p>
          <strong className="text-white">Alignment:</strong>{" "}
          {dkim.alignment}
        </p>
      )}

      {dkim.message && (
        <p>{dkim.message}</p>
      )}
    </div>
  ) : (
    <p className="mt-4 text-sm text-slate-400">
      Not analyzed
    </p>
  )}
</div>

 <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
  <div className="flex items-center justify-between">
    <h3 className="text-lg font-semibold">
      🛡️ DMARC
    </h3>

    <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-400">
      {dmarc?.status || "Pending"}
    </span>
  </div>

  {dmarc ? (
    <div className="mt-4 space-y-2 text-sm text-slate-400">
      <p>
        <strong className="text-white">Status:</strong>{" "}
        {dmarc.status}
      </p>

      {dmarc.domain && (
        <p>
          <strong className="text-white">Domain:</strong>{" "}
          {dmarc.domain}
        </p>
      )}

      {dmarc.dns_name && (
        <p>
          <strong className="text-white">DNS:</strong>{" "}
          {dmarc.dns_name}
        </p>
      )}

      {dmarc.record && (
        <p className="break-all">
          <strong className="text-white">Policy:</strong>{" "}
          {dmarc.record}
        </p>
      )}
    </div>
  ) : (
    <p className="mt-4 text-sm text-slate-400">
      Not analyzed
    </p>
  )}
</div> 
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {/* Extracted email headers */}
<div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
  <h3 className="text-xl font-semibold">
    📋 Email Headers
  </h3>

  {Object.keys(headers).length === 0 ? (
    <p className="mt-4 text-sm text-slate-400">
      No headers extracted yet. Analyze an email to see them here.
    </p>
  ) : (
    <div className="mt-4 space-y-3">
      {Object.entries(headers).map(([name, value]) => (
        <div
          key={name}
          className="rounded-lg border border-slate-800 bg-slate-950 p-3"
        >
          <p className="text-xs uppercase text-slate-500">
            {name}
          </p>

          <p className="mt-1 break-all text-sm text-slate-200">
            {value}
          </p>
        </div>
      ))}
    </div>
  )}
</div>
{analysis && relayPath.length > 0 && (
  <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
    <h4 className="font-semibold text-white">
      📡 Received Headers
    </h4>

    <div className="mt-3 space-y-2">
      {relayPath.map((hop) => (
        <div
          key={hop.hop}
          className="rounded-lg border border-slate-800 bg-slate-900 p-3"
        >
          <p className="text-xs font-semibold uppercase text-slate-500">
            Received Header — Hop {hop.hop}
          </p>

          <p className="mt-1 break-all text-sm text-slate-300">
            {hop.header}
          </p>
        </div>
      ))}
    </div>
  </div>
)}
        {ipIntelligence ? (
  <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
    <h3 className="text-xl font-semibold">
      🌐 IP & Geolocation
    </h3>
    {ipReputation.length > 0 && (
  <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
    <h4 className="font-semibold text-white">
      🛡️ IP Reputation
    </h4>

    <div className="mt-3 space-y-2 text-sm text-slate-400">
      {ipReputation.map((reputation, index) => (
        <div key={index}>
          <p>
            <strong className="text-white">IP:</strong>{" "}
            {reputation?.ip || "Unknown"}
          </p>

          <p>
            <strong className="text-white">Status:</strong>{" "}
            {reputation?.status || "Unknown"}
          </p>

          <p>
            <strong className="text-white">Malicious:</strong>{" "}
            {reputation?.malicious ?? 0}
          </p>

          <p>
            <strong className="text-white">Suspicious:</strong>{" "}
            {reputation?.suspicious ?? 0}
          </p>
        </div>
      ))}
    </div>
  </div>
)}

    <div className="mt-4 space-y-3 text-sm text-slate-400">
      <p>
        <strong className="text-white">Candidate Origin IP:</strong>{" "}
        {candidateOriginIp || "Not found"}
      </p>

      {ipIntelligence && (
        <>
          <p>
            <strong className="text-white">Country:</strong>{" "}
            {ipIntelligence.country || "Unknown"}
          </p>

          <p>
            <strong className="text-white">Region:</strong>{" "}
            {ipIntelligence.region || "Unknown"}
          </p>

          <p>
            <strong className="text-white">City:</strong>{" "}
            {ipIntelligence.city || "Unknown"}
          </p>

          <p>
            <strong className="text-white">ISP:</strong>{" "}
            {ipIntelligence.isp || "Unknown"}
          </p>

          <p>
            <strong className="text-white">Organization:</strong>{" "}
            {ipIntelligence.organization || "Unknown"}
          </p>

          <p>
            <strong className="text-white">ASN:</strong>{" "}
            {ipIntelligence.asn || "Unknown"}
          </p>
        </>
      )}

{ipIntelligence?.latitude != null &&
  ipIntelligence?.longitude != null && (
    <div className="mt-6">
      <div className="mb-3 flex flex-wrap items-center gap-4 text-xs text-slate-300">
  <div className="flex items-center gap-2">
    <span className="h-3 w-3 rounded-full bg-red-500" />
    Candidate Origin
  </div>

  <div className="flex items-center gap-2">
    <span className="h-3 w-3 rounded-full bg-blue-500" />
    Relay Server
  </div>

  <div className="flex items-center gap-2">
    <span className="h-3 w-3 rounded-full bg-orange-500" />
    Suspicious Infrastructure
  </div>
</div>
<MapView
  latitude={Number(ipIntelligence.latitude)}
  longitude={Number(ipIntelligence.longitude)}
  label={candidateOriginIp || "Candidate Origin"}
locations={ipLocations
  .filter(
    (location) =>
      location.latitude != null &&
      location.longitude != null
  )
  .map((location) => ({
    ip: location.ip,
    latitude: Number(location.latitude),
    longitude: Number(location.longitude),
    label:
      location.ip === candidateOriginIp
        ? `Candidate Origin: ${location.ip}`
        : `Relay IP: ${location.ip}`,
role:
  location.ip === candidateOriginIp
    ? "Candidate Origin"
    : location.role || "Relay Server",
    country: location.country,
    region: location.region,
    city: location.city,
    isp: location.isp,
    organization: location.organization,
    asn: location.asn,
  }))}
 />
    </div>
  )}

<p className="pt-2 text-xs text-yellow-400">
  ⚠️ Location is approximate and should not be treated as the
  exact physical location of the sender.
</p>
    </div>
  </div>
) : (
  <InfoCard
    title="🌐 IP & Geolocation"
    description="Origin IP, approximate location, ISP and network information will appear here after analysis."
  />
)}  

        {relayPath.length > 0 || ipAddresses.length > 0 ? (
  <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
    <h3 className="text-xl font-semibold">
      🔎 Forensic Intelligence
    </h3>

    {ipAddresses.length > 0 && (
      <div className="mt-4">
        <h4 className="font-semibold text-white">
          🌐 Detected IP Addresses
        </h4>

        <div className="mt-2 space-y-2">
          {ipAddresses.map((ip) => (
            <div
              key={ip}
              className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-sm text-slate-300"
            >
              {ip}
            </div>
          ))}
        </div>
      </div>
    )}

    {relayPath.length > 0 && (
      <div className="mt-6">
        <h4 className="font-semibold text-white">
          📡 SMTP Relay Path
        </h4>

        <div className="mt-3 space-y-3">
          {relayPath.map((hop) => (
            <div
              key={hop.hop}
              className="rounded-lg border border-slate-800 bg-slate-950 p-4"
            >
              <p className="text-sm font-semibold text-blue-400">
                Hop {hop.hop}
              </p>

              <p className="mt-2 break-all text-sm text-slate-300">
                {hop.header}
              </p>

              {hop.ip_addresses?.length > 0 && (
                <p className="mt-2 text-xs text-slate-500">
                  IPs: {hop.ip_addresses.join(", ")}
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    )}

    <p className="mt-4 text-xs text-yellow-400">
      ⚠️ Relay information is based on the email headers provided.
      It does not by itself prove the sender's identity or exact origin.
    </p>
  </div>
) : (
  <InfoCard
    title="🔎 Forensic Intelligence"
    description="SMTP relay path, sender infrastructure, domain information and investigation results will appear here."
  />
)}  
   
{attachments.length > 0 && (
  <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h3 className="text-xl font-semibold text-white">
          📎 Attachment Intelligence
        </h3>
        <p className="mt-1 text-sm text-slate-400">
          Passive analysis of email attachments. Files are not executed.
        </p>
      </div>

      <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">
        {attachments.length} attachment{attachments.length !== 1 ? "s" : ""}
      </span>
    </div>

    <div className="mt-5 space-y-4">
      {attachments.map((attachment, index) => {
        const filename = attachment.filename || "Unknown file";
        const risk = attachment.risk || "Low";
        const signals = Array.isArray(attachment.signals)
          ? attachment.signals
          : [];
        const size = Number(attachment.size || 0);

        const riskClass =
          risk === "Critical"
            ? "text-red-400 border-red-900/50"
            : risk === "High"
            ? "text-orange-400 border-orange-900/50"
            : risk === "Medium"
            ? "text-yellow-400 border-yellow-900/50"
            : "text-green-400 border-green-900/50";

        return (
          <div
            key={`${filename}-${index}`}
            className="rounded-xl border border-slate-800 bg-slate-950 p-5"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="break-all text-lg font-semibold text-slate-100">
                  {filename}
                </p>

                <div className="mt-2 space-y-1 text-sm text-slate-400">
                  <p>
                    <strong className="text-white">Type:</strong>{" "}
                    {attachment.content_type || "Unknown"}
                  </p>
                  <p>
                    <strong className="text-white">Size:</strong>{" "}
                    {size.toLocaleString()} bytes
                  </p>
                  {attachment.extension && (
                    <p>
                      <strong className="text-white">Extension:</strong>{" "}
                      {attachment.extension}
                    </p>
                  )}
                </div>
              </div>

              <span
                className={`rounded-full border bg-slate-900 px-3 py-1 text-xs font-semibold ${riskClass}`}
              >
                {risk} Risk
              </span>
            </div>

            {attachment.reason && (
              <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-3">
                <p className="text-sm font-semibold text-white">
                  🔎 Assessment
                </p>
                <p className="mt-1 text-sm text-slate-400">
                  {attachment.reason}
                </p>
              </div>
            )}

            {signals.length > 0 && (
              <div className="mt-4">
                <p className="text-sm font-semibold text-yellow-400">
                  ⚠️ Attachment Signals
                </p>
                <div className="mt-2 space-y-2">
                  {signals.map((signal: string, signalIndex: number) => (
                    <p
                      key={signalIndex}
                      className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm text-slate-300"
                    >
                      🔎 {signal}
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>

    <p className="mt-5 text-xs text-yellow-400">
      ⚠️ Attachment analysis is metadata-based. MailTrace AI never executes uploaded files.
    </p>
  </section>
)}
{/* URL Threat Intelligence */}
<div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
  <h3 className="text-xl font-semibold">
    🔗 URL & Domain Threat Intelligence
  </h3>

  {urls.length === 0 ? (
    <p className="mt-4 text-sm text-slate-400">
      No URLs detected in this email.
    </p>
  ) : (
    <div className="mt-4 space-y-4">
      {urls.map((url, index) => {
        const displayUrl =
          typeof url === "string"
            ? url
            : (url as any)?.url || String(url ?? "");

        const intelligence = urlIntelligence[index];

        return (
          <div
            key={`${displayUrl}-${index}`}
            className="rounded-xl border border-slate-800 bg-slate-950 p-4"
          >
            <p className="text-xs uppercase text-slate-500">
              URL
            </p>

            <p className="mt-1 break-all text-sm text-blue-400">
              {displayUrl}
            </p>

            {intelligence && (
              <div className="mt-4 space-y-2 text-sm text-slate-400">
                <p>
                  <strong className="text-white">Status:</strong>{" "}
                  {intelligence.status}
                </p>

                <p>
                  <strong className="text-white">
                    Malicious detections:
                  </strong>{" "}
                  {intelligence.malicious ?? 0}
                </p>

                <p>
                  <strong className="text-white">
                    Suspicious detections:
                  </strong>{" "}
                  {intelligence.suspicious ?? 0}
                </p>

                {intelligence.reputation !== undefined && (
                  <p>
                    <strong className="text-white">
                      Reputation:
                    </strong>{" "}
                    {intelligence.reputation}
                  </p>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  )}

  <p className="mt-5 text-xs text-yellow-400">
    ⚠️ URL reputation results are intelligence signals and
    should be reviewed together with other email evidence.
    </p>
</div>

{/* Domain Intelligence */}
{domainIntelligence.length > 0 && (
  <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
    <h3 className="text-xl font-semibold">
      🌐 Domain Intelligence
    </h3>

    <div className="mt-4 space-y-4">
      {domainIntelligence.map((domain: any, index: number) => (
        <div
          key={`${domain.domain || "domain"}-${index}`}
          className="rounded-xl border border-slate-800 bg-slate-950 p-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="break-all text-lg font-semibold text-blue-400">
              {domain.domain || "Unknown domain"}
            </p>
            <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">
              {domain.status || "Unknown"}
            </span>
          </div>

          <div className="mt-4 grid gap-3 text-sm text-slate-400 md:grid-cols-2">
            <p>
              <strong className="text-white">Registrar:</strong>{" "}
              {domain.registrar || "Unavailable"}
            </p>
            <p>
              <strong className="text-white">Created:</strong>{" "}
              {domain.created || "Unavailable"}
            </p>
            <p>
              <strong className="text-white">Updated:</strong>{" "}
              {domain.updated || "Unavailable"}
            </p>
            <p>
              <strong className="text-white">Expires:</strong>{" "}
              {domain.expires || "Unavailable"}
            </p>
          </div>

          {Array.isArray(domain.nameservers) && domain.nameservers.length > 0 && (
            <div className="mt-4">
              <p className="text-sm font-semibold text-white">Nameservers</p>
              <div className="mt-2 space-y-1 text-sm text-slate-400">
                {domain.nameservers.map((ns: string, nsIndex: number) => (
                  <p key={nsIndex} className="break-all">
                    {ns}
                  </p>
                ))}
              </div>
            </div>
          )}

          {domain.dns && typeof domain.dns === "object" && (
            <div className="mt-4">
              <p className="text-sm font-semibold text-white">DNS Records</p>
              <div className="mt-2 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
                {Object.entries(domain.dns).map(([recordType, values]: [string, any]) => (
                  <div
                    key={recordType}
                    className="rounded-lg border border-slate-800 bg-slate-900 p-3"
                  >
                    <p className="font-semibold uppercase text-slate-300">
                      {recordType}
                    </p>
                    <p className="mt-1 break-all">
                      {Array.isArray(values) ? values.join(", ") : String(values)}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {Array.isArray(domain.signals) && domain.signals.length > 0 && (
            <div className="mt-4">
              <p className="text-sm font-semibold text-yellow-400">
                ⚠️ Domain Signals
              </p>
              <div className="mt-2 space-y-2">
                {domain.signals.map((signal: string, signalIndex: number) => (
                  <p
                    key={signalIndex}
                    className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm text-slate-300"
                  >
                    🔎 {signal}
                  </p>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>

    <p className="mt-5 text-xs text-yellow-400">
      ⚠️ Domain registration and DNS intelligence may be unavailable for some domains.
    </p>
  </div>
)}
<InfrastructurePanel data={threatIntelligence} />
{/* Threat Intelligence Summary */}
        <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-xl font-semibold">🧠 Threat Intelligence</h3>
              <p className="mt-1 text-sm text-slate-400">
                Consolidated intelligence from IP reputation, URL reputation, and domain analysis.
              </p>
            </div>
            <span className="rounded-full bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-300">
              {threatIntelligence?.overall_status || "Pending"}
            </span>
          </div>

          {!threatIntelligence ? (
            <p className="mt-5 text-sm text-slate-400">
              Analyze an email to generate threat-intelligence results.
            </p>
          ) : (
            <>
              <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <ThreatIntelStat
                  label="IPs Checked"
                  value={threatIntelligence.summary?.ips_checked ?? 0}
                />
                <ThreatIntelStat
                  label="🔴 Malicious IPs"
                  value={threatIntelligence.summary?.malicious_ips ?? 0}
                />
                <ThreatIntelStat
                  label="🟠 Suspicious IPs"
                  value={threatIntelligence.summary?.suspicious_ips ?? 0}
                />
                <ThreatIntelStat
                  label="URLs Checked"
                  value={threatIntelligence.summary?.urls_checked ?? 0}
                />
                <ThreatIntelStat
                  label="🔴 Malicious URLs"
                  value={threatIntelligence.summary?.malicious_urls ?? 0}
                />
                <ThreatIntelStat
                  label="🟠 Suspicious URLs"
                  value={threatIntelligence.summary?.suspicious_urls ?? 0}
                />
                <ThreatIntelStat
                  label="Domains Checked"
                  value={threatIntelligence.summary?.domains_checked ?? 0}
                />
              </div>

              {Array.isArray(threatIntelligence.indicators) &&
                threatIntelligence.indicators.length > 0 && (
                  <div className="mt-5">
                    <h4 className="text-sm font-semibold text-white">
                      🚨 Intelligence Indicators
                    </h4>
                    <div className="mt-3 space-y-2">
                      {threatIntelligence.indicators.map(
                        (indicator: any, index: number) => (
                          <div
                            key={`${indicator.type || "indicator"}-${indicator.value || index}-${index}`}
                            className="rounded-lg border border-slate-800 bg-slate-950 p-3"
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="rounded-full bg-slate-800 px-2 py-1 text-xs font-semibold text-slate-300">
                                {indicator.type || "Indicator"}
                              </span>
                              <span className="rounded-full bg-slate-800 px-2 py-1 text-xs font-semibold text-slate-300">
                                {indicator.severity || "Info"}
                              </span>
                              <span className="break-all text-sm text-blue-400">
                                {indicator.value || "Unknown"}
                              </span>
                            </div>
                            {indicator.reason && (
                              <p className="mt-2 text-sm text-slate-400">
                                {indicator.reason}
                              </p>
                            )}
                          </div>
                        )
                      )}
                    </div>
                  </div>
                )}

              <p className="mt-5 text-xs text-yellow-400">
                ⚠️ Threat-intelligence results are evidence signals, not proof of malicious activity or sender identity.
              </p>
            </>
          )}
        </div>

        {/* Security Findings */}
{scoreBreakdown.length > 0 && (
  <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
    <h3 className="text-xl font-semibold text-white">
      📊 Threat Score Breakdown
    </h3>

    <div className="mt-4 space-y-3">
      {scoreBreakdown.map((item, index) => (
        <div
          key={index}
          className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-3"
        >
          <span className="text-sm text-slate-300">
            {item.reason}
          </span>

          <span className="font-semibold text-red-400">
            +{item.points}
          </span>
        </div>
      ))}
    </div>
  </div>
)}
<div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6 lg:col-span-2">
  <h3 className="text-xl font-semibold">
    🧠 Security Findings
  </h3>

  {findings.length === 0 ? (
    <p className="mt-4 text-sm text-slate-400">
      No findings available yet. Analyze an email to see the
      security findings.
    </p>
  ) : (
    <div className="mt-4 space-y-3">
      {findings.map((finding, index) => (
        <div
          key={index}
          className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300"
        >
          🔎 {finding}
        </div>
      ))}
    </div>
  )}
</div>

        <RelationshipGraph />
        <CaseManagement />
        <PrivacySettingsPanel />
        <AlertFeed />
        </div>
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-xl font-semibold">🗂️ Investigation History</h3>
              <p className="mt-1 text-sm text-slate-400">
                Previously analyzed emails saved by MailTrace AI.
              </p>
            </div>
            <button
              onClick={loadInvestigations}
              disabled={historyLoading}
              className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold hover:border-blue-500 disabled:opacity-50"
            >
              {historyLoading ? "Refreshing..." : "↻ Refresh"}
            </button>
          </div>

          {historyError && (
            <p className="mt-4 rounded-lg border border-red-900/50 bg-red-950/20 p-3 text-sm text-red-400">
              {historyError}
            </p>
          )}

          {investigations.length === 0 && !historyLoading ? (
            <p className="mt-5 text-sm text-slate-400">
              No saved investigations yet. Analyze an email to create one.
            </p>
          ) : (
            <div className="mt-5 overflow-x-auto">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-xs uppercase text-slate-500">
                    <th className="px-3 py-3">ID</th>
                    <th className="px-3 py-3">Date</th>
                    <th className="px-3 py-3">Sender</th>
                    <th className="px-3 py-3">Subject</th>
                    <th className="px-3 py-3">Score</th>
                    <th className="px-3 py-3">Risk</th>
                    <th className="px-3 py-3">Classification</th>
                    <th className="px-3 py-3">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {investigations.map((item) => (
                    <tr key={item.id} className="border-b border-slate-800/70 hover:bg-slate-950/60">
                      <td className="px-3 py-4 font-semibold text-blue-400">#{item.id}</td>
                      <td className="whitespace-nowrap px-3 py-4 text-slate-400">
                        {item.created_at ? new Date(item.created_at).toLocaleString() : "Unknown"}
                      </td>
                      <td className="max-w-[220px] break-all px-3 py-4 text-slate-300">{item.sender || "Unknown"}</td>
                      <td className="max-w-[220px] px-3 py-4 text-slate-300">{item.subject || "No subject"}</td>
                      <td className="px-3 py-4 font-bold text-yellow-400">{item.threat_score ?? "--"}</td>
                      <td className="px-3 py-4">
                        <span className="rounded-full bg-slate-800 px-3 py-1 text-xs">{item.risk_level || "Unknown"}</span>
                      </td>
                      <td className="px-3 py-4 text-slate-300">{item.classification || "Unknown"}</td>
                      <td className="px-3 py-4">
                        <button
                          onClick={() => viewInvestigation(item.id)}
                          className="rounded-lg bg-blue-600 px-3 py-2 text-xs font-semibold hover:bg-blue-500"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {selectedInvestigation && (
            <div className="mt-6 rounded-xl border border-blue-900/50 bg-slate-950 p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h4 className="text-lg font-semibold">🔍 Investigation #{selectedInvestigation.id}</h4>
                <button
                  onClick={() => setSelectedInvestigation(null)}
                  className="rounded-lg border border-slate-700 px-3 py-1 text-xs hover:border-slate-500"
                >
                  Close
                </button>
              </div>
              <div className="mt-4 grid gap-3 text-sm text-slate-400 md:grid-cols-2">
                <p><strong className="text-white">Sender:</strong> {selectedInvestigation.sender || "Unknown"}</p>
                <p><strong className="text-white">Recipient:</strong> {selectedInvestigation.recipient || "Unknown"}</p>
                <p><strong className="text-white">Subject:</strong> {selectedInvestigation.subject || "No subject"}</p>
                <p><strong className="text-white">Threat Score:</strong> {selectedInvestigation.threat_score ?? "--"}</p>
                <p><strong className="text-white">Risk:</strong> {selectedInvestigation.risk_level || "Unknown"}</p>
                <p><strong className="text-white">Classification:</strong> {selectedInvestigation.classification || "Unknown"}</p>
                <p><strong className="text-white">Origin IP:</strong> {selectedInvestigation.origin_ip || "Not available"}</p>
                <p><strong className="text-white">Created:</strong> {selectedInvestigation.created_at ? new Date(selectedInvestigation.created_at).toLocaleString() : "Unknown"}</p>
              </div>
              <EvidencePanel investigationId={selectedInvestigation.id ?? ""} />
              {selectedInvestigation.result && (
                <details className="mt-5">
                  <summary className="cursor-pointer text-sm font-semibold text-blue-400">
                    View complete stored analysis
                  </summary>
                  <pre className="mt-3 max-h-96 overflow-auto rounded-lg border border-slate-800 bg-black/30 p-4 text-xs text-slate-300">
                    {JSON.stringify(selectedInvestigation.result, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

function StatCard({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-2 text-3xl font-bold text-white">{value}</p>
    </div>
  );
}

function ThreatIntelStat({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
      <p className="text-xs text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-bold text-white">{value}</p>
    </div>
  );
}

function SecurityCard({
  title,
  icon,
  status,
}: {
  title: string;
  icon: string;
  status: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">
          {icon} {title}
        </h3>

        <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-400">
          Pending
        </span>
      </div>

      <p className="mt-4 text-sm text-slate-400">
        {status}
      </p>
    </div>
  );
}

function InfoCard({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h3 className="text-xl font-semibold">{title}</h3>

      <p className="mt-4 text-sm leading-6 text-slate-400">
        {description}
      </p>
    </div>
  );
}