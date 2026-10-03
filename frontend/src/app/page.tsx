"use client";
import dynamic from "next/dynamic";
import { useCallback, useEffect, useState } from "react";
import RelationshipGraph from "./RelationshipGraph";
import InfrastructurePanel from "./InfrastructurePanel";
import CaseManagement from "./CaseManagement";
import EvidencePanel from "./EvidencePanel";
import PrivacySettingsPanel from "./PrivacySettingsPanel";
import AlertFeed from "./AlertFeed";
import GmailMonitorPanel from "./GmailMonitorPanel";
import MlClassifierPanel from "./MlClassifierPanel";

type ScoreBreakdownItem = {
  reason?: string;
  points?: number;
};

type ReputationRecord = {
  ip?: string;
  status?: string;
  malicious?: number;
  suspicious?: number;
  [key: string]: unknown;
};

type IpLocationRecord = {
  ip?: string;
  latitude?: number | string | null;
  longitude?: number | string | null;
  role?: string;
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  organization?: string;
  asn?: string;
  reputation?: unknown;
  [key: string]: unknown;
};

type UrlRecord = {
  url?: string;
  [key: string]: unknown;
};

type DomainRecord = {
  domain?: string;
  status?: string;
  registrar?: string;
  created?: string;
  updated?: string;
  expires?: string;
  nameservers?: string[];
  dns?: Record<string, string[] | string | number | boolean | null>;
  signals?: string[];
  [key: string]: unknown;
};

type RelayHop = {
  hop: number;
  header: string;
  [key: string]: unknown;
};

type ThreatIndicator = {
  type?: string;
  value?: string | number | null;
  severity?: string;
  reason?: string;
  [key: string]: unknown;
};

type UrlIntelligenceRecord = {
  url?: string;
  status?: string;
  malicious?: number;
  suspicious?: number;
  reputation?: string | number | null;
  [key: string]: unknown;
};

type AttachmentRecord = {
  filename?: string;
  risk?: string;
  signals?: string[];
  size?: number | string | null;
  content_type?: string;
  extension?: string;
  reason?: string;
  [key: string]: unknown;
};

type SecurityRecord = {
  status?: string;
  domain?: string;
  sending_ip?: string;
  selector?: string;
  alignment?: string;
  explanation?: string;
  message?: string;
  dns_name?: string;
  record?: string;
  [key: string]: unknown;
};

type InvestigationRecord = {
  id?: number | string;
  sender?: string;
  recipient?: string;
  subject?: string;
  threat_score?: number;
  risk_level?: string;
  classification?: string;
  origin_ip?: string;
  created_at?: string | number | Date;
  result?: unknown;
  [key: string]: unknown;
};

async function fetchInvestigations(): Promise<InvestigationRecord[]> {
  const response = await fetch("https://threatloom.onrender.com/investigations");
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || "Failed to load investigations.");
  return Array.isArray(data.investigations) ? data.investigations : [];
}

type NlpAnalysis = {
  assessment?: string;
  signal_score?: number | null;
  primary_threat?: string;
  categories?: Record<string, unknown>;
  brand_context?: string;
  reply_to_domain_mismatch?: boolean;
  suspicious_url_context?: string;
  note?: string;
};

type MlClassifierRecord = {
  model?: string;
  classification?: string;
  confidence?: number;
  training_source?: string;
  training_samples?: number;
  class_counts?: Record<string, number>;
  training_warning?: string;
  confidence_note?: string;
};

type ThreatIntelligenceRecord = {
  overall_status?: string;
  summary?: {
    ips_checked?: number;
    malicious_ips?: number;
    suspicious_ips?: number;
    urls_checked?: number;
    malicious_urls?: number;
    suspicious_urls?: number;
    domains_checked?: number;
  };
  indicators?: ThreatIndicator[];
  [key: string]: unknown;
};

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
  const [scoreBreakdown, setScoreBreakdown] = useState<ScoreBreakdownItem[]>([]);
  const [classification, setClassification] = useState("");
  const [spf, setSpf] = useState<SecurityRecord | null>(null);
  const [dkim, setDkim] = useState<SecurityRecord | null>(null);
  const [dmarc, setDmarc] = useState<SecurityRecord | null>(null);
  const [candidateOriginIp, setCandidateOriginIp] = useState("");
  const [ipIntelligence, setIpIntelligence] = useState<IpLocationRecord | null>(null);
  const [ipLocations, setIpLocations] = useState<IpLocationRecord[]>([]);
  const [ipReputation, setIpReputation] = useState<ReputationRecord[]>([]);
  const [findings, setFindings] = useState<string[]>([]);
  const [relayPath, setRelayPath] = useState<RelayHop[]>([]);
  const [ipAddresses, setIpAddresses] = useState<string[]>([]);
  const [urls, setUrls] = useState<string[]>([]);
  const [urlIntelligence, setUrlIntelligence] = useState<UrlIntelligenceRecord[]>([]);
  const [domainIntelligence, setDomainIntelligence] = useState<DomainRecord[]>([]);
  const [attachments, setAttachments] = useState<AttachmentRecord[]>([]);
  const [threatIntelligence, setThreatIntelligence] = useState<ThreatIntelligenceRecord | null>(null);
  const [nlpAnalysis, setNlpAnalysis] = useState<NlpAnalysis | null>(null);
  const [mlClassifier, setMlClassifier] = useState<MlClassifierRecord | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [selectedInvestigation, setSelectedInvestigation] = useState<InvestigationRecord | null>(null);
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

  const loadInvestigations = useCallback(async () => {
    try {
      setInvestigations(await fetchInvestigations());
      setHistoryError("");
    } catch (error) {
      console.error("Investigation history failed:", error);
      setHistoryError("Could not load investigation history.");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchInitialHistory = async () => {
      try {
        const records = await fetchInvestigations();
        if (!cancelled) {
          setInvestigations(records);
          setHistoryError("");
        }
      } catch {
        if (!cancelled) setHistoryError("Could not load investigation history.");
      } finally {
        if (!cancelled) setHistoryLoading(false);
      }
    };
    void fetchInitialHistory();
    return () => {
      cancelled = true;
    };
  }, []);

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

  const investigationIdNumber = (value: number | string | undefined) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };

  const analyzeEmail = async () => {
    if (selectedFile) {
      setNlpAnalysis(null);
      setMlClassifier(null);
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
      setIpLocations(Array.isArray(data.ip_intelligence) ? data.ip_intelligence : []);
      setIpReputation(
        (Array.isArray(data.ip_intelligence) ? data.ip_intelligence : []).map((location: ReputationRecord) => ({
          ...location,
          reputation: location.reputation,
        }))
      );
          setFindings(data.findings || []);
          setRelayPath(data.relay_path || []);
          setIpAddresses(data.ip_addresses || []);
          setUrls(
            Array.isArray(data.urls)
              ? data.urls.map((item: string | UrlRecord | null | undefined) =>
                  typeof item === "string" ? item : item?.url || String(item ?? "")
                )
              : []
          );
          setUrlIntelligence(Array.isArray(data.url_intelligence) ? data.url_intelligence : []);
          setDomainIntelligence(Array.isArray(data.domain_intelligence) ? data.domain_intelligence : []);
          setAttachments(Array.isArray(data.attachments) ? data.attachments : []);
  setThreatIntelligence(data.threat_intelligence || null);
  setNlpAnalysis(data.nlp_analysis || null);
  setMlClassifier(data.ml_classifier || null);
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
    setMlClassifier(null);
  
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
      setUrls(
        Array.isArray(data.urls)
          ? data.urls.map((item: string | UrlRecord | null | undefined) =>
              typeof item === "string" ? item : item?.url || String(item ?? "")
            )
          : []
      );
      setUrlIntelligence(Array.isArray(data.url_intelligence) ? data.url_intelligence : []);
      setDomainIntelligence(Array.isArray(data.domain_intelligence) ? data.domain_intelligence : []);
      setThreatIntelligence(data.threat_intelligence || null);
      setMlClassifier(data.ml_classifier || null);
      setAnalysis(
        `Analysis complete. Threat Score: ${data.threat_score}`
      );
      await loadInvestigations();
    } catch {
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
            <h1 className="text-2xl font-bold">🛡️ MailCipherX-AI</h1>
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
                    {Object.entries((nlpAnalysis.categories ?? {}) as Record<string, unknown>).map(([category, matches]) => {
                      const formattedMatches = Array.isArray(matches)
                        ? matches
                            .map((item: unknown) =>
                              typeof item === "string"
                                ? item
                                : typeof item === "object" && item !== null && "url" in item
                                  ? String((item as { url?: string }).url ?? "")
                                  : typeof item === "object" && item !== null && "value" in item
                                    ? String((item as { value?: unknown }).value ?? "")
                                    : JSON.stringify(item)
                            )
                            .join(", ")
                        : typeof matches === "object" && matches !== null
                          ? JSON.stringify(matches)
                          : String(matches ?? "");

                      return (
                        <div
                          key={category}
                          className="rounded-lg border border-slate-800 bg-slate-900 p-3"
                        >
                          <p className="text-sm font-semibold capitalize text-slate-200">
                            {category.replaceAll("_", " ")}
                          </p>
                          <p className="mt-1 break-words text-sm text-slate-400">
                            {formattedMatches}
                          </p>
                        </div>
                      );
                    })}
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

        <MlClassifierPanel data={mlClassifier} />

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
    ip: location.ip ?? "unknown",
    latitude: Number(location.latitude),
    longitude: Number(location.longitude),
    label:
      location.ip === candidateOriginIp
        ? `Candidate Origin: ${location.ip ?? "unknown"}`
        : `Relay IP: ${location.ip ?? "unknown"}`,
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
          {relayPath.map((hop) => {
            const hopIps = Array.isArray((hop as { ip_addresses?: unknown }).ip_addresses)
              ? ((hop as { ip_addresses?: unknown[] }).ip_addresses as string[])
              : [];

            return (
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

                {hopIps.length > 0 && (
                  <p className="mt-2 text-xs text-slate-500">
                    IPs: {hopIps.join(", ")}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </div>
    )}

    <p className="mt-4 text-xs text-yellow-400">
      ⚠️ Relay information is based on the email headers provided.
      It does not by itself prove the sender&apos;s identity or exact origin.
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
      ⚠️ Attachment analysis is metadata-based. MailCipherX-AI never executes uploaded files.
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
            : typeof url === "object" && url !== null && "url" in url
              ? String((url as { url?: string }).url ?? "")
              : String(url ?? "");

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
      {domainIntelligence.map((domain: DomainRecord, index: number) => (
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
                {Object.entries(domain.dns ?? {}).map(([recordType, values]) => (
                  <div
                    key={recordType}
                    className="rounded-lg border border-slate-800 bg-slate-900 p-3"
                  >
                    <p className="font-semibold uppercase text-slate-300">
                      {recordType}
                    </p>
                    <p className="mt-1 break-all">
                      {Array.isArray(values) ? values.join(", ") : String(values ?? "")}
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
                          (indicator: ThreatIndicator, index: number) => (
                          <div
                              key={`${indicator.type || "indicator"}-${indicator.value ?? index}-${index}`}
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
                                  {String(indicator.value ?? "Unknown")}
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

        </div>
        <RelationshipGraph />
        <CaseManagement />
        <PrivacySettingsPanel />
        <GmailMonitorPanel />
        <AlertFeed />
        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-xl font-semibold">🗂️ Investigation History</h3>
              <p className="mt-1 text-sm text-slate-400">
                Previously analyzed emails saved by MailCipherX-AI.
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
                          onClick={() => {
                            const numericId = investigationIdNumber(item.id);
                            if (numericId !== null) {
                              void viewInvestigation(numericId);
                            }
                          }}
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
                    <p><strong className="text-white">Created:</strong> {(() => {
                      const createdAt = selectedInvestigation.created_at;
                      if (createdAt == null) return "Unknown";
                      const date = createdAt instanceof Date ? createdAt : new Date(createdAt);
                      return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
                    })()}</p>
              </div>
              <EvidencePanel investigationId={selectedInvestigation.id ?? ""} />
              {selectedInvestigation.result != null && (
                <details className="mt-5">
                  <summary className="cursor-pointer text-sm font-semibold text-blue-400">
                    View complete stored analysis
                  </summary>
                  <pre className="mt-3 max-h-96 overflow-auto rounded-lg border border-slate-800 bg-black/30 p-4 text-xs text-slate-300">
                    {typeof selectedInvestigation.result === "string"
                      ? selectedInvestigation.result
                      : JSON.stringify(selectedInvestigation.result, null, 2)}
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
