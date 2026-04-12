import { useEffect, useMemo, useState } from "react";

import { api, backendBaseUrl } from "../api/client";
import { useAuth } from "../context/AuthContext";
import ModelStatusGrid from "./ModelStatusGrid";

const PHASES = [
  { key: "recon", label: "Recon", model: "Nemotron 3 Nano" },
  { key: "infrastructure", label: "Infrastructure", model: "Gemma 4 31B" },
  { key: "auth", label: "Auth Testing", model: "Llama 3.3 / Nemotron Super" },
  { key: "injection", label: "API & Injection", model: "Llama 3.3 / Qwen3 Coder" },
  { key: "chain", label: "Chain Analysis", model: "Nemotron 3 Super" },
  { key: "reporting", label: "Reporting", model: "Llama 3.3 / GPT-4o" },
  { key: "monitoring", label: "Monitoring", model: "Nemotron 3 Nano" },
];

function flattenAgentEvent(event) {
  return {
    type: event.type,
    timestamp: event.timestamp || event.data?.timestamp,
    event: event.data?.event,
    role: event.data?.role,
    model_id: event.data?.model_id,
    task: event.data?.task,
    status: event.data?.status,
    success: event.data?.success,
    tokens_used: event.data?.tokens_used,
    message: event.data?.message,
    error: event.data?.error,
  };
}

function phaseIndex(currentPhase) {
  const phase = (currentPhase || "").toLowerCase();
  if (["queued", "recon", "passive_dns", "subfinder", "httpx", "gau", "waybackurls", "katana"].includes(phase)) {
    return 0;
  }
  if (["port_scan", "screenshots", "waf_fingerprint"].includes(phase)) {
    return 1;
  }
  if (["auth", "oauth", "mfa"].includes(phase)) {
    return 2;
  }
  if (["nuclei", "parameter_discovery", "content_fuzzing", "adaptive_analysis"].includes(phase)) {
    return 3;
  }
  if (["attack_path_generation", "payload_opportunity_detection", "chain"].includes(phase)) {
    return 4;
  }
  if (["completed", "reporting"].includes(phase)) {
    return 5;
  }
  if (["monitoring"].includes(phase)) {
    return 6;
  }
  return 0;
}

function ChainVisualizer({ chains }) {
  if (!chains.length) {
    return <p className="muted-copy">No confirmed vulnerability chains are available for this scan yet.</p>;
  }

  return (
    <div className="verification-chain-list">
      {chains.slice(0, 6).map((chain, index) => {
        const nodes = chain.nodes?.length
          ? chain.nodes.map((node, nodeIndex) => ({
              label: node.kind || node.value || `Node ${nodeIndex + 1}`,
              severity: node.severity || chain.combined_severity || "Medium",
            }))
          : (chain.finding_ids || []).map((nodeId, nodeIndex) => ({
              label: `Finding ${nodeId}`,
              severity: chain.combined_severity || "Medium",
            }));

        return (
          <article className="verification-chain-card" key={`${chain.title || chain.endpoint}-${index}`}>
            <div className="panel-header">
              <div>
                <h3>{chain.title || chain.endpoint || `Chain ${index + 1}`}</h3>
                <p className="muted-copy">{chain.narrative || "Connected findings increase exploitation leverage."}</p>
              </div>
              <span className={`status-pill status-${(chain.combined_severity || "medium").toLowerCase()}`}>
                {chain.combined_severity || "Medium"}
              </span>
            </div>
            <div className="verification-chain-nodes">
              {nodes.map((node, nodeIndex) => (
                <div className="verification-chain-row" key={`${chain.title || chain.endpoint}-${nodeIndex}`}>
                  <div className={`verification-node ${(node.severity || "medium").toLowerCase()}`}>
                    <span>{node.label}</span>
                  </div>
                  {nodeIndex < nodes.length - 1 ? <div className="verification-link" /> : null}
                </div>
              ))}
            </div>
          </article>
        );
      })}
    </div>
  );
}

export default function VerificationWorkspace() {
  const { accessToken } = useAuth();
  const [targets, setTargets] = useState([]);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [targetDetail, setTargetDetail] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [state, setState] = useState(null);
  const [findings, setFindings] = useState([]);
  const [agentLog, setAgentLog] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");

  async function loadTargets() {
    const response = await api.get("/targets");
    setTargets(response.data);
    if (!selectedTargetId && response.data.length) {
      setSelectedTargetId(String(response.data[0].id));
    }
  }

  async function loadTargetDetail(targetId) {
    if (!targetId) {
      setTargetDetail(null);
      return;
    }
    const response = await api.get(`/targets/${targetId}`);
    setTargetDetail(response.data);
    if (response.data.scans?.length) {
      setSelectedScanId((current) => {
        const hasCurrent = response.data.scans.some((scan) => String(scan.id) === current);
        return hasCurrent ? current : String(response.data.scans[0].id);
      });
    } else {
      setSelectedScanId("");
    }
  }

  async function loadVerificationState(targetId, scanId) {
    if (!targetId) {
      setState(null);
      setFindings([]);
      return;
    }
    setIsLoading(true);
    setError("");
    try {
      const stateUrl = `/api/state?target_id=${targetId}${scanId ? `&scan_id=${scanId}` : ""}`;
      const findingsUrl = `/api/findings?target_id=${targetId}${scanId ? `&scan_id=${scanId}` : ""}`;
      const [{ data: stateData }, { data: findingsData }, { data: logData }] = await Promise.all([
        api.get(stateUrl),
        api.get(findingsUrl),
        api.get("/api/agent-log?limit=80"),
      ]);
      setState(stateData);
      setFindings(findingsData.findings || []);
      setAgentLog(logData.events || []);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load verification workspace");
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    loadTargets().catch(() => {
      setError("Failed to load targets");
      setIsLoading(false);
    });
  }, []);

  useEffect(() => {
    if (!selectedTargetId) {
      return;
    }
    loadTargetDetail(selectedTargetId).catch(() => {
      setError("Failed to load target detail");
    });
  }, [selectedTargetId]);

  useEffect(() => {
    if (!selectedTargetId) {
      return;
    }
    loadVerificationState(selectedTargetId, selectedScanId).catch(() => {
      setError("Failed to load verification state");
      setIsLoading(false);
    });
  }, [selectedTargetId, selectedScanId]);

  useEffect(() => {
    if (!accessToken) {
      return undefined;
    }
    const wsUrl = `${backendBaseUrl.replace(/^http/, "ws")}/ws/agent-log?token=${encodeURIComponent(accessToken)}`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      socket.send(JSON.stringify({ type: "subscribe", channels: ["agent_log"] }));
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type !== "agent_log") {
          return;
        }
        const flattened = flattenAgentEvent(payload);
        setAgentLog((current) => [...current.slice(-79), flattened]);
      } catch (_error) {
        // ignore malformed websocket messages
      }
    };

    return () => {
      socket.close();
    };
  }, [accessToken]);

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      if (severityFilter !== "all" && finding.severity.toLowerCase() !== severityFilter) {
        return false;
      }
      if (statusFilter !== "all" && finding.status !== statusFilter) {
        return false;
      }
      if (typeFilter !== "all" && finding.type !== typeFilter) {
        return false;
      }
      return true;
    });
  }, [findings, severityFilter, statusFilter, typeFilter]);

  const findingTypes = useMemo(() => [...new Set(findings.map((finding) => finding.type))].sort(), [findings]);
  const activePhaseIndex = phaseIndex(state?.current_phase);

  if (isLoading && !state) {
    return <section className="panel-card">Loading verification workspace...</section>;
  }

  return (
    <section className="stack-list" style={{ gap: "1rem" }}>
      <section className="panel-card">
        <div className="panel-header" style={{ alignItems: "flex-start" }}>
          <div>
            <h2>Verification Workspace</h2>
            <p className="muted-copy">
              Audit the live model roster, per-scan state object, findings, and chain activity from one admin view.
            </p>
          </div>
          <div className="verification-controls">
            <select value={selectedTargetId} onChange={(event) => setSelectedTargetId(event.target.value)}>
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.domain}
                </option>
              ))}
            </select>
            <select value={selectedScanId} onChange={(event) => setSelectedScanId(event.target.value)}>
              <option value="">Latest scan</option>
              {(targetDetail?.scans || []).map((scan) => (
                <option key={scan.id} value={scan.id}>
                  Scan #{scan.id} - {scan.status}
                </option>
              ))}
            </select>
            <button className="ghost-button" onClick={() => loadVerificationState(selectedTargetId, selectedScanId)} type="button">
              Refresh
            </button>
          </div>
        </div>
        {error ? <p className="error-text">{error}</p> : null}
      </section>

      <section className="verification-pipeline">
        {PHASES.map((phase, index) => {
          const status = index < activePhaseIndex ? "done" : index === activePhaseIndex ? "active" : "pending";
          return (
            <article className={`verification-step ${status}`} key={phase.key}>
              <span className="verification-step-index">{index + 1}</span>
              <div>
                <strong>{phase.label}</strong>
                <div className="table-subcopy">{phase.model}</div>
              </div>
            </article>
          );
        })}
      </section>

      <section className="summary-strip" style={{ gridTemplateColumns: "repeat(4, minmax(0, 1fr))" }}>
        <article className="summary-card">
          <span>Subdomains Found</span>
          <strong>{state?.hosts?.total_discovered || 0}</strong>
        </article>
        <article className="summary-card">
          <span>Live Hosts</span>
          <strong>{state?.hosts?.live || 0}</strong>
        </article>
        <article className="summary-card highlight-card">
          <span>Findings</span>
          <strong>{findings.length}</strong>
        </article>
        <article className="summary-card">
          <span>Reports Drafted</span>
          <strong>{state?.reports_drafted || 0}</strong>
        </article>
      </section>

      <section className="layout-grid" style={{ gridTemplateColumns: "minmax(0, 1.2fr) minmax(0, 1fr)" }}>
        <article className="panel-card">
          <div className="panel-header">
            <h2>Agent Log</h2>
            <span className="pill">{agentLog.length} events</span>
          </div>
          <div className="verification-log-panel">
            {agentLog.length ? (
              agentLog
                .slice()
                .reverse()
                .map((entry, index) => (
                  <div className={`verification-log-line ${entry.status || "info"}`} key={`${entry.timestamp}-${index}`}>
                    <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                    <span>{entry.role || entry.type || "system"}</span>
                    <span>{entry.task || entry.event || "event"}</span>
                    <span>{entry.status || (entry.success ? "success" : "info")}</span>
                  </div>
                ))
            ) : (
              <p className="muted-copy">No agent log events yet.</p>
            )}
          </div>
        </article>

        <article className="panel-card">
          <h2>State Snapshot</h2>
          <div className="stack-list compact-stack">
            <div className="list-row">
              <strong>Target</strong>
              <span>{state?.target || "No target selected"}</span>
            </div>
            <div className="list-row">
              <strong>Current Phase</strong>
              <span className={`status-pill status-${(state?.current_phase || "queued").toLowerCase()}`}>{state?.current_phase || "queued"}</span>
            </div>
            <div className="list-row">
              <strong>Scan Mode</strong>
              <span>{state?.scan_mode || "balanced"}</span>
            </div>
            <div className="list-row">
              <strong>Next Action</strong>
              <span>{state?.next_action || "Awaiting scan context."}</span>
            </div>
          </div>
          {state?.escalations?.length ? (
            <>
              <h3 style={{ marginTop: "1rem" }}>Escalations</h3>
              <ul className="stack-list compact-stack">
                {state.escalations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </>
          ) : null}
        </article>
      </section>

      <section className="panel-card">
        <div className="panel-header">
          <h2>Findings</h2>
          <span className="pill">{filteredFindings.length}</span>
        </div>
        <div className="filter-row" style={{ marginBottom: "1rem" }}>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">All statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="reported">Reported</option>
            <option value="unconfirmed">Unconfirmed</option>
          </select>
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            <option value="all">All types</option>
            {findingTypes.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>
        <div className="stack-list">
          {filteredFindings.length ? (
            filteredFindings.map((finding) => (
              <details className="verification-finding-card" key={finding.id}>
                <summary>
                  <span className={`status-pill status-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                  <strong>{finding.type}</strong>
                  <span className="table-subcopy">{finding.endpoint}</span>
                </summary>
                <p>{finding.description || "No description available."}</p>
                <p className="table-subcopy">CVSS {finding.cvss_score || "0.0"} {finding.cvss_vector}</p>
                {finding.reproduction_steps?.length ? (
                  <div className="stack-list compact-stack">
                    {finding.reproduction_steps.map((step, index) => (
                      <div className="list-row" key={`${finding.id}-${index}`}>
                        <strong>Step {index + 1}</strong>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </details>
            ))
          ) : (
            <p className="muted-copy">No findings match the selected filters.</p>
          )}
        </div>
      </section>

      <section className="layout-grid" style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1.1fr)" }}>
        <article className="panel-card">
          <div className="panel-header">
            <h2>Chain Visualizer</h2>
            <span className="pill">{state?.chains_identified?.length || 0}</span>
          </div>
          <ChainVisualizer chains={state?.chains_identified || []} />
        </article>

        <ModelStatusGrid />
      </section>
    </section>
  );
}
