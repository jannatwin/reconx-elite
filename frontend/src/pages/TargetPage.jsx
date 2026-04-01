import { startTransition, useDeferredValue, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api, backendBaseUrl } from "../api/client";
import OverviewTab from "../components/OverviewTab";

const templateOptions = ["cves", "exposures", "misconfiguration", "fuzzing"];
const severityOptions = ["low", "medium", "high", "critical"];
const severityWeight = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export default function TargetPage() {
  const { targetId } = useParams();
  const [target, setTarget] = useState(null);
  const [bookmarks, setBookmarks] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [endpointSearch, setEndpointSearch] = useState("");
  const deferredEndpointSearch = useDeferredValue(endpointSearch);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [environmentFilter, setEnvironmentFilter] = useState("all");
  const [tagFilter, setTagFilter] = useState("all");
  const [focusMode, setFocusMode] = useState(false);
  const [selectedTemplates, setSelectedTemplates] = useState(["cves", "exposures"]);
  const [selectedSeverities, setSelectedSeverities] = useState(["high", "critical"]);
  const [targetNotes, setTargetNotes] = useState("");
  const [vulnNotes, setVulnNotes] = useState({});
  const [scheduleFrequency, setScheduleFrequency] = useState("daily");

  async function loadPage() {
    setIsLoading(true);
    try {
      const [targetResponse, bookmarkResponse, scheduleResponse] = await Promise.all([
        api.get(`/targets/${targetId}`),
        api.get("/bookmarks"),
        api.get("/schedules"),
      ]);
      startTransition(() => {
        setTarget(targetResponse.data);
        setBookmarks(bookmarkResponse.data);
        setSchedules(scheduleResponse.data.filter((item) => item.target_id === Number(targetId)));
      });
      setTargetNotes(targetResponse.data.notes || "");
      const latestScan = targetResponse.data.scans?.[0];
      setVulnNotes(
        Object.fromEntries((latestScan?.vulnerabilities || []).map((item) => [item.id, item.notes || ""])),
      );
      setError("");
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load target");
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    loadPage();
    const interval = window.setInterval(() => {
      loadPage();
    }, 5000);
    return () => window.clearInterval(interval);
  }, [targetId]);

  const latestScan = target?.scans?.[0] || null;
  const subdomains = latestScan?.subdomains || [];
  const endpoints = latestScan?.endpoints || [];
  const vulnerabilities = latestScan?.vulnerabilities || [];
  const attackPaths = latestScan?.attack_paths || [];
  const javascriptAssets = latestScan?.javascript_assets || [];
  const scanLogs = latestScan?.logs || [];
  const latestDiff = latestScan?.diffs?.[0] || null;

  const availableTags = useMemo(() => {
    const tags = new Set();
    for (const row of subdomains) {
      for (const tag of row.tags || []) {
        tags.add(tag);
      }
    }
    for (const row of endpoints) {
      for (const tag of row.tags || []) {
        tags.add(tag);
      }
    }
    return [...tags].sort();
  }, [subdomains, endpoints]);

  const summary = useMemo(() => {
    const liveHosts = subdomains.filter((item) => item.is_live).length;
    const highPriorityEndpoints = endpoints.filter((item) => item.priority_score >= 60).length;
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const vulnerability of vulnerabilities) {
      const severity = (vulnerability.severity || "info").toLowerCase();
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;
    }
    return {
      totalSubdomains: subdomains.length,
      liveHosts,
      endpoints: endpoints.length,
      highPriorityEndpoints,
      vulnerabilities: vulnerabilities.length,
      attackPaths: attackPaths.length,
      severityCounts,
    };
  }, [subdomains, endpoints, vulnerabilities, attackPaths]);

  const severityChartData = useMemo(
    () =>
      Object.entries(summary.severityCounts).map(([severity, count]) => ({
        severity,
        count,
      })),
    [summary],
  );

  const progressTimelineData = useMemo(() => {
    let cumulative = 0;
    return scanLogs.map((log, index) => {
      cumulative += log.duration_ms || 0;
      return {
        idx: index + 1,
        step: log.step,
        durationMs: log.duration_ms || 0,
        cumulativeMs: cumulative,
      };
    });
  }, [scanLogs]);

  const scanHistoryData = useMemo(() => {
    return (target?.scans || [])
      .filter((scan) => scan.status === "completed")
      .slice()
      .reverse()
      .map((scan) => ({
        date: new Date(scan.created_at).toLocaleDateString(),
        subdomains: scan.subdomains.length,
        endpoints: scan.endpoints.length,
        vulnerabilities: scan.vulnerabilities.length,
      }));
  }, [target]);

  const filteredSubdomains = useMemo(() => {
    return subdomains.filter((item) => {
      if (environmentFilter !== "all" && item.environment !== environmentFilter) {
        return false;
      }
      if (tagFilter !== "all" && !(item.tags || []).includes(tagFilter)) {
        return false;
      }
      if (focusMode && !item.is_live && !item.takeover_candidate) {
        return false;
      }
      return true;
    });
  }, [subdomains, environmentFilter, tagFilter, focusMode]);

  const filteredEndpoints = useMemo(() => {
    return endpoints
      .filter((item) => {
        const matchesSearch =
          !deferredEndpointSearch ||
          item.url.toLowerCase().includes(deferredEndpointSearch.toLowerCase()) ||
          item.normalized_url.toLowerCase().includes(deferredEndpointSearch.toLowerCase());
        if (!matchesSearch) {
          return false;
        }
        if (sourceFilter !== "all" && item.source !== sourceFilter) {
          return false;
        }
        if (tagFilter !== "all" && !(item.tags || []).includes(tagFilter)) {
          return false;
        }
        if (focusMode && item.priority_score < 60) {
          return false;
        }
        return true;
      })
      .sort((left, right) => right.priority_score - left.priority_score);
  }, [endpoints, deferredEndpointSearch, sourceFilter, tagFilter, focusMode]);

  const filteredVulnerabilities = useMemo(() => {
    return vulnerabilities
      .filter((item) => {
        if (severityFilter !== "all" && item.severity !== severityFilter) {
          return false;
        }
        if (sourceFilter !== "all" && item.source !== sourceFilter) {
          return false;
        }
        if (focusMode && !["critical", "high"].includes(item.severity)) {
          return false;
        }
        return true;
      })
      .sort((left, right) => severityWeight[right.severity] - severityWeight[left.severity]);
  }, [vulnerabilities, severityFilter, sourceFilter, focusMode]);

  const filteredAttackPaths = useMemo(() => {
    return attackPaths
      .filter((item) => {
        if (severityFilter !== "all" && item.severity !== severityFilter) {
          return false;
        }
        if (focusMode && item.score < 120) {
          return false;
        }
        return true;
      })
      .sort((left, right) => right.score - left.score);
  }, [attackPaths, severityFilter, focusMode]);

  async function triggerScan() {
    setError("");
    try {
      await api.post(`/scan/${targetId}`);
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Scan failed to start");
    }
  }

  async function triggerConfiguredScan() {
    setError("");
    try {
      await api.post(`/scan/${targetId}/config`, {
        selected_templates: selectedTemplates,
        severity_filter: selectedSeverities,
      });
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Configured scan failed to start");
    }
  }

  async function saveTargetNotes() {
    setIsSaving(true);
    try {
      await api.put(`/targets/${targetId}`, { notes: targetNotes });
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Could not save target notes");
    } finally {
      setIsSaving(false);
    }
  }

  async function saveVulnNotes(vulnerabilityId) {
    try {
      await api.put(`/vulnerabilities/${vulnerabilityId}`, { notes: vulnNotes[vulnerabilityId] || "" });
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Could not save vulnerability notes");
    }
  }

  async function toggleBookmark(endpointId) {
    const existing = bookmarks.find((bookmark) => bookmark.endpoint_id === endpointId);
    try {
      if (existing) {
        await api.delete(`/bookmarks/${existing.id}`);
      } else {
        await api.post("/bookmarks", { endpoint_id: endpointId });
      }
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Bookmark update failed");
    }
  }

  async function createSchedule() {
    try {
      await api.post("/schedules", {
        target_id: Number(targetId),
        frequency: scheduleFrequency,
        scan_config: {
          selected_templates: selectedTemplates,
          severity_filter: selectedSeverities,
        },
      });
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Could not create schedule");
    }
  }

  async function toggleSchedule(schedule) {
    try {
      await api.put(`/schedules/${schedule.id}`, { enabled: !schedule.enabled });
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Could not update schedule");
    }
  }

  async function deleteSchedule(scheduleId) {
    try {
      await api.delete(`/schedules/${scheduleId}`);
      await loadPage();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Could not delete schedule");
    }
  }

  function toggleListItem(list, setList, value) {
    setList(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  }

  if (isLoading) {
    return <main className="page-shell"><div className="panel-card">Loading target...</div></main>;
  }

  return (
    <main className="page-shell">
      <header className="page-header">
        <div>
          <Link className="text-link" to="/">
            Back to dashboard
          </Link>
          <h1>{target?.domain}</h1>
          <p className="lede">
            Latest stage: <span className={`status-pill status-${latestScan?.status || "idle"}`}>{latestScan?.metadata_json?.stage || latestScan?.status || "not-scanned"}</span>
          </p>
        </div>
        <div className="button-row">
          <a className="ghost-button link-button" href={`${backendBaseUrl}/reports/${targetId}/json`} rel="noreferrer" target="_blank">
            JSON report
          </a>
          <a className="ghost-button link-button" href={`${backendBaseUrl}/reports/${targetId}/pdf`} rel="noreferrer" target="_blank">
            PDF report
          </a>
          <button className="primary-button" onClick={triggerScan} type="button">
            Trigger default scan
          </button>
        </div>
      </header>

      {error ? <p className="error-text panel-card">{error}</p> : null}

      <section className="layout-grid">
        <article className="panel-card">
          <h2>Target notes</h2>
          <textarea
            className="notes-area"
            value={targetNotes}
            onChange={(event) => setTargetNotes(event.target.value)}
            placeholder="Capture scope notes, escalation paths, or account context here."
            rows={5}
          />
          <button className="primary-button" disabled={isSaving} onClick={saveTargetNotes} type="button">
            {isSaving ? "Saving..." : "Save notes"}
          </button>
        </article>

        <article className="panel-card">
          <h2>Configured scan</h2>
          <div className="chip-grid">
            {templateOptions.map((option) => (
              <button
                className={selectedTemplates.includes(option) ? "chip chip-active" : "chip"}
                key={option}
                onClick={() => toggleListItem(selectedTemplates, setSelectedTemplates, option)}
                type="button"
              >
                {option}
              </button>
            ))}
          </div>
          <div className="chip-grid">
            {severityOptions.map((option) => (
              <button
                className={selectedSeverities.includes(option) ? "chip chip-active" : "chip"}
                key={option}
                onClick={() => toggleListItem(selectedSeverities, setSelectedSeverities, option)}
                type="button"
              >
                {option}
              </button>
            ))}
          </div>
          <button className="primary-button" onClick={triggerConfiguredScan} type="button">
            Trigger configured scan
          </button>
        </article>

        <article className="panel-card">
          <div className="panel-header">
            <h2>Schedules</h2>
            <span className="pill">{schedules.length}</span>
          </div>
          <div className="button-row">
            <select value={scheduleFrequency} onChange={(event) => setScheduleFrequency(event.target.value)}>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
            <button className="ghost-button" onClick={createSchedule} type="button">
              Create schedule
            </button>
          </div>
          <div className="stack-list">
            {schedules.length ? (
              schedules.map((schedule) => (
                <div className="list-row" key={schedule.id}>
                  <div>
                    <strong>{schedule.frequency}</strong>
                    <div className="table-subcopy">Next run: {schedule.next_run ? new Date(schedule.next_run).toLocaleString() : "unset"}</div>
                  </div>
                  <div className="button-row">
                    <button className="ghost-button" onClick={() => toggleSchedule(schedule)} type="button">
                      {schedule.enabled ? "Pause" : "Enable"}
                    </button>
                    <button className="ghost-button danger-button" onClick={() => deleteSchedule(schedule.id)} type="button">
                      Delete
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <p className="muted-copy">No schedules yet.</p>
            )}
          </div>
        </article>
      </section>

      <section className="panel-card filter-bar">
        <div className="filter-row">
          <select value={environmentFilter} onChange={(event) => setEnvironmentFilter(event.target.value)}>
            <option value="all">All environments</option>
            <option value="prod">Prod</option>
            <option value="staging">Staging</option>
            <option value="dev">Dev</option>
            <option value="unknown">Unknown</option>
          </select>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
            <option value="all">All sources</option>
            <option value="gau">gau</option>
            <option value="js">js</option>
            <option value="nuclei">nuclei</option>
            <option value="heuristic">heuristic</option>
          </select>
          <select value={tagFilter} onChange={(event) => setTagFilter(event.target.value)}>
            <option value="all">All tags</option>
            {availableTags.map((tag) => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
          </select>
          <label className="toggle-inline">
            <input checked={focusMode} onChange={(event) => setFocusMode(event.target.checked)} type="checkbox" />
            Focus mode
          </label>
        </div>
      </section>

      <nav className="tab-row">
        {[
          ["overview", "Overview"],
          ["recon", "Recon Data"],
          ["vulnerabilities", "Vulnerabilities"],
          ["surface", "Attack Surface"],
          ["paths", "Attack Paths"],
        ].map(([value, label]) => (
          <button
            className={activeTab === value ? "tab-button tab-button-active" : "tab-button"}
            key={value}
            onClick={() => setActiveTab(value)}
            type="button"
          >
            {label}
          </button>
        ))}
      </nav>

      {activeTab === "overview" ? (
        <OverviewTab
          progressTimelineData={progressTimelineData}
          scanHistoryData={scanHistoryData}
          severityChartData={severityChartData}
          summary={summary}
        />
      ) : null}

      {activeTab === "recon" ? (
        <>
          {latestDiff ? (
            <section className="panel-card">
              <h2>Latest diff</h2>
              <p className="muted-copy">
                {latestDiff.new_subdomains.length} new subdomains, {latestDiff.new_endpoints.length} new endpoints, {latestDiff.new_vulnerabilities.length} new findings.
              </p>
            </section>
          ) : null}
          <section className="panel-card">
            <div className="panel-header">
              <h2>Subdomains</h2>
              <span className="pill">{filteredSubdomains.length}</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>Environment</th>
                    <th>Live</th>
                    <th>CDN/WAF</th>
                    <th>Takeover</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSubdomains.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <strong>{item.hostname}</strong>
                        <div className="table-subcopy">{(item.tags || []).join(", ") || "no tags"}</div>
                      </td>
                      <td>{item.environment}</td>
                      <td>{item.is_live ? "Live" : "No response"}</td>
                      <td>{item.cdn_waf || "-"}</td>
                      <td>{item.takeover_candidate ? "Candidate" : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel-card">
            <div className="panel-header">
              <h2>Stage logs</h2>
              <span className="pill">{scanLogs.length}</span>
            </div>
            <div className="stack-list">
              {scanLogs.map((log) => (
                <article className="log-row" key={log.id}>
                  <div className="log-row-head">
                    <strong>{log.step}</strong>
                    <span className={`status-pill status-${log.status}`}>{log.status}</span>
                  </div>
                  <p className="muted-copy">
                    {log.duration_ms} ms, attempt {log.attempts}
                  </p>
                  <pre>{JSON.stringify(log.details_json || {}, null, 2)}</pre>
                </article>
              ))}
            </div>
          </section>
        </>
      ) : null}

      {activeTab === "vulnerabilities" ? (
        <section className="panel-card">
          <div className="panel-header">
            <h2>Vulnerabilities</h2>
            <span className="pill">{filteredVulnerabilities.length}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Source</th>
                  <th>Template</th>
                  <th>Matched URL</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulnerabilities.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <span className={`status-pill status-${item.severity}`}>{item.severity}</span>
                    </td>
                    <td>{item.source}</td>
                    <td>
                      <strong>{item.template_id}</strong>
                      <div className="table-subcopy">confidence {item.confidence.toFixed(2)}</div>
                    </td>
                    <td>{item.matched_url || item.host || "-"}</td>
                    <td>
                      <textarea
                        className="notes-area compact"
                        rows={3}
                        value={vulnNotes[item.id] || ""}
                        onChange={(event) => setVulnNotes({ ...vulnNotes, [item.id]: event.target.value })}
                      />
                      <button className="ghost-button" onClick={() => saveVulnNotes(item.id)} type="button">
                        Save
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {activeTab === "surface" ? (
        <>
          <section className="panel-card">
            <div className="panel-header">
              <h2>Endpoints</h2>
              <span className="pill">{filteredEndpoints.length}</span>
            </div>
            <div className="button-row">
              <input
                value={endpointSearch}
                onChange={(event) => setEndpointSearch(event.target.value)}
                placeholder="Search endpoints"
              />
              <button
                className="ghost-button"
                onClick={() => navigator.clipboard.writeText(filteredEndpoints.map((item) => item.url).join("\n"))}
                type="button"
              >
                Copy URLs
              </button>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Source</th>
                    <th>Score</th>
                    <th>Focus</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEndpoints.map((item) => {
                    const isBookmarked = bookmarks.some((bookmark) => bookmark.endpoint_id === item.id);
                    return (
                      <tr key={item.id}>
                        <td>
                          <strong>{item.normalized_url}</strong>
                          <div className="table-subcopy">{(item.tags || []).join(", ") || "general"}</div>
                        </td>
                        <td>{item.source}</td>
                        <td>{item.priority_score}</td>
                        <td>{(item.focus_reasons || []).join(", ") || "-"}</td>
                        <td>
                          <div className="button-row">
                            <button className="ghost-button" onClick={() => window.open(item.url, "_blank", "noopener,noreferrer")} type="button">
                              Open
                            </button>
                            <button className="ghost-button" onClick={() => toggleBookmark(item.id)} type="button">
                              {isBookmarked ? "Unbookmark" : "Bookmark"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel-card">
            <div className="panel-header">
              <h2>JavaScript intelligence</h2>
              <span className="pill">{javascriptAssets.length}</span>
            </div>
            <div className="stack-list">
              {javascriptAssets.length ? (
                javascriptAssets.map((asset) => (
                  <article className="list-row" key={asset.id}>
                    <div>
                      <strong>{asset.url}</strong>
                      <div className="table-subcopy">
                        {asset.extracted_endpoints.length} extracted endpoints, {asset.secrets_json.length} secret candidates
                      </div>
                    </div>
                    <span className={`status-pill status-${asset.status}`}>{asset.status}</span>
                  </article>
                ))
              ) : (
                <p className="muted-copy">No JavaScript assets captured in the latest scan.</p>
              )}
            </div>
          </section>
        </>
      ) : null}

      {activeTab === "paths" ? (
        <section className="stack-list">
          {filteredAttackPaths.length ? (
            filteredAttackPaths.map((path) => (
              <article className="panel-card" key={path.id}>
                <div className="panel-header">
                  <div>
                    <h2>{path.title}</h2>
                    <p className="muted-copy">{path.summary}</p>
                  </div>
                  <span className={`status-pill status-${path.severity}`}>{path.score}</span>
                </div>
                <div className="stack-list compact-stack">
                  {(path.steps_json || []).map((step, index) => (
                    <div className="list-row" key={`${path.id}-${index}`}>
                      <strong>{step.kind}</strong>
                      <span>{step.value}</span>
                    </div>
                  ))}
                </div>
              </article>
            ))
          ) : (
            <section className="panel-card">
              <p className="muted-copy">No ranked attack paths were produced for the latest scan.</p>
            </section>
          )}
        </section>
      ) : null}
    </main>
  );
}
