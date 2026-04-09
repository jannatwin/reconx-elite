import { useCallback, useEffect, useState } from "react";

import { api, formatApiErrorDetail } from "../api/client";

const SECTIONS = [
  ["advanced", "Advanced recon"],
  ["manual", "Manual testing"],
  ["oob", "Out-of-band"],
  ["validation", "Exploit validation"],
  ["templates", "Custom templates"],
  ["intel", "Intelligence"],
];

const defaultStealth = {
  scan_mode: "balanced",
  requests_per_second: 5,
  random_delay_min: 100,
  random_delay_max: 500,
  concurrent_threads: 2,
  max_retries: 3,
  retry_backoff_factor: 2,
  rotate_user_agents: true,
  use_jitter: true,
  jitter_percentage: 20,
  respect_robots_txt: true,
};

export default function TargetToolsPanel({ targetId, scanId, vulnerabilities = [] }) {
  const [section, setSection] = useState("advanced");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const [stealth, setStealth] = useState(defaultStealth);
  const [paramUrlsText, setParamUrlsText] = useState("");
  const [fuzzUrlsText, setFuzzUrlsText] = useState("");
  const [fuzzCategory, setFuzzCategory] = useState("admin");
  const [discoveredParams, setDiscoveredParams] = useState([]);
  const [fuzzedEndpoints, setFuzzedEndpoints] = useState([]);

  const [manualMethod, setManualMethod] = useState("GET");
  const [manualUrl, setManualUrl] = useState("https://");
  const [manualHeaders, setManualHeaders] = useState("{}");
  const [manualBody, setManualBody] = useState("");
  const [manualResult, setManualResult] = useState(null);

  const [payloadType, setPayloadType] = useState("xss");
  const [payloadTemplates, setPayloadTemplates] = useState({});
  const [payloadTargetParam, setPayloadTargetParam] = useState("");
  const [payloadResult, setPayloadResult] = useState(null);
  const [testHistory, setTestHistory] = useState([]);

  const [oobType, setOobType] = useState("ssrf");
  const [oobVulnId, setOobVulnId] = useState("");
  const [oobCallback, setOobCallback] = useState(null);
  const [oobInteractions, setOobInteractions] = useState([]);

  const [valVulnId, setValVulnId] = useState("");
  const [valPayload, setValPayload] = useState("");
  const [valResults, setValResults] = useState([]);

  const [templates, setTemplates] = useState([]);
  const [newTplName, setNewTplName] = useState("");
  const [newTplYaml, setNewTplYaml] = useState("id: user-template\ninfo:\n  name: example\n  author: you\n");

  const [insights, setInsights] = useState(null);
  const [patterns, setPatterns] = useState([]);

  const tid = Number(targetId);

  const showMsg = useCallback((text) => {
    setMessage(text);
    setError("");
    window.setTimeout(() => setMessage(""), 5000);
  }, []);

  const showErr = useCallback((err) => {
    setError(formatApiErrorDetail(err?.response?.data?.detail) || err?.message || "Request failed");
    setMessage("");
  }, []);

  const loadStealth = useCallback(async () => {
    try {
      const { data } = await api.get(`/advanced-recon/stealth-config/${tid}`);
      if (data && data.scan_mode) {
        setStealth({
          scan_mode: data.scan_mode,
          requests_per_second: data.requests_per_second,
          random_delay_min: data.random_delay_min,
          random_delay_max: data.random_delay_max,
          concurrent_threads: data.concurrent_threads,
          max_retries: data.max_retries,
          retry_backoff_factor: data.retry_backoff_factor,
          rotate_user_agents: data.rotate_user_agents,
          use_jitter: data.use_jitter,
          jitter_percentage: data.jitter_percentage,
          respect_robots_txt: data.respect_robots_txt,
        });
      }
    } catch {
      /* defaults */
    }
  }, [tid]);

  const loadAdvancedLists = useCallback(async () => {
    try {
      const [pRes, fRes] = await Promise.all([
        api.get(`/advanced-recon/parameters/${tid}`),
        api.get(`/advanced-recon/fuzzed-endpoints/${tid}`),
      ]);
      setDiscoveredParams(pRes.data?.parameters || []);
      setFuzzedEndpoints(fRes.data?.endpoints || []);
    } catch (e) {
      showErr(e);
    }
  }, [tid, showErr]);

  const loadPayloadTemplates = useCallback(async () => {
    try {
      const { data } = await api.get("/testing/payloads/templates");
      setPayloadTemplates(data?.templates || {});
      const keys = data?.payload_types || Object.keys(data?.templates || {});
      if (keys.length) {
        setPayloadType((prev) => (keys.includes(prev) ? prev : keys[0]));
      }
    } catch {
      /* ignore */
    }
  }, []);

  const loadTestHistory = useCallback(async () => {
    try {
      const { data } = await api.get("/testing/history?limit=30");
      setTestHistory(data?.history || []);
    } catch {
      setTestHistory([]);
    }
  }, []);

  const loadOob = useCallback(async () => {
    try {
      const { data } = await api.get("/oob/interactions?limit=50");
      setOobInteractions(data?.interactions || []);
    } catch {
      setOobInteractions([]);
    }
  }, []);

  const loadTemplates = useCallback(async () => {
    try {
      const { data } = await api.get("/templates/?only_active=true");
      setTemplates(data?.templates || []);
    } catch {
      setTemplates([]);
    }
  }, []);

  const loadIntel = useCallback(async () => {
    try {
      const [ins, pat] = await Promise.all([
        api.get("/intelligence/insights"),
        api.get("/intelligence/patterns?limit=30"),
      ]);
      setInsights(ins.data?.insights ?? ins.data);
      setPatterns(pat.data?.patterns || []);
    } catch (e) {
      showErr(e);
    }
  }, [showErr]);

  useEffect(() => {
    loadStealth();
    loadAdvancedLists();
    loadPayloadTemplates();
    loadTestHistory();
  }, [loadStealth, loadAdvancedLists, loadPayloadTemplates, loadTestHistory]);

  useEffect(() => {
    if (section === "oob") loadOob();
    if (section === "templates") loadTemplates();
    if (section === "intel") loadIntel();
  }, [section, loadOob, loadTemplates, loadIntel]);

  async function saveStealthConfig(event) {
    event.preventDefault();
    try {
      await api.post(`/advanced-recon/stealth-config/${tid}`, stealth);
      showMsg("Stealth configuration saved.");
    } catch (e) {
      showErr(e);
    }
  }

  async function runParameterDiscovery(event) {
    event.preventDefault();
    const endpoint_urls = paramUrlsText
      .split(/\r?\n/)
      .map((u) => u.trim())
      .filter(Boolean);
    if (!endpoint_urls.length) {
      setError("Add at least one endpoint URL (one per line).");
      return;
    }
    try {
      await api.post("/advanced-recon/parameter-discovery", {
        target_id: tid,
        endpoint_urls,
        stealth_config: stealth,
      });
      showMsg("Parameter discovery queued (Celery worker). Refresh lists in a minute.");
    } catch (e) {
      showErr(e);
    }
  }

  async function runContentFuzz(event) {
    event.preventDefault();
    const base_urls = fuzzUrlsText
      .split(/\r?\n/)
      .map((u) => u.trim())
      .filter(Boolean);
    if (!base_urls.length) {
      setError("Add at least one base URL (one per line).");
      return;
    }
    try {
      await api.post("/advanced-recon/content-fuzzing", {
        target_id: tid,
        base_urls,
        wordlist_category: fuzzCategory,
        stealth_config: stealth,
      });
      showMsg("Content fuzzing queued (Celery worker). Refresh lists in a minute.");
    } catch (e) {
      showErr(e);
    }
  }

  async function sendManualSync(event) {
    event.preventDefault();
    let headers = {};
    try {
      headers = JSON.parse(manualHeaders || "{}");
    } catch {
      setError("Headers must be valid JSON.");
      return;
    }
    try {
      const { data } = await api.post("/testing/request/sync", {
        method: manualMethod,
        url: manualUrl,
        headers,
        body: manualBody || null,
        params: {},
      });
      setManualResult(data);
      loadTestHistory();
      showMsg("Request completed.");
    } catch (e) {
      showErr(e);
    }
  }

  async function runPayloadSync(event) {
    event.preventDefault();
    let headers = {};
    try {
      headers = JSON.parse(manualHeaders || "{}");
    } catch {
      setError("Headers must be valid JSON.");
      return;
    }
    try {
      const { data } = await api.post("/testing/payloads/sync", {
        base_request: {
          method: manualMethod,
          url: manualUrl,
          headers,
          body: manualBody || null,
          params: {},
        },
        payload_type: payloadType,
        target_param: payloadTargetParam || null,
      });
      setPayloadResult(data);
      loadTestHistory();
      showMsg(`Payload batch finished (${data.total_tests} tests).`);
    } catch (e) {
      showErr(e);
    }
  }

  async function generateOob(event) {
    event.preventDefault();
    const params = { interaction_type: oobType };
    if (scanId) params.scan_id = scanId;
    if (oobVulnId) params.vulnerability_id = Number(oobVulnId);
    try {
      const { data } = await api.post("/oob/generate-callback", null, { params });
      setOobCallback(data);
      showMsg("Callback generated. Use the URL in SSRF / blind payloads.");
      loadOob();
    } catch (e) {
      showErr(e);
    }
  }

  async function queueValidation(event) {
    event.preventDefault();
    if (!valVulnId) {
      setError("Select a vulnerability.");
      return;
    }
    try {
      await api.post(`/validation/vulnerability/${valVulnId}`, null, {
        params: valPayload ? { payload: valPayload } : {},
      });
      showMsg("Validation queued. Fetch results when the worker finishes.");
    } catch (e) {
      showErr(e);
    }
  }

  async function fetchValidationResults(event) {
    event.preventDefault();
    if (!valVulnId) {
      setError("Select a vulnerability.");
      return;
    }
    try {
      const { data } = await api.get(`/validation/vulnerability/${valVulnId}/results`);
      setValResults(data?.validations || []);
    } catch (e) {
      showErr(e);
    }
  }

  async function createTemplate(event) {
    event.preventDefault();
    if (!newTplName.trim()) {
      setError("Template name required.");
      return;
    }
    try {
      await api.post("/templates/", {
        name: newTplName.trim(),
        template_content: newTplYaml,
        is_public: false,
      });
      showMsg("Template created.");
      loadTemplates();
    } catch (e) {
      showErr(e);
    }
  }

  return (
    <div className="tools-panel">
      <nav className="tab-row" style={{ flexWrap: "wrap" }}>
        {SECTIONS.map(([value, label]) => (
          <button
            key={value}
            type="button"
            className={section === value ? "tab-button tab-button-active" : "tab-button"}
            onClick={() => {
              setSection(value);
              setError("");
            }}
          >
            {label}
          </button>
        ))}
      </nav>

      {message ? (
        <p className="muted-copy" style={{ color: "var(--success, #0a0)" }}>
          {message}
        </p>
      ) : null}
      {error ? (
        <p className="muted-copy" style={{ color: "#c00" }}>
          {error}
        </p>
      ) : null}

      {section === "advanced" ? (
        <div className="stack-list">
          <section className="panel-card">
            <h2>Stealth configuration</h2>
            <form className="stack-form" onSubmit={saveStealthConfig}>
              <label>
                Scan mode
                <select
                  value={stealth.scan_mode}
                  onChange={(e) => setStealth({ ...stealth, scan_mode: e.target.value })}
                >
                  <option value="balanced">balanced</option>
                  <option value="aggressive">aggressive</option>
                  <option value="stealth">stealth</option>
                </select>
              </label>
              <label>
                Requests / sec
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={stealth.requests_per_second}
                  onChange={(e) =>
                    setStealth({ ...stealth, requests_per_second: Number(e.target.value) })
                  }
                />
              </label>
              <label>
                Delay min (ms)
                <input
                  type="number"
                  value={stealth.random_delay_min}
                  onChange={(e) =>
                    setStealth({ ...stealth, random_delay_min: Number(e.target.value) })
                  }
                />
              </label>
              <label>
                Delay max (ms)
                <input
                  type="number"
                  value={stealth.random_delay_max}
                  onChange={(e) =>
                    setStealth({ ...stealth, random_delay_max: Number(e.target.value) })
                  }
                />
              </label>
              <button type="submit" className="primary-button">
                Save stealth profile
              </button>
            </form>
          </section>

          <section className="panel-card">
            <h2>Parameter discovery</h2>
            <p className="muted-copy">One URL per line. Requires Celery worker.</p>
            <textarea
              rows={6}
              value={paramUrlsText}
              onChange={(e) => setParamUrlsText(e.target.value)}
              placeholder="https://example.com/page&#10;https://example.com/api"
            />
            <button type="button" className="primary-button" onClick={runParameterDiscovery}>
              Queue parameter discovery
            </button>
          </section>

          <section className="panel-card">
            <h2>Content fuzzing</h2>
            <p className="muted-copy">Base URLs to fuzz (one per line). Requires Celery worker.</p>
            <textarea
              rows={4}
              value={fuzzUrlsText}
              onChange={(e) => setFuzzUrlsText(e.target.value)}
              placeholder="https://example.com/"
            />
            <label>
              Wordlist category
              <select value={fuzzCategory} onChange={(e) => setFuzzCategory(e.target.value)}>
                <option value="admin">admin</option>
                <option value="api">api</option>
                <option value="backup">backup</option>
                <option value="common">common</option>
              </select>
            </label>
            <button type="button" className="primary-button" onClick={runContentFuzz}>
              Queue content fuzzing
            </button>
          </section>

          <section className="panel-card">
            <div className="panel-header">
              <h2>Discovered parameters</h2>
              <button type="button" className="ghost-button" onClick={loadAdvancedLists}>
                Refresh
              </button>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Confidence</th>
                    <th>Scan</th>
                  </tr>
                </thead>
                <tbody>
                  {discoveredParams.map((p) => (
                    <tr key={p.id}>
                      <td>{p.parameter_name}</td>
                      <td>{p.parameter_type}</td>
                      <td>{p.confidence_score}</td>
                      <td>{p.scan_id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!discoveredParams.length ? (
                <p className="muted-copy">No rows yet. Run discovery above.</p>
              ) : null}
            </div>
          </section>

          <section className="panel-card">
            <div className="panel-header">
              <h2>Fuzzed endpoints</h2>
              <button type="button" className="ghost-button" onClick={loadAdvancedLists}>
                Refresh
              </button>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Interesting</th>
                  </tr>
                </thead>
                <tbody>
                  {fuzzedEndpoints.map((row) => (
                    <tr key={row.id}>
                      <td style={{ wordBreak: "break-all" }}>{row.url}</td>
                      <td>{row.status_code}</td>
                      <td>{row.is_interesting ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!fuzzedEndpoints.length ? (
                <p className="muted-copy">No rows yet. Run fuzzing above.</p>
              ) : null}
            </div>
          </section>
        </div>
      ) : null}

      {section === "manual" ? (
        <div className="stack-list">
          <section className="panel-card">
            <h2>HTTP request (sync)</h2>
            <form className="stack-form" onSubmit={sendManualSync}>
              <label>
                Method
                <input value={manualMethod} onChange={(e) => setManualMethod(e.target.value)} />
              </label>
              <label>
                URL
                <input value={manualUrl} onChange={(e) => setManualUrl(e.target.value)} />
              </label>
              <label>
                Headers (JSON)
                <textarea rows={3} value={manualHeaders} onChange={(e) => setManualHeaders(e.target.value)} />
              </label>
              <label>
                Body
                <textarea rows={3} value={manualBody} onChange={(e) => setManualBody(e.target.value)} />
              </label>
              <button type="submit" className="primary-button">
                Send request
              </button>
            </form>
            {manualResult ? <pre className="code-block">{JSON.stringify(manualResult, null, 2)}</pre> : null}
          </section>

          <section className="panel-card">
            <h2>Payload batch (sync)</h2>
            <form className="stack-form" onSubmit={runPayloadSync}>
              <label>
                Payload type
                <select value={payloadType} onChange={(e) => setPayloadType(e.target.value)}>
                  {Object.keys(payloadTemplates).map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Inject into param (optional)
                <input
                  value={payloadTargetParam}
                  onChange={(e) => setPayloadTargetParam(e.target.value)}
                  placeholder="e.g. q"
                />
              </label>
              <button type="submit" className="primary-button">
                Run payload batch
              </button>
            </form>
            {payloadResult ? <pre className="code-block">{JSON.stringify(payloadResult, null, 2)}</pre> : null}
          </section>

          <section className="panel-card">
            <div className="panel-header">
              <h2>Recent manual tests</h2>
              <button type="button" className="ghost-button" onClick={loadTestHistory}>
                Refresh
              </button>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Type</th>
                    <th>URL</th>
                    <th>OK</th>
                  </tr>
                </thead>
                <tbody>
                  {testHistory.map((row) => (
                    <tr key={row.id}>
                      <td>{row.created_at ? new Date(row.created_at).toLocaleString() : ""}</td>
                      <td>{row.event_type}</td>
                      <td style={{ wordBreak: "break-all" }}>{row.url || "—"}</td>
                      <td>{row.success ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!testHistory.length ? <p className="muted-copy">No history yet.</p> : null}
            </div>
          </section>
        </div>
      ) : null}

      {section === "oob" ? (
        <div className="stack-list">
          <section className="panel-card">
            <h2>Generate callback</h2>
            <form className="stack-form" onSubmit={generateOob}>
              <label>
                Type
                <select value={oobType} onChange={(e) => setOobType(e.target.value)}>
                  <option value="ssrf">ssrf</option>
                  <option value="blind_xss">blind_xss</option>
                  <option value="dns">dns</option>
                </select>
              </label>
              <label>
                Link vulnerability (optional)
                <select value={oobVulnId} onChange={(e) => setOobVulnId(e.target.value)}>
                  <option value="">—</option>
                  {vulnerabilities.map((v) => (
                    <option key={v.id} value={v.id}>
                      #{v.id} {v.template_id} ({v.severity})
                    </option>
                  ))}
                </select>
              </label>
              <p className="muted-copy">Scan context: {scanId ? `#${scanId}` : "none (optional)"}</p>
              <button type="submit" className="primary-button">
                Generate callback URL
              </button>
            </form>
            {oobCallback ? (
              <div>
                <p>
                  <strong>Callback URL</strong>
                </p>
                <pre className="code-block">{oobCallback.callback_url}</pre>
                <p className="muted-copy">Sample payloads</p>
                <ul>
                  {(oobCallback.payloads || []).slice(0, 6).map((p, i) => (
                    <li key={i} style={{ wordBreak: "break-all" }}>
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </section>

          <section className="panel-card">
            <div className="panel-header">
              <h2>Recorded interactions</h2>
              <button type="button" className="ghost-button" onClick={loadOob}>
                Refresh
              </button>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>IP</th>
                    <th>Confirmed</th>
                  </tr>
                </thead>
                <tbody>
                  {oobInteractions.map((row) => (
                    <tr key={row.id}>
                      <td>{row.timestamp ? new Date(row.timestamp).toLocaleString() : ""}</td>
                      <td>{row.interaction_type}</td>
                      <td>{row.source_ip}</td>
                      <td>{row.is_confirmed ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!oobInteractions.length ? <p className="muted-copy">No interactions yet.</p> : null}
            </div>
          </section>
        </div>
      ) : null}

      {section === "validation" ? (
        <section className="panel-card">
          <h2>Exploit validation</h2>
          <p className="muted-copy">Queues async validation on the worker. Select a finding from this scan.</p>
          <form className="stack-form" onSubmit={queueValidation}>
            <label>
              Vulnerability
              <select value={valVulnId} onChange={(e) => setValVulnId(e.target.value)}>
                <option value="">—</option>
                {vulnerabilities.map((v) => (
                  <option key={v.id} value={v.id}>
                    #{v.id} {v.template_id}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Optional payload override
              <input value={valPayload} onChange={(e) => setValPayload(e.target.value)} />
            </label>
            <div className="button-row">
              <button type="submit" className="primary-button">
                Queue validation
              </button>
              <button type="button" className="ghost-button" onClick={fetchValidationResults}>
                Load results
              </button>
            </div>
          </form>
          {valResults.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Confidence</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {valResults.map((r) => (
                    <tr key={r.id}>
                      <td>{r.validation_status}</td>
                      <td>{r.confidence_score}</td>
                      <td>{r.created_at ? new Date(r.created_at).toLocaleString() : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted-copy">No results loaded.</p>
          )}
        </section>
      ) : null}

      {section === "templates" ? (
        <div className="stack-list">
          <section className="panel-card">
            <h2>Create custom Nuclei template</h2>
            <form className="stack-form" onSubmit={createTemplate}>
              <label>
                Name
                <input value={newTplName} onChange={(e) => setNewTplName(e.target.value)} />
              </label>
              <label>
                YAML
                <textarea rows={12} value={newTplYaml} onChange={(e) => setNewTplYaml(e.target.value)} />
              </label>
              <button type="submit" className="primary-button">
                Save template
              </button>
            </form>
          </section>
          <section className="panel-card">
            <div className="panel-header">
              <h2>Your templates</h2>
              <button type="button" className="ghost-button" onClick={loadTemplates}>
                Refresh
              </button>
            </div>
            <ul className="stack-list compact-stack">
              {templates.map((t) => (
                <li key={t.id} className="list-row">
                  <strong>{t.name}</strong>
                  <span className="muted-copy">
                    {t.severity} · {t.template_type || "custom"}
                  </span>
                </li>
              ))}
            </ul>
            {!templates.length ? <p className="muted-copy">No templates yet.</p> : null}
          </section>
        </div>
      ) : null}

      {section === "intel" ? (
        <div className="stack-list">
          <section className="panel-card">
            <div className="panel-header">
              <h2>Learning insights</h2>
              <button type="button" className="ghost-button" onClick={loadIntel}>
                Refresh
              </button>
            </div>
            <pre className="code-block">{JSON.stringify(insights, null, 2)}</pre>
          </section>
          <section className="panel-card">
            <h2>Patterns</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Pattern</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {patterns.map((p) => (
                    <tr key={p.id}>
                      <td>{p.pattern_type}</td>
                      <td style={{ wordBreak: "break-all" }}>{p.pattern_value}</td>
                      <td>{p.confidence_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!patterns.length ? <p className="muted-copy">No patterns stored yet.</p> : null}
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}
