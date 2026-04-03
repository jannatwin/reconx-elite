import { useMemo, useState } from "react";

const SECTION_CONFIG = [
  { key: "ai_subdomain_analysis", label: "Subdomain triage" },
  { key: "ai_live_host_analysis", label: "Live hosts (HTTPX)" },
  { key: "ai_javascript_analysis", label: "JavaScript / GAU" },
  { key: "ai_nuclei_analysis", label: "Nuclei follow-ups" },
];

function normalizeTargets(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item) => {
      if (item && typeof item === "object" && !Array.isArray(item)) {
        return item;
      }
      if (typeof item === "string") {
        const t = item.trim();
        if (!t) return null;
        return { url: t, reason: "", priority: "" };
      }
      return null;
    })
    .filter(Boolean);
}

function InsightBlock({ data }) {
  if (!data || typeof data !== "object") {
    return <p className="muted-copy">No data.</p>;
  }

  if (data.error) {
    return <p className="error-text">{String(data.error)}</p>;
  }

  const targets = normalizeTargets(data.high_value_targets);
  const leaks = Array.isArray(data.potential_leaks) ? data.potential_leaks : [];
  const templates = Array.isArray(data.suggested_nuclei_templates) ? data.suggested_nuclei_templates : [];
  const flags = Array.isArray(data.security_flags) ? data.security_flags : [];
  const juicy = Array.isArray(data.juicy_js_files) ? data.juicy_js_files : [];
  const errs = Array.isArray(data.errors) ? data.errors.filter(Boolean) : [];

  const hasBody =
    targets.length > 0 ||
    leaks.length > 0 ||
    templates.length > 0 ||
    flags.length > 0 ||
    juicy.length > 0 ||
    errs.length > 0 ||
    data.confidence_score ||
    data.batches_processed != null;

  if (!hasBody) {
    return <p className="muted-copy">No ranked items in this section.</p>;
  }

  return (
    <div className="ai-insight-body">
      {data.confidence_score ? (
        <p className="table-subcopy">
          Confidence: <strong>{data.confidence_score}</strong>
          {data.batches_processed != null ? (
            <>
              {" "}
              · Batches: <strong>{data.batches_processed}</strong>
            </>
          ) : null}
          {data.total_processed != null ? (
            <>
              {" "}
              · Lines/items: <strong>{data.total_processed}</strong>
            </>
          ) : null}
        </p>
      ) : null}

      {errs.length ? (
        <div className="ai-insight-callout">
          <strong>Partial errors</strong>
          <ul className="compact-list">
            {errs.map((line, i) => (
              <li key={i}>{String(line)}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {targets.length ? (
        <div className="ai-insight-block">
          <h3 className="ai-insight-subhead">High-value targets</h3>
          <div className="table-scroll">
            <table className="data-table ai-target-table">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>URL / host</th>
                  <th>Reason</th>
                  <th>ffuf hint</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((row, idx) => (
                  <tr key={`${row.url || idx}-${idx}`}>
                    <td>{row.priority ?? "—"}</td>
                    <td className="mono-cell">{row.url || "—"}</td>
                    <td>{row.reason || "—"}</td>
                    <td>{row.ffuf_wordlist_category || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {juicy.length ? (
        <div className="ai-insight-block">
          <h3 className="ai-insight-subhead">Juicy JavaScript (manual review)</h3>
          <ul className="stack-list tight">
            {juicy.map((row, idx) => (
              <li key={`${row.url || idx}-${idx}`}>
                <div className="mono-cell">{row.url}</div>
                {row.rationale ? <div className="table-subcopy">{row.rationale}</div> : null}
                {row.focus_areas ? <div className="table-subcopy">Focus: {row.focus_areas}</div> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {leaks.length ? (
        <div className="ai-insight-block">
          <h3 className="ai-insight-subhead">Potential leaks / notes</h3>
          <ul className="compact-list">
            {leaks.map((row, idx) => {
              if (row && typeof row === "object") {
                return (
                  <li key={idx}>
                    <strong>{String(row.type || "note")}:</strong> {String(row.detail || "")}
                  </li>
                );
              }
              return <li key={idx}>{String(row)}</li>;
            })}
          </ul>
        </div>
      ) : null}

      {templates.length ? (
        <div className="ai-insight-block">
          <h3 className="ai-insight-subhead">Suggested Nuclei templates</h3>
          <ul className="compact-list mono-list">
            {templates.map((t, idx) => (
              <li key={idx}>{String(t)}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {flags.length ? (
        <div className="ai-insight-block">
          <h3 className="ai-insight-subhead">Security flags</h3>
          <ul className="compact-list">
            {flags.map((f, idx) => (
              <li key={idx}>{String(f)}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export default function ScanAiInsightsPanel({ scan }) {
  const meta = scan?.metadata_json;
  const [open, setOpen] = useState(() =>
    Object.fromEntries(SECTION_CONFIG.map((s) => [s.key, true])),
  );

  const sections = useMemo(() => {
    if (!meta || typeof meta !== "object") return [];
    return SECTION_CONFIG.map((s) => ({ ...s, data: meta[s.key] })).filter((s) => s.data != null);
  }, [meta]);

  if (!sections.length) {
    return null;
  }

  return (
    <article className="panel-card ai-insights-panel">
      <div className="panel-header">
        <h2>Gemini scan insights</h2>
        <span className="pill">{sections.length}</span>
      </div>
      <p className="muted-copy">Automated triage only. Validate findings manually and stay within program scope.</p>

      {sections.map(({ key, label, data }) => (
        <div className="ai-insight-section" key={key}>
          <button
            type="button"
            className="ai-insight-toggle"
            onClick={() => setOpen((prev) => ({ ...prev, [key]: !prev[key] }))}
            aria-expanded={open[key]}
          >
            <span className="ai-insight-chevron">{open[key] ? "−" : "+"}</span>
            {label}
          </button>
          {open[key] ? <InsightBlock data={data} /> : null}
        </div>
      ))}
    </article>
  );
}
