import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";

const severityMap = { xss: "critical", sqli: "critical", ssti: "high", ssrf: "high", openredirect: "medium" };
const vulnIconMap = {
  xss: "🔴",
  sqli: "🔴",
  ssti: "🟠",
  ssrf: "🟠",
  openredirect: "🟡",
};

export default function TestSuggestionsPanel({ targetId, scan }) {
  const [payloadData, setPayloadData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [expandedEndpoints, setExpandedEndpoints] = useState({});

  async function loadPayloadOpportunities() {
    setLoading(true);
    try {
      const response = await api.get(`/payloads/${targetId}`);
      setPayloadData(response.data);
    } catch (error) {
      console.error("Failed to load payload opportunities:", error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (targetId && scan?.status === "completed") {
      loadPayloadOpportunities();
    }
  }, [targetId, scan?.status]);

  const opportunitySummary = useMemo(() => {
    if (!payloadData) return null;
    const { opportunity_summary } = payloadData;
    const total = Object.values(opportunity_summary).reduce((a, b) => a + b, 0);
    const critical = (opportunity_summary.xss || 0) + (opportunity_summary.sqli || 0);
    return { total, critical, ...opportunity_summary };
  }, [payloadData]);

  if (!payloadData || !opportunitySummary) {
    return null;
  }

  if (opportunitySummary.total === 0) {
    return (
      <article className="panel-card">
        <h2>Test Suggestions</h2>
        <p className="info-text">No immediate testing opportunities detected in this scan.</p>
      </article>
    );
  }

  return (
    <article className="panel-card">
      <h2>
        Test Suggestions <span className="badge">{opportunitySummary.total} opportunities</span>
      </h2>

      <div className="opportunity-summary">
        {opportunitySummary.xss > 0 && (
          <div className="summary-item critical">
            <span className="icon">🔴</span>
            <span className="label">XSS</span>
            <span className="count">{opportunitySummary.xss}</span>
          </div>
        )}
        {opportunitySummary.sqli > 0 && (
          <div className="summary-item critical">
            <span className="icon">🔴</span>
            <span className="label">SQLi</span>
            <span className="count">{opportunitySummary.sqli}</span>
          </div>
        )}
        {opportunitySummary.ssti > 0 && (
          <div className="summary-item high">
            <span className="icon">🟠</span>
            <span className="label">SSTI</span>
            <span className="count">{opportunitySummary.ssti}</span>
          </div>
        )}
        {opportunitySummary.ssrf > 0 && (
          <div className="summary-item high">
            <span className="icon">🟠</span>
            <span className="label">SSRF</span>
            <span className="count">{opportunitySummary.ssrf}</span>
          </div>
        )}
        {opportunitySummary.openredirect > 0 && (
          <div className="summary-item medium">
            <span className="icon">🟡</span>
            <span className="label">Open Redirect</span>
            <span className="count">{opportunitySummary.openredirect}</span>
          </div>
        )}
      </div>

      <div className="opportunities-list">
        {payloadData.endpoints_with_opportunities
          .sort((a, b) => {
            // Sort by number of high-confidence opportunities
            const aHigh = a.payload_opportunities.filter((o) => o.confidence >= 70).length;
            const bHigh = b.payload_opportunities.filter((o) => o.confidence >= 70).length;
            return bHigh - aHigh;
          })
          .map((endpointData) => (
            <div key={endpointData.id} className="endpoint-opportunity-card">
              <div
                className="endpoint-header"
                onClick={() => setExpandedEndpoints((prev) => ({ ...prev, [endpointData.id]: !prev[endpointData.id] }))}
              >
                <span className="toggle-icon">{expandedEndpoints[endpointData.id] ? "▼" : "▶"}</span>
                <div className="endpoint-info">
                  <div className="method-url">
                    <span className="method">{endpointData.source.toUpperCase()}</span>
                    <span className="url">{endpointData.normalized_url}</span>
                  </div>
                  <div className="opportunity-badges">
                    {endpointData.payload_opportunities.map((opp) => (
                      <span key={opp.id} className={`vuln-badge ${severityMap[opp.vulnerability_type]}`} title={`${opp.vulnerability_type} (${opp.confidence}% confidence)`}>
                        {vulnIconMap[opp.vulnerability_type]} {opp.vulnerability_type.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
                <span className="priority-score">Priority: {endpointData.priority_score}</span>
              </div>

              {expandedEndpoints[endpointData.id] && (
                <div className="endpoint-details">
                  {endpointData.payload_opportunities
                    .sort((a, b) => b.confidence - a.confidence)
                    .map((opp) => (
                      <div key={opp.id} className={`opportunity-detail ${severityMap[opp.vulnerability_type]}`}>
                        <div className="opp-header">
                          <span className="vuln-type">
                            {vulnIconMap[opp.vulnerability_type]} {opp.vulnerability_type.toUpperCase()}
                          </span>
                          <span className="confidence-badge">{opp.confidence}% confidence</span>
                        </div>
                        <div className="opp-param">
                          <span className="label">Parameter:</span>
                          <code>{opp.parameter_name}</code>
                          <span className="location">({opp.parameter_location})</span>
                        </div>
                        {opp.notes && (
                          <div className="opp-notes">
                            <span className="label">Reason:</span>
                            <span>{opp.notes}</span>
                          </div>
                        )}
                        {opp.payloads_json && opp.payloads_json.length > 0 && (
                          <div className="opp-payloads">
                            <span className="label">Suggested payloads:</span>
                            <div className="payload-list">
                              {opp.payloads_json.slice(0, 3).map((payload, idx) => (
                                <code key={idx} className="payload-item">
                                  {payload.substring(0, 60)}
                                  {payload.length > 60 ? "..." : ""}
                                </code>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                </div>
              )}
            </div>
          ))}
      </div>

      <style>{`
        .opportunity-summary {
          display: flex;
          gap: 12px;
          margin-bottom: 20px;
          flex-wrap: wrap;
        }
        .summary-item {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 12px;
          border-radius: 6px;
          background: rgba(0, 0, 0, 0.05);
          border-left: 3px solid;
        }
        .summary-item.critical { border-color: #d32f2f; }
        .summary-item.high { border-color: #f57c00; }
        .summary-item.medium { border-color: #fbc02d; }
        .summary-item .icon { font-size: 16px; }
        .summary-item .label { font-weight: 500; }
        .summary-item .count { margin-left: 8px; font-weight: bold; }

        .opportunities-list { display: flex; flex-direction: column; gap: 12px; margin-top: 16px; }
        .endpoint-opportunity-card {
          border: 1px solid #e0e0e0;
          border-radius: 6px;
          overflow: hidden;
        }
        .endpoint-header {
          padding: 12px;
          cursor: pointer;
          background: #fafafa;
          display: flex;
          align-items: center;
          gap: 12px;
          transition: background 0.2s;
        }
        .endpoint-header:hover { background: #f5f5f5; }
        .toggle-icon { font-size: 12px; min-width: 16px; }
        .endpoint-info { flex: 1; }
        .method-url {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 8px;
        }
        .method {
          font-size: 11px;
          font-weight: bold;
          padding: 2px 6px;
          background: #e0e0e0;
          border-radius: 3px;
        }
        .url {
          font-family: monospace;
          font-size: 13px;
          color: #1976d2;
          word-break: break-all;
        }
        .opportunity-badges {
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
        }
        .vuln-badge {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          font-size: 11px;
          font-weight: bold;
          padding: 4px 8px;
          border-radius: 4px;
          color: white;
        }
        .vuln-badge.critical { background: #d32f2f; }
        .vuln-badge.high { background: #f57c00; }
        .vuln-badge.medium { background: #fbc02d; color: #000; }
        .priority-score {
          font-size: 12px;
          color: #666;
          white-space: nowrap;
        }

        .endpoint-details { padding: 12px; background: white; border-top: 1px solid #e0e0e0; }
        .opportunity-detail {
          padding: 10px;
          border-left: 3px solid;
          border-radius: 3px;
          margin-bottom: 10px;
          background: rgba(0, 0, 0, 0.02);
        }
        .opportunity-detail.critical { border-color: #d32f2f; }
        .opportunity-detail.high { border-color: #f57c00; }
        .opportunity-detail.medium { border-color: #fbc02d; }
        .opp-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          margin-bottom: 8px;
          font-size: 13px;
          font-weight: 500;
        }
        .confidence-badge {
          background: rgba(0, 0, 0, 0.1);
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 11px;
        }
        .opp-param, .opp-notes {
          margin-bottom: 8px;
          font-size: 12px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .opp-param .label, .opp-notes .label { font-weight: bold; }
        .opp-param code {
          background: rgba(0, 0, 0, 0.05);
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 11px;
        }
        .opp-param .location { font-size: 11px; color: #999; }
        .opp-payloads {
          margin-top: 8px;
          font-size: 12px;
        }
        .opp-payloads .label { font-weight: bold; display: block; margin-bottom: 6px; }
        .payload-list { display: flex; flex-direction: column; gap: 4px; }
        .payload-item {
          background: rgba(0, 0, 0, 0.08);
          padding: 4px 8px;
          border-radius: 3px;
          font-size: 11px;
          word-break: break-all;
          color: #d32f2f;
        }
      `}</style>
    </article>
  );
}
