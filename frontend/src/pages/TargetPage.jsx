import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { apiRequest } from "../api";

export default function TargetPage() {
  const { targetId } = useParams();
  const token = localStorage.getItem("reconx_token");
  const [target, setTarget] = useState(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");

  async function fetchTarget() {
    try {
      const data = await apiRequest(`/targets/${targetId}`, { token });
      setTarget(data);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    fetchTarget();
    const interval = setInterval(fetchTarget, 5000);
    return () => clearInterval(interval);
  }, [targetId]);

  async function triggerScan() {
    setError("");
    try {
      await apiRequest(`/scan/${targetId}`, { method: "POST", token });
      fetchTarget();
    } catch (err) {
      setError(err.message);
    }
  }

  const latestScan = useMemo(() => {
    if (!target?.scans?.length) return null;
    return [...target.scans].sort((a, b) => b.id - a.id)[0];
  }, [target]);

  const filteredEndpoints = (latestScan?.endpoints || []).filter((e) => e.url.includes(filter));

  return (
    <div className="container">
      <div className="row">
        <h1>Target Details</h1>
        <Link to="/">Back</Link>
      </div>
      {target && <h2>{target.domain}</h2>}
      <button onClick={triggerScan}>Trigger Scan</button>
      {latestScan && (
        <p>
          Latest scan #{latestScan.id} - <strong>{latestScan.status}</strong> (
          {latestScan.metadata_json?.step || "unknown"})
        </p>
      )}
      {error && <p className="error">{error}</p>}

      <div className="card">
        <h3>Subdomains</h3>
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Live</th>
            </tr>
          </thead>
          <tbody>
            {(latestScan?.subdomains || []).map((row) => (
              <tr key={row.hostname}>
                <td>{row.hostname}</td>
                <td>{row.is_live ? "Yes" : "No"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Endpoints</h3>
        <input placeholder="Filter URLs..." value={filter} onChange={(e) => setFilter(e.target.value)} />
        <table>
          <thead>
            <tr>
              <th>URL</th>
            </tr>
          </thead>
          <tbody>
            {filteredEndpoints.map((row) => (
              <tr key={row.url}>
                <td>{row.url}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Vulnerabilities</h3>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Template</th>
              <th>Host</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {(latestScan?.vulnerabilities || []).map((row, idx) => (
              <tr key={`${row.template_id}-${idx}`}>
                <td>{row.severity}</td>
                <td>{row.template_id}</td>
                <td>{row.host || "-"}</td>
                <td>{row.description || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
