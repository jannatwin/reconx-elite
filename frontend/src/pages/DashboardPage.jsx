import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { api, formatApiErrorDetail } from "../api/client";
import { useAuth } from "../context/AuthContext";

export default function DashboardPage() {
  const [targets, setTargets] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [domain, setDomain] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { logout, isAdmin } = useAuth();

  async function loadDashboard() {
    const [{ data: targetRows }, { data: notificationRows }] = await Promise.all([
      api.get("/targets"),
      api.get("/notifications"),
    ]);
    setTargets(targetRows);
    setNotifications(notificationRows);
  }

  useEffect(() => {
    loadDashboard().catch((requestError) => {
      setError(
        formatApiErrorDetail(requestError.response?.data?.detail) || "Failed to load dashboard",
      );
    });
  }, []);

  const summary = useMemo(() => {
    return targets.reduce(
      (accumulator, target) => {
        accumulator.targets += 1;
        accumulator.subdomains += target.latest_scan?.subdomain_count || 0;
        accumulator.endpoints += target.latest_scan?.endpoint_count || 0;
        accumulator.vulnerabilities += target.latest_scan?.vulnerability_count || 0;
        accumulator.highPriority += target.latest_scan?.high_priority_endpoint_count || 0;
        return accumulator;
      },
      { targets: 0, subdomains: 0, endpoints: 0, vulnerabilities: 0, highPriority: 0 },
    );
  }, [targets]);

  async function onAddTarget(event) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);
    try {
      await api.post("/targets", { domain });
      setDomain("");
      await loadDashboard();
    } catch (requestError) {
      setError(formatApiErrorDetail(requestError.response?.data?.detail) || "Could not add target");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="page-shell">
      <header className="page-header">
        <div>
          <p className="eyebrow">ReconX Elite</p>
          <h1>Recon dashboard</h1>
          <p className="lede">
            Track targets, live surface changes, and the assets worth manual attention first.
          </p>
        </div>
        <div style={{ display: "flex", gap: "1rem" }}>
          {isAdmin && (
            <Link to="/admin" className="primary-button">
              Admin Panel
            </Link>
          )}
          <button className="primary-button" onClick={logout} type="button">
            Logout
          </button>
        </div>
      </header>

      <section className="summary-strip">
        <article className="summary-card">
          <span>Targets</span>
          <strong>{summary.targets}</strong>
        </article>
        <article className="summary-card">
          <span>Subdomains</span>
          <strong>{summary.subdomains}</strong>
        </article>
        <article className="summary-card">
          <span>Endpoints</span>
          <strong>{summary.endpoints}</strong>
        </article>
        <article className="summary-card">
          <span>Vulnerabilities</span>
          <strong>{summary.vulnerabilities}</strong>
        </article>
        <article className="summary-card highlight-card">
          <span>High-priority assets</span>
          <strong>{summary.highPriority}</strong>
        </article>
      </section>

      <section className="layout-grid">
        <form className="panel-card" onSubmit={onAddTarget}>
          <h2>Add target</h2>
          <p className="muted-copy">
            Enter a hostname (e.g. example.com) or paste a URL — we keep the hostname only.
          </p>
          <label>
            Domain
            <input
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="example.com"
              required
            />
          </label>
          <button className="primary-button button-full" disabled={isSubmitting} type="submit">
            {isSubmitting ? "Adding..." : "Add target"}
          </button>
          <p className="legal-note">
            Legal reminder: scan only assets where you have explicit authorization.
          </p>
          {error ? <p className="error-text">{error}</p> : null}
        </form>

        <section className="panel-card">
          <div className="panel-header">
            <h2>Activity</h2>
            <span className="pill">{notifications.filter((item) => !item.read).length} unread</span>
          </div>
          <div className="notification-list">
            {notifications.length ? (
              notifications.slice(0, 6).map((notification) => (
                <article
                  className={notification.read ? "notification-item" : "notification-item unread"}
                  key={notification.id}
                >
                  <p>{notification.message}</p>
                  <span>{new Date(notification.created_at).toLocaleString()}</span>
                </article>
              ))
            ) : (
              <p className="muted-copy">No notifications yet.</p>
            )}
          </div>
        </section>
      </section>

      <section className="panel-card">
        <div className="panel-header">
          <h2>Targets</h2>
          <span className="pill">{targets.length} tracked</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Latest stage</th>
                <th>Surface</th>
                <th>Findings</th>
                <th>Priority</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr key={target.id}>
                  <td>
                    <strong>{target.domain}</strong>
                    <div className="table-subcopy">{target.scan_count} scans</div>
                  </td>
                  <td>
                    <span className={`status-pill status-${target.latest_scan?.status || "idle"}`}>
                      {target.latest_scan?.metadata_json?.stage ||
                        target.latest_scan?.status ||
                        "not-scanned"}
                    </span>
                  </td>
                  <td>{target.latest_scan?.endpoint_count || 0} endpoints</td>
                  <td>{target.latest_scan?.vulnerability_count || 0} findings</td>
                  <td>{target.latest_scan?.high_priority_endpoint_count || 0} high-priority</td>
                  <td>
                    <Link className="text-link" to={`/targets/${target.id}`}>
                      Open target
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
