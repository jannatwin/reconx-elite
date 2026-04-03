import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import AdminMetricsDashboard from "../components/AdminMetricsDashboard";
import ConfigurationManager from "../components/ConfigurationManager";
import SystemHealth from "../components/SystemHealth";
import UserManagement from "../components/UserManagement";

export default function AdminDashboardPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const [metrics, setMetrics] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [error, setError] = useState("");
  const { logout } = useAuth();

  async function loadMetrics() {
    try {
      const { data } = await api.get("/admin/metrics");
      setMetrics(data);
      setError("");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load metrics");
    }
  }

  async function loadAuditLogs() {
    try {
      const { data } = await api.get("/admin/audit-logs?limit=100");
      setAuditLogs(data);
      setError("");
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    }
  }

  useEffect(() => {
    loadMetrics();
    loadAuditLogs();
    const interval = setInterval(() => {
      loadMetrics();
      loadAuditLogs();
    }, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  return (
    <main className="page-shell">
      <header className="page-header">
        <div>
          <p className="eyebrow">ReconX Elite</p>
          <h1>Admin Dashboard</h1>
          <p className="lede">Manage users, monitor system health, and configure application settings.</p>
        </div>
        <div style={{ display: "flex", gap: "1rem" }}>
          <Link to="/" className="ghost-button">
            Back to Dashboard
          </Link>
          <button className="ghost-button" onClick={logout} type="button">
            Logout
          </button>
        </div>
      </header>

      {error && <div className="error-banner" style={{ padding: "1rem", marginBottom: "2rem", background: "#fee", borderLeft: "4px solid #f00" }}>{error}</div>}

      <nav className="tab-row">
        {[
          ["overview", "Overview"],
          ["metrics", "Metrics Dashboard"],
          ["users", "User Management"],
          ["health", "System Health"],
          ["config", "Configuration"],
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

      {activeTab === "overview" && (
        <>
          <section className="summary-strip">
            <article className="summary-card">
              <span>Total Users</span>
              <strong>{metrics?.users_total || 0}</strong>
            </article>
            <article className="summary-card">
              <span>Total Targets</span>
              <strong>{metrics?.targets_total || 0}</strong>
            </article>
            <article className="summary-card">
              <span>Total Scans</span>
              <strong>{metrics?.scans_total || 0}</strong>
            </article>
            <article className="summary-card">
              <span>Active Scans</span>
              <strong>{metrics?.tasks?.active_scans || 0}</strong>
            </article>
            <article className="summary-card highlight-card">
              <span>Queued Tasks</span>
              <strong>{metrics?.tasks?.queued_tasks || 0}</strong>
            </article>
          </section>

          <section className="panel-card">
            <h2>System Overview</h2>
            <p className="muted-copy">
              Quick access to admin functions. Click on tabs above to manage users, monitor system health, or change configuration.
            </p>
            <div className="layout-grid">
              <button
                onClick={() => setActiveTab("users")}
                className="panel-card"
                style={{
                  padding: "1.5rem",
                  border: "1px solid var(--border)",
                  background: "var(--panel-strong)",
                  borderRadius: "12px",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.2s ease",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem", fontSize: "1.1rem" }}>👥 Manage Users</strong>
                <span className="muted-copy">Create, edit, or delete user accounts</span>
              </button>
              <button
                onClick={() => setActiveTab("health")}
                className="panel-card"
                style={{
                  padding: "1.5rem",
                  border: "1px solid var(--border)",
                  background: "var(--panel-strong)",
                  borderRadius: "12px",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.2s ease",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem", fontSize: "1.1rem" }}>🏥 System Health</strong>
                <span className="muted-copy">Monitor PostgreSQL, Redis, Celery</span>
              </button>
              <button
                onClick={() => setActiveTab("config")}
                className="panel-card"
                style={{
                  padding: "1.5rem",
                  border: "1px solid var(--border)",
                  background: "var(--panel-strong)",
                  borderRadius: "12px",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.2s ease",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem", fontSize: "1.1rem" }}>⚙️ Configuration</strong>
                <span className="muted-copy">View and update application settings</span>
              </button>
              <button
                onClick={() => setActiveTab("metrics")}
                className="panel-card"
                style={{
                  padding: "1.5rem",
                  border: "1px solid var(--border)",
                  background: "var(--panel-strong)",
                  borderRadius: "12px",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.2s ease",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem", fontSize: "1.1rem" }}>📊 Metrics Dashboard</strong>
                <span className="muted-copy">View system analytics and usage patterns</span>
              </button>
            </div>
          </section>
        </>
      )}

      {activeTab === "metrics" && (
        <AdminMetricsDashboard metrics={metrics} auditLogs={auditLogs} />
      )}

      {activeTab === "users" && <UserManagement />}

      {activeTab === "health" && <SystemHealth />}

      {activeTab === "config" && <ConfigurationManager />}
    </main>
  );
}
