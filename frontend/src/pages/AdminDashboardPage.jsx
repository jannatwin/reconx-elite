import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import ConfigurationManager from "../components/ConfigurationManager";
import SystemHealth from "../components/SystemHealth";
import UserManagement from "../components/UserManagement";

export default function AdminDashboardPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const [metrics, setMetrics] = useState(null);
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

  useEffect(() => {
    loadMetrics();
    const interval = setInterval(loadMetrics, 30000); // Refresh every 30 seconds
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

      {metrics && (
        <section className="summary-strip">
          <article className="summary-card">
            <span>Total Users</span>
            <strong>{metrics.users_total}</strong>
          </article>
          <article className="summary-card">
            <span>Total Targets</span>
            <strong>{metrics.targets_total}</strong>
          </article>
          <article className="summary-card">
            <span>Total Scans</span>
            <strong>{metrics.scans_total}</strong>
          </article>
          <article className="summary-card">
            <span>Active Scans</span>
            <strong>{metrics.tasks.active_scans}</strong>
          </article>
          <article className="summary-card highlight-card">
            <span>Queued Tasks</span>
            <strong>{metrics.tasks.queued_tasks}</strong>
          </article>
        </section>
      )}

      <div style={{ marginTop: "2rem", borderBottom: "1px solid #eee" }}>
        <div style={{ display: "flex", gap: "1rem", paddingBottom: "1rem" }}>
          <button
            className={`tab-button ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => setActiveTab("overview")}
            style={{
              padding: "0.75rem 1rem",
              border: "none",
              cursor: "pointer",
              background: activeTab === "overview" ? "transparent" : "transparent",
              borderBottom: activeTab === "overview" ? "2px solid #0066cc" : "none",
              color: activeTab === "overview" ? "#0066cc" : "#666",
              fontWeight: activeTab === "overview" ? "600" : "400",
            }}
          >
            Overview
          </button>
          <button
            className={`tab-button ${activeTab === "users" ? "active" : ""}`}
            onClick={() => setActiveTab("users")}
            style={{
              padding: "0.75rem 1rem",
              border: "none",
              cursor: "pointer",
              background: activeTab === "users" ? "transparent" : "transparent",
              borderBottom: activeTab === "users" ? "2px solid #0066cc" : "none",
              color: activeTab === "users" ? "#0066cc" : "#666",
              fontWeight: activeTab === "users" ? "600" : "400",
            }}
          >
            Users
          </button>
          <button
            className={`tab-button ${activeTab === "health" ? "active" : ""}`}
            onClick={() => setActiveTab("health")}
            style={{
              padding: "0.75rem 1rem",
              border: "none",
              cursor: "pointer",
              background: activeTab === "health" ? "transparent" : "transparent",
              borderBottom: activeTab === "health" ? "2px solid #0066cc" : "none",
              color: activeTab === "health" ? "#0066cc" : "#666",
              fontWeight: activeTab === "health" ? "600" : "400",
            }}
          >
            System Health
          </button>
          <button
            className={`tab-button ${activeTab === "config" ? "active" : ""}`}
            onClick={() => setActiveTab("config")}
            style={{
              padding: "0.75rem 1rem",
              border: "none",
              cursor: "pointer",
              background: activeTab === "config" ? "transparent" : "transparent",
              borderBottom: activeTab === "config" ? "2px solid #0066cc" : "none",
              color: activeTab === "config" ? "#0066cc" : "#666",
              fontWeight: activeTab === "config" ? "600" : "400",
            }}
          >
            Configuration
          </button>
        </div>
      </div>

      <div style={{ marginTop: "2rem" }}>
        {activeTab === "overview" && (
          <section className="panel-card">
            <h2>System Overview</h2>
            <p style={{ color: "#666", marginBottom: "1.5rem" }}>
              Quick access to admin functions. Click on the tabs above to manage users, monitor system health, or change configuration.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem" }}>
              <button
                onClick={() => setActiveTab("users")}
                style={{
                  padding: "1rem",
                  border: "1px solid #ddd",
                  background: "#f9f9f9",
                  borderRadius: "4px",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem" }}>👥 Manage Users</strong>
                <small style={{ color: "#666" }}>Create, edit, or delete user accounts</small>
              </button>
              <button
                onClick={() => setActiveTab("health")}
                style={{
                  padding: "1rem",
                  border: "1px solid #ddd",
                  background: "#f9f9f9",
                  borderRadius: "4px",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem" }}>⚙️ System Health</strong>
                <small style={{ color: "#666" }}>Monitor PostgreSQL, Redis, Celery</small>
              </button>
              <button
                onClick={() => setActiveTab("config")}
                style={{
                  padding: "1rem",
                  border: "1px solid #ddd",
                  background: "#f9f9f9",
                  borderRadius: "4px",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <strong style={{ display: "block", marginBottom: "0.5rem" }}>⚙️ Configuration</strong>
                <small style={{ color: "#666" }}>View and update application settings</small>
              </button>
            </div>
          </section>
        )}

        {activeTab === "users" && <UserManagement />}
        {activeTab === "health" && <SystemHealth />}
        {activeTab === "config" && <ConfigurationManager />}
      </div>
    </main>
  );
}
