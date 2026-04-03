import { useEffect, useState } from "react";

import { api } from "../api/client";

function HealthIndicator({ label, status }) {
  const statusColors = {
    healthy: { bg: "#d4edda", color: "#155724", icon: "✓" },
    degraded: { bg: "#fff3cd", color: "#856404", icon: "⚠" },
    unhealthy: { bg: "#f8d7da", color: "#721c24", icon: "✕" },
    unknown: { bg: "#e2e3e5", color: "#383d41", icon: "?" },
  };

  const style = statusColors[status] || statusColors.unknown;

  return (
    <div
      style={{
        padding: "1.5rem",
        borderRadius: "8px",
        background: style.bg,
        color: style.color,
        border: `2px solid ${style.color}`,
        display: "flex",
        alignItems: "center",
        gap: "1rem",
      }}
    >
      <div
        style={{
          fontSize: "2rem",
          fontWeight: "bold",
          minWidth: "3rem",
          textAlign: "center",
        }}
      >
        {style.icon}
      </div>
      <div>
        <h3 style={{ margin: "0 0 0.25rem 0" }}>{label}</h3>
        <p style={{ margin: 0, fontSize: "0.875rem", textTransform: "capitalize" }}>{status}</p>
      </div>
    </div>
  );
}

function AuditLogPreview() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadLogs() {
      try {
        const { data } = await api.get("/admin/audit-logs?limit=10");
        setLogs(data);
      } catch (err) {
        console.error("Failed to load audit logs:", err);
      } finally {
        setLoading(false);
      }
    }
    loadLogs();
  }, []);

  if (loading) {
    return <div>Loading audit logs...</div>;
  }

  return (
    <div style={{ marginTop: "2rem" }}>
      <h3>Recent Audit Logs</h3>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "2px solid #ddd" }}>
              <th style={{ padding: "1rem", textAlign: "left" }}>Action</th>
              <th style={{ padding: "1rem", textAlign: "left" }}>User</th>
              <th style={{ padding: "1rem", textAlign: "left" }}>IP Address</th>
              <th style={{ padding: "1rem", textAlign: "left" }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id} style={{ borderBottom: "1px solid #eee" }}>
                <td style={{ padding: "1rem" }}>
                  <code style={{ background: "#f0f0f0", padding: "0.25rem 0.5rem", borderRadius: "3px", fontSize: "0.875rem" }}>
                    {log.action}
                  </code>
                </td>
                <td style={{ padding: "1rem" }}>{log.user_id ? `User #${log.user_id}` : "System"}</td>
                <td style={{ padding: "1rem", fontSize: "0.875rem" }}>{log.ip_address || "N/A"}</td>
                <td style={{ padding: "1rem", fontSize: "0.875rem" }}>{new Date(log.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function SystemHealth() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdate, setLastUpdate] = useState(null);

  async function loadHealth() {
    try {
      const { data } = await api.get("/admin/health");
      setHealth(data);
      setLastUpdate(new Date());
      setError("");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load health status");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <section className="panel-card">
        <h2>System Health</h2>
        <p>Loading health status...</p>
      </section>
    );
  }

  return (
    <section className="panel-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
        <h2 style={{ margin: 0 }}>System Health</h2>
        <button onClick={loadHealth} className="ghost-button" style={{ padding: "0.5rem 1rem", fontSize: "0.875rem" }}>
          🔄 Refresh
        </button>
      </div>

      {error && <div style={{ padding: "1rem", marginBottom: "1rem", background: "#fee", borderLeft: "4px solid #f00", color: "#d00" }}>{error}</div>}

      {lastUpdate && <p style={{ fontSize: "0.875rem", color: "#666", marginBottom: "1.5rem" }}>Last updated: {lastUpdate.toLocaleTimeString()}</p>}

      {health && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "1rem", marginBottom: "2rem" }}>
            <HealthIndicator label="Overall Status" status={health.status} />
            <HealthIndicator label="PostgreSQL Database" status={health.postgresql} />
            <HealthIndicator label="Redis Cache" status={health.redis} />
            <HealthIndicator label="Celery Worker" status={health.celery_worker} />
          </div>

          <div style={{ padding: "1.5rem", background: "#f5f5f5", borderRadius: "4px", marginBottom: "2rem" }}>
            <h3 style={{ marginTop: 0 }}>System Status Summary</h3>
            <ul style={{ margin: 0, paddingLeft: "1.5rem", lineHeight: 1.8 }}>
              <li>
                <strong>Database:</strong> {health.postgresql === "healthy" ? "✓ Ready to accept connections" : "✗ Connection issues detected"}
              </li>
              <li>
                <strong>Cache:</strong> {health.redis === "healthy" ? "✓ Ready for task queueing" : "✗ Cannot access cache"}
              </li>
              <li>
                <strong>Task Queue:</strong> {health.celery_worker === "healthy" ? "✓ Workers are active" : "✗ No active workers"}
              </li>
            </ul>
          </div>

          <AuditLogPreview />
        </div>
      )}
    </section>
  );
}
