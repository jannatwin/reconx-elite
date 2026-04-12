import { useEffect, useState } from "react";

import { api } from "../api/client";

export default function ModelStatusGrid() {
  const [modelStatus, setModelStatus] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState("");

  async function loadStatus() {
    try {
      const response = await api.get("/api/model-status");
      setModelStatus(response.data);
      setError("");
    } catch (_err) {
      setError("Failed to load model status");
    }
  }

  async function handleVerify() {
    setIsVerifying(true);
    setError("");
    try {
      await api.post("/api/verify-models");
      await loadStatus();
    } catch (_err) {
      setError("Verification failed");
    } finally {
      setIsVerifying(false);
    }
  }

  useEffect(() => {
    loadStatus();
    const interval = window.setInterval(loadStatus, 30000);
    return () => window.clearInterval(interval);
  }, []);

  if (!modelStatus) {
    return <div className="panel-card">Loading model status...</div>;
  }

  return (
    <div className="panel-card">
      <div className="panel-header" style={{ marginBottom: "1.5rem" }}>
        <div>
          <h2>AI Model Roster</h2>
          <p className="table-subcopy">
            Provider: <strong>{modelStatus.provider}</strong>
          </p>
        </div>
        <button
          className="primary-button"
          disabled={isVerifying}
          onClick={handleVerify}
          style={{ padding: "0.5rem 1rem", fontSize: "0.85rem" }}
          type="button"
        >
          {isVerifying ? "Verifying..." : "Verify All Models"}
        </button>
      </div>

      {error ? (
        <p className="error-text" style={{ marginBottom: "1rem" }}>
          {error}
        </p>
      ) : null}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
          gap: "1rem",
        }}
      >
        {Object.entries(modelStatus.models).map(([role, modelId]) => {
          const verification = modelStatus.statuses?.[role];
          const isOnline = verification?.status === "ONLINE";
          const isError = verification?.status === "ERROR";

          return (
            <div
              key={role}
              style={{
                padding: "1rem",
                background: "var(--panel-strong)",
                border: "1px solid var(--border)",
                borderRadius: "18px",
                display: "flex",
                flexDirection: "column",
                gap: "0.5rem",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong style={{ fontSize: "0.95rem", color: "var(--ink)" }}>
                  {role.replace(/_/g, " ").toUpperCase()}
                </strong>
                <span
                  style={{
                    fontSize: "0.75rem",
                    padding: "2px 8px",
                    borderRadius: "999px",
                    background: isOnline ? "#14532d" : isError ? "#7f1d1d" : "#594a42",
                    color: "#fff",
                  }}
                >
                  {verification?.status || "PENDING"}
                </span>
              </div>
              <code style={{ fontSize: "0.75rem", color: "var(--muted)", wordBreak: "break-all" }}>
                {modelId}
              </code>
              <span className="table-subcopy">Calls made: {verification?.calls_made || 0}</span>
              {verification?.response ? (
                <p style={{ fontSize: "0.75rem", fontStyle: "italic", marginTop: "4px", color: "#14532d" }}>
                  "{verification.response}"
                </p>
              ) : null}
              {verification?.error ? (
                <p style={{ fontSize: "0.75rem", color: "var(--danger)", marginTop: "4px" }}>
                  Error: {verification.error}
                </p>
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
