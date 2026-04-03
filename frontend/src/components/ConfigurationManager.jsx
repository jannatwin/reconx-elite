import { useEffect, useState } from "react";

import { api } from "../api/client";

export default function ConfigurationManager() {
  const [config, setConfig] = useState(null);
  const [editedConfig, setEditedConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function loadConfig() {
    try {
      const { data } = await api.get("/admin/config");
      setConfig(data);
      setEditedConfig(data);
      setError("");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load configuration");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadConfig();
  }, []);

  async function handleSave() {
    if (!editedConfig) return;

    const changes = {};
    const fieldsToCheck = [
      "cors_allowed_origins",
      "scan_throttle_seconds",
      "nuclei_templates",
      "takeover_cname_indicators",
      "scan_nuclei_target_cap",
      "scan_header_probe_cap",
    ];

    fieldsToCheck.forEach((field) => {
      if (editedConfig[field] !== config[field]) {
        changes[field] = editedConfig[field];
      }
    });

    if (Object.keys(changes).length === 0) {
      setError("No changes to save");
      return;
    }

    setSaving(true);
    try {
      await api.put("/admin/config", changes);
      setSuccess("Configuration updated successfully (in-memory only - changes will be lost on restart)");
      setConfig(editedConfig);
      setError("");
      setTimeout(() => setSuccess(""), 5000);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to update configuration");
    } finally {
      setSaving(false);
    }
  }

  function handleReset() {
    setEditedConfig(config);
    setError("");
  }

  function updateField(field, value) {
    setEditedConfig({
      ...editedConfig,
      [field]: value,
    });
  }

  if (loading) {
    return (
      <section className="panel-card">
        <h2>Configuration</h2>
        <p>Loading configuration...</p>
      </section>
    );
  }

  return (
    <section className="panel-card">
      <h2>Application Configuration</h2>

      <div style={{ background: "#fff3cd", border: "1px solid #ffc107", borderRadius: "4px", padding: "1rem", marginBottom: "2rem" }}>
        <p style={{ margin: 0, fontSize: "0.875rem" }}>
          <strong>⚠️ Warning:</strong> Configuration changes are applied to memory only. They will be lost when the application restarts. For permanent
          changes, update the <code>.env</code> file and restart the application.
        </p>
      </div>

      {error && <div style={{ padding: "1rem", marginBottom: "1rem", background: "#fee", borderLeft: "4px solid #f00", color: "#d00" }}>{error}</div>}
      {success && <div style={{ padding: "1rem", marginBottom: "1rem", background: "#efe", borderLeft: "4px solid #0a0", color: "#0a0" }}>{success}</div>}

      {editedConfig && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSave();
          }}
          style={{ display: "grid", gap: "2rem" }}
        >
          <div>
            <h3>Scan Configuration</h3>
            <div style={{ display: "grid", gap: "1.5rem" }}>
              <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
                <label style={{ display: "block", marginBottom: "0.5rem" }}>
                  <strong>Scan Throttle Seconds</strong>
                  <p style={{ margin: "0.25rem 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>
                    Cooldown between consecutive scans per user
                  </p>
                </label>
                <input
                  type="number"
                  value={editedConfig.scan_throttle_seconds}
                  onChange={(e) => updateField("scan_throttle_seconds", parseInt(e.target.value) || 0)}
                  min="1"
                  style={{ width: "100%", maxWidth: "200px", padding: "0.75rem", border: "1px solid #ddd", borderRadius: "4px" }}
                />
              </fieldset>

              <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
                <label style={{ display: "block", marginBottom: "0.5rem" }}>
                  <strong>Nuclei Target Cap</strong>
                  <p style={{ margin: "0.25rem 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>
                    Maximum number of URLs to pass to nuclei scanner
                  </p>
                </label>
                <input
                  type="number"
                  value={editedConfig.scan_nuclei_target_cap}
                  onChange={(e) => updateField("scan_nuclei_target_cap", parseInt(e.target.value) || 0)}
                  min="1"
                  style={{ width: "100%", maxWidth: "200px", padding: "0.75rem", border: "1px solid #ddd", borderRadius: "4px" }}
                />
              </fieldset>

              <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
                <label style={{ display: "block", marginBottom: "0.5rem" }}>
                  <strong>Header Probe Cap</strong>
                  <p style={{ margin: "0.25rem 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>
                    Maximum number of URLs for header probing
                  </p>
                </label>
                <input
                  type="number"
                  value={editedConfig.scan_header_probe_cap}
                  onChange={(e) => updateField("scan_header_probe_cap", parseInt(e.target.value) || 0)}
                  min="1"
                  style={{ width: "100%", maxWidth: "200px", padding: "0.75rem", border: "1px solid #ddd", borderRadius: "4px" }}
                />
              </fieldset>

              <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
                <label style={{ display: "block", marginBottom: "0.5rem" }}>
                  <strong>Nuclei Templates Path</strong>
                  <p style={{ margin: "0.25rem 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>
                    Path to custom nuclei templates (leave empty for default)
                  </p>
                </label>
                <input
                  type="text"
                  value={editedConfig.nuclei_templates}
                  onChange={(e) => updateField("nuclei_templates", e.target.value)}
                  placeholder="/path/to/templates"
                  style={{ width: "100%", padding: "0.75rem", border: "1px solid #ddd", borderRadius: "4px" }}
                />
              </fieldset>
            </div>
          </div>

          <div>
            <h3>Takeover Detection</h3>
            <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
              <label style={{ display: "block", marginBottom: "0.5rem" }}>
                <strong>CNAME Indicators</strong>
                <p style={{ margin: "0.25rem 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>
                  Comma-separated list of CNAME suffixes that indicate potential subdomain takeover vulnerabilities
                </p>
              </label>
              <textarea
                value={editedConfig.takeover_cname_indicators}
                onChange={(e) => updateField("takeover_cname_indicators", e.target.value)}
                style={{
                  width: "100%",
                  minHeight: "120px",
                  padding: "0.75rem",
                  border: "1px solid #ddd",
                  borderRadius: "4px",
                  fontFamily: "monospace",
                  fontSize: "0.875rem",
                }}
              />
            </fieldset>
          </div>

          <div>
            <h3>Security & CORS</h3>
            <fieldset style={{ border: "none", padding: 0, margin: 0 }}>
              <label style={{ display: "block", marginBottom: "0.5rem" }}>
                <strong>CORS Allowed Origins</strong>
                <p style={{ margin: "0.25rem 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>
                  Comma-separated list of origins allowed to access the API
                </p>
              </label>
              <textarea
                value={editedConfig.cors_allowed_origins}
                onChange={(e) => updateField("cors_allowed_origins", e.target.value)}
                style={{
                  width: "100%",
                  minHeight: "100px",
                  padding: "0.75rem",
                  border: "1px solid #ddd",
                  borderRadius: "4px",
                  fontFamily: "monospace",
                  fontSize: "0.875rem",
                }}
              />
            </fieldset>
          </div>

          <div>
            <h3>Read-Only Settings</h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "1rem" }}>
              <div style={{ padding: "1rem", background: "#f9f9f9", borderRadius: "4px" }}>
                <p style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>Access Token Expiry</p>
                <p style={{ margin: 0, fontSize: "1.125rem", fontWeight: "600" }}>{editedConfig.access_token_expire_minutes} minutes</p>
              </div>
              <div style={{ padding: "1rem", background: "#f9f9f9", borderRadius: "4px" }}>
                <p style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>Refresh Token Expiry</p>
                <p style={{ margin: 0, fontSize: "1.125rem", fontWeight: "600" }}>{editedConfig.refresh_token_expire_minutes} minutes</p>
              </div>
              <div style={{ padding: "1rem", background: "#f9f9f9", borderRadius: "4px" }}>
                <p style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>JS Fetch Timeout</p>
                <p style={{ margin: 0, fontSize: "1.125rem", fontWeight: "600" }}>{editedConfig.js_fetch_timeout_seconds}s</p>
              </div>
              <div style={{ padding: "1rem", background: "#f9f9f9", borderRadius: "4px" }}>
                <p style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", color: "#666" }}>Max JS Assets</p>
                <p style={{ margin: 0, fontSize: "1.125rem", fontWeight: "600" }}>{editedConfig.js_fetch_max_assets}</p>
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: "1rem", paddingTop: "1rem", borderTop: "1px solid #ddd" }}>
            <button type="submit" disabled={saving} className="primary-button" style={{ padding: "0.75rem 2rem" }}>
              {saving ? "Saving..." : "Save Configuration"}
            </button>
            <button type="button" onClick={handleReset} className="ghost-button" style={{ padding: "0.75rem 2rem" }}>
              Reset Changes
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
