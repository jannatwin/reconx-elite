import { useState } from "react";

import { api } from "../api/client";

function TicketingForm({ vulnerability, onSuccess, onError }) {
  const [platform, setPlatform] = useState("jira");
  const [config, setConfig] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const platformConfigs = {
    jira: {
      fields: [
        { name: "url", label: "Jira URL", type: "url", placeholder: "https://your-company.atlassian.net" },
        { name: "username", label: "Username/Email", type: "text", placeholder: "your-email@company.com" },
        { name: "api_token", label: "API Token", type: "password", placeholder: "Your Jira API token" },
        { name: "project_key", label: "Project Key", type: "text", placeholder: "SEC" },
        { name: "issue_type", label: "Issue Type", type: "text", placeholder: "Bug" }
      ]
    },
    github: {
      fields: [
        { name: "token", label: "Personal Access Token", type: "password", placeholder: "ghp_xxxxxxxxxxxx" },
        { name: "repository", label: "Repository", type: "text", placeholder: "owner/repo" },
        { name: "assignee", label: "Assignee (Optional)", type: "text", placeholder: "github-username" }
      ]
    },
    gitlab: {
      fields: [
        { name: "url", label: "GitLab URL", type: "url", placeholder: "https://gitlab.com" },
        { name: "token", label: "Personal Access Token", type: "password", placeholder: "glpat-xxxxxxxxxxxxxx" },
        { name: "project_id", label: "Project ID/Path", type: "text", placeholder: "1234 or group/project" },
        { name: "assignee_id", label: "Assignee ID (Optional)", type: "number", placeholder: "12345" }
      ]
    }
  };

  const handleConfigChange = (field, value) => {
    setConfig(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const testConnection = async () => {
    setIsLoading(true);
    setTestResult(null);
    
    try {
      const response = await api.post("/ticketing/test-connection", {
        platform,
        config
      });
      
      setTestResult({
        success: true,
        message: response.data.message
      });
    } catch (error) {
      setTestResult({
        success: false,
        message: error.response?.data?.detail || "Connection test failed"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const createTicket = async () => {
    setIsLoading(true);
    
    try {
      const response = await api.post("/ticketing/create-ticket", {
        vulnerability_id: vulnerability.id,
        platform,
        config,
        additional_context: {
          created_from: "ReconX Elite UI",
          severity_level: vulnerability.severity,
          template_id: vulnerability.template_id
        }
      });
      
      onSuccess(response.data);
    } catch (error) {
      onError(error.response?.data?.detail || "Failed to create ticket");
    } finally {
      setIsLoading(false);
    }
  };

  const currentFields = platformConfigs[platform]?.fields || [];

  return (
    <div className="ticketing-form">
      <div className="form-group">
        <label htmlFor="platform">Ticketing Platform</label>
        <select
          id="platform"
          value={platform}
          onChange={(e) => {
            setPlatform(e.target.value);
            setConfig({});
            setTestResult(null);
          }}
        >
          <option value="jira">Jira</option>
          <option value="github">GitHub Issues</option>
          <option value="gitlab">GitLab Issues</option>
        </select>
      </div>

      <div className="config-fields">
        {currentFields.map(field => (
          <div className="form-group" key={field.name}>
            <label htmlFor={field.name}>{field.label}</label>
            <input
              id={field.name}
              type={field.type}
              placeholder={field.placeholder}
              value={config[field.name] || ""}
              onChange={(e) => handleConfigChange(field.name, e.target.value)}
            />
          </div>
        ))}
      </div>

      {testResult && (
        <div className={`alert ${testResult.success ? "alert-success" : "alert-error"}`}>
          {testResult.message}
        </div>
      )}

      <div className="button-row">
        <button
          type="button"
          onClick={testConnection}
          disabled={isLoading || Object.keys(config).length === 0}
          className="ghost-button"
        >
          {isLoading ? "Testing..." : "Test Connection"}
        </button>
        
        <button
          type="button"
          onClick={createTicket}
          disabled={isLoading || !testResult?.success || Object.keys(config).length === 0}
          className="primary-button"
        >
          {isLoading ? "Creating..." : "Create Ticket"}
        </button>
      </div>
    </div>
  );
}

function TicketingIntegration({ vulnerabilities, targetDomain }) {
  const [selectedVulns, setSelectedVulns] = useState(new Set());
  const [showBulkForm, setShowBulkForm] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState("");

  const handleVulnSelection = (vulnId) => {
    const newSelection = new Set(selectedVulns);
    if (newSelection.has(vulnId)) {
      newSelection.delete(vulnId);
    } else {
      newSelection.add(vulnId);
    }
    setSelectedVulns(newSelection);
  };

  const handleSelectAll = () => {
    if (selectedVulns.size === vulnerabilities.length) {
      setSelectedVulns(new Set());
    } else {
      setSelectedVulns(new Set(vulnerabilities.map(v => v.id)));
    }
  };

  const handleTicketSuccess = (result) => {
    setResults(prev => [...prev, result]);
    setError("");
    // Remove the vulnerability from selection if single ticket
    if (!showBulkForm) {
      setSelectedVulns(new Set());
    }
  };

  const handleTicketError = (errorMessage) => {
    setError(errorMessage);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: "#DC2626",
      high: "#EA580C",
      medium: "#FCD34D",
      low: "#86EFAC",
      info: "#E5E7EB"
    };
    return colors[severity?.toLowerCase()] || "#E5E7EB";
  };

  return (
    <div className="ticketing-integration">
      <div className="panel-header">
        <h3>External Ticketing Integration</h3>
        <div className="button-row">
          <label className="toggle-inline">
            <input
              type="checkbox"
              checked={showBulkForm}
              onChange={(e) => setShowBulkForm(e.target.checked)}
            />
            Bulk Mode
          </label>
          <button
            onClick={handleSelectAll}
            className="ghost-button"
          >
            {selectedVulns.size === vulnerabilities.length ? "Deselect All" : "Select All"}
          </button>
        </div>
      </div>

      {selectedVulns.size > 0 && (
        <div className="selection-info">
          <span>{selectedVulns.size} vulnerabilities selected</span>
        </div>
      )}

      {!showBulkForm && selectedVulns.size === 1 ? (
        <div className="single-ticket-form">
          <h4>Create Ticket for Selected Vulnerability</h4>
          {vulnerabilities
            .filter(v => selectedVulns.has(v.id))
            .map(vulnerability => (
              <div key={vulnerability.id} className="vulnerability-summary">
                <div className="vuln-header">
                  <span 
                    className="severity-indicator"
                    style={{ backgroundColor: getSeverityColor(vulnerability.severity) }}
                  >
                    {vulnerability.severity?.toUpperCase()}
                  </span>
                  <strong>{vulnerability.template_id}</strong>
                </div>
                <p className="vuln-url">{vulnerability.matched_url}</p>
                <p className="vuln-description">{vulnerability.description}</p>
                
                <TicketingForm
                  vulnerability={vulnerability}
                  onSuccess={handleTicketSuccess}
                  onError={handleTicketError}
                />
              </div>
            ))}
        </div>
      ) : showBulkForm && selectedVulns.size > 0 ? (
        <div className="bulk-ticket-form">
          <h4>Create Bulk Tickets ({selectedVulns.size} vulnerabilities)</h4>
          <p className="muted-copy">
            This will create separate tickets for each selected vulnerability using the same configuration.
          </p>
          
          <TicketingForm
            vulnerability={vulnerabilities.find(v => selectedVulns.has(v.id))}
            onSuccess={handleTicketSuccess}
            onError={handleTicketError}
          />
          
          <div className="bulk-actions">
            <button
              onClick={async () => {
                const platform = document.querySelector('#platform').value;
                const config = {};
                
                // Collect config from form
                document.querySelectorAll('.config-fields input').forEach(input => {
                  config[input.name] = input.value;
                });
                
                try {
                  const response = await api.post("/ticketing/bulk-create-tickets", {
                    vulnerability_ids: Array.from(selectedVulns),
                    platform,
                    config
                  });
                  
                  setResults(prev => [...prev, ...response.data.results]);
                  setSelectedVulns(new Set());
                  setError("");
                } catch (error) {
                  setError(error.response?.data?.detail || "Failed to create bulk tickets");
                }
              }}
              className="primary-button"
            >
              Create {selectedVulns.size} Tickets
            </button>
          </div>
        </div>
      ) : (
        <div className="vulnerability-list">
          <h4>Select Vulnerabilities to Create Tickets</h4>
          <div className="vuln-grid">
            {vulnerabilities.map(vulnerability => (
              <div
                key={vulnerability.id}
                className={`vuln-card ${selectedVulns.has(vulnerability.id) ? 'selected' : ''}`}
                onClick={() => handleVulnSelection(vulnerability.id)}
              >
                <div className="vuln-header">
                  <input
                    type="checkbox"
                    checked={selectedVulns.has(vulnerability.id)}
                    onChange={() => handleVulnSelection(vulnerability.id)}
                    onClick={(e) => e.stopPropagation()}
                  />
                  <span 
                    className="severity-indicator"
                    style={{ backgroundColor: getSeverityColor(vulnerability.severity) }}
                  >
                    {vulnerability.severity?.toUpperCase()}
                  </span>
                  <strong>{vulnerability.template_id}</strong>
                </div>
                <p className="vuln-url">{vulnerability.matched_url}</p>
                <p className="vuln-description">{vulnerability.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-error">
          {error}
        </div>
      )}

      {results.length > 0 && (
        <div className="ticket-results">
          <h4>Created Tickets</h4>
          <div className="results-list">
            {results.map((result, index) => (
              <div key={index} className={`result-item ${result.success ? 'success' : 'error'}`}>
                {result.success ? (
                  <div>
                    <span className="success-indicator">✓</span>
                    <a 
                      href={result.ticket.ticket_url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="ticket-link"
                    >
                      {result.ticket.platform} #{result.ticket.ticket_id}
                    </a>
                  </div>
                ) : (
                  <div>
                    <span className="error-indicator">✗</span>
                    <span className="error-message">{result.error}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default TicketingIntegration;
