import { useEffect, useState } from "react";

import { api } from "../api/client";

export default function BlindHitsPanel({ targetId }) {
  const [hits, setHits] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadHits() {
    try {
      const response = await api.get("/payloads/blind-xss/hits");
      setHits(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load blind XSS hits");
    } finally {
      setIsLoading(false);
    }
  }

  async function markProcessed(hitId, processed) {
    try {
      await api.put(`/payloads/blind-xss/hits/${hitId}/processed`, { processed });
      await loadHits(); // Reload to get updated status
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to update hit status");
    }
  }

  useEffect(() => {
    loadHits();
  }, []);

  if (isLoading) {
    return <div className="panel-card">Loading blind XSS hits...</div>;
  }

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2>Blind XSS Hits</h2>
        <span className="pill">{hits.length}</span>
      </div>

      {error && <p className="error-text">{error}</p>}

      {hits.length === 0 ? (
        <p className="muted-copy">No blind XSS hits recorded yet.</p>
      ) : (
        <div className="stack-list">
          {hits.map((hit) => (
            <div key={hit.id} className="list-row">
              <div className="list-content">
                <div className="list-header">
                  <strong>{hit.ip_address}</strong>
                  <span className={`status-pill status-${hit.processed === 0 ? "pending" : hit.processed === 1 ? "success" : "muted"}`}>
                    {hit.processed === 0 ? "New" : hit.processed === 1 ? "Processed" : "Ignored"}
                  </span>
                </div>

                <div className="table-subcopy">
                  {hit.method} {hit.url_path || "Unknown URL"}
                </div>

                {hit.user_agent && (
                  <div className="table-subcopy">
                    User-Agent: {hit.user_agent.length > 50 ? `${hit.user_agent.substring(0, 50)}...` : hit.user_agent}
                  </div>
                )}

                {hit.referrer && (
                  <div className="table-subcopy">
                    Referrer: {hit.referrer.length > 50 ? `${hit.referrer.substring(0, 50)}...` : hit.referrer}
                  </div>
                )}

                <div className="table-subcopy">
                  Triggered: {new Date(hit.triggered_at).toLocaleString()}
                </div>

                {hit.payload_opportunity && (
                  <div className="table-subcopy">
                    From: {hit.payload_opportunity.endpoint_url} ({hit.payload_opportunity.parameter_name})
                  </div>
                )}
              </div>

              <div className="button-row">
                {hit.processed === 0 && (
                  <>
                    <button
                      className="ghost-button"
                      onClick={() => markProcessed(hit.id, 1)}
                      type="button"
                    >
                      Mark Processed
                    </button>
                    <button
                      className="ghost-button danger-button"
                      onClick={() => markProcessed(hit.id, 2)}
                      type="button"
                    >
                      Ignore
                    </button>
                  </>
                )}
                {hit.processed === 1 && (
                  <button
                    className="ghost-button"
                    onClick={() => markProcessed(hit.id, 0)}
                    type="button"
                  >
                    Mark Unprocessed
                  </button>
                )}
                {hit.processed === 2 && (
                  <button
                    className="ghost-button"
                    onClick={() => markProcessed(hit.id, 0)}
                    type="button"
                  >
                    Mark Unprocessed
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}