import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export default function OverviewTab({ summary, severityChartData, progressTimelineData, scanHistoryData }) {
  return (
    <>
      <div className="summary-grid">
        <div className="summary-card">
          <span>Subdomains</span>
          <strong>{summary.totalSubdomains}</strong>
        </div>
        <div className="summary-card">
          <span>Live hosts</span>
          <strong>{summary.liveHosts}</strong>
        </div>
        <div className="summary-card">
          <span>Endpoints</span>
          <strong>{summary.endpoints}</strong>
        </div>
        <div className="summary-card">
          <span>High-priority</span>
          <strong>{summary.highPriorityEndpoints}</strong>
        </div>
        <div className="summary-card highlight-card">
          <span>Attack paths</span>
          <strong>{summary.attackPaths}</strong>
        </div>
      </div>

      <section className="panel-card">
        <h3>Vulnerabilities by severity</h3>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={severityChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#d8c9b5" />
              <XAxis dataKey="severity" stroke="#60483e" />
              <YAxis stroke="#60483e" />
              <Tooltip />
              <Bar dataKey="count" fill="#d36f4a" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="panel-card">
        <h3>Stage timeline</h3>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={progressTimelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#d8c9b5" />
              <XAxis dataKey="idx" stroke="#60483e" />
              <YAxis stroke="#60483e" />
              <Tooltip />
              <Line type="monotone" dataKey="cumulativeMs" stroke="#1f6f78" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      {scanHistoryData.length > 1 ? (
        <section className="panel-card">
          <h3>Historical trend</h3>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={scanHistoryData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d8c9b5" />
                <XAxis dataKey="date" stroke="#60483e" />
                <YAxis stroke="#60483e" />
                <Tooltip />
                <Line type="monotone" dataKey="subdomains" stroke="#1f6f78" strokeWidth={2} />
                <Line type="monotone" dataKey="endpoints" stroke="#d36f4a" strokeWidth={2} />
                <Line type="monotone" dataKey="vulnerabilities" stroke="#7f5539" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>
      ) : null}
    </>
  );
}
