import React, { useMemo } from 'react';
import { Treemap, ResponsiveContainer, Tooltip } from 'recharts';

const SubdomainTreeMap = ({ subdomains, vulnerabilities, endpoints }) => {
  const treeData = useMemo(() => {
    // Group subdomains by environment
    const environmentGroups = subdomains.reduce((acc, subdomain) => {
      const env = subdomain.environment || 'unknown';
      if (!acc[env]) {
        acc[env] = {
          name: env,
          children: [],
          totalVulns: 0,
          totalEndpoints: 0,
          totalSize: 0
        };
      }
      
      // Count vulnerabilities and endpoints for this subdomain
      const subdomainVulns = vulnerabilities.filter(v => 
        v.matched_url && v.matched_url.includes(subdomain.hostname)
      ).length;
      
      const subdomainEndpoints = endpoints.filter(e => 
        e.hostname === subdomain.hostname
      ).length;
      
      const size = Math.max(100, subdomainVulns * 50 + subdomainEndpoints * 20 + (subdomain.is_live ? 100 : 20));
      
      acc[env].children.push({
        name: subdomain.hostname,
        size: size,
        is_live: subdomain.is_live,
        takeover_candidate: subdomain.takeover_candidate,
        vulnerabilities: subdomainVulns,
        endpoints: subdomainEndpoints,
        cdn: subdomain.cdn,
        waf: subdomain.waf,
        tags: subdomain.tags || []
      });
      
      acc[env].totalVulns += subdomainVulns;
      acc[env].totalEndpoints += subdomainEndpoints;
      acc[env].totalSize += size;
      
      return acc;
    }, {});

    // Convert to tree format
    return {
      name: 'Target Domain',
      children: Object.values(environmentGroups).map(env => ({
        ...env,
        // Add color based on risk level
        riskLevel: env.totalVulns > 5 ? 'high' : env.totalVulns > 2 ? 'medium' : 'low'
      }))
    };
  }, [subdomains, vulnerabilities, endpoints]);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload[0]) {
      const data = payload[0].payload;
      
      if (data.children) {
        // Environment group
        return (
          <div className="custom-tooltip">
            <h4>{data.name} Environment</h4>
            <p><strong>Subdomains:</strong> {data.children.length}</p>
            <p><strong>Total Vulnerabilities:</strong> {data.totalVulns}</p>
            <p><strong>Total Endpoints:</strong> {data.totalEndpoints}</p>
            <p><strong>Risk Level:</strong> 
              <span className={`risk-indicator risk-${data.riskLevel}`}>
                {data.riskLevel}
              </span>
            </p>
          </div>
        );
      } else {
        // Individual subdomain
        return (
          <div className="custom-tooltip">
            <h4>{data.name}</h4>
            <p><strong>Status:</strong> 
              <span className={`status-indicator ${data.is_live ? 'live' : 'non-live'}`}>
                {data.is_live ? 'Live' : 'Non-live'}
              </span>
            </p>
            <p><strong>Vulnerabilities:</strong> {data.vulnerabilities}</p>
            <p><strong>Endpoints:</strong> {data.endpoints}</p>
            {data.takeover_candidate && (
              <p><strong>⚠️ Takeover Candidate</strong></p>
            )}
            {data.cdn && <p><strong>CDN:</strong> {data.cdn}</p>}
            {data.waf && <p><strong>WAF:</strong> {data.waf}</p>}
            {data.tags.length > 0 && (
              <p><strong>Tags:</strong> {data.tags.join(', ')}</p>
            )}
          </div>
        );
      }
    }
    return null;
  };

  const CustomContent = (props) => {
    const { x, y, width, height, name, is_live, takeover_candidate, riskLevel } = props;
    
    let fillColor = '#E5E7EB'; // Default gray
    
    if (riskLevel) {
      // Environment level coloring
      if (riskLevel === 'high') fillColor = '#FEE2E2';
      else if (riskLevel === 'medium') fillColor = '#FEF3C7';
      else fillColor = '#D1FAE5';
    } else if (is_live !== undefined) {
      // Subdomain level coloring
      if (takeover_candidate) {
        fillColor = '#FED7AA'; // Orange for takeover candidates
      } else if (is_live) {
        fillColor = '#D1FAE5'; // Green for live
      } else {
        fillColor = '#F3F4F6'; // Light gray for non-live
      }
    }

    return (
      <g>
        <rect
          x={x}
          y={y}
          width={width}
          height={height}
          style={{
            fill: fillColor,
            stroke: '#D1D5DB',
            strokeWidth: 1,
            strokeOpacity: 1,
          }}
        />
        {width > 50 && height > 30 && (
          <>
            <text
              x={x + width / 2}
              y={y + height / 2 - 5}
              textAnchor="middle"
              fill="#374151"
              fontSize={12}
              fontWeight="bold"
            >
              {name.length > Math.floor(width / 8) 
                ? name.substring(0, Math.floor(width / 8) - 3) + '...'
                : name
              }
            </text>
            {is_live !== undefined && (
              <text
                x={x + width / 2}
                y={y + height / 2 + 10}
                textAnchor="middle"
                fill="#6B7280"
                fontSize={10}
              >
                {is_live ? '🟢 Live' : '🔴 Non-live'}
                {takeover_candidate && ' ⚠️'}
              </text>
            )}
            {riskLevel && (
              <text
                x={x + width / 2}
                y={y + height / 2 + 10}
                textAnchor="middle"
                fill="#374151"
                fontSize={10}
              >
                Risk: {riskLevel}
              </text>
            )}
          </>
        )}
      </g>
    );
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'high': return '#DC2626';
      case 'medium': return '#F59E0B';
      case 'low': return '#059669';
      default: return '#6B7280';
    }
  };

  return (
    <div className="subdomain-treemap">
      <div className="treemap-header">
        <h3>Subdomain Risk Analysis</h3>
        <div className="treemap-legend">
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#D1FAE5' }}></div>
            <span>Live Subdomain</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#F3F4F6' }}></div>
            <span>Non-live Subdomain</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#FED7AA' }}></div>
            <span>Takeover Candidate</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#FEE2E2' }}></div>
            <span>High Risk Environment</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#FEF3C7' }}></div>
            <span>Medium Risk Environment</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#D1FAE5' }}></div>
            <span>Low Risk Environment</span>
          </div>
        </div>
      </div>
      
      <ResponsiveContainer width="100%" height={400}>
        <Treemap
          data={[treeData]}
          dataKey="size"
          aspectRatio={4/3}
          stroke="#fff"
          content={<CustomContent />}
        >
          <Tooltip content={<CustomTooltip />} />
        </Treemap>
      </ResponsiveContainer>
      
      <div className="treemap-stats">
        <h4>Environment Summary</h4>
        {treeData.children.map(env => (
          <div key={env.name} className="env-stat">
            <h5>
              {env.name} 
              <span className={`risk-indicator risk-${env.riskLevel}`}>
                {env.riskLevel} risk
              </span>
            </h5>
            <div className="stat-details">
              <span>{env.children.length} subdomains</span>
              <span>{env.totalVulns} vulnerabilities</span>
              <span>{env.totalEndpoints} endpoints</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SubdomainTreeMap;
