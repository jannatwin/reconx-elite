import React, { useMemo, useRef, useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const AttackPathVisualization = ({ attackPaths, vulnerabilities, endpoints, subdomains }) => {
  const graphRef = useRef();
  const [highlightNodes, setHighlightNodes] = useState(new Set());
  const [highlightLinks, setHighlightLinks] = useState(new Set());
  const [hoverNode, setHoverNode] = useState(null);
  const [selectedPath, setSelectedPath] = useState(null);

  const graphData = useMemo(() => {
    const nodes = [];
    const links = [];
    const nodeMap = new Map();
    let nodeId = 0;

    // Add target domain as central node
    const targetNode = {
      id: nodeId++,
      name: 'Target Domain',
      type: 'target',
      color: '#2E4057',
      size: 20,
      group: 'target'
    };
    nodes.push(targetNode);
    nodeMap.set('target', 0);

    // Add subdomain nodes
    subdomains.forEach((subdomain, index) => {
      const id = nodeId++;
      const node = {
        id,
        name: subdomain.hostname,
        type: 'subdomain',
        color: subdomain.is_live ? '#048A81' : '#6B7280',
        size: subdomain.is_live ? 12 : 8,
        group: 'subdomain',
        data: subdomain
      };
      nodes.push(node);
      nodeMap.set(`subdomain_${subdomain.id}`, id);

      // Link to target
      links.push({
        source: 0,
        target: id,
        color: subdomain.is_live ? '#048A81' : '#E5E7EB',
        width: subdomain.is_live ? 2 : 1
      });
    });

    // Add endpoint nodes
    endpoints.forEach((endpoint, index) => {
      const id = nodeId++;
      const node = {
        id,
        name: endpoint.normalized_url.length > 50 
          ? endpoint.normalized_url.substring(0, 47) + '...' 
          : endpoint.normalized_url,
        type: 'endpoint',
        color: endpoint.priority_score >= 60 ? '#DC2626' : '#F59E0B',
        size: Math.max(6, Math.min(15, endpoint.priority_score / 10)),
        group: 'endpoint',
        data: endpoint
      };
      nodes.push(node);
      nodeMap.set(`endpoint_${endpoint.id}`, id);

      // Link to relevant subdomain (extract hostname)
      const hostname = new URL(endpoint.url).hostname;
      const subdomainNode = Array.from(nodeMap.entries()).find(([key]) => 
        key.includes('subdomain') && subdomains.find(s => s.hostname === hostname)
      );
      
      if (subdomainNode) {
        links.push({
          source: subdomainNode[1],
          target: id,
          color: '#94A3B8',
          width: 1
        });
      }
    });

    // Add vulnerability nodes
    vulnerabilities.forEach((vuln, index) => {
      const id = nodeId++;
      const severityColors = {
        critical: '#DC2626',
        high: '#EA580C',
        medium: '#FCD34D',
        low: '#86EFAC',
        info: '#E5E7EB'
      };
      
      const node = {
        id,
        name: vuln.template_id,
        type: 'vulnerability',
        color: severityColors[vuln.severity?.toLowerCase()] || '#E5E7EB',
        size: 8 + (vuln.confidence * 5),
        group: 'vulnerability',
        data: vuln
      };
      nodes.push(node);
      nodeMap.set(`vulnerability_${vuln.id}`, id);

      // Link to affected endpoint
      const endpointNode = nodeMap.get(`endpoint_${vuln.endpoint_id}`);
      if (endpointNode !== undefined) {
        links.push({
          source: endpointNode,
          target: id,
          color: severityColors[vuln.severity?.toLowerCase()] || '#E5E7EB',
          width: 2
        });
      }
    });

    // Add attack path connections
    attackPaths.forEach((path, pathIndex) => {
      if (path.steps_json && Array.isArray(path.steps_json)) {
        let previousNodeId = null;
        
        path.steps_json.forEach((step, stepIndex) => {
          let currentNodeId = null;
          
          // Find or create node for this step
          if (step.type === 'endpoint' && step.endpoint_id) {
            currentNodeId = nodeMap.get(`endpoint_${step.endpoint_id}`);
          } else if (step.type === 'vulnerability' && step.vulnerability_id) {
            currentNodeId = nodeMap.get(`vulnerability_${step.vulnerability_id}`);
          } else if (step.type === 'subdomain' && step.subdomain_id) {
            currentNodeId = nodeMap.get(`subdomain_${step.subdomain_id}`);
          }
          
          // Create connection if we have both nodes
          if (previousNodeId !== null && currentNodeId !== null) {
            links.push({
              source: previousNodeId,
              target: currentNodeId,
              color: '#8B5CF6',
              width: 3,
              pathId: path.id,
              type: 'attack_path'
            });
          }
          
          previousNodeId = currentNodeId;
        });
      }
    });

    return { nodes, links };
  }, [attackPaths, vulnerabilities, endpoints, subdomains]);

  const handleNodeHover = (node) => {
    setHoverNode(node || null);
    
    if (!node) {
      setHighlightNodes(new Set());
      setHighlightLinks(new Set());
      return;
    }

    const neighbors = new Set();
    const linkIds = new Set();

    graphData.links.forEach(link => {
      if (link.source.id === node.id || link.target.id === node.id) {
        neighbors.add(link.source.id);
        neighbors.add(link.target.id);
        linkIds.add(link);
      }
    });

    setHighlightNodes(neighbors);
    setHighlightLinks(linkIds);
  };

  const handleNodeClick = (node) => {
    if (node.type === 'vulnerability') {
      setSelectedPath(node.data);
    } else if (node.type === 'endpoint') {
      setSelectedPath(node.data);
    }
  };

  const paintNode = (node, ctx) => {
    const isHighlighted = highlightNodes.has(node.id);
    const size = isHighlighted ? node.size * 1.5 : node.size;
    
    // Draw node circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
    ctx.fillStyle = node.color;
    ctx.fill();
    
    if (isHighlighted) {
      ctx.strokeStyle = '#8B5CF6';
      ctx.lineWidth = 3;
      ctx.stroke();
    }
    
    // Draw label for important nodes
    if (node.type === 'target' || node.type === 'vulnerability' || isHighlighted) {
      ctx.fillStyle = '#1F2937';
      ctx.font = `${isHighlighted ? 'bold' : 'normal'} 10px Arial`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      
      const label = node.name.length > 20 ? node.name.substring(0, 17) + '...' : node.name;
      ctx.fillText(label, node.x, node.y + size + 10);
    }
  };

  const paintLink = (link, ctx) => {
    const isHighlighted = highlightLinks.has(link);
    
    ctx.beginPath();
    ctx.moveTo(link.source.x, link.source.y);
    ctx.lineTo(link.target.x, link.target.y);
    
    if (isHighlighted) {
      ctx.strokeStyle = '#8B5CF6';
      ctx.lineWidth = link.width * 2;
    } else {
      ctx.strokeStyle = link.color || '#94A3B8';
      ctx.lineWidth = link.width || 1;
    }
    
    ctx.stroke();
    
    // Draw arrow for attack paths
    if (link.type === 'attack_path') {
      const dx = link.target.x - link.source.x;
      const dy = link.target.y - link.source.y;
      const angle = Math.atan2(dy, dx);
      const arrowLength = 8;
      const arrowAngle = Math.PI / 6;
      
      ctx.beginPath();
      ctx.moveTo(link.target.x, link.target.y);
      ctx.lineTo(
        link.target.x - arrowLength * Math.cos(angle - arrowAngle),
        link.target.y - arrowLength * Math.sin(angle - arrowAngle)
      );
      ctx.moveTo(link.target.x, link.target.y);
      ctx.lineTo(
        link.target.x - arrowLength * Math.cos(angle + arrowAngle),
        link.target.y - arrowLength * Math.sin(angle + arrowAngle)
      );
      ctx.stroke();
    }
  };

  return (
    <div className="attack-path-visualization">
      <div className="visualization-controls">
        <h3>Attack Path Network Graph</h3>
        <div className="legend">
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#2E4057' }}></div>
            <span>Target Domain</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#048A81' }}></div>
            <span>Live Subdomain</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#6B7280' }}></div>
            <span>Non-live Subdomain</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#DC2626' }}></div>
            <span>High-Priority Endpoint</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#F59E0B' }}></div>
            <span>Low-Priority Endpoint</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#8B5CF6' }}></div>
            <span>Attack Path</span>
          </div>
        </div>
      </div>
      
      <div className="graph-container">
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel="name"
          nodeAutoColorBy="group"
          nodeVal="size"
          linkColor="color"
          linkWidth="width"
          linkDirectionalArrowLength={6}
          linkDirectionalArrowRelPos={1}
          onNodeHover={handleNodeHover}
          onNodeClick={handleNodeClick}
          nodeCanvasObject={paintNode}
          linkCanvasObject={paintLink}
          enableNodeDrag={true}
          enableZoomPanInteraction={true}
          cooldownTicks={100}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
        />
      </div>
      
      {hoverNode && (
        <div className="node-tooltip">
          <h4>{hoverNode.name}</h4>
          <p><strong>Type:</strong> {hoverNode.type}</p>
          {hoverNode.data && (
            <>
              {hoverNode.type === 'vulnerability' && (
                <>
                  <p><strong>Severity:</strong> {hoverNode.data.severity}</p>
                  <p><strong>Confidence:</strong> {hoverNode.data.confidence}</p>
                  <p><strong>Description:</strong> {hoverNode.data.description}</p>
                </>
              )}
              {hoverNode.type === 'endpoint' && (
                <>
                  <p><strong>Priority Score:</strong> {hoverNode.data.priority_score}</p>
                  <p><strong>Category:</strong> {hoverNode.data.category}</p>
                  <p><strong>Tags:</strong> {(hoverNode.data.tags || []).join(', ')}</p>
                </>
              )}
              {hoverNode.type === 'subdomain' && (
                <>
                  <p><strong>Live:</strong> {hoverNode.data.is_live ? 'Yes' : 'No'}</p>
                  <p><strong>Environment:</strong> {hoverNode.data.environment}</p>
                  <p><strong>Takeover Candidate:</strong> {hoverNode.data.takeover_candidate ? 'Yes' : 'No'}</p>
                </>
              )}
            </>
          )}
        </div>
      )}
      
      {selectedPath && (
        <div className="selected-path-panel">
          <div className="panel-header">
            <h3>Selected Details</h3>
            <button onClick={() => setSelectedPath(null)} className="close-button">×</button>
          </div>
          <div className="panel-content">
            {selectedPath.template_id ? (
              // Vulnerability details
              <div>
                <h4>{selectedPath.template_id}</h4>
                <p><strong>Severity:</strong> 
                  <span className={`status-pill status-${selectedPath.severity}`}>
                    {selectedPath.severity}
                  </span>
                </p>
                <p><strong>Confidence:</strong> {selectedPath.confidence}</p>
                <p><strong>Matched URL:</strong> {selectedPath.matched_url}</p>
                <p><strong>Description:</strong> {selectedPath.description}</p>
                {selectedPath.evidence_json && (
                  <details>
                    <summary>Evidence</summary>
                    <pre>{JSON.stringify(selectedPath.evidence_json, null, 2)}</pre>
                  </details>
                )}
              </div>
            ) : (
              // Endpoint details
              <div>
                <h4>Endpoint Details</h4>
                <p><strong>URL:</strong> {selectedPath.url}</p>
                <p><strong>Priority Score:</strong> {selectedPath.priority_score}</p>
                <p><strong>Category:</strong> {selectedPath.category}</p>
                <p><strong>Source:</strong> {selectedPath.source}</p>
                <p><strong>Tags:</strong> {(selectedPath.tags || []).join(', ')}</p>
                <p><strong>Focus Reasons:</strong> {(selectedPath.focus_reasons || []).join(', ')}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default AttackPathVisualization;
