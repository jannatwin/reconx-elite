import React, { useMemo } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';

const AdminMetricsDashboard = ({ metrics, auditLogs }) => {
  // Process audit logs for activity timeline
  const activityData = useMemo(() => {
    if (!auditLogs || auditLogs.length === 0) return [];
    
    const last7Days = [];
    const now = new Date();
    
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      date.setHours(0, 0, 0, 0);
      
      const nextDate = new Date(date);
      nextDate.setDate(nextDate.getDate() + 1);
      
      const dayLogs = auditLogs.filter(log => {
        const logDate = new Date(log.created_at);
        return logDate >= date && logDate < nextDate;
      });
      
      last7Days.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        logins: dayLogs.filter(log => log.action === 'login').length,
        scans: dayLogs.filter(log => log.action === 'scan_triggered').length,
        reports: dayLogs.filter(log => log.action === 'report_downloaded').length,
        admin: dayLogs.filter(log => log.action.startsWith('admin_')).length,
        total: dayLogs.length
      });
    }
    
    return last7Days;
  }, [auditLogs]);

  // User activity breakdown
  const userActivityData = useMemo(() => {
    if (!auditLogs || auditLogs.length === 0) return [];
    
    const actionCounts = {};
    auditLogs.forEach(log => {
      const action = log.action.replace('_', ' ').toUpperCase();
      actionCounts[action] = (actionCounts[action] || 0) + 1;
    });
    
    return Object.entries(actionCounts)
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [auditLogs]);

  // System health indicators
  const healthData = useMemo(() => {
    if (!metrics) return [];
    
    return [
      { name: 'Active Scans', value: metrics.tasks?.active_scans || 0, max: 10, status: 'active' },
      { name: 'Queued Tasks', value: metrics.tasks?.queued_tasks || 0, max: 50, status: 'queued' },
      { name: 'Completed (1h)', value: metrics.tasks?.completed_tasks_1h || 0, max: 100, status: 'completed' },
      { name: 'Total Users', value: metrics.users_total || 0, max: 1000, status: 'users' },
      { name: 'Total Targets', value: metrics.targets_total || 0, max: 5000, status: 'targets' },
      { name: 'Total Scans', value: metrics.scans_total || 0, max: 10000, status: 'scans' }
    ];
  }, [metrics]);

  // Resource utilization pie chart
  const resourceData = useMemo(() => {
    if (!metrics) return [];
    
    return [
      { name: 'Users', value: metrics.users_total || 0, color: '#3B82F6' },
      { name: 'Targets', value: metrics.targets_total || 0, color: '#10B981' },
      { name: 'Scans', value: metrics.scans_total || 0, color: '#F59E0B' }
    ];
  }, [metrics]);

  const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#6B7280'];

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="custom-tooltip">
          <p className="tooltip-label">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} className="tooltip-value" style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  const HealthBar = ({ item }) => {
    const percentage = Math.min((item.value / item.max) * 100, 100);
    let statusColor = '#10B981'; // green
    
    if (percentage > 80) {
      statusColor = '#EF4444'; // red
    } else if (percentage > 60) {
      statusColor = '#F59E0B'; // yellow
    }
    
    return (
      <div className="health-bar">
        <div className="health-bar-header">
          <span className="health-bar-name">{item.name}</span>
          <span className="health-bar-value">{item.value}</span>
        </div>
        <div className="health-bar-container">
          <div 
            className="health-bar-fill" 
            style={{ 
              width: `${percentage}%`,
              backgroundColor: statusColor 
            }}
          ></div>
        </div>
      </div>
    );
  };

  return (
    <div className="admin-metrics-dashboard">
      <div className="metrics-grid">
        {/* Activity Timeline */}
        <div className="metric-card">
          <h3>7-Day Activity Timeline</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={activityData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip content={<CustomTooltip />} />
              <Legend />
              <Line type="monotone" dataKey="logins" stroke="#3B82F6" strokeWidth={2} />
              <Line type="monotone" dataKey="scans" stroke="#10B981" strokeWidth={2} />
              <Line type="monotone" dataKey="reports" stroke="#F59E0B" strokeWidth={2} />
              <Line type="monotone" dataKey="admin" stroke="#EF4444" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* User Activity Breakdown */}
        <div className="metric-card">
          <h3>User Activity Breakdown</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={userActivityData} layout="horizontal">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="action" type="category" width={100} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" fill="#8B5CF6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* System Health Indicators */}
        <div className="metric-card">
          <h3>System Health Indicators</h3>
          <div className="health-indicators">
            {healthData.map((item, index) => (
              <HealthBar key={index} item={item} />
            ))}
          </div>
        </div>

        {/* Resource Distribution */}
        <div className="metric-card">
          <h3>Resource Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={resourceData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {resourceData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="quick-stats">
        <div className="stat-card">
          <h4>Active Users</h4>
          <span className="stat-number">{metrics?.users_total || 0}</span>
        </div>
        <div className="stat-card">
          <h4>Targets Monitored</h4>
          <span className="stat-number">{metrics?.targets_total || 0}</span>
        </div>
        <div className="stat-card">
          <h4>Scans Completed</h4>
          <span className="stat-number">{metrics?.scans_total || 0}</span>
        </div>
        <div className="stat-card">
          <h4>Active Scans</h4>
          <span className="stat-number">{metrics?.tasks?.active_scans || 0}</span>
        </div>
        <div className="stat-card">
          <h4>Queued Tasks</h4>
          <span className="stat-number">{metrics?.tasks?.queued_tasks || 0}</span>
        </div>
        <div className="stat-card">
          <h4>Recent Activity (1h)</h4>
          <span className="stat-number">{metrics?.tasks?.completed_tasks_1h || 0}</span>
        </div>
      </div>
    </div>
  );
};

export default AdminMetricsDashboard;
