import { useState, useEffect, useContext, createContext } from "react";
import { useAuth } from "../context/AuthContext";
import websocketService from "../services/websocket";

const NotificationContext = createContext(null);

export const useNotifications = () => useContext(NotificationContext);

function NotificationCenter({ children }) {
  const { user, isAuthenticated, accessToken } = useAuth();
  const [notifications, setNotifications] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [showNotifications, setShowNotifications] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  // Initialize WebSocket connection when user is authenticated
  useEffect(() => {
    if (isAuthenticated && user) {
      // Connect to WebSocket
      websocketService.connect(user.id, accessToken).then(() => {
        setConnectionStatus('connected');
      }).catch(error => {
        console.error('Failed to connect WebSocket:', error);
        setConnectionStatus('error');
      });

      // Start ping to keep connection alive
      websocketService.startPing();

      // Set up event listeners
      setupEventListeners();

      // Cleanup on unmount
      return () => {
        websocketService.stopPing();
        websocketService.disconnect();
        cleanupEventListeners();
      };
    } else {
      // Disconnect when user logs out
      websocketService.disconnect();
      setConnectionStatus('disconnected');
    }
  }, [isAuthenticated, user, accessToken]);

  const setupEventListeners = () => {
    // Connection events
    websocketService.on('connected', () => {
      setConnectionStatus('connected');
    });

    websocketService.on('disconnected', () => {
      setConnectionStatus('disconnected');
    });

    websocketService.on('error', (error) => {
      setConnectionStatus('error');
      console.error('WebSocket error:', error);
    });

    // Notification events
    websocketService.on('notification', (notification) => {
      addNotification(notification);
    });

    websocketService.on('scanStarted', (data) => {
      addNotification({
        title: 'Scan Started',
        message: data.message,
        type: 'info',
        timestamp: new Date().toISOString(),
        category: 'scan'
      });
    });

    websocketService.on('scanCompleted', (data) => {
      addNotification({
        title: 'Scan Completed',
        message: data.message,
        type: 'success',
        timestamp: new Date().toISOString(),
        category: 'scan',
        data: data.results
      });
    });

    websocketService.on('scanFailed', (data) => {
      addNotification({
        title: 'Scan Failed',
        message: data.message,
        type: 'error',
        timestamp: new Date().toISOString(),
        category: 'scan'
      });
    });

    websocketService.on('criticalVulnerability', (data) => {
      addNotification({
        title: 'Critical Vulnerability Found',
        message: data.message,
        type: 'error',
        timestamp: new Date().toISOString(),
        category: 'security',
        persistent: true,
        data: data.vulnerability
      });
    });

    websocketService.on('systemAlert', (data) => {
      addNotification({
        title: data.title || 'System Alert',
        message: data.message,
        type: 'warning',
        timestamp: new Date().toISOString(),
        category: 'system'
      });
    });
  };

  const cleanupEventListeners = () => {
    // Remove all event listeners
    websocketService.off('connected');
    websocketService.off('disconnected');
    websocketService.off('error');
    websocketService.off('notification');
    websocketService.off('scanStarted');
    websocketService.off('scanCompleted');
    websocketService.off('scanFailed');
    websocketService.off('criticalVulnerability');
    websocketService.off('systemAlert');
  };

  const addNotification = (notification) => {
    const notificationWithId = {
      ...notification,
      id: Date.now() + Math.random(), // Unique ID
      read: false
    };

    setNotifications(prev => [notificationWithId, ...prev].slice(0, 50)); // Keep max 50 notifications
    setUnreadCount(prev => prev + 1);
  };

  const markAsRead = (notificationId) => {
    setNotifications(prev => 
      prev.map(notif => 
        notif.id === notificationId ? { ...notif, read: true } : notif
      )
    );
    setUnreadCount(prev => Math.max(0, prev - 1));
  };

  const markAllAsRead = () => {
    setNotifications(prev => 
      prev.map(notif => ({ ...notif, read: true }))
    );
    setUnreadCount(0);
  };

  const clearNotification = (notificationId) => {
    setNotifications(prev => prev.filter(notif => notif.id !== notificationId));
    if (notifications.find(n => n.id === notificationId && !n.read)) {
      setUnreadCount(prev => Math.max(0, prev - 1));
    }
  };

  const clearAllNotifications = () => {
    setNotifications([]);
    setUnreadCount(0);
  };

  const getConnectionStatusColor = () => {
    switch (connectionStatus) {
      case 'connected': return '#10B981';
      case 'connecting': return '#F59E0B';
      case 'error': return '#EF4444';
      default: return '#6B7280';
    }
  };

  const getConnectionStatusText = () => {
    switch (connectionStatus) {
      case 'connected': return 'Connected';
      case 'connecting': return 'Connecting...';
      case 'error': return 'Connection Error';
      default: return 'Disconnected';
    }
  };

  const getNotificationIcon = (type) => {
    const icons = {
      info: '📢',
      success: '✅',
      warning: '⚠️',
      error: '❌'
    };
    return icons[type] || '📢';
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const contextValue = {
    notifications,
    unreadCount,
    connectionStatus,
    markAsRead,
    markAllAsRead,
    clearNotification,
    clearAllNotifications
  };

  return (
    <NotificationContext.Provider value={contextValue}>
      {children}
      
      {/* Connection Status Indicator */}
      {isAuthenticated && (
        <div className="notification-indicator">
          <div 
            className="connection-status"
            style={{ backgroundColor: getConnectionStatusColor() }}
            title={getConnectionStatusText()}
          />
          {unreadCount > 0 && (
            <span className="unread-badge" onClick={() => setShowNotifications(!showNotifications)}>
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </div>
      )}

      {/* Notifications Panel */}
      {showNotifications && (
        <div className="notifications-panel">
          <div className="notifications-header">
            <h3>Notifications</h3>
            <div className="notifications-controls">
              <button 
                onClick={markAllAsRead}
                className="ghost-button"
                disabled={unreadCount === 0}
              >
                Mark All Read
              </button>
              <button 
                onClick={clearAllNotifications}
                className="ghost-button danger-button"
                disabled={notifications.length === 0}
              >
                Clear All
              </button>
              <button 
                onClick={() => setShowNotifications(false)}
                className="close-button"
              >
                ×
              </button>
            </div>
          </div>

          <div className="notifications-list">
            {notifications.length === 0 ? (
              <div className="no-notifications">
                <p>No notifications</p>
              </div>
            ) : (
              notifications.map(notification => (
                <div 
                  key={notification.id}
                  className={`notification-item ${notification.read ? 'read' : 'unread'}`}
                  onClick={() => markAsRead(notification.id)}
                >
                  <div className="notification-content">
                    <div className="notification-header">
                      <span className="notification-icon">
                        {getNotificationIcon(notification.type)}
                      </span>
                      <span className="notification-title">
                        {notification.title}
                      </span>
                      <span className="notification-time">
                        {formatTimestamp(notification.timestamp)}
                      </span>
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          clearNotification(notification.id);
                        }}
                        className="clear-notification"
                      >
                        ×
                      </button>
                    </div>
                    <p className="notification-message">
                      {notification.message}
                    </p>
                    {notification.data && (
                      <div className="notification-details">
                        <details>
                          <summary>Details</summary>
                          <pre>{JSON.stringify(notification.data, null, 2)}</pre>
                        </details>
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </NotificationContext.Provider>
  );
}

export default NotificationCenter;
