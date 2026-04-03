class WebSocketService {
  constructor() {
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectInterval = 5000;
    this.isConnecting = false;
    this.messageQueue = [];
    this.eventListeners = new Map();
    this.userId = null;
    this.accessToken = null;
    this.reconnectTimer = null;
  }

  connect(userId, accessToken) {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return Promise.resolve();
    }

    this.userId = userId;
    this.accessToken = accessToken || null;
    this.isConnecting = true;

    return new Promise((resolve, reject) => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const tokenParam = accessToken ? `?token=${encodeURIComponent(accessToken)}` : "";
        const wsUrl = `${protocol}//${window.location.host}/ws/${userId}${tokenParam}`;
        
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          
          // Send queued messages
          this.flushMessageQueue();
          
          // Send initial subscription message
          this.send({
            type: 'subscribe',
            channels: ['scan_events', 'security_alerts', 'system_alerts']
          });
          
          this.emit('connected');
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (error) {
            console.error('Error parsing WebSocket message:', error);
          }
        };

        this.ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason);
          this.isConnecting = false;
          this.ws = null;
          this.emit('disconnected', { code: event.code, reason: event.reason });
          
          // Attempt to reconnect if not a normal closure
          if (event.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.isConnecting = false;
          this.emit('error', error);
          reject(error);
        };

      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }

    this.messageQueue = [];
    this.eventListeners.clear();
  }

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      // Queue message if not connected
      this.messageQueue.push(message);
    }
  }

  flushMessageQueue() {
    while (this.messageQueue.length > 0 && this.ws && this.ws.readyState === WebSocket.OPEN) {
      const message = this.messageQueue.shift();
      this.ws.send(JSON.stringify(message));
    }
  }

  handleMessage(data) {
    const { type, data: messageData, timestamp } = data;
    
    // Handle different message types
    switch (type) {
      case 'pong':
        // Handle pong response (if we implement ping/pong)
        break;
      
      case 'subscription_acknowledged':
        console.log('Subscribed to channels:', messageData.channels);
        this.emit('subscribed', messageData);
        break;
      
      case 'scan_started':
        this.emit('scanStarted', messageData);
        this.showNotification('Scan Started', messageData.message, 'info');
        break;
      
      case 'scan_completed':
        this.emit('scanCompleted', messageData);
        this.showNotification('Scan Completed', messageData.message, 'success');
        break;
      
      case 'scan_failed':
        this.emit('scanFailed', messageData);
        this.showNotification('Scan Failed', messageData.message, 'error');
        break;
      
      case 'critical_vulnerability':
        this.emit('criticalVulnerability', messageData);
        this.showNotification('Critical Vulnerability Found', messageData.message, 'error', true);
        break;
      
      case 'system_alert':
        this.emit('systemAlert', messageData);
        this.showNotification(messageData.title || 'System Alert', messageData.message, 'warning');
        break;
      
      case 'user_notification':
        this.emit('userNotification', messageData);
        this.showNotification(messageData.title, messageData.message, messageData.notification_type || 'info');
        break;
      
      case 'error':
        console.error('WebSocket error from server:', messageData);
        this.emit('serverError', messageData);
        break;
      
      default:
        console.log('Unknown WebSocket message type:', type, data);
        this.emit('message', data);
    }
  }

  showNotification(title, message, type = 'info', persistent = false) {
    // Check if browser supports notifications
    if ('Notification' in window) {
      // Request permission if not granted
      if (Notification.permission === 'default') {
        Notification.requestPermission();
      }
      
      if (Notification.permission === 'granted') {
        const notification = new Notification(title, {
          body: message,
          icon: this.getNotificationIcon(type),
          tag: persistent ? 'persistent' : null,
          requireInteraction: persistent
        });

        if (!persistent) {
          // Auto-close non-persistent notifications after 5 seconds
          setTimeout(() => {
            notification.close();
          }, 5000);
        }
      }
    }

    // Also emit a custom event for the UI to handle
    this.emit('notification', {
      title,
      message,
      type,
      persistent,
      timestamp: new Date().toISOString()
    });
  }

  getNotificationIcon(type) {
    const icons = {
      info: '/icons/info-icon.png',
      success: '/icons/success-icon.png',
      warning: '/icons/warning-icon.png',
      error: '/icons/error-icon.png'
    };
    return icons[type] || icons.info;
  }

  scheduleReconnect() {
    if (this.reconnectTimer) {
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectInterval * Math.pow(2, this.reconnectAttempts - 1), 30000);
    
    console.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect(this.userId, this.accessToken).catch(error => {
        console.error('Reconnect failed:', error);
      });
    }, delay);
  }

  // Event emitter methods
  on(event, callback) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event).push(callback);
  }

  off(event, callback) {
    if (this.eventListeners.has(event)) {
      if (!callback) {
        this.eventListeners.set(event, []);
        return;
      }
      const listeners = this.eventListeners.get(event);
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  emit(event, data) {
    if (this.eventListeners.has(event)) {
      this.eventListeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in WebSocket event listener for ${event}:`, error);
        }
      });
    }
  }

  // Utility methods
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  getConnectionStatus() {
    if (!this.ws) return 'disconnected';
    
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING: return 'connecting';
      case WebSocket.OPEN: return 'connected';
      case WebSocket.CLOSING: return 'closing';
      case WebSocket.CLOSED: return 'disconnected';
      default: return 'unknown';
    }
  }

  // Ping method to keep connection alive
  startPing() {
    this.pingInterval = setInterval(() => {
      if (this.isConnected()) {
        this.send({ type: 'ping' });
      }
    }, 30000); // Ping every 30 seconds
  }

  stopPing() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }
}

// Create singleton instance
const websocketService = new WebSocketService();

export default websocketService;
