/**
 * YOUR SENTINEL v8.0 — Shared frontend utilities
 * API_BASE detection, WebSocket, push toasts, notification panel dropdown, health checks
 */

(function (global) {
  'use strict';

  // 1. API_BASE auto-detection
  const isLocal =
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1';
  const API_BASE = isLocal
    ? 'http://127.0.0.1:8000'
    : window.location.origin;

  let ws = null;
  let unreadCount = 0;
  let wsPingInterval = null;

  // HTML escaping utility
  function esc(str) {
    if (str == null) return '';
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  // Format date/time to Indian locale
  function fmtTime(isoString) {
    if (!isoString) return '';
    try {
      const d = new Date(isoString);
      return d.toLocaleString('en-IN', {
        day: '2-digit',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return String(isoString);
    }
  }

  // Generic fetch API wrapper
  async function api(path, options = {}) {
    const url = API_BASE + path;
    const res = await fetch(url, options);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || err.message || res.statusText);
    }
    return res.json();
  }

  // Risk styling classes mapping
  function riskClass(level) {
    const map = {
      LOW: 'risk-low',
      MODERATE: 'risk-moderate',
      HIGH: 'risk-high',
      CRITICAL: 'risk-critical',
      VERIFY: 'risk-verify',
    };
    return map[level] || 'risk-low';
  }

  // Severity dot indicator classes
  function severityDot(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'dot-critical';
    if (s === 'HIGH') return 'dot-high';
    if (s === 'MODERATE') return 'dot-moderate';
    return 'dot-low';
  }

  // 7. Push sliding toast (bottom-left)
  function showPushToast(title, message, severity = 'MODERATE') {
    let container = document.getElementById('push-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'push-container';
      container.style.position = 'fixed';
      container.style.bottom = '1.5rem';
      container.style.left = '1.5rem';
      container.style.zIndex = '9999';
      container.style.display = 'flex';
      container.style.flexDirection = 'column';
      container.style.gap = '0.5rem';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${severity.toLowerCase()}`;
    toast.style.background = 'var(--bg-surface)';
    toast.style.borderLeft = `4px solid var(--${severity.toLowerCase()})`;
    toast.style.padding = '0.75rem 1rem';
    toast.style.borderRadius = 'var(--radius-sm)';
    toast.style.boxShadow = 'var(--shadow)';
    toast.style.minWidth = '280px';
    toast.style.maxWidth = '360px';
    toast.style.transition = 'all 0.3s ease';
    toast.style.transform = 'translateX(-120%)';

    toast.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:start;">
        <strong style="font-size:0.875rem;">${esc(title)}</strong>
        <span class="notif-sev ${severityDot(severity)}"></span>
      </div>
      <p style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">${esc(message)}</p>
    `;
    container.appendChild(toast);

    // Slide in
    setTimeout(() => {
      toast.style.transform = 'translateX(0)';
    }, 50);

    // Auto-remove after 6 seconds
    setTimeout(() => {
      toast.style.transform = 'translateX(-120%)';
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 6000);
  }

  // 6. Update badge count and visibility
  function updateNotifBadge(count) {
    unreadCount = count;
    const badge = document.getElementById('notif-badge');
    if (!badge) return;
    badge.textContent = count;
    if (count > 0) {
      badge.removeAttribute('hidden');
      badge.classList.add('show');
    } else {
      badge.setAttribute('hidden', '');
      badge.classList.remove('show');
    }
  }

  // 2. WebSocket management
  function connectWebSocket() {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const hostPort = API_BASE.replace(/^https?:\/\//, '');
    const wsUrl = `${wsProtocol}//${hostPort}/ws/notifications`;

    console.log(`Connecting WebSocket to: ${wsUrl}`);
    if (ws) {
      try { ws.close(); } catch (e) { }
    }

    ws = new WebSocket(wsUrl);

    ws.onopen = function () {
      console.log('WebSocket Connection Opened.');
      // 2. Ping every 20 seconds
      if (wsPingInterval) clearInterval(wsPingInterval);
      wsPingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send('ping');
        }
      }, 20000);
    };

    ws.onmessage = function (e) {
      if (e.data === 'pong') return;
      try {
        const payload = JSON.parse(e.data);
        if (payload.event === 'notification' && payload.data) {
          const d = payload.data;
          showPushToast(d.title || 'Notification', d.message || '', d.severity || 'MODERATE');
          updateNotifBadge(unreadCount + 1);

          const panel = document.getElementById('notif-panel');
          if (panel && panel.classList.contains('open')) {
            loadNotifications();
          }
        }
      } catch (err) {
        console.warn('WS parse error:', err);
      }
    };

    ws.onclose = function () {
      console.warn('WebSocket connection closed. Reconnecting in 5 seconds...');
      if (wsPingInterval) clearInterval(wsPingInterval);
      setTimeout(connectWebSocket, 5000);
    };

    ws.onerror = function (err) {
      console.error('WebSocket Error:', err);
    };
  }

  // 3. Load notifications into panel
  async function loadNotifications() {
    const list = document.getElementById('notif-list');
    if (!list) return;
    try {
      const res = await api('/notifications?limit=30');
      const items = res.data || [];

      let unread = 0;
      if (items.length === 0) {
        list.innerHTML = '<li class="empty-state" style="padding:1.5rem; text-align:center; color:var(--text-muted); font-size:0.8rem;">No notifications</li>';
      } else {
        list.innerHTML = items.map(n => {
          const isUnread = !n.is_read;
          if (isUnread) unread++;

          let icon = 'ℹ️';
          if (n.severity === 'CRITICAL' || n.severity === 'HIGH') icon = '🚨';
          else if (n.severity === 'MODERATE') icon = '⚠️';
          else if (n.is_read) icon = '✅';

          const severityClass = (n.severity || 'MODERATE').toLowerCase();
          const borderStyle = isUnread ? `style="border-left: 3px solid var(--${severityClass})"` : '';

          return `
            <li class="notif-item ${isUnread ? 'unread' : ''}" ${borderStyle} onclick="Sentinel.markOneRead('${n.notification_id}', this)">
              <div style="font-size:1.1rem; margin-top:2px;">${icon}</div>
              <div class="notif-body">
                <strong>${esc(n.title)}</strong>
                <p>${esc(n.message)}</p>
                <time>${fmtTime(n.created_at)}</time>
              </div>
            </li>
          `;
        }).join('');
      }

      // Update unread badge count from the count endpoint for reliability
      const countRes = await api('/notifications/unread-count');
      updateNotifBadge(countRes.count ?? unread);
    } catch (e) {
      console.warn('Failed to load notifications:', e);
    }
  }

  // 4. Mark single notification as read
  async function markOneRead(notifId, element) {
    try {
      await api('/notifications/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notification_ids: [notifId] }),
      });
      if (element) {
        element.classList.remove('unread');
        element.style.borderLeft = 'none';
      }
      const countRes = await api('/notifications/unread-count');
      updateNotifBadge(countRes.count);
    } catch (e) {
      console.warn('Failed to mark notification as read:', e);
    }
  }

  // 5. Mark all read
  async function markAllRead() {
    try {
      await api('/notifications/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notification_ids: null }),
      });
      await loadNotifications();
      updateNotifBadge(0);
    } catch (e) {
      console.warn('Failed to mark all as read:', e);
    }
  }

  // 8. Health check system
  async function checkHealth() {
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-label');
    if (!dot || !label) return;
    try {
      const res = await api('/health');
      if (res && res.success) {
        dot.className = 'status-dot online';
        const aiStatus = res.ai_status || {};
        const totalAIs = Object.keys(aiStatus).length || 8;
        const onlineAIs = Object.values(aiStatus).filter(Boolean).length;
        label.textContent = `${onlineAIs}/${totalAIs} AI Active`;
      } else {
        dot.className = 'status-dot offline';
        label.textContent = 'Degraded';
      }
    } catch (e) {
      dot.className = 'status-dot offline';
      label.textContent = 'SERVER OFFLINE';
    }
  }

  // Toggle notification panel utility
  function toggleNotifPanel() {
    const panel = document.getElementById('notif-panel');
    if (!panel) return;
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) {
      loadNotifications();
    }
  }

  // Standalone Toast notification for alerts (bottom-right stacking)
  function showToast(title, message, severity = 'MODERATE') {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${severity.toLowerCase()}`;
    toast.innerHTML = `
      <strong>${esc(title)}</strong>
      <p>${esc(message)}</p>
    `;
    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('visible');
    }, 50);

    setTimeout(() => {
      toast.classList.remove('visible');
      setTimeout(() => toast.remove(), 400);
    }, 5000);
  }

  // Export everything onto the global scope so inline scripts can access them
  const Sentinel = {
    API_BASE,
    esc,
    fmtTime,
    api,
    riskClass,
    severityDot,
    showPushToast,
    showToast,
    updateNotifBadge,
    connectWebSocket,
    loadNotifications,
    markOneRead,
    markAllRead,
    checkHealth,
    toggleNotifPanel
  };

  global.Sentinel = Sentinel;

  // Trigger immediate actions on load
  document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
    connectWebSocket();

    // Wire global click listener for mark all read if button exists
    const markAllBtn = document.getElementById('notif-mark-all');
    if (markAllBtn) {
      markAllBtn.addEventListener('click', markAllRead);
    }
  });

})(window);
