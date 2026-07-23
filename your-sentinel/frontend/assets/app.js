/**
 * YOUR SENTINEL v8.0 — Shared frontend utilities
 * API_BASE detection, WebSocket, push toasts, notification badge, helpers
 */

(function (global) {
  'use strict';

  const isLocal =
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1';
  const API_BASE = isLocal
    ? 'http://localhost:8000'
    : window.location.origin;

  const WS_URL = (API_BASE.replace(/^http/, 'ws')) + '/ws/notifications';

  let ws = null;
  let wsReconnectTimer = null;
  let unreadCount = 0;

  function esc(str) {
    if (str == null) return '';
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function fmtTime(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      return d.toLocaleString('en-IN', {
        day: '2-digit',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return String(iso);
    }
  }

  async function api(path, options = {}) {
    const url = API_BASE + path;
    const res = await fetch(url, options);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || err.message || res.statusText);
    }
    return res.json();
  }

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

  function severityDot(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'dot-critical';
    if (s === 'HIGH') return 'dot-high';
    if (s === 'MODERATE') return 'dot-moderate';
    return 'dot-low';
  }

  /* ---- Toast notifications ---- */
  function showToast(title, message, severity = 'MODERATE') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${severity.toLowerCase()}`;
    toast.innerHTML =
      '<strong>' + esc(title) + '</strong><p>' + esc(message) + '</p>';
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 400);
    }, 6000);
  }

  /* ---- Badge ---- */
  function updateBadge(count) {
    unreadCount = count;
    const badge = document.getElementById('notif-badge');
    if (!badge) return;
    if (count > 0) {
      badge.textContent = count > 99 ? '99+' : String(count);
      badge.hidden = false;
    } else {
      badge.hidden = true;
    }
  }

  async function refreshUnreadCount() {
    try {
      const res = await api('/notifications/unread-count');
      updateBadge(res.count || 0);
    } catch (e) {
      console.warn('unread count', e);
    }
  }

  /* ---- Notification panel ---- */
  async function loadNotifications() {
    const list = document.getElementById('notif-list');
    if (!list) return;
    try {
      const res = await api('/notifications?limit=30');
      list.innerHTML = '';
      if (!res.data || !res.data.length) {
        list.innerHTML = '<li class="notif-empty">No notifications yet</li>';
        return;
      }
      res.data.forEach((n) => {
        const li = document.createElement('li');
        li.className = 'notif-item' + (n.is_read ? '' : ' unread');
        li.dataset.id = n.notification_id;
        li.innerHTML =
          '<span class="notif-sev ' +
          severityDot(n.severity) +
          '"></span>' +
          '<div class="notif-body">' +
          '<strong>' +
          esc(n.title) +
          '</strong>' +
          '<p>' +
          esc(n.message) +
          '</p>' +
          '<time>' +
          fmtTime(n.created_at) +
          '</time></div>';
        li.addEventListener('click', () => markOneRead(n.notification_id, li));
        list.appendChild(li);
      });
    } catch (e) {
      list.innerHTML = '<li class="notif-empty">Failed to load</li>';
    }
  }

  async function markOneRead(id, el) {
    try {
      await api('/notifications/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notification_ids: [id] }),
      });
      if (el) el.classList.remove('unread');
      refreshUnreadCount();
    } catch (e) {
      console.warn(e);
    }
  }

  async function markAllRead() {
    try {
      await api('/notifications/mark-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      refreshUnreadCount();
      loadNotifications();
    } catch (e) {
      console.warn(e);
    }
  }

  function toggleNotifPanel() {
    const panel = document.getElementById('notif-panel');
    if (!panel) return;
    const open = panel.classList.toggle('open');
    if (open) loadNotifications();
  }

  /* ---- WebSocket ---- */
  function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;
    try {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        console.log('WS connected');
        if (wsReconnectTimer) {
          clearInterval(wsReconnectTimer);
          wsReconnectTimer = null;
        }
        setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) ws.send('ping');
        }, 25000);
      };
      ws.onmessage = (ev) => {
        if (ev.data === 'pong') return;
        try {
          const msg = JSON.parse(ev.data);
          if (msg.event === 'notification' && msg.data) {
            showToast(msg.data.title, msg.data.message, msg.data.severity);
            refreshUnreadCount();
          }
        } catch (e) {
          console.warn('WS parse', e);
        }
      };
      ws.onclose = () => {
        ws = null;
        if (!wsReconnectTimer) {
          wsReconnectTimer = setInterval(connectWebSocket, 5000);
        }
      };
      ws.onerror = () => ws?.close();
    } catch (e) {
      console.warn('WS connect failed', e);
    }
  }

  /* ---- Health status dot ---- */
  async function checkHealth() {
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-label');
    try {
      const res = await api('/health');
      if (dot) {
        dot.className = 'status-dot online';
      }
      if (label) label.textContent = res.status === 'healthy' ? 'Online' : 'Degraded';
    } catch {
      if (dot) dot.className = 'status-dot offline';
      if (label) label.textContent = 'Offline';
    }
  }

  global.Sentinel = {
    API_BASE,
    api,
    esc,
    fmtTime,
    riskClass,
    severityDot,
    showToast,
    updateBadge,
    refreshUnreadCount,
    loadNotifications,
    markAllRead,
    toggleNotifPanel,
    connectWebSocket,
    checkHealth,
  };

  document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    refreshUnreadCount();
    checkHealth();
    setInterval(checkHealth, 60000);

    const bell = document.getElementById('notif-bell');
    if (bell) bell.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleNotifPanel();
    });

    const markAll = document.getElementById('notif-mark-all');
    if (markAll) markAll.addEventListener('click', markAllRead);

    document.addEventListener('click', (e) => {
      const panel = document.getElementById('notif-panel');
      if (panel && panel.classList.contains('open')) {
        if (!panel.contains(e.target) && e.target.id !== 'notif-bell') {
          panel.classList.remove('open');
        }
      }
    });
  });
})(window);
