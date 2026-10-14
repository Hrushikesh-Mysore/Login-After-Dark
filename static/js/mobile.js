// ====================================================
// Security Guardian — Instagram Lite Controller
// ====================================================

document.addEventListener('DOMContentLoaded', () => {
  loadMobileData();
  initSSE();

  // Low-frequency 30s background safety sync (SSE provides instant push)
  setInterval(loadMobileData, 30000);

  // Request browser notification permission if available
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }

  // Register PWA Service Worker for standalone installability
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/static/sw.js')
      .then(reg => console.log('Guardian Lite Service Worker registered:', reg.scope))
      .catch(err => console.warn('Service Worker registration skipped:', err));
  }
});

let eventSource = null;

function initSSE() {
  if (!window.EventSource) return;

  eventSource = new EventSource('/api/events/stream');

  eventSource.onmessage = (e) => {
    try {
      const payload = JSON.parse(e.data);
      handleIncomingSSE(payload);
    } catch (err) {
      console.warn('SSE parse error:', err);
    }
  };

  eventSource.onerror = (err) => {
    console.warn('SSE connection interrupted, retrying in 5s...');
    if (eventSource) eventSource.close();
    setTimeout(initSSE, 5000);
  };
}

function handleIncomingSSE(evt) {
  const userSelect = document.getElementById('mobile-user-select');
  const currentUsername = userSelect ? userSelect.value : 'admin';

  if (evt.type === 'AUTH_LOG') {
    fetchFeedLogs(currentUsername);
  } else if (evt.type === 'NEW_DEVICE_ALERT') {
    if (evt.data.username === currentUsername) {
      fetchPendingAlerts(currentUsername);
      if (navigator.vibrate) navigator.vibrate([250, 100, 250]);
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification("🚨 Intrusion Alert: New Device!", {
          body: `Unrecognized device (${evt.data.device_name}) attempted access from ${evt.data.location}. Tap to review!`,
          icon: "/static/manifest.json"
        });
      }
    }
  } else if (evt.type === 'DEVICE_RESOLVED' || evt.type === 'DEVICE_ACTION') {
    fetchPendingAlerts(currentUsername);
    fetchUserDevices(currentUsername);
  } else if (evt.type === 'SHIFT_UPDATED') {
    fetchUserProfile(currentUsername);
  }
}

let currentActiveTab = 'tab-feed';

// Tab Switching (Feed, Alerts, Devices, Profile)
function switchMobileTab(tabId) {
  currentActiveTab = tabId;

  // Toggle tab panes
  document.querySelectorAll('.insta-tab-pane').forEach(el => el.classList.remove('active'));
  const targetPane = document.getElementById(tabId);
  if (targetPane) targetPane.classList.add('active');

  // Toggle bottom nav buttons
  document.querySelectorAll('.nav-tab-btn').forEach(btn => btn.classList.remove('active'));
  const btnMap = {
    'tab-feed': 'nav-btn-feed',
    'tab-alerts': 'nav-btn-alerts',
    'tab-devices': 'nav-btn-devices',
    'tab-profile': 'nav-btn-profile'
  };
  const activeBtn = document.getElementById(btnMap[tabId]);
  if (activeBtn) activeBtn.classList.add('active');
}

// Master Data Refresh
async function loadMobileData() {
  const userSelect = document.getElementById('mobile-user-select');
  const username = userSelect ? userSelect.value : 'admin';

  await Promise.all([
    fetchFeedLogs(username),
    fetchPendingAlerts(username),
    fetchUserDevices(username),
    fetchUserProfile(username)
  ]);
}

// ----------------------------------------------------
// 1. Live Security Feed (Instagram Post Style)
// ----------------------------------------------------
async function fetchFeedLogs(username) {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const logs = await res.json();
    const container = document.getElementById('feed-posts-container');
    if (!container) return;

    if (!logs || logs.length === 0) {
      container.innerHTML = `
        <div class="empty-feed-card">
          <div class="empty-icon">📡</div>
          <p>No authentication events recorded yet.</p>
        </div>
      `;
      return;
    }

    // Render latest 15 logs
    container.innerHTML = logs.slice(0, 15).map(log => {
      const classification = (log.classification || 'SAFE').toLowerCase();
      const badgeClass = `badge-${classification}`;
      const timeStr = log.timestamp ? log.timestamp.substring(11) : 'Just now';
      const city = log.city || 'Unknown';
      const country = log.country || 'Unknown';
      const isNight = (log.triggered_rules || []).some(r => r.code === 'AUTHORIZED_NIGHT_SHIFT');

      const chipsHtml = (log.triggered_rules || []).map(r => 
        `<span class="post-chip">⚡ ${escapeHtml(r.code)}</span>`
      ).join('');

      return `
        <div class="insta-post-card">
          <div class="post-header">
            <div class="post-user-info">
              <div class="post-avatar">${isNight ? '🦉' : '👤'}</div>
              <div>
                <div class="post-username">${escapeHtml(log.username)}</div>
                <div class="post-location">📍 ${escapeHtml(city)}, ${escapeHtml(country)}</div>
              </div>
            </div>
            <span class="post-time">${timeStr}</span>
          </div>

          <div class="post-body">
            <div class="post-status-row">
              <span class="post-badge ${badgeClass}">${log.classification || 'SAFE'}</span>
              <span class="post-risk" style="color: ${log.risk_score > 60 ? '#f87171' : (log.risk_score > 30 ? '#fbbf24' : '#34d399')}">
                Risk: ${log.risk_score}/100
              </span>
            </div>
            <div class="post-details">
              <b>Device:</b> ${escapeHtml(log.device_name || 'Browser')}<br>
              <b>IP:</b> <code>${escapeHtml(log.ip || '127.0.0.1')}</code>
            </div>
            ${chipsHtml ? `<div class="post-chips">${chipsHtml}</div>` : ''}
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Fetch feed error:', err);
  }
}

// ----------------------------------------------------
// 2. Pending Intrusion Alerts (Push Cards)
// ----------------------------------------------------
let lastKnownAlertCount = 0;

async function fetchPendingAlerts(username) {
  try {
    const res = await fetch(`/api/mobile/alerts?username=${username}`);
    if (!res.ok) return;
    const alerts = await res.json();

    const count = alerts.length;
    const countBadge = document.getElementById('pending-count');
    const navBadge = document.getElementById('nav-alert-badge');
    const storyBadge = document.getElementById('story-alert-badge');
    const storyRing = document.getElementById('story-alert-ring');
    const container = document.getElementById('alerts-container');

    if (countBadge) countBadge.textContent = count;
    if (storyBadge) storyBadge.textContent = count;

    if (navBadge) {
      navBadge.textContent = count;
      navBadge.style.display = count > 0 ? 'inline-block' : 'none';
    }

    if (storyRing) {
      if (count > 0) storyRing.classList.add('alert-ring');
      else storyRing.classList.remove('alert-ring');
    }

    // Trigger Notification & Haptic Feedback if new alert appeared
    if (count > lastKnownAlertCount && lastKnownAlertCount !== -1) {
      if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification("⚠️ Security Guardian Alert!", {
          body: `Unrecognized device attempting access for ${username}! Tap to review.`,
          icon: "/static/manifest.json"
        });
      }
    }
    lastKnownAlertCount = count;

    if (!container) return;

    if (alerts.length === 0) {
      container.innerHTML = `
        <div class="empty-alerts-card">
          <div class="check-icon">✓</div>
          <h4>All Devices Secured</h4>
          <p>No unrecognized devices attempting access for ${escapeHtml(username)}.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = alerts.map(a => `
      <div class="insta-alert-card">
        <div class="alert-top">
          <span class="alert-title-tag">🚨 NEW DEVICE SIGN-IN ATTEMPT</span>
          <span style="font-family:monospace; font-size:0.65rem; color:#94a3b8;">${escapeHtml(a.created_at || 'Just now')}</span>
        </div>

        <div class="alert-body-info">
          <b>Target Account:</b> ${escapeHtml(a.username)}<br>
          <b>Device Name:</b> ${escapeHtml(a.device_name)}<br>
          <b>Location:</b> 📍 ${escapeHtml(a.location)}<br>
          <b>IP Address:</b> <code>${escapeHtml(a.ip)}</code><br>
          <span style="color:#fca5a5; font-size:0.7rem; font-weight:600;">Did you just sign in from this device?</span>
        </div>

        <div class="alert-actions-grid">
          <button class="btn-insta-auth" onclick="handleMobileAlertAction(${a.id}, 'APPROVE')">
            ✓ Authorize & Trust
          </button>
          <button class="btn-insta-block" onclick="handleMobileAlertAction(${a.id}, 'BLOCK')">
            ✕ Block & Lock
          </button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Fetch alerts error:', err);
  }
}

async function handleMobileAlertAction(alertId, action) {
  try {
    const res = await fetch('/api/mobile/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId, action })
    });
    const data = await res.json();
    if (res.ok) {
      alert(`🛡️ Action Confirmed:\n\n${data.message}`);
      loadMobileData();
    } else {
      alert(`Error: ${data.error || 'Failed'}`);
    }
  } catch (err) {
    alert("Connection error executing action.");
  }
}

// ----------------------------------------------------
// 3. User Devices Hardware Inventory
// ----------------------------------------------------
async function fetchUserDevices(username) {
  try {
    const res = await fetch(`/api/devices?username=${username}`);
    if (!res.ok) return;
    const devices = await res.json();
    const container = document.getElementById('devices-list');
    if (!container) return;

    if (!devices || devices.length === 0) {
      container.innerHTML = `<p style="font-size:0.75rem; color:#94a3b8;">No registered devices.</p>`;
      return;
    }

    container.innerHTML = devices.map(d => {
      const isBlocked = d.is_blocked === 1;
      const isTrusted = d.is_trusted === 1;
      const statusText = isBlocked ? 'BLOCKED' : (isTrusted ? 'TRUSTED' : 'PENDING');
      const actionBtn = isBlocked
        ? `<button class="device-toggle-btn btn-trust-dev" onclick="setDeviceAction(${d.id}, 'TRUST')">Unblock</button>`
        : `<button class="device-toggle-btn btn-block-dev" onclick="setDeviceAction(${d.id}, 'BLOCK')">Block</button>`;

      return `
        <div class="device-card-item">
          <div class="device-info-col">
            <h4>${escapeHtml(d.device_name)}</h4>
            <div class="device-meta">
              ${escapeHtml(d.device_type)} • ${escapeHtml(d.browser)} on ${escapeHtml(d.os)}<br>
              <span style="color:${isBlocked ? '#f87171' : '#34d399'}; font-weight:700;">Status: ${statusText}</span>
            </div>
          </div>
          <div>${actionBtn}</div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Fetch devices error:', err);
  }
}

async function setDeviceAction(deviceId, action) {
  try {
    const res = await fetch('/api/devices/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, action })
    });
    if (res.ok) {
      loadMobileData();
    }
  } catch (err) {
    console.error('Device action error:', err);
  }
}

// ----------------------------------------------------
// 4. User Profile & Work Shift Settings
// ----------------------------------------------------
async function fetchUserProfile(username) {
  try {
    const res = await fetch('/api/users');
    if (!res.ok) return;
    const users = await res.json();
    const user = users.find(u => u.username === username);
    if (!user) return;

    const nameEl = document.getElementById('profile-username');
    const roleEl = document.getElementById('profile-role');
    const shiftBadge = document.getElementById('profile-shift-badge');
    const storyShiftIcon = document.getElementById('story-shift-icon');
    const storyShiftLabel = document.getElementById('story-shift-label');

    if (nameEl) nameEl.textContent = user.display_name || user.username;
    if (roleEl) roleEl.textContent = `${user.role || 'Analyst'} • @${user.username}`;

    let shiftText = `Day Shift (${user.shift_start_hour}:00 – ${user.shift_end_hour}:00)`;
    let icon = '☀️';

    if (user.shift_type === 'NIGHT') {
      shiftText = `🌙 Night Shift (${user.shift_start_hour}:00 – 07:00)`;
      icon = '🦉';
    } else if (user.shift_type === 'FLEX_247') {
      shiftText = `⚡ 24/7 Flex Clearance`;
      icon = '⚡';
    }

    if (shiftBadge) shiftBadge.textContent = shiftText;
    if (storyShiftIcon) storyShiftIcon.textContent = icon;
    if (storyShiftLabel) storyShiftLabel.textContent = user.shift_type;
  } catch (err) {
    console.error('Fetch profile error:', err);
  }
}

async function quickUpdateShift(shiftType, startHour, endHour) {
  const username = document.getElementById('mobile-user-select').value;
  try {
    const usersRes = await fetch('/api/users');
    const users = await usersRes.json();
    const user = users.find(u => u.username === username);
    if (!user) return;

    const res = await fetch('/api/users/shift', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: user.id,
        shift_type: shiftType,
        shift_start_hour: startHour,
        shift_end_hour: endHour
      })
    });

    if (res.ok) {
      alert(`⏰ Shift Updated Successfully!\n\n${username} is now registered under ${shiftType} (${startHour}:00 - ${endHour}:00).`);
      loadMobileData();
    }
  } catch (err) {
    alert("Failed to update shift schedule.");
  }
}

// ----------------------------------------------------
// 5. GPS Geolocation Pinpoint
// ----------------------------------------------------
function detectMobileGPS() {
  if (!navigator.geolocation) {
    alert("Geolocation is not supported by your phone browser.");
    return;
  }

  navigator.geolocation.getCurrentPosition(
    pos => {
      const lat = pos.coords.latitude;
      const lon = pos.coords.longitude;
      const acc = Math.round(pos.coords.accuracy || 10);

      const coordsEl = document.getElementById('mobile-gps-coords');
      const mapEl = document.getElementById('mobile-google-map');
      if (coordsEl) coordsEl.textContent = `📍 Lat: ${lat.toFixed(4)}°, Lon: ${lon.toFixed(4)}° (±${acc}m)`;
      if (mapEl) mapEl.src = `https://maps.google.com/maps?q=${lat},${lon}&hl=en&z=15&output=embed`;
    },
    err => {
      alert("⚠️ Phone location access was denied. Please allow location in your browser.");
    },
    { enableHighAccuracy: true, timeout: 8000 }
  );
}

async function handleLogout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.reload();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
