// ====================================================
// Security Guardian - Mobile Companion App Controller
// ====================================================

document.addEventListener('DOMContentLoaded', () => {
  loadMobileData();
  setInterval(loadMobileData, 3000);
});

async function loadMobileData() {
  const username = document.getElementById('mobile-user-select').value;
  await Promise.all([
    fetchPendingAlerts(username),
    fetchUserDevices(username)
  ]);
}

// Live Mobile GPS Tracking
function detectMobileGPS() {
  if (!navigator.geolocation) {
    alert("Geolocation is not supported by your phone browser.");
    return;
  }
  alert("🔐 Mobile Location Verification:\n\nRequesting your smartphone's live GPS coordinates to verify your location. Please tap Allow on the browser prompt.");

  navigator.geolocation.getCurrentPosition(
    pos => {
      const lat = pos.coords.latitude;
      const lon = pos.coords.longitude;
      const acc = Math.round(pos.coords.accuracy || 10);

      const coordsEl = document.getElementById('mobile-gps-coords');
      const mapEl = document.getElementById('mobile-google-map');
      if (coordsEl) coordsEl.textContent = `${lat.toFixed(4)}°, ${lon.toFixed(4)}° (±${acc}m)`;
      if (mapEl) mapEl.src = `https://maps.google.com/maps?q=${lat},${lon}&hl=en&z=15&output=embed`;
    },
    err => {
      console.warn("Mobile GPS error:", err);
      alert("⚠️ Phone location access was denied. Please enable Location Services in your mobile browser settings.");
    },
    { enableHighAccuracy: true, timeout: 8000 }
  );
}

// ----------------------------------------------------
// 1. Pending Intrusion Alerts
// ----------------------------------------------------
async function fetchPendingAlerts(username) {
  try {
    const res = await fetch(`/api/mobile/alerts?username=${username}`);
    if (!res.ok) return;
    const alerts = await res.json();

    const countBadge = document.getElementById('pending-count');
    const container = document.getElementById('alerts-container');
    countBadge.textContent = alerts.length;

    if (alerts.length === 0) {
      container.innerHTML = `
        <div class="empty-alerts-card">
          <div class="check-icon">✓</div>
          <h4>All Devices Secured</h4>
          <p>No unauthorized or unrecognized devices have attempted to access your account.</p>
        </div>
      `;
      return;
    }

    // Try triggering device vibration if supported (haptic feedback)
    if (navigator.vibrate) {
      navigator.vibrate([150, 100, 150]);
    }

    container.innerHTML = alerts.map(a => `
      <div class="active-alert-card">
        <div class="alert-card-header">
          <span class="alert-badge-danger">⚠️ SECURITY ALERT</span>
          <span class="alert-card-title">New Device Sign-In Attempt</span>
        </div>

        <div class="alert-card-body">
          <b>Target Account:</b> ${escapeHtml(a.username)}<br>
          <b>Device:</b> ${escapeHtml(a.device_name)}<br>
          <b>Location:</b> ${escapeHtml(a.location)}<br>
          <b>IP Address:</b> <code>${escapeHtml(a.ip)}</code><br>
          <span style="font-size:0.72rem; color:#fca5a5;">Was this you attempting to log in?</span>
        </div>

        <div class="alert-card-actions">
          <button class="mobile-action-btn btn-mobile-approve" onclick="handleMobileAlertAction(${a.id}, 'APPROVE')">
            ✓ Authorize & Trust
          </button>
          <button class="mobile-action-btn btn-mobile-block" onclick="handleMobileAlertAction(${a.id}, 'BLOCK')">
            ✕ Block & Lock
          </button>
        </div>
      </div>
    `).join('');
  } catch (e) {
    console.error('Fetch alerts error:', e);
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
    alert(data.message || 'Action executed.');
    loadMobileData();
  } catch (e) {
    console.error('Alert action error:', e);
  }
}

// ----------------------------------------------------
// 2. User Registered Devices
// ----------------------------------------------------
async function fetchUserDevices(username) {
  try {
    const res = await fetch(`/api/devices?username=${username}`);
    if (!res.ok) return;
    const devices = await res.json();

    const list = document.getElementById('devices-list');
    if (!devices || devices.length === 0) {
      list.innerHTML = `<div style="color:var(--text-dim); font-size:0.72rem; text-align:center; padding:12px;">No devices registered yet.</div>`;
      return;
    }

    list.innerHTML = devices.map(d => {
      const isBlocked = d.is_blocked === 1;
      const isTrusted = d.is_trusted === 1 && !isBlocked;

      let statusBadge = `<span style="color:#34d399; font-size:0.68rem; font-weight:600;">✓ Trusted</span>`;
      if (isBlocked) statusBadge = `<span style="color:#f87171; font-size:0.68rem; font-weight:600;">🚫 Blocked</span>`;
      else if (!isTrusted) statusBadge = `<span style="color:#fbbf24; font-size:0.68rem; font-weight:600;">⚠️ Pending</span>`;

      const actionBtn = isBlocked
        ? `<button class="btn-dev-action btn-dev-trust" onclick="toggleDeviceTrust(${d.id}, 'TRUST')">Unblock</button>`
        : `<button class="btn-dev-action btn-dev-block" onclick="toggleDeviceTrust(${d.id}, 'BLOCK')">Block</button>`;

      return `
        <div class="device-item-card">
          <div class="device-item-info">
            <h5>${escapeHtml(d.device_name)}</h5>
            <span>${escapeHtml(d.browser)} • ${escapeHtml(d.os)}</span><br>
            ${statusBadge}
          </div>
          <div class="device-item-actions">
            ${actionBtn}
          </div>
        </div>
      `;
    }).join('');
  } catch (e) {
    console.error('Fetch devices error:', e);
  }
}

async function toggleDeviceTrust(deviceId, action) {
  try {
    await fetch('/api/devices/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, action })
    });
    loadMobileData();
  } catch (e) {
    console.error('Toggle device trust error:', e);
  }
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
