// Coordinates dictionary for free Google Maps integration
const CITY_COORDS = {
  "New York": { lat: 40.7128, lon: -74.0060, label: "New York, USA (Corporate HQ)" },
  "London": { lat: 51.5074, lon: -0.1278, label: "London, UK (Europe Branch)" },
  "Tokyo": { lat: 35.6762, lon: 139.6503, label: "Tokyo, Japan (APAC Office)" },
  "Frankfurt": { lat: 50.1109, lon: 8.6821, label: "Frankfurt, Germany (Tor Exit)" },
  "Moscow": { lat: 55.7558, lon: 37.6173, label: "Moscow, Russia (High-Risk IP)" },
  "Sydney": { lat: -33.8688, lon: 151.2093, label: "Sydney, Australia (Remote Hub)" }
};

let realUserGPS = null;

document.addEventListener('DOMContentLoaded', () => {
  initMap();
  refreshAll();
  setInterval(refreshAll, 4000);

  // Setup city dropdown sync with Google Maps
  const citySelect = document.getElementById('sim-city-select');
  if (citySelect) {
    citySelect.addEventListener('change', () => {
      const city = citySelect.value;
      if (CITY_COORDS[city]) {
        updateGoogleDeviceMap(CITY_COORDS[city].lat, CITY_COORDS[city].lon, CITY_COORDS[city].label, "Baseline Selected");
      }
    });
  }

  // Update phone simulator clock
  setInterval(updatePhoneClock, 1000);
  updatePhoneClock();
});

function updatePhoneClock() {
  const clock = document.getElementById('phone-clock');
  if (clock) {
    const d = new Date();
    clock.textContent = d.toTimeString().substring(0, 5);
  }
}

function getLiveCoordinates() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation unsupported"));
      return;
    }
    navigator.geolocation.getCurrentPosition(
      pos => resolve(pos),
      err => reject(err),
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 0 }
    );
  });
}

// ------------------------------------------------------------------
// 1. Google Maps Device Location Controller (Below Login Div)
// ------------------------------------------------------------------
function updateGoogleDeviceMap(lat, lon, label, statusText, statusClass = 'val-safe', accuracyText = null) {
  const mapFrame = document.getElementById('google-maps-frame');
  const targetName = document.getElementById('geo-target-name');
  const coordsLabel = document.getElementById('geo-coords');
  const statusLabel = document.getElementById('geo-device-status');
  const accuracyLabel = document.getElementById('geo-accuracy');

  if (mapFrame) {
    mapFrame.src = `https://maps.google.com/maps?q=${lat},${lon}&hl=en&z=14&output=embed`;
  }
  if (targetName) targetName.textContent = label;
  if (coordsLabel) {
    const latStr = `${Math.abs(lat).toFixed(4)}° ${lat >= 0 ? 'N' : 'S'}`;
    const lonStr = `${Math.abs(lon).toFixed(4)}° ${lon >= 0 ? 'E' : 'W'}`;
    coordsLabel.textContent = `${latStr}, ${lonStr}`;
  }
  if (statusLabel) {
    statusLabel.textContent = statusText;
    statusLabel.className = `geo-stat-val ${statusClass}`;
  }
  if (accuracyLabel && accuracyText) {
    accuracyLabel.textContent = accuracyText;
  }
}

async function detectRealDeviceLocation() {
  const btn = document.querySelector('.btn-locate-gps');
  if (btn) btn.innerHTML = '🛰️ Pinpointing GPS...';

  alert("🔐 Device Location Verification:\n\nRequesting your physical device location (laptop, computer, or mobile). Click OK to grant browser permission.");

  try {
    const pos = await getLiveCoordinates();
    const lat = pos.coords.latitude;
    const lon = pos.coords.longitude;
    const acc = Math.round(pos.coords.accuracy || 10);
    realUserGPS = { lat, lon };
    updateGoogleDeviceMap(lat, lon, "Your Physical Device (GPS)", "Live GPS Locked", "val-safe", `±${acc}m accuracy`);
    if (btn) btn.innerHTML = '✓ GPS Locked';
  } catch (err) {
    console.warn("GPS error:", err);
    alert("⚠️ Browser location permission was denied or unavailable. Fallback to network baseline.");
    if (btn) btn.innerHTML = '🎯 Locate My Device';
  }
}

// ------------------------------------------------------------------
// 2. Leaflet Fallback (If Active)
// ------------------------------------------------------------------
function initMap() {
  // Leaflet initialization retained for seamless background compatibility
}

function plotMapMarker(lat, lon, city, country, risk, classification, user, ip) {
  // Update Google Maps directly below login card
  let statusClass = 'val-safe';
  if (classification === 'CRITICAL') statusClass = 'val-critical';
  else if (classification === 'SUSPICIOUS') statusClass = 'val-suspicious';

  updateGoogleDeviceMap(lat, lon, `${city}, ${country}`, `${classification} Threat (${risk}/100)`, statusClass);
}

// ------------------------------------------------------------------
// 2. Data Synchronization & Fetching
// ------------------------------------------------------------------
async function refreshAll() {
  await Promise.all([
    fetchStats(),
    fetchLogs(),
    fetchDevices(),
    fetchShifts(),
    fetchMobileAlerts()
  ]);
}

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const stats = await res.json();

    document.getElementById('stat-total').textContent = stats.total_attempts || 0;
    document.getElementById('stat-suspicious').textContent = stats.suspicious_count || 0;
    document.getElementById('stat-critical').textContent = stats.critical_count || 0;
    document.getElementById('stat-alerts').textContent = stats.pending_alerts || 0;
    document.getElementById('stat-devices').textContent = stats.total_devices || 0;
    document.getElementById('header-alert-count').textContent = stats.pending_alerts || 0;
  } catch (err) {
    console.error('Stats error:', err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const logs = await res.json();
    renderLogsTable(logs);
  } catch (err) {
    console.error('Logs error:', err);
  }
}

function renderLogsTable(logs) {
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;

  if (!logs || logs.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No logs recorded yet. Run a simulation or submit a login.</td></tr>`;
    return;
  }

  tbody.innerHTML = logs.map(entry => {
    const authBadge = entry.auth_success
      ? `<span class="badge badge-auth-success">SUCCESS</span>`
      : `<span class="badge badge-auth-failed">FAILED</span>`;

    const threatClass = (entry.classification || 'SAFE').toLowerCase();
    const threatBadge = `<span class="badge badge-threat-${threatClass}">${entry.classification}</span>`;

    const chips = (entry.triggered_rules || []).map(r => {
      let icon = '⚡';
      if (r.code === 'SHIFT_VIOLATION' || r.code === 'UNUSUAL_HOURS') icon = '🌙';
      if (r.code === 'AUTHORIZED_NIGHT_SHIFT') icon = '🦉';
      if (r.code === 'NEW_DEVICE_DETECTED') icon = '📱';
      if (r.code === 'IMPOSSIBLE_TRAVEL') icon = '✈️';
      if (r.code === 'BRUTE_FORCE') icon = '⚔️';
      if (r.code === 'BLOCKED_DEVICE') icon = '🚫';

      const isSafe = r.code === 'AUTHORIZED_NIGHT_SHIFT';
      return `<span class="rule-flag-chip ${isSafe ? 'rule-chip-safe' : ''}" title="${escapeHtml(r.description)}">${icon} ${escapeHtml(r.code)}</span>`;
    }).join(' ');

    return `
      <tr>
        <td style="font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(entry.timestamp.substring(11))}</td>
        <td style="font-weight:600; color:#fff;">${escapeHtml(entry.username)}</td>
        <td>${escapeHtml(entry.city)}, ${escapeHtml(entry.country)}</td>
        <td style="font-size:0.7rem; color:var(--text-dim);">${escapeHtml(entry.device_name || 'Browser')}</td>
        <td>${authBadge}</td>
        <td>${threatBadge}</td>
        <td style="font-family:var(--font-mono); font-weight:600;">${entry.risk_score}/100</td>
        <td>${chips || '<span style="color:var(--text-dim);font-size:0.68rem;">✓ Standard baseline</span>'}</td>
      </tr>
    `;
  }).join('');
}

// ------------------------------------------------------------------
// 3. Multi-Device Inventory Management
// ------------------------------------------------------------------
async function fetchDevices() {
  try {
    const res = await fetch('/api/devices');
    if (!res.ok) return;
    const devices = await res.json();
    renderDevicesTable(devices);
  } catch (err) {
    console.error('Devices error:', err);
  }
}

function renderDevicesTable(devices) {
  const tbody = document.getElementById('devices-tbody');
  if (!tbody) return;

  if (!devices || devices.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No registered devices.</td></tr>`;
    return;
  }

  tbody.innerHTML = devices.map(d => {
    const status = d.is_blocked
      ? `<span class="badge badge-threat-critical">BLOCKED</span>`
      : (d.is_trusted ? `<span class="badge badge-threat-safe">TRUSTED</span>` : `<span class="badge badge-threat-suspicious">PENDING</span>`);

    const toggleAction = d.is_blocked
      ? `<button class="chip" style="color:#34d399;" onclick="setDeviceAction(${d.id}, 'TRUST')">Unblock</button>`
      : `<button class="chip chip-fail" onclick="setDeviceAction(${d.id}, 'BLOCK')">Block Device</button>`;

    return `
      <tr>
        <td style="font-weight:600; color:#fff;">${escapeHtml(d.username || 'User')}</td>
        <td>${escapeHtml(d.device_name)}</td>
        <td>${escapeHtml(d.device_type)}</td>
        <td style="color:var(--text-muted);">${escapeHtml(d.browser)} / ${escapeHtml(d.os)}</td>
        <td style="font-family:var(--font-mono); font-size:0.65rem; color:var(--text-dim);">${escapeHtml(d.device_fingerprint)}</td>
        <td>${status}</td>
        <td>${toggleAction}</td>
      </tr>
    `;
  }).join('');
}

async function setDeviceAction(deviceId, action) {
  try {
    await fetch('/api/devices/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, action })
    });
    refreshAll();
  } catch (e) {
    console.error(e);
  }
}

// ------------------------------------------------------------------
// 4. Employee Shift & Schedule Policy Manager
// ------------------------------------------------------------------
async function fetchShifts() {
  try {
    const res = await fetch('/api/users');
    if (!res.ok) return;
    const users = await res.json();
    renderShiftsGrid(users);
  } catch (err) {
    console.error('Shifts error:', err);
  }
}

function renderShiftsGrid(users) {
  const container = document.getElementById('shifts-grid');
  if (!container) return;

  container.innerHTML = users.map(u => {
    let badgeClass = 'shift-badge-day';
    if (u.shift_type === 'NIGHT') badgeClass = 'shift-badge-night';
    if (u.shift_type === 'FLEX_247') badgeClass = 'shift-badge-flex';

    return `
      <div class="shift-user-card">
        <div class="shift-user-header">
          <div>
            <span class="shift-user-name">${escapeHtml(u.display_name || u.username)}</span>
            <div style="font-size:0.68rem; color:var(--text-dim);">@${escapeHtml(u.username)} • ${escapeHtml(u.role)}</div>
          </div>
          <span class="${badgeClass}">${escapeHtml(u.shift_type)}</span>
        </div>

        <div class="shift-inputs">
          <select id="shift-type-${u.id}">
            <option value="DAY" ${u.shift_type === 'DAY' ? 'selected' : ''}>Day (09:00 - 18:00)</option>
            <option value="NIGHT" ${u.shift_type === 'NIGHT' ? 'selected' : ''}>Night-Shift (22:00 - 07:00)</option>
            <option value="FLEX_247" ${u.shift_type === 'FLEX_247' ? 'selected' : ''}>24/7 Flex (All Hours)</option>
          </select>
          <button class="save-shift-btn" onclick="saveUserShift(${u.id})">Save Policy</button>
        </div>
      </div>
    `;
  }).join('');
}

async function saveUserShift(userId) {
  const typeSelect = document.getElementById(`shift-type-${userId}`);
  const shiftType = typeSelect.value;
  let start = 9, end = 18;
  if (shiftType === 'NIGHT') { start = 22; end = 7; }
  if (shiftType === 'FLEX_247') { start = 0; end = 24; }

  try {
    await fetch('/api/users/shift', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        shift_type: shiftType,
        shift_start_hour: start,
        shift_end_hour: end
      })
    });
    alert('Shift schedule updated! The detection engine will now respect this employee\'s hours.');
    refreshAll();
  } catch (e) {
    console.error(e);
  }
}

// ------------------------------------------------------------------
// 5. Interactive Login Submission & Anomaly Testing
// ------------------------------------------------------------------
async function handleLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  const origText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-text">INSPECTING BEHAVIOR...</span>';

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const city = document.getElementById('sim-city-select').value;
  const devSelect = document.getElementById('sim-device-select').value;
  const timeSelect = document.getElementById('sim-time-select').value;
  const simulatedHour = timeSelect === 'real' ? null : parseInt(timeSelect, 10);
  const requireGPS = document.getElementById('require-live-gps')?.checked;

  // Real-time Device Detection (Laptop/Desktop vs Smartphone)
  const isMobileClient = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
  let detectedType = isMobileClient ? "Mobile" : "Desktop";
  let detectedBrowser = navigator.userAgent.includes("Chrome") ? "Chrome" : (navigator.userAgent.includes("Firefox") ? "Firefox" : "Safari");
  let detectedOS = navigator.platform || (isMobileClient ? "Mobile OS" : "Desktop OS");

  // Device Profile Based on Selector
  let device_fp = "fp-admin-workstation-lin-01";
  let device_name = `${detectedType} (${detectedBrowser})`;
  let device_type = detectedType;
  let browser = detectedBrowser;
  let os = detectedOS;

  if (devSelect === 'known_admin') {
    device_fp = "fp-admin-workstation-lin-01";
    device_name = "Admin Primary Workstation";
  } else if (devSelect === 'known_night') {
    device_fp = "fp-night-laptop-mac-01";
    device_name = "Night Owl Ops MacBook";
    os = "macOS Sonoma";
  } else if (devSelect === 'unrecognized_pc') {
    device_fp = `fp-unrecognized-laptop-${Math.floor(Math.random() * 9000 + 1000)}`;
    device_name = "Alienware Linux (Unrecognized)";
    browser = "Firefox 124";
  } else if (devSelect === 'unrecognized_phone') {
    device_fp = `fp-mobile-android-${Math.floor(Math.random() * 9000 + 1000)}`;
    device_name = "Samsung Galaxy S24 (Unregistered)";
    device_type = "Mobile";
    os = "Android 14";
  }

  // --- LIVE LOCATION ACQUISITION WITH PERMISSION ALERT ---
  let activeLat = null;
  let activeLon = null;
  let cityReporting = city;

  if (city === 'LIVE_GPS' || requireGPS) {
    // Alert prompt to user as required
    alert("🔐 Live Location Security Check:\n\nWe need your live device location (laptop, computer, or mobile) to verify login authenticity.\n\nPlease grant location permission when prompted by your browser.");

    try {
      const pos = await getLiveCoordinates();
      activeLat = pos.coords.latitude;
      activeLon = pos.coords.longitude;
      const acc = Math.round(pos.coords.accuracy || 10);
      cityReporting = `Live Device GPS (${activeLat.toFixed(3)}, ${activeLon.toFixed(3)})`;
      
      updateGoogleDeviceMap(activeLat, activeLon, "Your Real Device (Live GPS)", "Live Location Verified", "val-safe", `±${acc}m accuracy`);
    } catch (gpsErr) {
      console.warn("Live GPS error:", gpsErr);
      alert("⚠️ Notice: Location permission was not granted or GPS unavailable. Proceeding with network/IP baseline fallback.");
      if (CITY_COORDS[city]) {
        activeLat = CITY_COORDS[city].lat;
        activeLon = CITY_COORDS[city].lon;
      }
    }
  } else if (CITY_COORDS[city]) {
    activeLat = CITY_COORDS[city].lat;
    activeLon = CITY_COORDS[city].lon;
  }

  // Choose representative IP
  let ip = "192.168.1.105";
  if (city === "Frankfurt") ip = "185.220.101.5"; // Known Tor
  if (city === "Moscow") ip = "203.0.113.88"; // Threat

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        ip,
        city: cityReporting,
        lat: activeLat,
        lon: activeLon,
        device_fingerprint: device_fp,
        device_name,
        device_type,
        browser,
        os,
        simulated_hour: simulatedHour
      })
    });

    const data = await res.json();
    renderAssessment(data, res.status);

    if (data.evaluation && data.evaluation.location) {
      const loc = data.evaluation.location;
      plotMapMarker(loc.lat, loc.lon, loc.city, loc.country, data.evaluation.risk_score, data.evaluation.classification, username, ip);
    }

    refreshAll();
  } catch (err) {
    console.error('Login error:', err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = origText;
  }
}

function renderAssessment(data, httpStatus) {
  const container = document.getElementById('assessment-container');
  const verdictTag = document.getElementById('verdict-tag');
  const verdictScore = document.getElementById('verdict-score');
  const msgEl = document.getElementById('assessment-msg');
  const listEl = document.getElementById('triggered-list');

  const evalData = data.evaluation || {};
  const classification = evalData.classification || (httpStatus === 200 ? 'SAFE' : 'SUSPICIOUS');
  const score = evalData.risk_score || 0;
  const rules = evalData.triggered_rules || [];

  verdictTag.textContent = classification;
  verdictTag.className = `verdict-tag badge-threat-${classification.toLowerCase()}`;
  verdictScore.textContent = `Score: ${score}/100`;
  msgEl.textContent = data.message;

  if (rules.length > 0) {
    listEl.innerHTML = rules.map(r => `
      <div class="rule-alert-item severity-${r.severity}">
        <strong>${escapeHtml(r.name)} [${r.severity}]</strong>
        <span>${escapeHtml(r.description)}</span>
      </div>
    `).join('');
  } else {
    listEl.innerHTML = `
      <div style="font-size:0.72rem; color:var(--safe-green); margin-top:2px;">
        ✓ Zero behavioral anomalies detected. Verified legitimate access.
      </div>
    `;
  }

  container.className = 'assessment-container visible';
}

// ------------------------------------------------------------------
// 6. Mobile Phone Simulator (Embedded Widget)
// ------------------------------------------------------------------
function toggleMobileSimulator() {
  const sim = document.getElementById('mobile-phone-simulator');
  const label = document.getElementById('toggle-sim-label');
  if (sim.classList.contains('active')) {
    sim.classList.remove('active');
    label.textContent = 'Show Mobile Simulator';
  } else {
    sim.classList.add('active');
    label.textContent = 'Hide Mobile Simulator';
    fetchMobileAlerts();
  }
}

let activeAlertId = null;

async function fetchMobileAlerts() {
  const userSelect = document.getElementById('phone-user-select');
  const username = userSelect ? userSelect.value : 'admin';

  try {
    const res = await fetch(`/api/mobile/alerts?username=${username}`);
    if (!res.ok) return;
    const alerts = await res.json();

    const card = document.getElementById('phone-alert-card');
    const details = document.getElementById('alert-details');
    const actions = document.getElementById('alert-actions');

    if (alerts.length > 0) {
      const topAlert = alerts[0];
      activeAlertId = topAlert.id;
      card.classList.add('ringing');
      details.innerHTML = `
        <strong>⚠️ Unrecognized Device Attempt</strong><br>
        <b>Device:</b> ${escapeHtml(topAlert.device_name)}<br>
        <b>Location:</b> ${escapeHtml(topAlert.location)}<br>
        <b>IP:</b> ${escapeHtml(topAlert.ip)}<br>
        <span style="color:#f87171;font-size:0.65rem;">Did you just attempt to sign in?</span>
      `;
      actions.style.display = 'flex';
    } else {
      activeAlertId = null;
      card.classList.remove('ringing');
      details.textContent = 'No active security alerts for this user. System secure.';
      actions.style.display = 'none';
    }
  } catch (e) {
    console.error('Mobile alerts error:', e);
  }
}

async function resolveMobileAlert(action) {
  if (!activeAlertId) return;

  try {
    await fetch('/api/mobile/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: activeAlertId, action })
    });
    alert(action === 'APPROVE' ? 'Device Authorized and added to trusted devices!' : 'Intruder Device Blocked!');
    fetchMobileAlerts();
    refreshAll();
  } catch (e) {
    console.error(e);
  }
}

// ------------------------------------------------------------------
// 7. Preset Attack & Feature Simulations
// ------------------------------------------------------------------
async function simulateScenario(scenario) {
  try {
    const res = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });

    const data = await res.json();
    if (data.result) {
      renderAssessment({
        status: data.result.auth_success ? 'success' : 'failed',
        message: data.result.details,
        evaluation: {
          risk_score: data.result.risk_score,
          classification: data.result.classification,
          triggered_rules: data.result.triggered_rules,
          location: { lat: data.result.lat, lon: data.result.lon, city: data.result.city, country: data.result.country }
        }
      }, data.result.auth_success ? 200 : 401);

      plotMapMarker(data.result.lat, data.result.lon, data.result.city, data.result.country, data.result.risk_score, data.result.classification, data.result.username, data.result.ip);
    }
    refreshAll();
  } catch (err) {
    console.error('Simulation error:', err);
  }
}

async function clearAllData() {
  if (!confirm('Clear all SQLite authentication logs and mobile alerts?')) return;
  try {
    await fetch('/api/clear', { method: 'POST' });
    document.getElementById('assessment-container').className = 'assessment-container';
    refreshAll();
  } catch (e) {
    console.error(e);
  }
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
function fillCreds(u, p) {
  document.getElementById('username').value = u;
  document.getElementById('password').value = p;
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  event.currentTarget.classList.add('active');
  const target = document.getElementById(tabId);
  if (target) target.classList.add('active');
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
