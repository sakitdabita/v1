// State management
let state = {
  authenticated: false,
  username: null,
  profile: null,
  loading: true,
};

// Check session on load
async function checkSession() {
  try {
    const response = await fetch('/api/session');
    const data = await response.json();
    state.authenticated = data.authenticated;
    state.username = data.username;
    state.loading = false;
    render();
  } catch (error) {
    console.error('Session check failed:', error);
    state.loading = false;
    render();
  }
}

// Login
async function login(username) {
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const data = await response.json();
    if (data.success) {
      state.authenticated = true;
      state.username = data.username;
      render();
    } else {
      alert(data.error || 'Login failed');
    }
  } catch (error) {
    alert('Login failed: ' + error.message);
  }
}

// Logout
async function logout() {
  try {
    await fetch('/api/logout', { method: 'POST' });
    state.authenticated = false;
    state.username = null;
    state.profile = null;
    render();
  } catch (error) {
    alert('Logout failed: ' + error.message);
  }
}

// Fetch profile
async function fetchProfile() {
  try {
    const response = await fetch('/api/profile');
    if (response.ok) {
      state.profile = await response.json();
      render();
    } else {
      alert('Failed to fetch profile');
    }
  } catch (error) {
    alert('Failed to fetch profile: ' + error.message);
  }
}

// Threat lookup
async function threatLookup(provider, type, value) {
  try {
    const response = await fetch('/api/threat-lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, type, value }),
    });
    const data = await response.json();
    return data;
  } catch (error) {
    return { status: 'error', error: error.message };
  }
}

// Health check - outbound
async function healthOutbound(target) {
  try {
    const response = await fetch(`/api/health/outbound?target=${encodeURIComponent(target)}`);
    const data = await response.json();
    return data;
  } catch (error) {
    return { status: 'error', error: error.message };
  }
}

// Health check - internal
async function healthInternal() {
  try {
    const response = await fetch('/api/health/internal');
    const data = await response.json();
    return data;
  } catch (error) {
    return { status: 'error', error: error.message };
  }
}

// Render functions
function renderLoginCard() {
  return `
    <div class="max-w-md mx-auto mt-20">
      <div class="bg-white shadow-lg rounded-lg p-8">
        <h2 class="text-2xl font-bold mb-6 text-center text-gray-800">Security Dashboard Login</h2>
        <form onsubmit="handleLogin(event)" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Username</label>
            <input 
              type="text" 
              id="username" 
              class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter username"
              required
            />
          </div>
          <button 
            type="submit"
            class="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Login
          </button>
        </form>
        <p class="mt-4 text-sm text-gray-600 text-center">Demo mode - enter any username</p>
      </div>
    </div>
  `;
}

function renderDashboard() {
  return `
    <div class="max-w-7xl mx-auto">
      <!-- Header -->
      <div class="bg-white shadow-sm rounded-lg p-6 mb-6">
        <div class="flex justify-between items-center">
          <div>
            <h1 class="text-3xl font-bold text-gray-800">Security Dashboard</h1>
            <p class="text-gray-600 mt-1">Welcome, ${state.username}</p>
          </div>
          <button 
            onclick="handleLogout()"
            class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
          >
            Logout
          </button>
        </div>
      </div>

      <!-- Profile Card -->
      <div class="bg-white shadow-sm rounded-lg p-6 mb-6">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-xl font-semibold text-gray-800">Profile</h2>
          <button 
            onclick="handleFetchProfile()"
            class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors text-sm"
          >
            Load Profile
          </button>
        </div>
        <div id="profile-content">
          ${state.profile ? renderProfile() : '<p class="text-gray-500">Click "Load Profile" to view your profile details</p>'}
        </div>
      </div>

      <!-- Threat Lookup -->
      <div class="bg-white shadow-sm rounded-lg p-6 mb-6">
        <h2 class="text-xl font-semibold text-gray-800 mb-4">Threat Intelligence Lookup</h2>
        <form onsubmit="handleThreatLookup(event)" class="space-y-4">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">Provider</label>
              <select 
                id="provider" 
                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="virustotal">VirusTotal (Very High)</option>
                <option value="threatfox">ThreatFox (High)</option>
                <option value="otx">OTX/LevelBlue (Medium)</option>
                <option value="abuseipdb">AbuseIPDB (High, IP only)</option>
                <option value="ibm-xforce">IBM X-Force (Medium)</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">Type</label>
              <select 
                id="lookup-type" 
                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="hash">File Hash</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">Value</label>
              <input 
                type="text" 
                id="lookup-value" 
                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                placeholder="e.g., 8.8.8.8"
                required
              />
            </div>
          </div>
          <button 
            type="submit"
            class="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 transition-colors"
          >
            Lookup
          </button>
        </form>
        <div id="threat-results" class="mt-6"></div>
      </div>

      <!-- API Sandbox Health Checks -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Outbound Health -->
        <div class="bg-white shadow-sm rounded-lg p-6">
          <h2 class="text-xl font-semibold text-gray-800 mb-4">Outbound Health Check</h2>
          <form onsubmit="handleOutboundHealth(event)" class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">Target URL</label>
              <input 
                type="url" 
                id="outbound-target" 
                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                placeholder="https://example.com"
                value="https://cloudflare.com"
                required
              />
            </div>
            <button 
              type="submit"
              class="bg-purple-600 text-white px-6 py-2 rounded-lg hover:bg-purple-700 transition-colors"
            >
              Test
            </button>
          </form>
          <div id="outbound-results" class="mt-4"></div>
        </div>

        <!-- Internal Health -->
        <div class="bg-white shadow-sm rounded-lg p-6">
          <h2 class="text-xl font-semibold text-gray-800 mb-4">Internal D1 Health Check</h2>
          <button 
            onclick="handleInternalHealth()"
            class="bg-purple-600 text-white px-6 py-2 rounded-lg hover:bg-purple-700 transition-colors"
          >
            Check Database
          </button>
          <div id="internal-results" class="mt-4"></div>
        </div>
      </div>
    </div>
  `;
}

function renderProfile() {
  const p = state.profile;
  return `
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div><span class="font-medium">Username:</span> ${p.username}</div>
      <div><span class="font-medium">Email:</span> ${p.email}</div>
      <div><span class="font-medium">Role:</span> ${p.role}</div>
      <div><span class="font-medium">Joined:</span> ${p.joined}</div>
      <div><span class="font-medium">Queries:</span> ${p.queriesCount}</div>
      <div><span class="font-medium">Last Login:</span> ${new Date(p.lastLogin).toLocaleString()}</div>
    </div>
  `;
}

// Main render
function render() {
  const app = document.getElementById('app');
  if (state.loading) {
    app.innerHTML = '<div class="text-center mt-20"><p class="text-gray-600">Loading...</p></div>';
    return;
  }

  if (!state.authenticated) {
    app.innerHTML = renderLoginCard();
  } else {
    app.innerHTML = renderDashboard();
  }
}

// Event handlers
function handleLogin(event) {
  event.preventDefault();
  const username = document.getElementById('username').value;
  login(username);
}

function handleLogout() {
  logout();
}

function handleFetchProfile() {
  fetchProfile();
}

async function handleThreatLookup(event) {
  event.preventDefault();
  const provider = document.getElementById('provider').value;
  const type = document.getElementById('lookup-type').value;
  const value = document.getElementById('lookup-value').value;

  const resultsDiv = document.getElementById('threat-results');
  resultsDiv.innerHTML = '<p class="text-gray-600">Looking up...</p>';

  const result = await threatLookup(provider, type, value);
  
  let html = '<div class="border border-gray-300 rounded-lg p-4">';
  html += `<div class="mb-2"><span class="font-semibold">Provider:</span> ${result.provider}</div>`;
  html += `<div class="mb-2"><span class="font-semibold">Confidence:</span> <span class="px-2 py-1 rounded text-sm ${getConfidenceBadge(result.confidence)}">${result.confidence}</span></div>`;
  html += `<div class="mb-2"><span class="font-semibold">Status:</span> <span class="px-2 py-1 rounded text-sm ${getStatusBadge(result.status)}">${result.status}</span></div>`;
  
  if (result.error) {
    html += `<div class="mb-2 text-red-600"><span class="font-semibold">Error:</span> ${result.error}</div>`;
  }
  
  if (result.data) {
    html += `<div class="mt-4"><span class="font-semibold">Response Data:</span></div>`;
    html += `<pre class="mt-2 bg-gray-100 p-3 rounded text-xs overflow-auto max-h-96">${JSON.stringify(result.data, null, 2)}</pre>`;
  }
  
  html += '</div>';
  resultsDiv.innerHTML = html;
}

async function handleOutboundHealth(event) {
  event.preventDefault();
  const target = document.getElementById('outbound-target').value;

  const resultsDiv = document.getElementById('outbound-results');
  resultsDiv.innerHTML = '<p class="text-gray-600 text-sm">Testing...</p>';

  const result = await healthOutbound(target);
  
  let html = '<div class="border border-gray-300 rounded-lg p-3 text-sm">';
  html += `<div><span class="font-semibold">Status:</span> <span class="px-2 py-1 rounded text-xs ${getStatusBadge(result.status)}">${result.status}</span></div>`;
  
  if (result.statusCode) {
    html += `<div class="mt-2"><span class="font-semibold">HTTP Status:</span> ${result.statusCode} ${result.statusText}</div>`;
    html += `<div><span class="font-semibold">Duration:</span> ${result.duration}</div>`;
  }
  
  if (result.error) {
    html += `<div class="mt-2 text-red-600"><span class="font-semibold">Error:</span> ${result.error}</div>`;
  }
  
  html += '</div>';
  resultsDiv.innerHTML = html;
}

async function handleInternalHealth() {
  const resultsDiv = document.getElementById('internal-results');
  resultsDiv.innerHTML = '<p class="text-gray-600 text-sm">Checking...</p>';

  const result = await healthInternal();
  
  let html = '<div class="border border-gray-300 rounded-lg p-3 text-sm">';
  html += `<div><span class="font-semibold">Status:</span> <span class="px-2 py-1 rounded text-xs ${getStatusBadge(result.status)}">${result.status}</span></div>`;
  
  if (result.database) {
    html += `<div class="mt-2"><span class="font-semibold">Database:</span> ${result.database}</div>`;
    html += `<div><span class="font-semibold">Duration:</span> ${result.duration}</div>`;
  }
  
  if (result.result) {
    html += `<div class="mt-2"><span class="font-semibold">Result:</span> ${JSON.stringify(result.result)}</div>`;
  }
  
  if (result.error) {
    html += `<div class="mt-2 text-red-600"><span class="font-semibold">Error:</span> ${result.error}</div>`;
  }
  
  html += '</div>';
  resultsDiv.innerHTML = html;
}

// Helper functions
function getConfidenceBadge(confidence) {
  switch (confidence) {
    case 'very_high': return 'bg-red-100 text-red-800';
    case 'high': return 'bg-orange-100 text-orange-800';
    case 'medium': return 'bg-yellow-100 text-yellow-800';
    default: return 'bg-gray-100 text-gray-800';
  }
}

function getStatusBadge(status) {
  switch (status) {
    case 'success': return 'bg-green-100 text-green-800';
    case 'error': return 'bg-red-100 text-red-800';
    case 'no_key': return 'bg-yellow-100 text-yellow-800';
    default: return 'bg-gray-100 text-gray-800';
  }
}

// Initialize
checkSession();
