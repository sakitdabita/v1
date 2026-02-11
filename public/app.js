// State management
let state = {
  authenticated: false,
  username: null,
  profile: null,
  loading: true,
  currentTab: 'dashboard',
  bulkCheckResults: [],
  whoisResults: [],
  darkMode: true, // Default to dark mode
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

// Bulk threat lookup
async function bulkThreatLookup(provider, type, indicators, options) {
  try {
    const response = await fetch('/api/bulk-threat-lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, type, indicators, options }),
    });
    const data = await response.json();
    return data;
  } catch (error) {
    return { error: error.message };
  }
}

// Ping recon
async function pingRecon(target) {
  try {
    const response = await fetch('/api/ping-recon', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await response.json();
    return data;
  } catch (error) {
    return { status: 'error', error: error.message };
  }
}

// Bulk WHOIS
async function bulkWhois(targets) {
  try {
    const response = await fetch('/api/bulk-whois', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets }),
    });
    const data = await response.json();
    return data;
  } catch (error) {
    return { error: error.message };
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
    <div class="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      <div class="max-w-md w-full mx-4">
        <div class="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8 border border-gray-100 dark:border-gray-700">
          <div class="text-center mb-8">
            <div class="inline-block p-3 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-full mb-4">
              <svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
              </svg>
            </div>
            <h2 class="text-3xl font-bold mb-2 bg-gradient-to-r from-blue-600 to-indigo-600 text-transparent bg-clip-text">Security Dashboard</h2>
            <p class="text-gray-600 dark:text-gray-400">Threat Intelligence & Network Recon</p>
          </div>
          <form onsubmit="handleLogin(event)" class="space-y-5">
            <div>
              <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Username</label>
              <input 
                type="text" 
                id="username" 
                class="w-full px-4 py-3 border-2 border-gray-200 dark:border-gray-600 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                placeholder="Enter username"
                required
              />
            </div>
            <button 
              type="submit"
              class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-3 px-4 rounded-xl hover:from-blue-700 hover:to-indigo-700 transition-all transform hover:scale-[1.02] font-semibold shadow-lg"
            >
              Sign In
            </button>
          </form>
          <p class="mt-6 text-sm text-gray-500 dark:text-gray-400 text-center">Demo mode - enter any username</p>
        </div>
      </div>
    </div>
  `;
}

function renderDashboard() {
  return `
    <div class="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <!-- Header -->
      <div class="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div class="flex justify-between items-center py-4">
            <div class="flex items-center space-x-4">
              <div class="p-2 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-lg">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
              </div>
              <div>
                <h1 class="text-2xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 text-transparent bg-clip-text">Security Dashboard</h1>
                <p class="text-sm text-gray-600 dark:text-gray-400">Welcome back, <span class="font-semibold">${state.username}</span></p>
              </div>
            </div>
            <button 
              onclick="handleLogout()"
              class="flex items-center space-x-2 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-all shadow-md"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
              </svg>
              <span>Logout</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav class="flex space-x-8">
            <button 
              onclick="switchTab('dashboard')" 
              class="tab-btn ${state.currentTab === 'dashboard' ? 'tab-active' : ''} py-4 px-1 border-b-2 font-medium text-sm transition-colors"
            >
              Dashboard
            </button>
            <button 
              onclick="switchTab('bulk-check')" 
              class="tab-btn ${state.currentTab === 'bulk-check' ? 'tab-active' : ''} py-4 px-1 border-b-2 font-medium text-sm transition-colors"
            >
              Bulk Check
            </button>
            <button 
              onclick="switchTab('ping-recon')" 
              class="tab-btn ${state.currentTab === 'ping-recon' ? 'tab-active' : ''} py-4 px-1 border-b-2 font-medium text-sm transition-colors"
            >
              Ping Recon
            </button>
            <button 
              onclick="switchTab('bulk-whois')" 
              class="tab-btn ${state.currentTab === 'bulk-whois' ? 'tab-active' : ''} py-4 px-1 border-b-2 font-medium text-sm transition-colors"
            >
              Bulk WHOIS
            </button>
            <button 
              onclick="switchTab('api-lab')" 
              class="tab-btn ${state.currentTab === 'api-lab' ? 'tab-active' : ''} py-4 px-1 border-b-2 font-medium text-sm transition-colors"
            >
              API Lab
            </button>
            <button 
              onclick="switchTab('health')" 
              class="tab-btn ${state.currentTab === 'health' ? 'tab-active' : ''} py-4 px-1 border-b-2 font-medium text-sm transition-colors"
            >
              Health
            </button>
          </nav>
        </div>
      </div>

      <!-- Content -->
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div id="tab-content">
          ${renderTabContent()}
        </div>
      </div>
    </div>
  `;
}

function renderTabContent() {
  switch (state.currentTab) {
    case 'dashboard':
      return renderDashboardTab();
    case 'bulk-check':
      return renderBulkCheckTab();
    case 'ping-recon':
      return renderPingReconTab();
    case 'bulk-whois':
      return renderBulkWhoisTab();
    case 'api-lab':
      return renderApiLabTab();
    case 'health':
      return renderHealthTab();
    default:
      return renderDashboardTab();
  }
}

function renderDashboardTab() {
  return `
    <!-- Profile Card -->
    <div class="bg-white shadow-lg rounded-2xl p-6 mb-6 border border-gray-200">
      <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-bold text-gray-800 flex items-center">
          <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
          </svg>
          Profile
        </h2>
        <button 
          onclick="handleFetchProfile()"
          class="bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-4 py-2 rounded-lg hover:from-blue-700 hover:to-indigo-700 transition-all text-sm font-semibold shadow-md"
        >
          Load Profile
        </button>
      </div>
      <div id="profile-content">
        ${state.profile ? renderProfile() : '<p class="text-gray-500">Click "Load Profile" to view your profile details</p>'}
      </div>
    </div>

    <!-- Single Threat Lookup -->
    <div class="bg-white shadow-lg rounded-2xl p-6 border border-gray-200">
      <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
        <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
        </svg>
        Threat Intelligence Lookup
      </h2>
      <form onsubmit="handleThreatLookup(event)" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label class="block text-sm font-semibold text-gray-700 mb-2">Provider</label>
            <select 
              id="provider" 
              class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="virustotal">VirusTotal (Very High)</option>
              <option value="threatfox">ThreatFox (High)</option>
              <option value="otx">OTX/LevelBlue (Medium)</option>
              <option value="abuseipdb">AbuseIPDB (High, IP only)</option>
              <option value="ibm-xforce">IBM X-Force (Medium)</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-semibold text-gray-700 mb-2">Type</label>
            <select 
              id="lookup-type" 
              class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">File Hash</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-semibold text-gray-700 mb-2">Value</label>
            <input 
              type="text" 
              id="lookup-value" 
              class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="e.g., 8.8.8.8"
              required
            />
          </div>
        </div>
        <button 
          type="submit"
          class="bg-gradient-to-r from-green-600 to-emerald-600 text-white px-6 py-2 rounded-lg hover:from-green-700 hover:to-emerald-700 transition-all font-semibold shadow-md"
        >
          Lookup
        </button>
      </form>
      <div id="threat-results" class="mt-6"></div>
    </div>
  `;
}

function renderBulkCheckTab() {
  return `
    <div class="bg-white shadow-lg rounded-2xl p-6 border border-gray-200">
      <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
        <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path>
        </svg>
        Bulk Threat Intelligence Check
      </h2>
      <p class="text-gray-600 mb-4 text-sm">Enter one indicator per line. For VirusTotal, maximum 10 indicators allowed.</p>
      <form onsubmit="handleBulkCheck(event)" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-semibold text-gray-700 mb-2">Provider</label>
            <select 
              id="bulk-provider" 
              class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="virustotal">VirusTotal (Very High) - Max 10</option>
              <option value="threatfox">ThreatFox (High)</option>
              <option value="otx">OTX/LevelBlue (Medium)</option>
              <option value="abuseipdb">AbuseIPDB (High, IP only)</option>
              <option value="ibm-xforce">IBM X-Force (Medium)</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-semibold text-gray-700 mb-2">Type</label>
            <select 
              id="bulk-type" 
              class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">File Hash</option>
            </select>
          </div>
        </div>
        <div>
          <label class="block text-sm font-semibold text-gray-700 mb-2">Indicators (one per line)</label>
          <textarea 
            id="bulk-indicators" 
            class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
            rows="8"
            placeholder="8.8.8.8&#10;1.1.1.1&#10;9.9.9.9"
            required
          ></textarea>
        </div>
        <div id="abuseipdb-options" style="display: none;">
          <label class="block text-sm font-semibold text-gray-700 mb-2">Max Age in Days (AbuseIPDB only)</label>
          <input 
            type="number" 
            id="max-age-days" 
            class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="180"
            value="180"
            min="1"
            max="365"
          />
          <p class="text-xs text-gray-500 mt-1">Specifies how far back in time to look for reported abuse (1-365 days)</p>
        </div>
        <button 
          type="submit"
          class="bg-gradient-to-r from-green-600 to-emerald-600 text-white px-6 py-2 rounded-lg hover:from-green-700 hover:to-emerald-700 transition-all font-semibold shadow-md"
        >
          Run Bulk Check
        </button>
      </form>
      <div id="bulk-results" class="mt-6"></div>
    </div>
  `;
}

function renderPingReconTab() {
  return `
    <div class="bg-white shadow-lg rounded-2xl p-6 border border-gray-200">
      <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
        <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
        </svg>
        Ping Recon
      </h2>
      <p class="text-gray-600 mb-4 text-sm">Perform network reconnaissance on an IP address or domain.</p>
      <form onsubmit="handlePingRecon(event)" class="space-y-4">
        <div>
          <label class="block text-sm font-semibold text-gray-700 mb-2">Target (IP or Domain)</label>
          <input 
            type="text" 
            id="ping-target" 
            class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="e.g., google.com or 8.8.8.8"
            required
          />
        </div>
        <button 
          type="submit"
          class="bg-gradient-to-r from-purple-600 to-pink-600 text-white px-6 py-2 rounded-lg hover:from-purple-700 hover:to-pink-700 transition-all font-semibold shadow-md"
        >
          Run Recon
        </button>
      </form>
      <div id="ping-results" class="mt-6"></div>
    </div>
  `;
}

function renderBulkWhoisTab() {
  return `
    <div class="bg-white shadow-lg rounded-2xl p-6 border border-gray-200">
      <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
        <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
        Bulk WHOIS Lookup
      </h2>
      <p class="text-gray-600 mb-4 text-sm">Lookup WHOIS information for multiple IPs or domains using ipinfo.io.</p>
      <form onsubmit="handleBulkWhois(event)" class="space-y-4">
        <div>
          <label class="block text-sm font-semibold text-gray-700 mb-2">Targets (one per line)</label>
          <textarea 
            id="whois-targets" 
            class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
            rows="8"
            placeholder="8.8.8.8&#10;google.com&#10;1.1.1.1"
            required
          ></textarea>
        </div>
        <button 
          type="submit"
          class="bg-gradient-to-r from-indigo-600 to-blue-600 text-white px-6 py-2 rounded-lg hover:from-indigo-700 hover:to-blue-700 transition-all font-semibold shadow-md"
        >
          Run Bulk WHOIS
        </button>
      </form>
      <div id="whois-results" class="mt-6"></div>
    </div>
  `;
}

function renderHealthTab() {
  return `
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <!-- Outbound Health -->
      <div class="bg-white shadow-lg rounded-2xl p-6 border border-gray-200">
        <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
          <svg class="w-6 h-6 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
          </svg>
          Outbound Health
        </h2>
        <form onsubmit="handleOutboundHealth(event)" class="space-y-4">
          <div>
            <label class="block text-sm font-semibold text-gray-700 mb-2">Target URL</label>
            <input 
              type="url" 
              id="outbound-target" 
              class="w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              placeholder="https://example.com"
              value="https://cloudflare.com"
              required
            />
          </div>
          <button 
            type="submit"
            class="bg-gradient-to-r from-purple-600 to-pink-600 text-white px-6 py-2 rounded-lg hover:from-purple-700 hover:to-pink-700 transition-all font-semibold shadow-md"
          >
            Test Connection
          </button>
        </form>
        <div id="outbound-results" class="mt-4"></div>
      </div>

      <!-- Internal Health -->
      <div class="bg-white shadow-lg rounded-2xl p-6 border border-gray-200">
        <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
          <svg class="w-6 h-6 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path>
          </svg>
          D1 Database Health
        </h2>
        <button 
          onclick="handleInternalHealth()"
          class="bg-gradient-to-r from-purple-600 to-pink-600 text-white px-6 py-2 rounded-lg hover:from-purple-700 hover:to-pink-700 transition-all font-semibold shadow-md"
        >
          Check Database
        </button>
        <div id="internal-results" class="mt-4"></div>
      </div>
    </div>
  `;
}

function renderApiLabTab() {
  return `
    <div class="bg-white dark:bg-gray-800 shadow-lg rounded-2xl p-6 border border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
        <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
        </svg>
        API Lab
      </h2>
      <p class="text-gray-600 dark:text-gray-400 mb-4 text-sm">Experiment with internal and external API requests</p>
      
      <form onsubmit="handleApiLab(event)" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Method</label>
            <select 
              id="api-method" 
              class="w-full px-4 py-2 border-2 border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">URL</label>
            <input 
              type="text" 
              id="api-url" 
              class="w-full px-4 py-2 border-2 border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
              placeholder="https://api.example.com/endpoint"
              required
            />
          </div>
        </div>
        
        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Headers (JSON format, optional)</label>
          <textarea 
            id="api-headers" 
            class="w-full px-4 py-2 border-2 border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
            rows="3"
            placeholder='{"Content-Type": "application/json"}'
          ></textarea>
        </div>
        
        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Body (JSON format, optional)</label>
          <textarea 
            id="api-body" 
            class="w-full px-4 py-2 border-2 border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
            rows="6"
            placeholder='{"key": "value"}'
          ></textarea>
        </div>
        
        <button 
          type="submit"
          class="bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-6 py-2 rounded-lg hover:from-blue-700 hover:to-indigo-700 transition-all font-semibold shadow-md"
        >
          Send Request
        </button>
      </form>
      
      <div id="api-lab-results" class="mt-6"></div>
    </div>
  `;
}

function renderProfile() {
  const p = state.profile;
  return `
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="flex items-center space-x-2">
        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
        </svg>
        <span><span class="font-semibold">Username:</span> ${p.username}</span>
      </div>
      <div class="flex items-center space-x-2">
        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
        </svg>
        <span><span class="font-semibold">Email:</span> ${p.email}</span>
      </div>
      <div class="flex items-center space-x-2">
        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
        </svg>
        <span><span class="font-semibold">Role:</span> ${p.role}</span>
      </div>
      <div class="flex items-center space-x-2">
        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
        </svg>
        <span><span class="font-semibold">Joined:</span> ${p.joined}</span>
      </div>
      <div class="flex items-center space-x-2">
        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
        </svg>
        <span><span class="font-semibold">Queries:</span> ${p.queriesCount}</span>
      </div>
      <div class="flex items-center space-x-2">
        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
        <span><span class="font-semibold">Last Login:</span> ${new Date(p.lastLogin).toLocaleString()}</span>
      </div>
    </div>
  `;
}

// Main render
function render() {
  const app = document.getElementById('app');
  if (state.loading) {
    app.innerHTML = '<div class="flex items-center justify-center min-h-screen"><div class="text-center"><div class="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div><p class="text-gray-600 mt-4">Loading...</p></div></div>';
    return;
  }

  if (!state.authenticated) {
    app.innerHTML = renderLoginCard();
  } else {
    app.innerHTML = renderDashboard();
    
    // Add event listener for provider change if on bulk check tab
    if (state.currentTab === 'bulk-check') {
      // Use setTimeout to ensure DOM is ready
      setTimeout(() => {
        const providerSelect = document.getElementById('bulk-provider');
        if (providerSelect && !providerSelect.dataset.listenerAttached) {
          providerSelect.addEventListener('change', handleProviderChange);
          providerSelect.dataset.listenerAttached = 'true';
          // Trigger once to set initial state
          handleProviderChange();
        }
      }, 0);
    }
  }
}

// Handler for provider change to show/hide AbuseIPDB options
function handleProviderChange() {
  const provider = document.getElementById('bulk-provider').value;
  const abuseipdbOptions = document.getElementById('abuseipdb-options');
  
  if (abuseipdbOptions) {
    if (provider === 'abuseipdb') {
      abuseipdbOptions.style.display = 'block';
    } else {
      abuseipdbOptions.style.display = 'none';
    }
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

function switchTab(tab) {
  state.currentTab = tab;
  render();
}

async function handleThreatLookup(event) {
  event.preventDefault();
  const provider = document.getElementById('provider').value;
  const type = document.getElementById('lookup-type').value;
  const value = document.getElementById('lookup-value').value;

  const resultsDiv = document.getElementById('threat-results');
  resultsDiv.innerHTML = '<div class="flex items-center space-x-2 text-gray-600"><div class="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div><span>Looking up...</span></div>';

  const result = await threatLookup(provider, type, value);
  
  let html = '<div class="border-2 border-gray-200 rounded-xl p-4 bg-gradient-to-br from-white to-gray-50">';
  html += `<div class="mb-2 flex items-center"><span class="font-semibold">Provider:</span> <span class="ml-2">${result.provider}</span></div>`;
  html += `<div class="mb-2 flex items-center"><span class="font-semibold">Confidence:</span> <span class="ml-2 px-3 py-1 rounded-full text-sm font-semibold ${getConfidenceBadge(result.confidence)}">${result.confidence}</span></div>`;
  html += `<div class="mb-2 flex items-center"><span class="font-semibold">Status:</span> <span class="ml-2 px-3 py-1 rounded-full text-sm font-semibold ${getStatusBadge(result.status)}">${result.status}</span></div>`;
  
  if (result.error) {
    html += `<div class="mb-2 text-red-600 flex items-start"><svg class="w-5 h-5 mr-2 mt-0.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg><span><span class="font-semibold">Error:</span> ${result.error}</span></div>`;
  }
  
  if (result.data) {
    html += `<div class="mt-4"><span class="font-semibold">Response Data:</span></div>`;
    html += `<pre class="mt-2 bg-gray-800 text-gray-100 p-4 rounded-lg text-xs overflow-auto max-h-96 font-mono">${JSON.stringify(result.data, null, 2)}</pre>`;
  }
  
  html += '</div>';
  resultsDiv.innerHTML = html;
}

async function handleBulkCheck(event) {
  event.preventDefault();
  const provider = document.getElementById('bulk-provider').value;
  const type = document.getElementById('bulk-type').value;
  const indicatorsText = document.getElementById('bulk-indicators').value;
  const indicators = indicatorsText.split('\n').map(i => i.trim()).filter(i => i.length > 0);

  const resultsDiv = document.getElementById('bulk-results');
  
  if (provider === 'virustotal' && indicators.length > 10) {
    resultsDiv.innerHTML = '<div class="text-red-600 dark:text-red-400 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">VirusTotal is limited to maximum 10 indicators per request. Please remove some indicators.</div>';
    return;
  }

  // Build options object
  const options = {};
  if (provider === 'abuseipdb') {
    const maxAgeDays = document.getElementById('max-age-days').value;
    if (maxAgeDays) {
      options.maxAgeInDays = parseInt(maxAgeDays);
    }
  }

  resultsDiv.innerHTML = '<div class="flex items-center space-x-2 text-gray-600 dark:text-gray-400"><div class="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div><span>Processing bulk check...</span></div>';

  logAction('bulk_check', { provider, type, count: indicators.length });
  
  const data = await bulkThreatLookup(provider, type, indicators, options);
  
  if (data.error) {
    resultsDiv.innerHTML = `<div class="text-red-600 dark:text-red-400 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">Error: ${data.error}</div>`;
    return;
  }

  // Build compact table with breakdown columns
  let html = '<div class="mb-4">';
  html += '<button onclick="copyTableToClipboard(\'bulk-check-table\')" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-semibold shadow-md transition-all flex items-center space-x-2">';
  html += '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>';
  html += '<span>Copy Table</span>';
  html += '</button></div>';
  
  html += '<div class="overflow-x-auto">';
  html += '<table id="bulk-check-table" class="min-w-full divide-y divide-gray-200 dark:divide-gray-700 border-2 border-gray-200 dark:border-gray-700 rounded-lg">';
  html += '<thead class="bg-gradient-to-r from-blue-600 to-indigo-600 text-white">';
  html += '<tr>';
  html += '<th class="px-3 py-2 text-left text-xs font-bold uppercase">Indicator</th>';
  html += '<th class="px-3 py-2 text-left text-xs font-bold uppercase">Status</th>';
  
  // Add provider-specific columns
  const columns = getProviderColumns(provider);
  columns.forEach(col => {
    html += `<th class="px-3 py-2 text-left text-xs font-bold uppercase">${col}</th>`;
  });
  
  html += '<th class="px-3 py-2 text-left text-xs font-bold uppercase">Actions</th>';
  html += '</tr>';
  html += '</thead><tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">';
  
  data.results.forEach((result, index) => {
    html += '<tr class="hover:bg-gray-50 dark:hover:bg-gray-700">';
    html += `<td class="px-3 py-2 whitespace-nowrap font-mono text-xs text-gray-900 dark:text-gray-100">${result.indicator}</td>`;
    html += `<td class="px-3 py-2 whitespace-nowrap"><span class="px-2 py-1 rounded-full text-xs font-semibold ${getStatusBadge(result.status)}">${result.status}</span></td>`;
    
    // Extract provider-specific data into columns
    const rowData = extractProviderColumns(result.provider, result.data, result.status);
    rowData.forEach(value => {
      html += `<td class="px-3 py-2 text-xs text-gray-700 dark:text-gray-300">${value}</td>`;
    });
    
    html += `<td class="px-3 py-2 whitespace-nowrap"><button onclick="showRawJson(${index})" class="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-semibold text-xs">JSON</button></td>`;
    html += '</tr>';
  });
  
  html += '</tbody></table></div>';
  
  // Store results in state for JSON viewing
  state.bulkCheckResults = data.results;
  
  resultsDiv.innerHTML = html;
}

function showRawJson(index) {
  const result = state.bulkCheckResults[index];
  const modal = document.createElement('div');
  modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('aria-labelledby', 'modal-title');
  
  // Add keyboard accessibility
  const closeModal = () => {
    modal.remove();
    document.removeEventListener('keydown', handleKeyDown);
  };
  
  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      closeModal();
    }
  };
  document.addEventListener('keydown', handleKeyDown);
  
  // Close on backdrop click
  modal.onclick = (e) => { 
    if (e.target === modal) {
      closeModal();
    }
  };
  
  modal.innerHTML = `
    <div class="bg-white rounded-2xl p-6 max-w-4xl w-full max-h-[90vh] overflow-auto shadow-2xl">
      <div class="flex justify-between items-center mb-4">
        <h3 id="modal-title" class="text-xl font-bold text-gray-800">Raw JSON - ${result.indicator}</h3>
        <button id="close-modal-btn" class="text-gray-500 hover:text-gray-700" aria-label="Close modal">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
          </svg>
        </button>
      </div>
      <pre class="bg-gray-800 text-gray-100 p-4 rounded-lg text-xs overflow-auto font-mono">${JSON.stringify(result, null, 2)}</pre>
    </div>
  `;
  
  // Add click handler to close button
  modal.querySelector('#close-modal-btn').addEventListener('click', closeModal);
  
  document.body.appendChild(modal);
}

async function handlePingRecon(event) {
  event.preventDefault();
  const target = document.getElementById('ping-target').value;

  const resultsDiv = document.getElementById('ping-results');
  resultsDiv.innerHTML = '<div class="flex items-center space-x-2 text-gray-600"><div class="animate-spin rounded-full h-5 w-5 border-b-2 border-purple-600"></div><span>Running recon...</span></div>';

  const result = await pingRecon(target);
  
  let html = '<div class="border-2 border-gray-200 rounded-xl p-6 bg-gradient-to-br from-white to-purple-50">';
  
  if (result.status === 'success') {
    html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';
    html += `<div class="flex items-center space-x-2"><svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 21v-4m0 0V5a2 2 0 012-2h6.5l1 1H21l-3 6 3 6h-8.5l-1-1H5a2 2 0 00-2 2zm9-13.5V9"></path></svg><span><span class="font-semibold">Target:</span> ${result.target}</span></div>`;
    html += `<div class="flex items-center space-x-2"><svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path></svg><span><span class="font-semibold">Resolved IP:</span> ${result.resolvedIP}</span></div>`;
    html += `<div class="flex items-center space-x-2"><svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"></path></svg><span><span class="font-semibold">Type:</span> ${result.isIP ? 'IP Address' : 'Domain'}</span></div>`;
    
    if (result.httpCheck) {
      const status = result.httpCheck.reachable ? 'Reachable' : 'Unreachable';
      const statusClass = result.httpCheck.reachable ? 'text-green-600' : 'text-red-600';
      html += `<div class="flex items-center space-x-2"><svg class="w-5 h-5 ${statusClass}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg><span class="${statusClass} font-semibold">${status}</span>`;
      if (result.httpCheck.reachable) {
        html += ` <span class="text-gray-600 text-sm">(${result.httpCheck.statusCode}, ${result.httpCheck.responseTime}ms)</span>`;
      }
      html += '</div>';
    }
    
    html += `<div class="flex items-center space-x-2"><svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg><span class="text-sm text-gray-600">${new Date(result.timestamp).toLocaleString()}</span></div>`;
    html += '</div>';
  } else {
    html += `<div class="text-red-600 flex items-start"><svg class="w-5 h-5 mr-2 mt-0.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg><span>Error: ${result.error}</span></div>`;
  }
  
  html += '</div>';
  resultsDiv.innerHTML = html;
}

async function handleBulkWhois(event) {
  event.preventDefault();
  const targetsText = document.getElementById('whois-targets').value;
  const targets = targetsText.split('\n').map(t => t.trim()).filter(t => t.length > 0);

  const resultsDiv = document.getElementById('whois-results');
  resultsDiv.innerHTML = '<div class="flex items-center space-x-2 text-gray-600"><div class="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div><span>Processing bulk WHOIS...</span></div>';

  const data = await bulkWhois(targets);
  
  if (data.error) {
    resultsDiv.innerHTML = `<div class="text-red-600 p-4 bg-red-50 rounded-lg border border-red-200">Error: ${data.error}</div>`;
    return;
  }

  let html = '<div class="overflow-x-auto">';
  html += '<table class="min-w-full divide-y divide-gray-200 border-2 border-gray-200 rounded-lg">';
  html += '<thead class="bg-gradient-to-r from-indigo-600 to-blue-600 text-white">';
  html += '<tr><th class="px-6 py-3 text-left text-xs font-bold uppercase tracking-wider">Target</th>';
  html += '<th class="px-6 py-3 text-left text-xs font-bold uppercase tracking-wider">Status</th>';
  html += '<th class="px-6 py-3 text-left text-xs font-bold uppercase tracking-wider">Info</th>';
  html += '<th class="px-6 py-3 text-left text-xs font-bold uppercase tracking-wider">Actions</th></tr>';
  html += '</thead><tbody class="bg-white divide-y divide-gray-200">';
  
  data.results.forEach((result, index) => {
    html += '<tr class="hover:bg-gray-50">';
    html += `<td class="px-6 py-4 whitespace-nowrap font-mono text-sm">${result.target}</td>`;
    html += `<td class="px-6 py-4 whitespace-nowrap"><span class="px-3 py-1 rounded-full text-xs font-semibold ${getStatusBadge(result.status)}">${result.status}</span></td>`;
    
    if (result.status === 'success' && result.data) {
      const info = [];
      if (result.data.city) info.push(result.data.city);
      if (result.data.country) info.push(result.data.country);
      if (result.data.org) info.push(result.data.org);
      html += `<td class="px-6 py-4 text-sm text-gray-600">${info.join(', ') || 'N/A'}</td>`;
    } else {
      html += `<td class="px-6 py-4 text-sm text-red-600">${result.error || 'N/A'}</td>`;
    }
    
    html += `<td class="px-6 py-4 whitespace-nowrap"><button onclick="showWhoisJson(${index})" class="text-blue-600 hover:text-blue-800 font-semibold text-sm">View JSON</button></td>`;
    html += '</tr>';
  });
  
  html += '</tbody></table></div>';
  
  // Store results in state for JSON viewing
  state.whoisResults = data.results;
  
  resultsDiv.innerHTML = html;
}

function showWhoisJson(index) {
  const result = state.whoisResults[index];
  const modal = document.createElement('div');
  modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('aria-labelledby', 'whois-modal-title');
  
  // Add keyboard accessibility
  const closeModal = () => {
    modal.remove();
    document.removeEventListener('keydown', handleKeyDown);
  };
  
  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      closeModal();
    }
  };
  document.addEventListener('keydown', handleKeyDown);
  
  // Close on backdrop click
  modal.onclick = (e) => { 
    if (e.target === modal) {
      closeModal();
    }
  };
  
  modal.innerHTML = `
    <div class="bg-white rounded-2xl p-6 max-w-4xl w-full max-h-[90vh] overflow-auto shadow-2xl">
      <div class="flex justify-between items-center mb-4">
        <h3 id="whois-modal-title" class="text-xl font-bold text-gray-800">WHOIS Data - ${result.target}</h3>
        <button id="close-whois-modal-btn" class="text-gray-500 hover:text-gray-700" aria-label="Close modal">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
          </svg>
        </button>
      </div>
      <pre class="bg-gray-800 text-gray-100 p-4 rounded-lg text-xs overflow-auto font-mono">${JSON.stringify(result, null, 2)}</pre>
    </div>
  `;
  
  // Add click handler to close button
  modal.querySelector('#close-whois-modal-btn').addEventListener('click', closeModal);
  
  document.body.appendChild(modal);
}

async function handleOutboundHealth(event) {
  event.preventDefault();
  const target = document.getElementById('outbound-target').value;

  const resultsDiv = document.getElementById('outbound-results');
  resultsDiv.innerHTML = '<p class="text-gray-600 text-sm flex items-center space-x-2"><div class="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-600"></div><span>Testing...</span></p>';

  const result = await healthOutbound(target);
  
  let html = '<div class="border-2 border-gray-200 rounded-lg p-4 text-sm bg-gradient-to-br from-white to-gray-50 mt-4">';
  html += `<div class="flex items-center mb-2"><span class="font-semibold">Status:</span> <span class="ml-2 px-3 py-1 rounded-full text-xs font-semibold ${getStatusBadge(result.status)}">${result.status}</span></div>`;
  
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
  resultsDiv.innerHTML = '<p class="text-gray-600 text-sm flex items-center space-x-2 mt-4"><div class="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-600"></div><span>Checking...</span></p>';

  const result = await healthInternal();
  
  let html = '<div class="border-2 border-gray-200 rounded-lg p-4 text-sm bg-gradient-to-br from-white to-gray-50 mt-4">';
  html += `<div class="flex items-center mb-2"><span class="font-semibold">Status:</span> <span class="ml-2 px-3 py-1 rounded-full text-xs font-semibold ${getStatusBadge(result.status)}">${result.status}</span></div>`;
  
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

async function handleApiLab(event) {
  event.preventDefault();
  
  const method = document.getElementById('api-method').value;
  const url = document.getElementById('api-url').value;
  const headersText = document.getElementById('api-headers').value;
  const bodyText = document.getElementById('api-body').value;
  
  const resultsDiv = document.getElementById('api-lab-results');
  resultsDiv.innerHTML = '<div class="flex items-center space-x-2 text-gray-600 dark:text-gray-400"><div class="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div><span>Sending request...</span></div>';
  
  try {
    // Parse headers and body if provided
    let headers = {};
    if (headersText.trim()) {
      try {
        headers = JSON.parse(headersText);
      } catch (e) {
        resultsDiv.innerHTML = '<div class="text-red-600 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">Invalid JSON in headers</div>';
        return;
      }
    }
    
    let body = null;
    if (bodyText.trim() && (method === 'POST' || method === 'PUT')) {
      try {
        body = JSON.parse(bodyText);
      } catch (e) {
        resultsDiv.innerHTML = '<div class="text-red-600 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">Invalid JSON in body</div>';
        return;
      }
    }
    
    // Log the API lab request
    logAction('api_lab_request', { method, url });
    
    // Make the request through our backend proxy
    const response = await fetch('/api/proxy-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, url, headers, body })
    });
    
    const result = await response.json();
    
    // Display results
    let html = '<div class="border-2 border-gray-200 dark:border-gray-700 rounded-xl p-4 bg-gradient-to-br from-white to-gray-50 dark:from-gray-800 dark:to-gray-900">';
    html += `<div class="mb-2"><span class="font-semibold text-gray-800 dark:text-gray-200">Status:</span> <span class="ml-2 px-3 py-1 rounded-full text-xs font-semibold ${result.status >= 200 && result.status < 300 ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'}">${result.status || 'N/A'}</span></div>`;
    html += `<div class="mb-2"><span class="font-semibold text-gray-800 dark:text-gray-200">Duration:</span> <span class="ml-2 text-gray-700 dark:text-gray-300">${result.duration || 'N/A'}</span></div>`;
    
    if (result.headers) {
      html += `<div class="mt-4"><span class="font-semibold text-gray-800 dark:text-gray-200">Response Headers:</span></div>`;
      html += `<pre class="mt-2 bg-gray-800 dark:bg-gray-950 text-gray-100 p-4 rounded-lg text-xs overflow-auto max-h-48 font-mono">${JSON.stringify(result.headers, null, 2)}</pre>`;
    }
    
    if (result.data) {
      html += `<div class="mt-4"><span class="font-semibold text-gray-800 dark:text-gray-200">Response Data:</span></div>`;
      html += `<pre class="mt-2 bg-gray-800 dark:bg-gray-950 text-gray-100 p-4 rounded-lg text-xs overflow-auto max-h-96 font-mono">${JSON.stringify(result.data, null, 2)}</pre>`;
    }
    
    if (result.error) {
      html += `<div class="mt-2 text-red-600 dark:text-red-400"><span class="font-semibold">Error:</span> ${result.error}</div>`;
    }
    
    html += '</div>';
    resultsDiv.innerHTML = html;
  } catch (error) {
    resultsDiv.innerHTML = `<div class="text-red-600 dark:text-red-400 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">Request failed: ${error.message}</div>`;
  }
}

// Helper functions
function getProviderColumns(provider) {
  switch (provider) {
    case 'virustotal':
      return ['Malicious', 'Suspicious', 'Clean', 'Country', 'Reputation'];
    case 'threatfox':
      return ['Threat Type', 'Malware', 'Confidence', 'IOCs'];
    case 'abuseipdb':
      return ['Abuse Score', 'Reports', 'Users', 'Country', 'Whitelisted'];
    case 'otx':
      return ['Pulses', 'Latest Pulse', 'Country', 'ASN'];
    case 'ibm-xforce':
      return ['Risk Score', 'Categories', 'Country'];
    default:
      return ['Info'];
  }
}

function extractProviderColumns(provider, data, status) {
  if (status !== 'success' || !data) {
    const columns = getProviderColumns(provider);
    return columns.map(() => '-');
  }
  
  try {
    switch (provider) {
      case 'VirusTotal':
        if (data.data && data.data.attributes) {
          const attrs = data.data.attributes;
          const stats = attrs.last_analysis_stats || {};
          return [
            stats.malicious || 0,
            stats.suspicious || 0,
            stats.harmless || 0,
            attrs.country || '-',
            attrs.reputation !== undefined ? attrs.reputation : '-'
          ];
        }
        return ['-', '-', '-', '-', '-'];
        
      case 'ThreatFox':
        if (data.data && Array.isArray(data.data) && data.data.length > 0) {
          const threat = data.data[0];
          return [
            threat.threat_type || '-',
            threat.malware || '-',
            threat.confidence_level ? `${threat.confidence_level}%` : '-',
            data.data.length
          ];
        }
        return ['-', '-', '-', '0'];
        
      case 'AbuseIPDB':
        if (data.data) {
          const d = data.data;
          return [
            `${d.abuseConfidenceScore || 0}%`,
            d.totalReports || 0,
            d.numDistinctUsers || 0,
            d.countryCode || '-',
            d.isWhitelisted ? 'Yes' : 'No'
          ];
        }
        return ['-', '-', '-', '-', '-'];
        
      case 'OTX/LevelBlue':
        const pulseCount = data.pulse_info?.count || 0;
        const latestPulse = data.pulse_info?.pulses?.[0]?.name || '-';
        return [
          pulseCount,
          latestPulse.length > 30 ? latestPulse.substring(0, 30) + '...' : latestPulse,
          data.country_name || '-',
          data.asn || '-'
        ];
        
      case 'IBM X-Force':
        const score = data.score || '-';
        const cats = data.cats ? Object.keys(data.cats).join(', ') : '-';
        const country = data.geo?.country || '-';
        return [
          score,
          cats.length > 30 ? cats.substring(0, 30) + '...' : cats,
          country
        ];
        
      default:
        return ['Data available'];
    }
  } catch (e) {
    const columns = getProviderColumns(provider);
    return columns.map(() => 'Error');
  }
}

function copyTableToClipboard(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  
  let text = '';
  const rows = table.querySelectorAll('tr');
  rows.forEach((row) => {
    const cells = row.querySelectorAll('th, td');
    const rowText = Array.from(cells).map(cell => cell.textContent.trim()).join('\t');
    text += rowText + '\n';
  });
  
  navigator.clipboard.writeText(text).then(() => {
    // Show success message
    const btn = event.target.closest('button');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg><span>Copied!</span>';
    setTimeout(() => {
      btn.innerHTML = originalText;
    }, 2000);
    
    logAction('copy_table', { tableId });
  }).catch(err => {
    console.error('Copy failed:', err);
    alert('Failed to copy table');
  });
}

function extractProviderDetails(provider, data) {
  let details = [];
  
  try {
    switch (provider) {
      case 'VirusTotal':
        if (data.data && data.data.attributes) {
          const attrs = data.data.attributes;
          const stats = attrs.last_analysis_stats || {};
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          const harmless = stats.harmless || 0;
          const total = malicious + suspicious + harmless + (stats.undetected || 0);
          
          details.push(`<span class="font-semibold text-red-600">Malicious: ${malicious}</span>`);
          details.push(`<span class="text-orange-600">Suspicious: ${suspicious}</span>`);
          details.push(`<span class="text-green-600">Clean: ${harmless}</span>`);
          details.push(`<span class="text-gray-600">Total: ${total}</span>`);
          
          if (attrs.country) {
            details.push(`Country: ${attrs.country}`);
          }
          if (attrs.reputation !== undefined) {
            details.push(`Reputation: ${attrs.reputation}`);
          }
        }
        break;
        
      case 'ThreatFox':
        if (data.data && Array.isArray(data.data) && data.data.length > 0) {
          const threat = data.data[0];
          details.push(`<span class="font-semibold text-red-600">Threat: ${threat.threat_type || 'Unknown'}</span>`);
          if (threat.malware) {
            details.push(`Malware: ${threat.malware}`);
          }
          if (threat.confidence_level) {
            details.push(`Confidence: ${threat.confidence_level}%`);
          }
          details.push(`IOCs Found: ${data.data.length}`);
        } else {
          details.push('<span class="text-green-600">No threats found</span>');
        }
        break;
        
      case 'AbuseIPDB':
        if (data.data) {
          const d = data.data;
          const score = d.abuseConfidenceScore || 0;
          const scoreClass = score > 75 ? 'text-red-600' : score > 25 ? 'text-orange-600' : 'text-green-600';
          
          details.push(`<span class="font-semibold ${scoreClass}">Abuse Score: ${score}%</span>`);
          details.push(`Reports: ${d.totalReports || 0}`);
          details.push(`Distinct Users: ${d.numDistinctUsers || 0}`);
          
          if (d.usageType) {
            details.push(`Type: ${d.usageType}`);
          }
          if (d.countryCode) {
            details.push(`Country: ${d.countryCode}`);
          }
          if (d.isWhitelisted) {
            details.push('<span class="text-green-600">✓ Whitelisted</span>');
          }
        }
        break;
        
      case 'OTX/LevelBlue':
        if (data.pulse_info && data.pulse_info.count > 0) {
          details.push(`<span class="font-semibold text-red-600">Pulses: ${data.pulse_info.count}</span>`);
          if (data.pulse_info.pulses && data.pulse_info.pulses[0]) {
            const pulse = data.pulse_info.pulses[0];
            details.push(`Latest: ${pulse.name}`);
          }
        } else {
          details.push('<span class="text-green-600">No pulses found</span>');
        }
        
        if (data.country_name) {
          details.push(`Country: ${data.country_name}`);
        }
        if (data.asn) {
          details.push(`ASN: ${data.asn}`);
        }
        break;
        
      case 'IBM X-Force':
        if (data.score) {
          const score = data.score;
          const scoreClass = score > 7 ? 'text-red-600' : score > 4 ? 'text-orange-600' : 'text-green-600';
          details.push(`<span class="font-semibold ${scoreClass}">Risk Score: ${score}/10</span>`);
        }
        
        if (data.cats) {
          const categories = Object.keys(data.cats).join(', ');
          if (categories) {
            details.push(`Categories: ${categories}`);
          }
        }
        
        if (data.categoryDescriptions) {
          const cats = Object.values(data.categoryDescriptions).join(', ');
          if (cats) {
            details.push(`${cats}`);
          }
        }
        
        if (data.geo && data.geo.country) {
          details.push(`Country: ${data.geo.country}`);
        }
        break;
        
      default:
        details.push('<span class="text-gray-600">Data available in JSON view</span>');
    }
  } catch (e) {
    details.push('<span class="text-gray-600">Error parsing data</span>');
  }
  
  return details.length > 0 ? details.join(' • ') : '<span class="text-gray-400">No details available</span>';
}

function getConfidenceBadge(confidence) {
  switch (confidence) {
    case 'very_high': return 'bg-red-100 text-red-800 border border-red-200';
    case 'high': return 'bg-orange-100 text-orange-800 border border-orange-200';
    case 'medium': return 'bg-yellow-100 text-yellow-800 border border-yellow-200';
    default: return 'bg-gray-100 text-gray-800 border border-gray-200';
  }
}

function getStatusBadge(status) {
  switch (status) {
    case 'success': return 'bg-green-100 text-green-800 border border-green-200';
    case 'error': return 'bg-red-100 text-red-800 border border-red-200';
    case 'no_key': return 'bg-yellow-100 text-yellow-800 border border-yellow-200';
    default: return 'bg-gray-100 text-gray-800 border border-gray-200';
  }
}

// Initialize custom styles once
(function initStyles() {
  if (!document.getElementById('custom-tab-styles')) {
    const style = document.createElement('style');
    style.id = 'custom-tab-styles';
    style.textContent = `
      .tab-btn {
        border-color: transparent;
        color: #6b7280;
      }
      .dark .tab-btn {
        color: #9ca3af;
      }
      .tab-btn:hover {
        color: #3b82f6;
        border-color: #93c5fd;
      }
      .tab-active {
        color: #3b82f6;
        border-color: #3b82f6 !important;
      }
    `;
    document.head.appendChild(style);
  }
})();

// Theme management
function initializeTheme() {
  // Check localStorage for saved theme preference, default to dark
  const savedTheme = localStorage.getItem('theme');
  state.darkMode = savedTheme ? savedTheme === 'dark' : true;
  applyTheme();
}

function applyTheme() {
  const html = document.documentElement;
  if (state.darkMode) {
    html.classList.add('dark');
    document.body.style.backgroundColor = '#1f2937';
  } else {
    html.classList.remove('dark');
    document.body.style.backgroundColor = '#f9fafb';
  }
  localStorage.setItem('theme', state.darkMode ? 'dark' : 'light');
}

function toggleTheme() {
  state.darkMode = !state.darkMode;
  applyTheme();
  logAction('theme_toggle', { theme: state.darkMode ? 'dark' : 'light' });
}

// Logging function
async function logAction(action, details = {}) {
  try {
    await fetch('/api/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: state.username || 'anonymous',
        action,
        details,
        timestamp: new Date().toISOString()
      })
    });
  } catch (error) {
    console.error('Logging failed:', error);
  }
}

// Initialize
initializeTheme();
checkSession();
