import { Hono } from 'hono';
import { getSession, setSession, clearSession, requireAuth } from '../lib/session';
import { lookupThreat, bulkLookupThreat, pingRecon, bulkWhois } from '../lib/providers';

type Bindings = {
  DB: D1Database;
  SESSION_SECRET: string;
  VT_API_KEY?: string;
  THREATFOX_API_KEY?: string;
  OTX_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
  IBM_XF_API_KEY?: string;
  IPINFO_API_KEY?: string;
};

const app = new Hono<{ Bindings: Bindings }>({ strict: false }).basePath('/api');

// Login endpoint
app.post('/login', async (c) => {
  try {
    const body = await c.req.json();
    const { username } = body;

    if (!username || typeof username !== 'string' || username.trim().length === 0) {
      return c.json({ error: 'Username is required' }, 400);
    }

    await setSession(c, { username: username.trim() });
    return c.json({ success: true, username: username.trim() });
  } catch (error: any) {
    return c.json({ error: error.message || 'Login failed' }, 500);
  }
});

// Logout endpoint
app.post('/logout', (c) => {
  clearSession(c);
  return c.json({ success: true });
});

// Session check endpoint
app.get('/session', async (c) => {
  try {
    const session = await getSession(c);
    if (session) {
      return c.json({ authenticated: true, username: session.username });
    } else {
      return c.json({ authenticated: false });
    }
  } catch (error: any) {
    return c.json({ authenticated: false, error: error.message }, 500);
  }
});

// Profile endpoint (requires auth)
app.get('/profile', async (c) => {
  try {
    const session = await requireAuth(c);
    
    // Demo profile data
    const profile = {
      username: session.username,
      email: `${session.username}@example.com`,
      role: 'Security Analyst',
      joined: new Date().toISOString().split('T')[0],
      queriesCount: 42,
      lastLogin: new Date().toISOString(),
    };

    return c.json(profile);
  } catch (error: any) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
});

// Threat lookup endpoint (requires auth)
app.post('/threat-lookup', async (c) => {
  try {
    await requireAuth(c);

    const body = await c.req.json();
    const { provider, type, value } = body;

    if (!provider || !type || !value) {
      return c.json({ error: 'Provider, type, and value are required' }, 400);
    }

    if (!['ip', 'domain', 'hash'].includes(type)) {
      return c.json({ error: 'Type must be ip, domain, or hash' }, 400);
    }

    const result = await lookupThreat(provider, type as any, value, c.env);
    return c.json(result);
  } catch (error: any) {
    if (error.message === 'Unauthorized') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return c.json({ error: error.message || 'Lookup failed' }, 500);
  }
});

// Bulk threat lookup endpoint (requires auth)
app.post('/bulk-threat-lookup', async (c) => {
  try {
    await requireAuth(c);

    const body = await c.req.json();
    const { provider, type, indicators } = body;

    if (!provider || !type || !indicators) {
      return c.json({ error: 'Provider, type, and indicators are required' }, 400);
    }

    if (!['ip', 'domain', 'hash'].includes(type)) {
      return c.json({ error: 'Type must be ip, domain, or hash' }, 400);
    }

    if (!Array.isArray(indicators)) {
      return c.json({ error: 'Indicators must be an array' }, 400);
    }

    // Limit VirusTotal to max 10 indicators
    if (provider === 'virustotal' && indicators.length > 10) {
      return c.json({ error: 'VirusTotal is limited to maximum 10 indicators per request' }, 400);
    }

    const results = await bulkLookupThreat(provider, type as any, indicators, c.env);
    return c.json({ results });
  } catch (error: any) {
    if (error.message === 'Unauthorized') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return c.json({ error: error.message || 'Bulk lookup failed' }, 500);
  }
});

// Ping recon endpoint (requires auth)
app.post('/ping-recon', async (c) => {
  try {
    await requireAuth(c);

    const body = await c.req.json();
    const { target } = body;

    if (!target) {
      return c.json({ error: 'Target (IP or domain) is required' }, 400);
    }

    const result = await pingRecon(target);
    return c.json(result);
  } catch (error: any) {
    if (error.message === 'Unauthorized') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return c.json({ error: error.message || 'Ping recon failed' }, 500);
  }
});

// Bulk WHOIS endpoint (requires auth)
app.post('/bulk-whois', async (c) => {
  try {
    await requireAuth(c);

    const body = await c.req.json();
    const { targets } = body;

    if (!targets || !Array.isArray(targets)) {
      return c.json({ error: 'Targets array is required' }, 400);
    }

    const results = await bulkWhois(targets, c.env.IPINFO_API_KEY);
    return c.json({ results });
  } catch (error: any) {
    if (error.message === 'Unauthorized') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return c.json({ error: error.message || 'Bulk WHOIS failed' }, 500);
  }
});

// API Sandbox - Outbound health check
app.get('/health/outbound', async (c) => {
  try {
    await requireAuth(c);

    const target = c.req.query('target');
    if (!target) {
      return c.json({ error: 'Target parameter is required' }, 400);
    }

    try {
      const startTime = Date.now();
      const response = await fetch(target, { method: 'HEAD' });
      const duration = Date.now() - startTime;

      return c.json({
        status: 'success',
        target,
        statusCode: response.status,
        statusText: response.statusText,
        duration: `${duration}ms`,
        ok: response.ok,
      });
    } catch (error: any) {
      return c.json({
        status: 'error',
        target,
        error: error.message,
      });
    }
  } catch (error: any) {
    if (error.message === 'Unauthorized') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return c.json({ error: error.message }, 500);
  }
});

// API Sandbox - Internal D1 health check
app.get('/health/internal', async (c) => {
  try {
    await requireAuth(c);

    try {
      const startTime = Date.now();
      const result = await c.env.DB.prepare('SELECT 1 as health').first();
      const duration = Date.now() - startTime;

      return c.json({
        status: 'success',
        database: 'connected',
        result,
        duration: `${duration}ms`,
      });
    } catch (error: any) {
      return c.json({
        status: 'error',
        database: 'error',
        error: error.message,
      });
    }
  } catch (error: any) {
    if (error.message === 'Unauthorized') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return c.json({ error: error.message }, 500);
  }
});

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: err.message || 'Internal server error' }, 500);
});

// Export for Cloudflare Pages Functions
export const onRequest = async (context: any) => {
  return app.fetch(context.request, context.env, context);
};
