import { Hono } from 'hono';
import { getSession, setSession, clearSession, requireAuth } from './lib/session';
import { lookupThreat } from './lib/providers';

type Bindings = {
  DB: D1Database;
  SESSION_SECRET: string;
  VT_API_KEY?: string;
  THREATFOX_API_KEY?: string;
  OTX_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
  IBM_XF_API_KEY?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Root route - serve SPA container
app.get('/', (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
  <div id="app"></div>
  <script src="/app.js"></script>
</body>
</html>`);
});

// Login endpoint
app.post('/api/login', async (c) => {
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
app.post('/api/logout', (c) => {
  clearSession(c);
  return c.json({ success: true });
});

// Session check endpoint
app.get('/api/session', async (c) => {
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
app.get('/api/profile', async (c) => {
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
app.post('/api/threat-lookup', async (c) => {
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

// API Sandbox - Outbound health check
app.get('/api/health/outbound', async (c) => {
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
app.get('/api/health/internal', async (c) => {
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

export const onRequest = app.fetch;
