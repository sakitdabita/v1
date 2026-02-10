import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { Context } from 'hono';

export interface SessionData {
  username: string;
}

// Simple HMAC-based signing for cookies
async function signData(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyData(data: string, signature: string, secret: string): Promise<boolean> {
  const expectedSignature = await signData(data, secret);
  return expectedSignature === signature;
}

export async function getSession(c: Context): Promise<SessionData | null> {
  const sessionSecret = c.env.SESSION_SECRET as string;
  if (!sessionSecret) {
    throw new Error('SESSION_SECRET not configured');
  }

  const sessionCookie = getCookie(c, 'session');
  const signatureCookie = getCookie(c, 'session.sig');

  if (!sessionCookie || !signatureCookie) {
    return null;
  }

  const isValid = await verifyData(sessionCookie, signatureCookie, sessionSecret);
  if (!isValid) {
    return null;
  }

  try {
    return JSON.parse(decodeURIComponent(sessionCookie));
  } catch {
    return null;
  }
}

export async function setSession(c: Context, data: SessionData): Promise<void> {
  const sessionSecret = c.env.SESSION_SECRET as string;
  if (!sessionSecret) {
    throw new Error('SESSION_SECRET not configured');
  }

  const sessionData = encodeURIComponent(JSON.stringify(data));
  const signature = await signData(sessionData, sessionSecret);

  setCookie(c, 'session', sessionData, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 60 * 60 * 24 * 7, // 7 days
    path: '/',
  });

  setCookie(c, 'session.sig', signature, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
  });
}

export function clearSession(c: Context): void {
  deleteCookie(c, 'session', { path: '/' });
  deleteCookie(c, 'session.sig', { path: '/' });
}

export async function requireAuth(c: Context): Promise<SessionData> {
  const session = await getSession(c);
  if (!session) {
    throw new Error('Unauthorized');
  }
  return session;
}
