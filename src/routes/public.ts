import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { GATEWAY_PORT } from '../config';
import { findExistingGatewayProcess, ensureGateway } from '../gateway';

/**
 * Public routes - NO Cloudflare Access authentication required
 *
 * These routes are mounted BEFORE the auth middleware is applied.
 * Includes: health checks, static assets, and public API endpoints.
 */
const publicRoutes = new Hono<AppEnv>();

// GET /sandbox-health - Health check endpoint
publicRoutes.get('/sandbox-health', (c) => {
  return c.json({
    status: 'ok',
    service: 'openclaw-sandbox',
    gateway_port: GATEWAY_PORT,
  });
});

// GET /logo.png - Serve logo from ASSETS binding
publicRoutes.get('/logo.png', (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

// GET /logo-small.png - Serve small logo from ASSETS binding
publicRoutes.get('/logo-small.png', (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

// GET /api/status - Public health check for gateway status (no auth required)
publicRoutes.get('/api/status', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    let process = await findExistingGatewayProcess(sandbox);
    if (!process) {
      // No gateway process found — start it synchronously.
      // The loading page polls /api/status, so this ensures the gateway
      // eventually starts even if the initial waitUntil from the catch-all
      // route didn't fire (e.g., due to DO execution context limitations).
      try {
        await ensureGateway(sandbox, c.env);
        process = await findExistingGatewayProcess(sandbox);
      } catch (err: unknown) {
        console.error('[api/status] Gateway start failed:', err);
        return c.json({
          ok: false,
          status: 'start_failed',
          error: err instanceof Error ? err.message : String(err),
        });
      }
      if (!process) {
        return c.json({ ok: false, status: 'not_running' });
      }
    }

    // Process exists, check if it's actually responding
    // Try to reach the gateway with a short timeout
    try {
      await process.waitForPort(18789, { mode: 'tcp', timeout: 5000 });
      return c.json({ ok: true, status: 'running', processId: process.id });
    } catch {
      return c.json({ ok: false, status: 'not_responding', processId: process.id });
    }
  } catch (err) {
    return c.json({
      ok: false,
      status: 'error',
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

// GET /_admin/assets/* - Admin UI static assets (CSS, JS need to load for login redirect)
// Assets are built to dist/client with base "/_admin/"
publicRoutes.get('/_admin/assets/*', async (c) => {
  const url = new URL(c.req.url);
  // Rewrite /_admin/assets/* to /assets/* for the ASSETS binding
  const assetPath = url.pathname.replace('/_admin/assets/', '/assets/');
  const assetUrl = new URL(assetPath, url.origin);
  return c.env.ASSETS.fetch(new Request(assetUrl.toString(), c.req.raw));
});

export { publicRoutes };
