import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { GATEWAY_PORT } from '../config';
import { findExistingGatewayProcess, ensureGateway } from '../gateway';
import { restoreIfNeeded } from '../persistence';

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
    console.log('[api/status] existing process:', process?.id ?? 'none', process?.status ?? '');
    if (!process) {
      // Restore from backup only when the gateway needs to start.
      // Restoring while the gateway is running would mount a FUSE overlay
      // that interferes with createBackup.
      let restoreFailed = false;
      try {
        await Promise.race([
          restoreIfNeeded(sandbox, c.env.BACKUP_BUCKET),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Restore timeout')), 15_000),
          ),
        ]);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[api/status] Backup restore failed/timeout:', msg);
        // If restore timed out, DON'T start the gateway yet — the next poll
        // will retry the restore. Starting without the overlay would lose
        // restored files.
        if (msg.includes('timeout')) {
          return c.json({ ok: false, status: 'starting', error: 'Restore in progress' });
        }
        restoreFailed = true;
      }

      // No gateway process found — start it with a short timeout.
      // The loading page polls /api/status every few seconds, so even
      // if this attempt times out, subsequent polls will retry.
      console.log('[api/status] No process found, starting gateway...');
      const QUICK_START_TIMEOUT = 30_000;
      try {
        await Promise.race([
          ensureGateway(sandbox, c.env),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Gateway start timeout')), QUICK_START_TIMEOUT),
          ),
        ]);
        process = await findExistingGatewayProcess(sandbox);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[api/status] Gateway start failed/timeout:', msg);
        return c.json({
          ok: false,
          status: msg.includes('timeout') ? 'starting' : 'start_failed',
          error: msg,
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
