/**
 * OpenClaw + Cloudflare Sandbox
 *
 * This Worker runs OpenClaw personal AI assistant in a Cloudflare Sandbox container.
 * It proxies all requests to the OpenClaw Gateway's web UI and WebSocket endpoint.
 *
 * Features:
 * - Web UI (Control Dashboard + WebChat) at /
 * - WebSocket support for real-time communication
 * - Admin UI at /_admin/ for device management
 * - Configuration via environment secrets
 *
 * Required secrets (set via `wrangler secret put`):
 * - ANTHROPIC_API_KEY: Your Anthropic API key
 *
 * Optional secrets:
 * - MOLTBOT_GATEWAY_TOKEN: Token to protect gateway access
 * - TELEGRAM_BOT_TOKEN: Telegram bot token
 * - DISCORD_BOT_TOKEN: Discord bot token
 * - SLACK_BOT_TOKEN + SLACK_APP_TOKEN: Slack tokens
 */

import { Hono } from 'hono';
import { getSandbox, Sandbox, type SandboxOptions } from '@cloudflare/sandbox';

import type { AppEnv, OpenClawEnv } from './types';
import { GATEWAY_PORT } from './config';
import { createAccessMiddleware } from './auth';
import { ensureGateway, findExistingGatewayProcess, killGateway } from './gateway';
import { publicRoutes, api, adminUi, debug, cdp } from './routes';
import { redactSensitiveParams } from './utils/logging';
import { restoreIfNeeded, createSnapshot } from './persistence';
import { shouldWakeContainer, DEFAULT_LEAD_TIME_MS, CRON_STORE_R2_KEY } from './cron/wake';
import loadingPageHtml from './assets/loading.html';
import configErrorHtml from './assets/config-error.html';

/**
 * Transform error messages from the gateway to be more user-friendly.
 */
function transformErrorMessage(message: string, host: string): string {
  if (message.includes('gateway token missing') || message.includes('gateway token mismatch')) {
    return `Invalid or missing token. Visit https://${host}?token={REPLACE_WITH_YOUR_TOKEN}`;
  }

  if (message.includes('pairing required')) {
    return `Pairing required. Visit https://${host}/_admin/`;
  }

  return message;
}

/**
 * Check if an error indicates the gateway process has crashed.
 * The Sandbox SDK throws this when containerFetch/wsConnect is called
 * but the target process is no longer listening.
 */
function isGatewayCrashedError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.message.includes('is not listening');
}

// killGateway is imported from './gateway' (shared with restart handler)

export { Sandbox };

/**
 * Validate required environment variables.
 * Returns an array of missing variable descriptions, or empty array if all are set.
 */
function validateRequiredEnv(env: OpenClawEnv): string[] {
  const missing: string[] = [];
  const isTestMode = env.DEV_MODE === 'true' || env.E2E_TEST_MODE === 'true';

  if (!env.MOLTBOT_GATEWAY_TOKEN) {
    missing.push('MOLTBOT_GATEWAY_TOKEN');
  }

  // CF Access vars not required in dev/test mode since auth is skipped
  if (!isTestMode) {
    if (!env.CF_ACCESS_TEAM_DOMAIN) {
      missing.push('CF_ACCESS_TEAM_DOMAIN');
    }

    if (!env.CF_ACCESS_AUD) {
      missing.push('CF_ACCESS_AUD');
    }
  }

  // Check for AI provider configuration (at least one must be set)
  const hasCloudflareGateway = !!(
    env.CLOUDFLARE_AI_GATEWAY_API_KEY &&
    env.CF_AI_GATEWAY_ACCOUNT_ID &&
    env.CF_AI_GATEWAY_GATEWAY_ID
  );
  const hasLegacyGateway = !!(env.AI_GATEWAY_API_KEY && env.AI_GATEWAY_BASE_URL);
  const hasAnthropicKey = !!env.ANTHROPIC_API_KEY;
  const hasOpenAIKey = !!env.OPENAI_API_KEY;

  if (!hasCloudflareGateway && !hasLegacyGateway && !hasAnthropicKey && !hasOpenAIKey) {
    missing.push(
      'ANTHROPIC_API_KEY, OPENAI_API_KEY, or CLOUDFLARE_AI_GATEWAY_API_KEY + CF_AI_GATEWAY_ACCOUNT_ID + CF_AI_GATEWAY_GATEWAY_ID',
    );
  }

  return missing;
}

/**
 * Build sandbox options based on environment configuration.
 *
 * SANDBOX_SLEEP_AFTER controls how long the container stays alive after inactivity:
 * - 'never' (default): Container stays alive indefinitely (recommended due to long cold starts)
 * - Duration string: e.g., '10m', '1h', '30s' - container sleeps after this period of inactivity
 *
 * To reduce costs at the expense of cold start latency, set SANDBOX_SLEEP_AFTER to a duration:
 *   npx wrangler secret put SANDBOX_SLEEP_AFTER
 *   # Enter: 10m (or 1h, 30m, etc.)
 */
function buildSandboxOptions(env: OpenClawEnv): SandboxOptions {
  const sleepAfter = env.SANDBOX_SLEEP_AFTER?.toLowerCase() || 'never';

  // 'never' means keep the container alive indefinitely
  if (sleepAfter === 'never') {
    return { keepAlive: true };
  }

  // Otherwise, use the specified duration
  return { sleepAfter };
}

// Main app
const app = new Hono<AppEnv>();

// =============================================================================
// MIDDLEWARE: Applied to ALL routes
// =============================================================================

// Middleware: Log every request
app.use('*', async (c, next) => {
  const url = new URL(c.req.url);
  const redactedSearch = redactSensitiveParams(url);
  console.log(`[REQ] ${c.req.method} ${url.pathname}${redactedSearch}`);
  console.log(`[REQ] Has ANTHROPIC_API_KEY: ${!!c.env.ANTHROPIC_API_KEY}`);
  console.log(`[REQ] DEV_MODE: ${c.env.DEV_MODE}`);
  console.log(`[REQ] DEBUG_ROUTES: ${c.env.DEBUG_ROUTES}`);
  await next();
});

// Middleware: Initialize sandbox stub and restore backup if available.
// Note: we intentionally do NOT call sandbox.start() here. The Sandbox SDK's
// containerFetch() auto-starts the container when needed, and the catch-all
// proxy route uses ensureGateway() which handles startup explicitly.
// Adding start() here would add an unnecessary RPC call on every request,
// including static assets and health checks that don't need the container.
app.use('*', async (c, next) => {
  const options = buildSandboxOptions(c.env);
  const sandbox = getSandbox(c.env.Sandbox, 'openclaw', options);
  c.set('sandbox', sandbox);

  // NOTE: restoreIfNeeded is NOT called here in the global middleware.
  // It's called only from the catch-all route (gateway proxy) and /api/status.
  // Calling it on admin routes (sync, debug/cli) would mount a FUSE overlay
  // that interferes with createBackup — the SDK resets the overlay on backup,
  // wiping any upper-layer writes made since the last restore.

  await next();
});

// =============================================================================
// PUBLIC ROUTES: No Cloudflare Access authentication required
// =============================================================================

// Mount public routes first (before auth middleware)
// Includes: /sandbox-health, /logo.png, /logo-small.png, /api/status, /_admin/assets/*
app.route('/', publicRoutes);

// Mount CDP routes (uses shared secret auth via query param, not CF Access)
app.route('/cdp', cdp);

// =============================================================================
// PROTECTED ROUTES: Cloudflare Access authentication required
// =============================================================================

// Middleware: Validate required environment variables (skip in dev mode and for debug routes)
app.use('*', async (c, next) => {
  const url = new URL(c.req.url);

  // Skip validation for debug routes (they have their own enable check)
  if (url.pathname.startsWith('/debug')) {
    return next();
  }

  // Skip validation in dev mode
  if (c.env.DEV_MODE === 'true') {
    return next();
  }

  const missingVars = validateRequiredEnv(c.env);
  if (missingVars.length > 0) {
    console.error('[CONFIG] Missing required environment variables:', missingVars.join(', '));

    const acceptsHtml = c.req.header('Accept')?.includes('text/html');
    if (acceptsHtml) {
      // Return a user-friendly HTML error page
      const html = configErrorHtml.replace('{{MISSING_VARS}}', missingVars.join(', '));
      return c.html(html, 503);
    }

    // Return JSON error for API requests
    return c.json(
      {
        error: 'Configuration error',
        message: 'Required environment variables are not configured',
        missing: missingVars,
        hint: 'Set these using: wrangler secret put <VARIABLE_NAME>',
      },
      503,
    );
  }

  return next();
});

// Middleware: Cloudflare Access authentication for protected routes
app.use('*', async (c, next) => {
  // Determine response type based on Accept header
  const acceptsHtml = c.req.header('Accept')?.includes('text/html');
  const middleware = createAccessMiddleware({
    type: acceptsHtml ? 'html' : 'json',
    redirectOnMissing: acceptsHtml,
  });

  return middleware(c, next);
});

// Mount API routes (protected by Cloudflare Access)
app.route('/api', api);

// Mount Admin UI routes (protected by Cloudflare Access)
app.route('/_admin', adminUi);

// Mount debug routes (protected by Cloudflare Access, only when DEBUG_ROUTES is enabled)
app.use('/debug/*', async (c, next) => {
  if (c.env.DEBUG_ROUTES !== 'true') {
    return c.json({ error: 'Debug routes are disabled' }, 404);
  }
  return next();
});
app.route('/debug', debug);

// =============================================================================
// CATCH-ALL: Proxy to OpenClaw gateway
// =============================================================================

app.all('*', async (c) => {
  const sandbox = c.get('sandbox');
  const request = c.req.raw;
  const url = new URL(request.url);

  console.log('[PROXY] Handling request:', url.pathname);

  // Check if gateway is already running (with timeout to avoid hanging on cold start)
  let existingProcess = null;
  try {
    existingProcess = await Promise.race([
      findExistingGatewayProcess(sandbox),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 10_000)),
    ]);
  } catch {
    // Treat as not running
  }
  const isGatewayReady = existingProcess !== null && existingProcess.status === 'running';

  // Only restore from backup when the gateway needs to start.
  // Restoring on every request (including WebSocket reconnects) would mount a
  // FUSE overlay that interferes with createBackup — the SDK resets the overlay
  // on backup, wiping upper-layer writes.
  let restoreTimedOut = false;
  if (!isGatewayReady) {
    try {
      await Promise.race([
        restoreIfNeeded(sandbox, c.env.BACKUP_BUCKET),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Restore timeout')), 15_000)),
      ]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[PROXY] Backup restore failed/timeout:', msg);
      if (msg.includes('timeout')) restoreTimedOut = true;
    }
  }

  // For browser requests (non-WebSocket, non-API), show loading page if gateway isn't ready
  const isWebSocketRequest = request.headers.get('Upgrade')?.toLowerCase() === 'websocket';
  const acceptsHtml = request.headers.get('Accept')?.includes('text/html');

  if (!isGatewayReady && !isWebSocketRequest && acceptsHtml) {
    console.log('[PROXY] Gateway not ready, serving loading page');

    // Only start the gateway if restore didn't time out — starting without
    // the FUSE overlay would lose restored files. The loading page polls
    // /api/status which will retry the restore.
    if (!restoreTimedOut) {
      c.executionCtx.waitUntil(
        ensureGateway(sandbox, c.env).catch((err: Error) => {
          console.error('[PROXY] Background gateway start failed:', err);
        }),
      );
    }

    // Return the loading page immediately
    return c.html(loadingPageHtml);
  }

  // Ensure gateway is running (this will wait for startup)
  try {
    await ensureGateway(sandbox, c.env);
  } catch (error) {
    console.error('[PROXY] Failed to start gateway:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    let hint = 'Check worker logs with: wrangler tail';
    if (!c.env.ANTHROPIC_API_KEY) {
      hint = 'ANTHROPIC_API_KEY is not set. Run: wrangler secret put ANTHROPIC_API_KEY';
    } else if (errorMessage.includes('heap out of memory') || errorMessage.includes('OOM')) {
      hint = 'Gateway ran out of memory. Try again or check for memory leaks.';
    }

    return c.json(
      {
        error: 'Gateway failed to start',
        details: errorMessage,
        hint,
      },
      503,
    );
  }

  // Proxy to gateway with WebSocket message interception
  if (isWebSocketRequest) {
    const debugLogs = c.env.DEBUG_ROUTES === 'true';
    const redactedSearch = redactSensitiveParams(url);

    console.log('[WS] Proxying WebSocket connection to gateway');
    if (debugLogs) {
      console.log('[WS] URL:', url.pathname + redactedSearch);
    }

    // Inject gateway token into WebSocket request if not already present.
    // CF Access redirects strip query params, so authenticated users lose ?token=.
    // Since the user already passed CF Access auth, we inject the token server-side.
    let wsRequest = request;
    if (c.env.MOLTBOT_GATEWAY_TOKEN && !url.searchParams.has('token')) {
      const tokenUrl = new URL(url.toString());
      tokenUrl.searchParams.set('token', c.env.MOLTBOT_GATEWAY_TOKEN);
      wsRequest = new Request(tokenUrl.toString(), request);
    }

    // Get WebSocket connection to the container (with retry on crash)
    let containerResponse: Response;
    try {
      containerResponse = await sandbox.wsConnect(wsRequest, GATEWAY_PORT);
    } catch (err) {
      if (isGatewayCrashedError(err)) {
        console.log('[WS] Gateway crashed, attempting restart and retry...');
        await killGateway(sandbox);
        await ensureGateway(sandbox, c.env);
        try {
          containerResponse = await sandbox.wsConnect(wsRequest, GATEWAY_PORT);
        } catch (retryErr) {
          console.error('[WS] Retry after restart also failed:', retryErr);
          return new Response('Gateway crashed and recovery failed', { status: 503 });
        }
      } else {
        console.error('[WS] WebSocket proxy error:', err);
        return new Response('WebSocket proxy error', { status: 502 });
      }
    }
    console.log('[WS] wsConnect response status:', containerResponse.status);

    // Get the container-side WebSocket
    const containerWs = containerResponse.webSocket;
    if (!containerWs) {
      console.error('[WS] No WebSocket in container response - falling back to direct proxy');
      return containerResponse;
    }

    if (debugLogs) {
      console.log('[WS] Got container WebSocket, setting up interception');
    }

    // Create a WebSocket pair for the client
    const [clientWs, serverWs] = Object.values(new WebSocketPair());

    // Accept both WebSockets
    serverWs.accept();
    containerWs.accept();

    if (debugLogs) {
      console.log('[WS] Both WebSockets accepted');
      console.log('[WS] containerWs.readyState:', containerWs.readyState);
      console.log('[WS] serverWs.readyState:', serverWs.readyState);
    }

    // Relay messages from client to container
    serverWs.addEventListener('message', (event) => {
      if (debugLogs) {
        console.log(
          '[WS] Client -> Container:',
          typeof event.data,
          typeof event.data === 'string' ? event.data.slice(0, 200) : '(binary)',
        );
      }
      if (containerWs.readyState === WebSocket.OPEN) {
        containerWs.send(event.data);
      } else if (debugLogs) {
        console.log('[WS] Container not open, readyState:', containerWs.readyState);
      }
    });

    // Relay messages from container to client, with error transformation
    containerWs.addEventListener('message', (event) => {
      if (debugLogs) {
        console.log(
          '[WS] Container -> Client (raw):',
          typeof event.data,
          typeof event.data === 'string' ? event.data.slice(0, 500) : '(binary)',
        );
      }
      let data = event.data;

      // Try to intercept and transform error messages
      if (typeof data === 'string') {
        try {
          const parsed = JSON.parse(data);
          if (debugLogs) {
            console.log('[WS] Parsed JSON, has error.message:', !!parsed.error?.message);
          }
          if (parsed.error?.message) {
            if (debugLogs) {
              console.log('[WS] Original error.message:', parsed.error.message);
            }
            parsed.error.message = transformErrorMessage(parsed.error.message, url.host);
            if (debugLogs) {
              console.log('[WS] Transformed error.message:', parsed.error.message);
            }
            data = JSON.stringify(parsed);
          }
        } catch (e) {
          if (debugLogs) {
            console.log('[WS] Not JSON or parse error:', e);
          }
        }
      }

      if (serverWs.readyState === WebSocket.OPEN) {
        serverWs.send(data);
      } else if (debugLogs) {
        console.log('[WS] Server not open, readyState:', serverWs.readyState);
      }
    });

    // Handle close events
    serverWs.addEventListener('close', (event) => {
      if (debugLogs) {
        console.log('[WS] Client closed:', event.code, event.reason);
      }
      containerWs.close(event.code, event.reason);
    });

    containerWs.addEventListener('close', (event) => {
      if (debugLogs) {
        console.log('[WS] Container closed:', event.code, event.reason);
      }
      // Transform the close reason (truncate to 123 bytes max for WebSocket spec)
      let reason = transformErrorMessage(event.reason, url.host);
      if (reason.length > 123) {
        reason = reason.slice(0, 120) + '...';
      }
      if (debugLogs) {
        console.log('[WS] Transformed close reason:', reason);
      }
      serverWs.close(event.code, reason);
    });

    // Handle errors
    serverWs.addEventListener('error', (event) => {
      console.error('[WS] Client error:', event);
      containerWs.close(1011, 'Client error');
    });

    containerWs.addEventListener('error', (event) => {
      console.error('[WS] Container error:', event);
      serverWs.close(1011, 'Container error');
    });

    if (debugLogs) {
      console.log('[WS] Returning intercepted WebSocket response');
    }
    return new Response(null, {
      status: 101,
      webSocket: clientWs,
    });
  }

  console.log('[HTTP] Proxying:', url.pathname + url.search);

  let httpResponse: Response;
  try {
    httpResponse = await sandbox.containerFetch(request, GATEWAY_PORT);
  } catch (err) {
    if (isGatewayCrashedError(err)) {
      console.log('[HTTP] Gateway crashed, attempting restart and retry...');
      await killGateway(sandbox);
      await ensureGateway(sandbox, c.env);
      try {
        httpResponse = await sandbox.containerFetch(request, GATEWAY_PORT);
      } catch (retryErr) {
        console.error('[HTTP] Retry after restart also failed:', retryErr);
        return c.json({ error: 'Gateway crashed and recovery failed' }, 503);
      }
    } else {
      console.error('[HTTP] Proxy error:', err);
      return c.json(
        { error: 'Proxy error', message: err instanceof Error ? err.message : String(err) },
        502,
      );
    }
  }
  console.log('[HTTP] Response status:', httpResponse.status);

  // Add debug header to verify worker handled the request
  const newHeaders = new Headers(httpResponse.headers);
  newHeaders.set('X-Worker-Debug', 'proxy-to-gateway');
  newHeaders.set('X-Debug-Path', url.pathname);

  return new Response(httpResponse.body, {
    status: httpResponse.status,
    statusText: httpResponse.statusText,
    headers: newHeaders,
  });
});

/**
 * Handle Workers Cron Trigger: wake the container if OpenClaw has upcoming cron jobs.
 *
 * Reads the cron job store from R2 (synced by the background sync loop in the container)
 * and checks if any job is scheduled to fire within the lead time window. If so, wakes
 * the container so OpenClaw's internal timers can fire on time.
 *
 * Configure via environment variables:
 * - CRON_WAKE_AHEAD_MINUTES: How many minutes before a cron job to wake (default: 10)
 *
 * Configure the check interval in wrangler.jsonc triggers.crons (default: every 1 minute).
 */
async function handleScheduled(env: OpenClawEnv): Promise<void> {
  const cronStoreObject = await env.BACKUP_BUCKET.get(CRON_STORE_R2_KEY);
  if (!cronStoreObject) {
    console.log('[CRON] No cron store found in R2, skipping');
    return;
  }

  const cronStoreJson = await cronStoreObject.text();
  const leadMinutes = parseInt(env.CRON_WAKE_AHEAD_MINUTES || '', 10);
  const leadTimeMs = leadMinutes > 0 ? leadMinutes * 60 * 1000 : DEFAULT_LEAD_TIME_MS;
  const nowMs = Date.now();

  const earliestRun = shouldWakeContainer(cronStoreJson, nowMs, leadTimeMs);
  if (!earliestRun) {
    console.log('[CRON] No upcoming cron jobs within lead time, skipping wake');
    return;
  }

  const deltaMinutes = ((earliestRun - nowMs) / 60_000).toFixed(1);
  console.log(`[CRON] Cron job due in ${deltaMinutes}m, waking container`);

  const sandbox = getSandbox(env.Sandbox, 'openclaw', buildSandboxOptions(env));
  await ensureGateway(sandbox, env);
  console.log('[CRON] Container woken successfully');
}

export default {
  fetch: app.fetch,
  async scheduled(_controller: ScheduledController, env: OpenClawEnv, ctx: ExecutionContext) {
    ctx.waitUntil(handleScheduled(env));
  },
};
