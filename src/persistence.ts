import type { Sandbox } from '@cloudflare/sandbox';

const BACKUP_DIR = '/home/openclaw';
const HANDLE_KEY = 'backup-handle.json';

// Tracks whether a restore has already happened in this Worker isolate lifetime.
// The FUSE mount is ephemeral — lost when the container sleeps or restarts —
// but within a single isolate we only need to restore once.
let restored = false;

export function clearPersistenceCache(): void {
  restored = false;
}

async function getStoredHandle(bucket: R2Bucket): Promise<{ id: string; dir: string } | null> {
  const obj = await bucket.get(HANDLE_KEY);
  if (!obj) return null;
  return obj.json();
}

async function storeHandle(bucket: R2Bucket, handle: { id: string; dir: string }): Promise<void> {
  await bucket.put(HANDLE_KEY, JSON.stringify(handle));
}

async function deleteHandle(bucket: R2Bucket): Promise<void> {
  await bucket.delete(HANDLE_KEY);
}

/**
 * Restore the most recent backup if one exists and hasn't been restored yet.
 * Called on every request before proxying to the gateway.
 *
 * The backup handle is read from R2 (persisted across Worker isolate restarts).
 * An in-memory flag prevents redundant restores within the same isolate.
 */
export async function restoreIfNeeded(sandbox: Sandbox, bucket: R2Bucket): Promise<void> {
  if (restored) return;

  const handle = await getStoredHandle(bucket);
  if (!handle) {
    console.log('[persistence] No backup handle found in R2, skipping restore');
    restored = true;
    return;
  }

  console.log(`[persistence] Restoring backup ${handle.id}...`);
  const t0 = Date.now();
  try {
    await sandbox.restoreBackup(handle);
    console.log(`[persistence] Restore complete in ${Date.now() - t0}ms`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('BACKUP_EXPIRED') || msg.includes('BACKUP_NOT_FOUND')) {
      console.log(`[persistence] Backup ${handle.id} expired/gone, clearing handle`);
      await deleteHandle(bucket);
    } else {
      console.error(`[persistence] Restore failed:`, err);
      throw err;
    }
  }
  restored = true;
}

/**
 * Create a new snapshot of /home/openclaw (config + workspace + skills).
 *
 * Follows the delete-then-write pattern from the Cloudflare docs: the previous
 * backup's R2 objects are removed before creating a new one, and the handle is
 * persisted to R2 for cross-isolate access.
 *
 * The Sandbox SDK only allows backup of directories under /home, /workspace,
 * /tmp, or /var/tmp. The Dockerfile sets HOME=/home/openclaw and symlinks
 * /root/.openclaw and /root/clawd there.
 */
export async function createSnapshot(
  sandbox: Sandbox,
  bucket: R2Bucket,
): Promise<{ id: string; dir: string }> {
  // Delete previous backup objects from R2
  const previousHandle = await getStoredHandle(bucket);
  if (previousHandle) {
    await bucket.delete(`backups/${previousHandle.id}/data.sqsh`);
    await bucket.delete(`backups/${previousHandle.id}/meta.json`);
  }

  console.log('[persistence] Creating backup...');
  const t0 = Date.now();
  const handle = await sandbox.createBackup({
    dir: BACKUP_DIR,
    ttl: 604800, // 7 days
  });

  await storeHandle(bucket, handle);
  console.log(`[persistence] Backup ${handle.id} created in ${Date.now() - t0}ms`);
  return handle;
}

/**
 * Get the last stored backup handle (for status reporting).
 */
export async function getLastBackupId(bucket: R2Bucket): Promise<string | null> {
  const handle = await getStoredHandle(bucket);
  return handle?.id ?? null;
}
