import fs from 'node:fs';

/**
 * The data folder holds password hashes, API token hashes, session hashes and the encrypted device secrets, so only the
 * account that runs FlowScope should be able to read it. Unix only. Set FLOWSCOPE_KEEP_DATA_PERMS=1 to leave permissions alone,
 * for example when a backup account reads the folder through group access.
 */
function enabled(): boolean { return process.platform !== 'win32' && process.env.FLOWSCOPE_KEEP_DATA_PERMS !== '1'; }
function ours(st: fs.Stats): boolean { return typeof process.getuid !== 'function' || st.uid === process.getuid(); }

/** Creates the folder if needed and removes group and other access from it. Folders that belong to someone else are left as they are. */
export function secureDataDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
  if (!enabled()) return;
  try {
    const st = fs.statSync(dir);
    if (ours(st) && (st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
  } catch { /* a read-only or foreign mount: nothing to change */ }
}

/** Limits a database file and its SQLite side files to the owner. */
export function secureDbFiles(file: string): void {
  if (!enabled()) return;
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      const st = fs.statSync(file + suffix);
      if (ours(st) && (st.mode & 0o077) !== 0) fs.chmodSync(file + suffix, 0o600);
    } catch { /* the side files exist only while the database is in use */ }
  }
}
