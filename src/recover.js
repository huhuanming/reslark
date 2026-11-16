import path from 'node:path';
import { promises as fs } from 'node:fs';
import { listSessions, registryPath } from './store.js';
import { control } from './session.js';
import { atomicJSON, readJSON, now } from './util.js';
import { restoreSystemProxy } from './platform.js';

export async function recover(home) {
  const results = [];
  for (const record of await listSessions(home)) {
    try { await control(record, '/status'); results.push({ session_id: record.session_id, action: 'running' }); continue; } catch { /* Only recover sessions whose authenticated controller is absent. */ }
    const state = path.join(record.output_dir, '.state');
    const lockPath = path.join(state, 'lock'); const lock = await readJSON(lockPath, null);
    if (lock?.session_id === record.session_id) {
      let alive = false; try { process.kill(lock.pid, 0); alive = true; } catch (error) { alive = error.code === 'EPERM'; }
      if (alive) { results.push({ session_id: record.session_id, action: 'requires-review', reason: 'LOCK_OWNER_STILL_ALIVE' }); continue; }
    }
    const proxy = await readJSON(path.join(state, 'system-proxy.json'), null);
    let restoration;
    if (proxy) {
      try { restoration = await restoreSystemProxy(proxy.snapshot, proxy.port); if (restoration.restored) await fs.rm(path.join(state, 'system-proxy.json')); }
      catch (error) { restoration = { restored: false, reason: error.code || 'RESTORE_FAILED' }; }
    }
    // Never kill a persisted PID: it may have been reused by another program.
    let unlocked = false;
    if (lock?.session_id === record.session_id) {
      await fs.rm(lockPath); unlocked = true;
    }
    if (['ready', 'starting', 'stopping', 'downloading'].includes(record.state)) {
      record.state = 'interrupted'; record.updated_at = now(); delete record.control;
      await atomicJSON(registryPath(home, record.session_id), record);
      const visible = await readJSON(path.join(record.output_dir, 'session.json'), {});
      await atomicJSON(path.join(record.output_dir, 'session.json'), { ...visible, state: record.state, updated_at: record.updated_at });
    }
    results.push({ session_id: record.session_id, action: 'checked', unlocked, ...(restoration ? { system_proxy: restoration } : {}) });
  }
  return results;
}
