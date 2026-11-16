import { spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { atomicJSON, mkdir, now } from './util.js';
import { ReslarkError, fail } from './errors.js';
import { hostRegex } from './rules.js';

export const exec = promisify(execFile);
export const addonPath = fileURLToPath(new URL('../addon/reslark.py', import.meta.url));
export function mitmBinary(config = {}) { return config.mitmdump || process.env.RESLARK_MITMDUMP || 'mitmdump'; }
export async function probe(binary, args = ['--version']) {
  try { const { stdout, stderr } = await exec(binary, args, { timeout: 10000, windowsHide: true, maxBuffer: 1024 * 1024 }); return { available: true, version: (stdout || stderr).trim() }; }
  catch (error) { return { available: false, error: error.code || 'EXEC_FAILED' }; }
}
export async function requireBackend(config) {
  const binary = mitmBinary(config);
  const info = await probe(binary);
  if (!info.available) fail('BACKEND_UNAVAILABLE', 'mitmdump is required. Install mitmproxy or set RESLARK_MITMDUMP to its executable.', { exitCode: 3, details: { executable: binary } });
  return binary;
}
export function backendArgs(config, configPath, caDir) {
  const args = ['-q', '-s', addonPath, '--listen-host', '127.0.0.1', '--listen-port', String(config.port), '--set', `confdir=${caDir}`, '--set', 'flow_detail=0', '--set', 'termlog_verbosity=error', '--set', 'websocket=true'];
  if (config.mode === 'local') {
    args.push('--mode', `local:${config.processes.join(',')}`);
  } else if (config.upstream) {
    args.push('--mode', `upstream:${config.upstream}`);
  } else args.push('--mode', 'regular');
  if (!config.related && config.domains.length) for (const expression of hostRegex(config.domains)) args.push('--set', `allow_hosts=${expression}`);
  for (const expression of hostRegex(config.exclude)) args.push('--set', `ignore_hosts=${expression}`);
  if (config.anticache) args.push('--set', 'anticache=true');
  if (config.insecure) args.push('--ssl-insecure');
  return args;
}
export async function startBackend(store, onMessage) {
  const config = store.config;
  const binary = await requireBackend(config);
  const caDir = path.join(store.home, 'ca');
  await mkdir(caDir);
  const configPath = path.join(store.state, 'backend.json');
  await atomicJSON(configPath, { spool: path.join(store.state, 'spool'), scan_bytes: config.scanBytes, max_body_bytes: config.maxBodyBytes, max_spool_bytes: config.maxSpoolBytes, targets: config.mode === 'local' ? path.join(store.state, 'targets.json') : null });
  const log = await fs.open(path.join(store.state, 'backend.log'), 'a', 0o600);
  const child = spawn(binary, backendArgs(config, configPath, caDir), { env: { ...process.env, RESLARK_CONFIG: configPath, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['ignore', 'pipe', log.fd], windowsHide: true });
  await log.close();
  const lines = createInterface({ input: child.stdout });
  let ready = false;
  let chain = Promise.resolve();
  let queued = 0;
  let failure;
  const exited = new Promise((resolve) => child.once('close', (code, signal) => resolve({ code, signal, time: now() })));
  const startup = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new ReslarkError('BACKEND_START_TIMEOUT', 'mitmdump did not become ready in 30 seconds; inspect .state/backend.log', { exitCode: 3 })), 30000);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code) => { clearTimeout(timer); if (!ready) reject(new ReslarkError('BACKEND_START_FAILED', `mitmdump exited with code ${code}; inspect .state/backend.log`, { exitCode: 3 })); });
    lines.on('line', (line) => {
      if (!line.startsWith('RESLARK:')) return;
      let message;
      try { message = JSON.parse(line.slice('RESLARK:'.length)); } catch { return; }
      if (message.type === 'backend.ready') { ready = true; clearTimeout(timer); resolve(); return; }
      queued++;
      if (queued >= 100) child.stdout.pause();
      chain = chain.then(() => onMessage(message)).catch((error) => { failure ||= error; child.kill('SIGTERM'); }).finally(() => { queued--; if (queued < 50) child.stdout.resume(); });
    });
  });
  try { await startup; } catch (error) { child.kill('SIGTERM'); await exited; throw error; }
  return {
    child, exited,
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      const force = setTimeout(() => child.kill('SIGKILL'), 8000);
      await exited; clearTimeout(force); await chain; lines.close();
      if (failure) throw failure;
    },
  };
}
