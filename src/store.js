import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { atomicJSON, readJSON, mkdir, appendJSON, now, id, latestBy } from './util.js';
import { fail, invalid } from './errors.js';

export function homeDir(value) { return path.resolve(value || process.env.RESLARK_HOME || path.join(os.homedir(), '.reslark')); }
export function registryPath(home, session) {
  if (!/^s_[a-f0-9]{20}$/.test(session || '')) invalid('Expected a session ID (s_...)');
  return path.join(home, 'sessions', `${session}.json`);
}
export async function loadSession(home, session) {
  const record = await readJSON(registryPath(home, session), null);
  if (!record) fail('SESSION_NOT_FOUND', `Session ${session} does not exist`, { exitCode: 3 });
  return record;
}
export async function listSessions(home) {
  await mkdir(path.join(home, 'sessions'));
  const files = await fs.readdir(path.join(home, 'sessions'));
  return (await Promise.all(files.filter((file) => /^s_[a-f0-9]{20}\.json$/.test(file)).map((file) => readJSON(path.join(home, 'sessions', file))))).sort((a, b) => b.created_at.localeCompare(a.created_at));
}
export class Store {
  constructor(home, config, sessionId = id('s')) {
    this.home = home; this.config = config; this.id = sessionId;
    this.out = config.out; this.state = path.join(this.out, '.state');
    this.seq = 0; this.writes = Promise.resolve();
    this.record = { schema_version: 1, session_id: this.id, state: 'starting', created_at: now(), output_dir: this.out, config, counts: { resources: 0, files: 0, bytes: 0, errors: 0 }, limitations: [] };
  }
  async init() {
    await mkdir(this.home); await mkdir(path.join(this.home, 'sessions'));
    await mkdir(this.out); await mkdir(this.state);
    const existing = await readJSON(path.join(this.out, 'session.json'), null);
    if (existing && existing.session_id !== this.id) fail('OUTPUT_IN_USE', 'Choose a fresh output directory; this directory belongs to another session');
    try { this.lock = await fs.open(path.join(this.state, 'lock'), 'wx', 0o600); }
    catch (error) { if (error.code === 'EEXIST') fail('OUTPUT_LOCKED', 'Output directory is owned by another or interrupted session; use recover first'); throw error; }
    await this.lock.writeFile(JSON.stringify({ session_id: this.id, pid: process.pid, home: this.home }));
    await mkdir(path.join(this.state, 'spool')); await mkdir(path.join(this.out, 'files')); await mkdir(path.join(this.out, 'manifests'));
    await this.save();
  }
  serial(operation) {
    const result = this.writes.then(operation);
    this.writes = result.catch(() => {});
    return result;
  }
  async save() {
    return this.serial(async () => {
      this.record.updated_at = now();
      await atomicJSON(registryPath(this.home, this.id), this.record);
      const { control, config, ...visible } = this.record;
      const { command, cdp, ...publicConfig } = config;
      await atomicJSON(path.join(this.out, 'session.json'), { ...visible, config: publicConfig, ...(command?.length ? { command: '[private]' } : {}) });
    });
  }
  async event(type, details = {}) {
    return this.serial(async () => {
      const event = { schema_version: 1, seq: ++this.seq, time: now(), type, session_id: this.id, ...details };
      await appendJSON(path.join(this.out, 'events.jsonl'), event);
      return event;
    });
  }
  async resource(record, privateRecord) {
    await this.serial(async () => {
      await appendJSON(path.join(this.out, 'resources.jsonl'), record);
      if (privateRecord) await appendJSON(path.join(this.state, 'resources.jsonl'), privateRecord);
    });
  }
  async relation(relation) { await this.serial(() => appendJSON(path.join(this.out, 'relations.jsonl'), relation)); }
  async download(record) { await this.serial(() => appendJSON(path.join(this.out, 'downloads.jsonl'), record)); }
  async close() {
    await this.writes;
    if (this.lock) { await this.lock.close(); await fs.rm(path.join(this.state, 'lock'), { force: true }); this.lock = null; }
  }
}
export async function resourcesFor(record, privateData = false) {
  return latestBy(path.join(record.output_dir, privateData ? '.state/resources.jsonl' : 'resources.jsonl'));
}
