import { createHash, randomBytes } from 'node:crypto';
import { promises as fs, createReadStream } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as sleep } from 'node:timers/promises';
import { invalid } from './errors.js';

export { sleep };
export const now = () => new Date().toISOString();
export const hash = (value) => createHash('sha256').update(value).digest('hex');
export const id = (prefix) => `${prefix}_${randomBytes(10).toString('hex')}`;
export async function mkdir(directory) { await fs.mkdir(directory, { recursive: true, mode: 0o700 }); }
export async function atomicJSON(file, data) {
  await mkdir(path.dirname(file));
  const temporary = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }); }
}
export async function readJSON(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT' && arguments.length > 1) return fallback; throw error; }
}
export async function appendJSON(file, data) { await fs.appendFile(file, `${JSON.stringify(data)}\n`, { mode: 0o600 }); }
export async function* jsonLines(file) {
  try { await fs.access(file); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  const input = createReadStream(file);
  const lines = createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (!line.trim()) continue;
      try { yield JSON.parse(line); } catch { /* An interrupted final append is recoverable. */ }
    }
  } finally { lines.close(); input.destroy(); }
}
export async function latestBy(file, key = 'id') {
  const values = new Map();
  for await (const item of jsonLines(file)) values.set(item[key], item);
  return [...values.values()];
}
export function integer(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) invalid(`${name} must be an integer between ${min} and ${max}`);
  return number;
}
export function duration(value, fallback = 0) {
  if (value === undefined) return fallback;
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(String(value));
  if (!match) invalid(`Invalid duration: ${value}`);
  const result = Number(match[1]) * ({ ms: 1, s: 1000, m: 60000, h: 3600000 }[match[2] || 's']);
  if (!Number.isFinite(result) || result > 2147483647) invalid('Duration is too large');
  return result;
}
export function byteSize(value, fallback = 0) {
  if (value === undefined) return fallback;
  const match = /^(\d+(?:\.\d+)?)(b|kb|mb|gb|kib|mib|gib)?$/i.exec(String(value));
  if (!match) invalid(`Invalid byte size: ${value}`);
  const units = { b: 1, kb: 1000, mb: 1e6, gb: 1e9, kib: 1024, mib: 1048576, gib: 1073741824 };
  const result = Math.floor(Number(match[1]) * units[(match[2] || 'b').toLowerCase()]);
  if (!Number.isSafeInteger(result)) invalid('Byte size is too large');
  return result;
}
const secret = /token|secret|password|signature|credential|authorization|cookie|session|api[-_]?key|^(key|auth|sig|policy)$/i;
export function publicURL(raw) {
  try {
    const url = new URL(raw);
    url.username = ''; url.password = '';
    for (const key of [...url.searchParams.keys()]) if (secret.test(key)) url.searchParams.set(key, '[REDACTED]');
    return url.href;
  } catch { return '[invalid URL]'; }
}
export function publicHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).filter(([key]) => !secret.test(key) && !/^proxy-/i.test(key)).map(([key, value]) => [key, /^(referer|location|content-location)$/i.test(key) ? publicURL(value) : value]));
}
export function normalizeURL(raw, base) {
  try {
    const url = new URL(raw, base);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    url.hash = '';
    return url.href;
  } catch { return null; }
}
export function safeName(value) {
  const name = value.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').replace(/^[. ]+|[. ]+$/g, '').slice(0, 100) || 'resource';
  return /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name) ? `_${name}` : name;
}
export function within(root, target) {
  const relative = path.relative(path.resolve(root), path.resolve(target));
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
export async function fileHash(file) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(file)) digest.update(chunk);
  return digest.digest('hex');
}
