import path from 'node:path';
import { promises as fs } from 'node:fs';
import { spawn } from 'node:child_process';
import { resourcesFor } from './store.js';
import { mkdir, normalizeURL, safeName, id, within } from './util.js';
import { probe } from './backend.js';
import { ReslarkError, fail } from './errors.js';

export async function mergeMedia(record, resourceId, { out, allowNetwork = false, duration = 0, ffmpeg = process.env.RESLARK_FFMPEG || 'ffmpeg' } = {}) {
  if (allowNetwork && record.config.exclude.length) fail('MEDIA_NETWORK_SCOPE', 'ffmpeg network mode cannot enforce session exclusions; use fully captured local resources');
  if (!(await probe(ffmpeg, ['-version'])).available) fail('MEDIA_BACKEND_UNAVAILABLE', 'Install ffmpeg or set RESLARK_FFMPEG', { exitCode: 3 });
  const resources = await resourcesFor(record, true);
  const resource = resources.find((item) => item.id === resourceId);
  if (!resource?.path || resource.kind !== 'manifest') fail('MANIFEST_NOT_FOUND', 'Select a saved HLS or DASH manifest');
  if (!resource.complete || !within(record.output_dir, path.resolve(record.output_dir, resource.path))) fail('MANIFEST_INCOMPLETE', 'Manifest must be complete and inside the session directory');
  const directory = path.join(record.output_dir, '.state', 'media', id('m')); await mkdir(directory);
  const byURL = new Map(resources.filter((item) => item.complete && item.path).map((item) => [item.url, item]));
  const prepared = new Map();
  const prepare = async (item) => {
    if (prepared.has(item.id)) return prepared.get(item.id);
    const original = path.resolve(record.output_dir, item.path);
    if (!within(record.output_dir, original)) throw new ReslarkError('INVALID_RESOURCE_PATH', 'Resource path is outside session directory');
    if (item.kind !== 'manifest') return original;
    const target = path.join(directory, `${item.id}${new URL(item.url).pathname.endsWith('.mpd') ? '.mpd' : '.m3u8'}`); prepared.set(item.id, target);
    let text = await fs.readFile(original, 'utf8');
    const resolve = async (value) => {
      const url = normalizeURL(value, item.url); const found = byURL.get(url);
      if (found) return prepare(found);
      if (allowNetwork && url) return url;
      throw new ReslarkError('MEDIA_RESOURCE_MISSING', 'Manifest references an uncaptured resource. Complete the capture/download or explicitly use --allow-network.');
    };
    if (text.trimStart().startsWith('#EXTM3U')) {
      const lines = [];
      for (const line of text.split(/\r?\n/)) {
        if (line.trim() && !line.startsWith('#')) lines.push(await resolve(line.trim()));
        else {
          let updated = line;
          for (const match of line.matchAll(/URI="([^"]+)"/g)) updated = updated.replace(match[0], `URI="${await resolve(match[1])}"`);
          lines.push(updated);
        }
      }
      text = lines.join('\n');
    } else {
      if (!allowNetwork && /\$(Number|Time|RepresentationID|Bandwidth)/.test(text)) throw new ReslarkError('DASH_TEMPLATE_NETWORK_REQUIRED', 'Template-based DASH requires ffmpeg network access (--allow-network)');
      // An absolute source base lets ffmpeg expand DASH templates itself.
      const base = new URL('.', item.url).href.replaceAll('&', '&amp;');
      if (!/<BaseURL\b/.test(text)) text = text.replace(/(<MPD\b[^>]*>)/, `$1<BaseURL>${base}</BaseURL>`);
      if (!allowNetwork) {
        for (const match of [...text.matchAll(/\b(media|sourceURL|initialization)="([^"]+)"/g)]) text = text.replace(match[0], `${match[1]}="${(await resolve(match[2])).replaceAll('&', '&amp;')}"`);
      }
    }
    await fs.writeFile(target, text, { mode: 0o600 }); return target;
  };
  const input = await prepare(resource);
  const destination = path.resolve(out || path.join(record.output_dir, 'files', `${resource.id}-merged.mp4`));
  await mkdir(path.dirname(destination));
  const temp = path.join(directory, `output${path.extname(destination) || '.mp4'}`);
  const args = ['-nostdin', '-hide_banner', '-loglevel', 'error', '-protocol_whitelist', allowNetwork ? 'file,http,https,tcp,tls,crypto,data' : 'file,crypto,data', '-allowed_extensions', 'ALL', '-i', input, ...(duration ? ['-t', String(duration / 1000)] : []), '-c', 'copy', temp];
  const log = await fs.open(path.join(directory, 'ffmpeg.log'), 'a', 0o600);
  const child = spawn(ffmpeg, args, { stdio: ['ignore', 'ignore', log.fd], windowsHide: true }); await log.close();
  await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code) => code === 0 ? resolve() : reject(new ReslarkError('MEDIA_MERGE_FAILED', 'ffmpeg failed; inspect the private media log'))); });
  try {
    try { await fs.link(temp, destination); }
    catch (error) { if (!['EXDEV', 'EPERM', 'ENOTSUP', 'EOPNOTSUPP'].includes(error.code)) throw error; await fs.copyFile(temp, destination, fs.constants.COPYFILE_EXCL); }
  } catch (error) { if (error.code === 'EEXIST') throw new ReslarkError('OUTPUT_EXISTS', 'Media output already exists'); throw error; }
  await fs.rm(temp); return { resource_id: resourceId, path: destination, state: 'completed', network_access: allowNetwork };
}
