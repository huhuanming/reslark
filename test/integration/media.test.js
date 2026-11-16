import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const cliPath = fileURLToPath(new URL('../../bin/reslark.js', import.meta.url));
const ffmpeg = process.env.RESLARK_FFMPEG || 'ffmpeg';
const available = await exec(ffmpeg, ['-version']).then(() => true, () => false);

test('real HLS download captures playlist/segments and ffmpeg merges local files', { skip: !available, timeout: 30000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-media-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const media = path.join(directory, 'origin'); await fs.mkdir(media);
  await exec(ffmpeg, ['-nostdin', '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'color=c=blue:s=64x64:r=10', '-t', '1', '-c:v', 'libx264', '-f', 'hls', '-hls_time', '1', '-hls_list_size', '0', path.join(media, 'index.m3u8')]);
  const origin = http.createServer(async (request, response) => {
    const file = path.join(media, path.basename(new URL(request.url, 'http://localhost').pathname));
    try { response.setHeader('content-type', file.endsWith('.m3u8') ? 'application/vnd.apple.mpegurl' : 'video/mp2t'); response.end(await fs.readFile(file)); }
    catch { response.writeHead(404); response.end(); }
  });
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); }));
  const home = path.join(directory, 'home'); const out = path.join(directory, 'out');
  const cli = async (...args) => JSON.parse((await exec(process.execPath, [cliPath, ...args, '--home', home, '--json'], { timeout: 20000 })).stdout);
  const download = await cli('download', '--url', `http://127.0.0.1:${origin.address().port}/index.m3u8`, '--out', out, '--related', '--complete');
  const resources = await cli('resources', download.session_id);
  assert.equal(resources.items.filter((item) => item.complete).length, 2);
  const manifest = resources.items.find((item) => item.kind === 'manifest');
  const merged = await cli('media', manifest.id, '--ffmpeg', ffmpeg);
  assert.equal(merged.state, 'completed'); assert.ok((await fs.stat(merged.path)).size > 0);
  await assert.rejects(cli('media', manifest.id, '--ffmpeg', ffmpeg), /already exists/);
});

test('DASH templates are merged by ffmpeg only with explicit network access', { skip: !available, timeout: 30000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-dash-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const media = path.join(directory, 'origin'); await fs.mkdir(media);
  await exec(ffmpeg, ['-nostdin', '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'color=c=red:s=64x64:r=10', '-t', '1', '-c:v', 'libx264', '-f', 'dash', path.join(media, 'index.mpd')]);
  const origin = http.createServer(async (request, response) => {
    const file = path.join(media, path.basename(new URL(request.url, 'http://localhost').pathname));
    try { response.setHeader('content-type', file.endsWith('.mpd') ? 'application/dash+xml' : 'video/mp4'); response.end(await fs.readFile(file)); }
    catch { response.writeHead(404); response.end(); }
  });
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); }));
  const home = path.join(directory, 'home');
  const cli = async (...args) => JSON.parse((await exec(process.execPath, [cliPath, ...args, '--home', home, '--json'], { timeout: 20000 })).stdout);
  const download = await cli('download', '--url', `http://127.0.0.1:${origin.address().port}/index.mpd`, '--out', path.join(directory, 'out'));
  const manifest = (await cli('resources', download.session_id)).items[0];
  await assert.rejects(cli('media', manifest.id, '--ffmpeg', ffmpeg), /explicit network|network access/);
  const merged = await cli('media', manifest.id, '--ffmpeg', ffmpeg, '--allow-network');
  assert.ok((await fs.stat(merged.path)).size > 0);
});
