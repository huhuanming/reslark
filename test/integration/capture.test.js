import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const binary = process.env.RESLARK_MITMDUMP;

test('real mitmdump captures HTTPS, correlates cross-domain responses, supports AI lifecycle and packaged addon', { skip: !binary, timeout: 90000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-integration-'));
  const home = path.join(directory, 'home'); const out = path.join(directory, 'out');
  const cli = async (...args) => {
    const { stdout } = await exec(process.execPath, [path.join(root, 'bin/reslark.js'), ...args, '--home', home, '--json'], { timeout: 45000, env: { ...process.env, RESLARK_MITMDUMP: binary } });
    return JSON.parse(stdout);
  };
  const origin = http.createServer((request, response) => {
    if (request.url === '/page') { response.setHeader('content-type', 'text/html'); response.end(`<img src="http://localhost:${origin.address().port}/image.png?token=private-token"><link rel="stylesheet" href="/style.css">`); }
    else if (request.url === '/style.css') { response.setHeader('content-type', 'text/css'); response.end('body{background:url(/leaf.png)}'); }
    else { response.setHeader('content-type', 'image/png'); response.end(`image:${request.url}`); }
  });
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  const originPort = origin.address().port;
  let session; let tlsSession; let secure;
  t.after(async () => {
    if (session) await cli('stop', session.session_id, '--no-drain').catch(() => {});
    if (tlsSession) await cli('stop', tlsSession.session_id, '--no-drain').catch(() => {});
    if (secure) await new Promise((resolve) => { secure.close(resolve); secure.closeAllConnections(); });
    await new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); });
    await fs.rm(directory, { recursive: true, force: true });
  });
  session = await cli('capture', '--domain', '127.0.0.1', '--related', '--complete', '--out', out, '--background', '--request-id', 'integration');
  assert.equal(session.state, 'ready'); assert.match(session.proxy_url, /^http:\/\/127\.0\.0\.1:/);
  assert.equal(session.control, undefined);
  const same = await cli('capture', '--domain', '127.0.0.1', '--related', '--complete', '--out', out, '--background', '--request-id', 'integration');
  assert.equal(same.session_id, session.session_id);
  // Capture CDN first, before the source page establishes the relationship.
  await exec('curl', ['--fail', '--silent', '--show-error', '--noproxy', '', '--proxy', session.proxy_url, `http://localhost:${originPort}/image.png?token=private-token`]);
  await exec('curl', ['--fail', '--silent', '--show-error', '--noproxy', '', '--proxy', session.proxy_url, `http://127.0.0.1:${originPort}/page`]);
  await cli('wait', session.session_id, '--until', 'files', '--count', '4', '--timeout', '15s');
  const resources = await cli('resources', session.session_id);
  assert.ok(resources.items.some((item) => new URL(item.url).hostname === 'localhost' && item.complete));
  assert.ok(resources.items.some((item) => item.url.includes('/leaf.png') && item.complete));
  assert.equal(JSON.stringify(resources).includes('private-token'), false);
  const image = resources.items.find((item) => new URL(item.url).hostname === 'localhost');
  assert.ok((await cli('inspect', image.id)).relations.length);
  const exported = await cli('export', session.session_id, '--format', 'har');
  assert.equal(exported.log.version, '1.2');
  // A private origin CA is explicitly allowed for this isolated test only.
  await exec('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(directory, 'key.pem'), '-out', path.join(directory, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost']);
  secure = https.createServer({ key: await fs.readFile(path.join(directory, 'key.pem')), cert: await fs.readFile(path.join(directory, 'cert.pem')) }, (_request, response) => { response.setHeader('content-type', 'application/json'); response.end('{"secure":true}'); });
  await new Promise((resolve) => secure.listen(0, '127.0.0.1', resolve));
  tlsSession = await cli('capture', '--domain', '127.0.0.1', '--out', path.join(directory, 'tls'), '--background', '--insecure');
  const tlsResult = await exec('curl', ['--fail', '--silent', '--show-error', '--noproxy', '', '--proxy', tlsSession.proxy_url, '--cacert', tlsSession.ca_path, `https://127.0.0.1:${secure.address().port}/secure`]);
  assert.equal(JSON.parse(tlsResult.stdout).secure, true);
  await cli('wait', tlsSession.session_id, '--until', 'files', '--timeout', '10s');
  assert.equal((await cli('resources', tlsSession.session_id)).items[0].complete, true);
  const proxiedDownload = await cli('download', '--url', `https://127.0.0.1:${secure.address().port}/download`, '--out', path.join(directory, 'upstream'), '--upstream', tlsSession.proxy_url, '--insecure');
  assert.equal(proxiedDownload.state, 'completed');
  assert.equal((await cli('stop', tlsSession.session_id)).state, 'stopped');
  assert.equal((await cli('stop', session.session_id)).state, 'stopped');
  assert.equal((await cli('recover')).sessions.every((item) => item.action === 'checked'), true);
});

test('run starts a proxy-aware program and stops after its exit', { skip: !binary, timeout: 45000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-run-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const origin = http.createServer((_request, response) => { response.setHeader('content-type', 'image/png'); response.end('program-resource'); });
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); }));
  const { stdout } = await exec(process.execPath, [path.join(root, 'bin/reslark.js'), 'run', '--domain', '127.0.0.1', '--out', path.join(directory, 'out'), '--home', path.join(directory, 'home'), '--json', '--', 'curl', '--fail', '--silent', `http://127.0.0.1:${origin.address().port}/image.png`], { timeout: 40000 });
  const session = JSON.parse(stdout);
  const summary = JSON.parse(await fs.readFile(path.join(directory, 'out/session.json'), 'utf8'));
  assert.equal(summary.state, 'stopped'); assert.equal(summary.stop_reason, 'program-exited'); assert.equal(summary.counts.files, 1);
  assert.equal(session.state, 'ready');
});

test('stopping a live SSE capture preserves received bytes as a partial response', { skip: !binary, timeout: 30000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-stream-')); const home = path.join(directory, 'home'); let session;
  const cli = async (...args) => JSON.parse((await exec(process.execPath, [path.join(root, 'bin/reslark.js'), ...args, '--home', home, '--json'], { timeout: 20000 })).stdout);
  const origin = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream' }); response.write('data: first\n\n');
    const timer = setInterval(() => response.write('data: next\n\n'), 50); response.on('close', () => clearInterval(timer));
  });
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    if (session) await cli('stop', session.session_id, '--no-drain').catch(() => {});
    await new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); });
    await fs.rm(directory, { recursive: true, force: true });
  });
  session = await cli('capture', '--domain', '127.0.0.1', '--out', path.join(directory, 'out'), '--background', '--duration', '1s');
  const client = exec('curl', ['--silent', '--max-time', '5', '--noproxy', '', '--proxy', session.proxy_url, `http://127.0.0.1:${origin.address().port}/events`]).catch(() => {});
  await cli('wait', session.session_id, '--until', 'stopped', '--timeout', '10s'); await client;
  const resources = await cli('resources', session.session_id);
  assert.equal(resources.items.length, 1); assert.equal(resources.items[0].complete, false); assert.equal(resources.items[0].state, 'partial');
  assert.match(await fs.readFile(path.join(directory, 'out', resources.items[0].path), 'utf8'), /data: first/);
});
