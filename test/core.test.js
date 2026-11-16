import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import { domainMatches, normalizeDomain, hostRegex } from '../src/rules.js';
import { publicURL, publicHeaders, duration, byteSize, latestBy, jsonLines, hash } from '../src/util.js';
import { captureConfig } from '../src/cli.js';
import { Store, resourcesFor } from '../src/store.js';
import { ResourceGraph } from '../src/resources.js';
import { extractReferences } from '../src/scan.js';

test('domain rules honor boundaries, wildcard roots, IDNs and exclusions', () => {
  assert.equal(normalizeDomain('*.EXAMPLE.com.'), '*.example.com');
  assert.equal(domainMatches('a.example.com', ['*.example.com']), true);
  assert.equal(domainMatches('example.com', ['*.example.com']), true);
  assert.equal(domainMatches('badexample.com', ['*.example.com']), false);
  assert.equal(domainMatches('a.example.com', ['example.com']), false);
  assert.match(normalizeDomain('例子.中国'), /^xn--/);
  assert.throws(() => normalizeDomain('https://example.com'), /hostname/);
  const expression = new RegExp(hostRegex(['*.example.com'])[0]);
  assert.equal(expression.test('a.example.com:443'), true); assert.equal(expression.test('exampleXcom:443'), false);
});

test('public metadata removes secrets without changing private URL identity', () => {
  const url = 'https://example.com/a?token=very-secret&v=2&signature=signed';
  assert.equal(new URL(publicURL(url)).searchParams.get('v'), '2');
  assert.equal(publicURL(url).includes('very-secret'), false);
  assert.deepEqual(publicHeaders({ authorization: 'secret', cookie: 'secret', 'content-type': 'image/png' }), { 'content-type': 'image/png' });
  assert.equal(duration('1.5m'), 90000); assert.equal(byteSize('1MiB'), 1048576);
  assert.throws(() => duration('-1'), /Invalid/);
});

test('capture configuration refuses implicit global capture and contradictory modes', () => {
  assert.throws(() => captureConfig({ out: '/tmp/assets' }), /Specify/);
  assert.throws(() => captureConfig({ out: '/tmp/assets', pid: ['12'], mode: 'regular' }), /local mode/);
  assert.throws(() => captureConfig({ out: '/tmp/assets', all: true, complete: true }), /requires --related/);
  assert.equal(captureConfig({ out: '/tmp/assets', pid: ['12'] }).mode, 'local');
  assert.equal(captureConfig({ out: '/tmp/assets', domain: ['example.com'] }).concurrency, 4);
});

test('reference extraction resolves HTML, CSS, JSON, HLS and ignores executable URLs', () => {
  const html = extractReferences('<base href="https://cdn.example/a/"><img src="one.png" srcset="two.png 2x, three.png 3x"><script src="javascript:evil"></script>', 'https://example.com/', 'text/html');
  assert.ok(html.references.some((item) => item.url === 'https://cdn.example/a/one.png'));
  assert.ok(html.references.some((item) => item.url === 'https://cdn.example/a/three.png'));
  assert.equal(html.references.some((item) => item.url.includes('javascript:')), false);
  assert.ok(extractReferences('@import "./other.css"; a{background:url(../image.png)}', 'https://example.com/css/main.css', 'text/css').references.some((item) => item.url === 'https://example.com/image.png'));
  const playlist = extractReferences('#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="key.bin"\nsegment.ts', 'https://cdn.example/a/list.m3u8', 'application/vnd.apple.mpegurl');
  assert.equal(playlist.references.length, 2);
  assert.equal(extractReferences('{"url":"/video.mp4?token=secret"}', 'https://example.com/api', 'application/json').references[0].url, 'https://example.com/video.mp4?token=secret');
});

async function fixture(t, extra = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const config = captureConfig({ out: path.join(directory, 'out'), home: path.join(directory, 'home'), domain: ['example.com'], related: true, ...extra });
  const store = new Store(config.home, config); await store.init();
  t.after(() => store.close());
  const graph = new ResourceGraph(store); t.after(() => graph.close());
  const flow = async (url, body = 'hello', overrides = {}) => {
    const file = path.join(store.state, 'spool', `${Math.random()}.part`); await fs.writeFile(file, body);
    return { url, method: 'GET', request_headers: {}, response_headers: { 'content-type': 'image/png' }, status: 200, body_path: file, bytes: Buffer.byteLength(body), observed_bytes: Buffer.byteLength(body), sha256: hash(body), truncated: false, references: [], limitations: [], ...overrides };
  };
  return { store, graph, flow, config };
}

test('late cross-domain references select already captured resources and preserve provenance', async (t) => {
  const { store, graph, flow } = await fixture(t);
  await graph.ingest(await flow('https://cdn.other.net/image.png', 'image'));
  assert.equal((await resourcesFor(store.record)).length, 0);
  await graph.ingest(await flow('https://example.com/page', 'page', { response_headers: { 'content-type': 'text/html' }, references: [{ url: 'https://cdn.other.net/image.png', relation: 'html-reference' }] }));
  const resources = await resourcesFor(store.record);
  assert.equal(resources.length, 2); assert.equal(resources.every((item) => item.complete), true);
  const edges = []; for await (const item of jsonLines(path.join(store.out, 'relations.jsonl'))) edges.push(item);
  assert.equal(edges[0].relation, 'html-reference'); assert.equal(edges[0].evidence, 'explicit');
});

test('partial ranges and truncated bodies never become completed files', async (t) => {
  const { store, graph, flow } = await fixture(t);
  await graph.ingest(await flow('https://example.com/video', 'part', { status: 206, response_headers: { 'content-type': 'video/mp4', 'content-range': 'bytes 0-3/100' } }));
  const resource = (await resourcesFor(store.record))[0];
  assert.equal(resource.complete, false); assert.equal(resource.state, 'partial'); assert.ok(resource.path.endsWith('.partial'));
});

test('a later 304 or range preserves the earlier complete object and records observations', async (t) => {
  const { store, graph, flow } = await fixture(t);
  await graph.ingest(await flow('https://example.com/video', 'complete'));
  await graph.ingest(await flow('https://example.com/video', '', { status: 304 }));
  const resource = (await resourcesFor(store.record))[0];
  assert.equal(resource.complete, true); assert.equal(resource.last_response.status, 304);
  assert.equal(await fs.readFile(path.join(store.out, resource.path), 'utf8'), 'complete');
  const requests = []; for await (const item of jsonLines(path.join(store.out, 'requests.jsonl'))) requests.push(item);
  assert.deepEqual(requests.map((item) => item.status), [200, 304]);
});

test('content deduplication keeps separate URLs and does not discard query variants', async (t) => {
  const { store, graph, flow } = await fixture(t);
  await graph.ingest(await flow('https://example.com/a?v=1'));
  await graph.ingest(await flow('https://example.com/a?v=2'));
  const resources = await resourcesFor(store.record);
  assert.equal(resources.length, 2); assert.equal(resources[0].path, resources[1].path);
  assert.equal(store.record.counts.files, 1);
});

test('exclusions take priority over explicit related references', async (t) => {
  const { store, graph, flow } = await fixture(t, { 'exclude-domain': ['blocked.example'] });
  await graph.ingest(await flow('https://example.com/a', 'a', { references: [{ url: 'https://blocked.example/image.png', relation: 'html-reference' }] }));
  assert.equal((await resourcesFor(store.record)).length, 1);
});

test('output ownership and exclusive lock prevent concurrent corruption', async (t) => {
  const { store, config } = await fixture(t);
  const conflicting = new Store(config.home, config);
  await assert.rejects(conflicting.init(), /another session/);
  const same = new Store(config.home, config, store.id);
  await assert.rejects(same.init(), /owned by another/);
});
