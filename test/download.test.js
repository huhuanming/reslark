import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { captureConfig } from '../src/cli.js';
import { Store, resourcesFor } from '../src/store.js';
import { ResourceGraph } from '../src/resources.js';
import { DownloadQueue } from '../src/download.js';
import { requestViaProxy } from '../src/network.js';

async function harness(t, handler, options = {}) {
  const server = http.createServer(handler); await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-download-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const config = captureConfig({ home: path.join(directory, 'home'), out: path.join(directory, 'out'), domain: ['127.0.0.1'], retries: '2', ...options });
  const store = new Store(config.home, config); await store.init(); t.after(() => store.close());
  const graph = new ResourceGraph(store); t.after(() => graph.close());
  const queue = new DownloadQueue(store, (flow, options) => graph.ingest(flow, options)); graph.queue = queue; t.after(() => queue.stop(false));
  return { server, store, graph, queue, url: `http://127.0.0.1:${server.address().port}` };
}

test('download retries resume partial bytes using validators and verify full size', async (t) => {
  const content = Buffer.alloc(50000, 7); const seen = [];
  const { store, graph, queue, url } = await harness(t, (request, response) => {
    seen.push(request.headers.range || 'full');
    response.setHeader('etag', '"stable"'); response.setHeader('content-type', 'application/octet-stream');
    if (seen.length === 1) {
      response.writeHead(200, { 'content-length': content.length }); response.write(content.subarray(0, 10000)); setTimeout(() => response.destroy(), 30);
    } else {
      const start = Number(/bytes=(\d+)-/.exec(request.headers.range || '')?.[1] || 0);
      response.writeHead(start ? 206 : 200, { 'content-length': content.length - start, ...(start ? { 'content-range': `bytes ${start}-${content.length - 1}/${content.length}` } : {}) });
      response.end(content.subarray(start));
    }
  });
  const resource = graph.ensure(`${url}/file`, 'GET', {}); resource.selected = true; resource.depth = 0;
  const job = await queue.enqueue(resource); await queue.waitIdle(10000);
  assert.equal(queue.jobs.get(job.id).state, 'completed'); assert.equal(seen[1], 'bytes=10000-');
  const saved = (await resourcesFor(store.record))[0]; assert.equal(saved.complete, true);
  assert.deepEqual(await fs.readFile(path.join(store.out, saved.path)), content);
});

test('active completion recursively downloads JSON, CSS and leaf assets', async (t) => {
  const requests = [];
  const { graph, queue, url, store } = await harness(t, (request, response) => {
    requests.push(request.url);
    if (request.url === '/api') { response.setHeader('content-type', 'application/json'); response.end('{"asset":"/main.css"}'); }
    else if (request.url === '/main.css') { response.setHeader('content-type', 'text/css'); response.end('body{background:url(/image.png)}'); }
    else { response.setHeader('content-type', 'image/png'); response.end('png'); }
  }, { related: true, complete: true });
  const root = graph.ensure(`${url}/api`, 'GET', {}); root.selected = true; root.depth = 0;
  await queue.enqueue(root); await queue.waitIdle(10000);
  assert.deepEqual(requests.sort(), ['/api', '/image.png', '/main.css']);
  assert.equal((await resourcesFor(store.record)).filter((item) => item.complete).length, 3);
});

test('failed HTTP requests remain failed and do not become completed files', async (t) => {
  const { graph, queue, url } = await harness(t, (_request, response) => { response.writeHead(403); response.end('denied'); });
  const resource = graph.ensure(`${url}/private`, 'GET', {}); resource.selected = true; resource.depth = 0;
  const job = await queue.enqueue(resource); await queue.waitIdle(10000);
  assert.equal(queue.jobs.get(job.id).state, 'failed'); assert.equal(queue.jobs.get(job.id).attempt, 1);
  assert.equal(queue.jobs.get(job.id).error.code, 'HTTP_ERROR');
});

test('downloads enforce body size limits without marking truncated data complete', async (t) => {
  const { graph, queue, url } = await harness(t, (_request, response) => { response.end(Buffer.alloc(500)); }, { 'max-body-bytes': '100', retries: '0' });
  const resource = graph.ensure(`${url}/large`, 'GET', {}); resource.selected = true; resource.depth = 0;
  const job = await queue.enqueue(resource); await queue.waitIdle(10000);
  assert.equal(queue.jobs.get(job.id).state, 'failed'); assert.equal(resource.complete, false);
});

test('unsafe POST replay is rejected', async (t) => {
  const { graph, queue, url } = await harness(t, (_request, response) => response.end('ok'));
  const resource = graph.ensure(`${url}/submit`, 'POST', {});
  await assert.rejects(queue.enqueue(resource), /GET\/HEAD/);
});

test('cross-origin redirects never inherit authentication or application-specific headers', async (t) => {
  let received;
  const other = http.createServer((request, response) => { received = request.headers; response.end('ok'); });
  await new Promise((resolve) => other.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { other.close(resolve); other.closeAllConnections(); }));
  const { graph, queue, url } = await harness(t, (_request, response) => { response.writeHead(302, { location: `http://127.0.0.1:${other.address().port}/asset` }); response.end(); });
  const resource = graph.ensure(`${url}/start`, 'GET', { authorization: 'Bearer private', cookie: 'session=private', 'x-application-auth': 'private', 'user-agent': 'Reslark-test' }); resource.selected = true; resource.depth = 0;
  const job = await queue.enqueue(resource); await queue.waitIdle(10000);
  assert.equal(queue.jobs.get(job.id).state, 'completed');
  assert.equal(received.authorization, undefined); assert.equal(received.cookie, undefined); assert.equal(received['x-application-auth'], undefined); assert.equal(received['user-agent'], 'Reslark-test');
});
