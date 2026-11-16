import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import { connectCDP } from '../src/cdp.js';
import { Store, resourcesFor } from '../src/store.js';
import { ResourceGraph } from '../src/resources.js';
import { captureConfig } from '../src/cli.js';
import { sleep } from '../src/util.js';

test('CDP supplement records cache bodies, normalizes decoded representation and initiators', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-browser-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const original = globalThis.WebSocket;
  let socket;
  class FakeSocket extends EventTarget {
    constructor() { super(); socket = this; setImmediate(() => this.dispatchEvent(new Event('open'))); }
    send(text) {
      const command = JSON.parse(text);
      const result = command.method === 'Network.getResponseBody' ? { body: 'cached-image', base64Encoded: false } : {};
      setImmediate(() => this.message({ id: command.id, result }));
    }
    message(value) { const event = new Event('message'); event.data = JSON.stringify(value); this.dispatchEvent(event); }
    close() {}
  }
  globalThis.WebSocket = FakeSocket; t.after(() => { globalThis.WebSocket = original; });
  const config = captureConfig({ home: path.join(directory, 'home'), out: path.join(directory, 'out'), domain: ['example.com'], related: true });
  const store = new Store(config.home, config); await store.init(); t.after(() => store.close());
  const graph = new ResourceGraph(store); t.after(() => graph.close());
  const source = graph.ensure('https://example.com/page', 'GET', {}); source.selected = true; source.depth = 0; await graph.persist(source);
  const browser = await connectCDP('ws://127.0.0.1/fake', graph, store); t.after(() => browser.close());
  socket.message({ method: 'Network.requestWillBeSent', params: { requestId: '1', request: { url: 'https://cdn.other.net/image.png', method: 'GET', headers: {} }, initiator: { url: source.url } } });
  socket.message({ method: 'Network.responseReceived', params: { requestId: '1', response: { status: 200, headers: { 'Content-Type': 'image/png', 'Content-Encoding': 'gzip' }, mimeType: 'image/png', fromDiskCache: true } } });
  socket.message({ method: 'Network.loadingFinished', params: { requestId: '1', encodedDataLength: 0 } });
  let resources;
  for (let attempt = 0; attempt < 100; attempt++) { resources = await resourcesFor(store.record); if (resources.some((item) => item.complete)) break; await sleep(10); }
  const image = resources.find((item) => item.kind === 'image');
  assert.equal(image.complete, true); assert.equal(image.content_encoding, 'identity'); assert.equal(image.bytes, 12);
  assert.equal(await fs.readFile(path.join(store.out, image.path), 'utf8'), 'cached-image');
});
