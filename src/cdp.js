import { ReslarkError } from './errors.js';
import { normalizeURL, publicURL } from './util.js';
import { urlAllowed } from './rules.js';

// An optional supplement: debugger initiators and cache/service-worker response bodies.
export async function connectCDP(endpoint, graph, store) {
  let socketURL = endpoint;
  if (/^https?:/.test(endpoint)) {
    const targets = await (await fetch(new URL('/json/list', endpoint), { signal: AbortSignal.timeout(5000) })).json();
    const page = targets.find((item) => item.type === 'page' && item.webSocketDebuggerUrl);
    if (!page) throw new ReslarkError('CDP_TARGET_NOT_FOUND', 'No browser page target is available');
    socketURL = page.webSocketDebuggerUrl;
  }
  const socket = new WebSocket(socketURL); const pending = new Map(); const requests = new Map(); let sequence = 0;
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new ReslarkError('CDP_TIMEOUT', `${method} timed out`)); }, 5000);
    pending.set(id, { resolve, reject, timer }); socket.send(JSON.stringify({ id, method, params }));
  });
  const ready = new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', () => reject(new ReslarkError('CDP_CONNECT_FAILED', 'Cannot connect to browser debugger')), { once: true }); });
  socket.addEventListener('message', ({ data }) => {
    let message; try { message = JSON.parse(data); } catch { return; }
    if (message.id) {
      const request = pending.get(message.id); if (!request) return;
      clearTimeout(request.timer); pending.delete(message.id);
      message.error ? request.reject(new ReslarkError('CDP_ERROR', message.error.message)) : request.resolve(message.result); return;
    }
    if (message.method === 'Network.requestWillBeSent') {
      const { requestId, request, initiator } = message.params;
      if (requests.size >= store.config.maxPending) requests.delete(requests.keys().next().value);
      requests.set(requestId, { request, initiator });
      const sourceURL = normalizeURL(initiator.url || initiator.stack?.callFrames?.[0]?.url);
      const targetURL = normalizeURL(request.url);
      const source = sourceURL && [...(graph.byURL.get(sourceURL) || [])].map((id) => graph.records.get(id)).find((item) => item.selected);
      if (source && targetURL && urlAllowed(targetURL, store.config)) {
        const target = graph.ensure(targetURL, request.method, request.headers);
        graph.link(source, target, 'browser-initiator').catch((error) => store.event('browser.error', { message: error.message }));
      }
    }
    if (message.method === 'Network.responseReceived') {
      const item = requests.get(message.params.requestId); if (item) item.response = message.params.response;
    }
    if (message.method === 'Network.loadingFinished') {
      const { requestId } = message.params; const item = requests.get(requestId); requests.delete(requestId);
      if (!item?.response || !(item.response.fromDiskCache || item.response.fromServiceWorker || item.response.fromPrefetchCache)) return;
      if (message.params.encodedDataLength > store.config.scanBytes) { store.event('browser.body_omitted', { code: 'CDP_BODY_LIMIT', url: publicURL(item.request.url) }); return; }
      call('Network.getResponseBody', { requestId }).then(async ({ body, base64Encoded }) => {
        const bytes = Buffer.from(body, base64Encoded ? 'base64' : 'utf8');
        if (bytes.length > store.config.scanBytes) { await store.event('browser.body_omitted', { code: 'CDP_BODY_LIMIT', url: publicURL(item.request.url) }); return; }
        const { promises: fs } = await import('node:fs'); const path = await import('node:path'); const { id, hash } = await import('./util.js');
        const flowId = id('browser'); const spool = path.join(store.state, 'spool', `${flowId}.part`);
        await fs.writeFile(spool, bytes, { mode: 0o600 });
        const headers = Object.fromEntries(Object.entries(item.response.headers).filter(([key]) => !/^(content-encoding|content-length)$/i.test(key)).map(([key, value]) => [key.toLowerCase(), value]));
        headers['content-length'] = String(bytes.length);
        const { extractReferences } = await import('./scan.js');
        const scanned = extractReferences(bytes.toString('utf8'), item.request.url, item.response.mimeType || '');
        await graph.ingest({ flow_id: flowId, url: item.request.url, method: item.request.method, request_headers: item.request.headers, response_headers: headers, status: item.response.status, body_path: spool, bytes: bytes.length, observed_bytes: bytes.length, sha256: hash(bytes), truncated: false, limitations: ['BROWSER_CACHE_RESPONSE', ...scanned.limitations], references: scanned.references });
      }).catch((error) => store.event('browser.error', { message: error.message }));
    }
  });
  try {
    await Promise.race([ready, new Promise((_, reject) => { const timer = setTimeout(() => reject(new ReslarkError('CDP_CONNECT_TIMEOUT', 'Browser debugger connection timed out')), 5000); timer.unref(); })]);
    await call('Network.enable', { maxTotalBufferSize: store.config.scanBytes * 2, maxResourceBufferSize: store.config.scanBytes });
  } catch (error) { socket.close(); for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); } pending.clear(); throw error; }
  return { close() { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new ReslarkError('CDP_CLOSED', 'Browser connection closed')); } pending.clear(); socket.close(); } };
}
