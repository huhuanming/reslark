import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { Store, loadSession, registryPath, resourcesFor } from './store.js';
import { atomicJSON, readJSON, now, sleep, id, hash, mkdir, publicURL, normalizeURL } from './util.js';
import { startBackend, requireBackend } from './backend.js';
import { ResourceGraph } from './resources.js';
import { DownloadQueue } from './download.js';
import { getSystemProxy, setSystemProxy, restoreSystemProxy, processList, descendants, initCert } from './platform.js';
import { connectCDP } from './cdp.js';
import { ReslarkError, asError, fail } from './errors.js';
import { isRoot, urlAllowed } from './rules.js';
import { extractReferences } from './scan.js';
import { crossOriginHeaders } from './network.js';

const executable = fileURLToPath(new URL('../bin/reslark.js', import.meta.url));
export function publicSession(record) {
  const { control, config, ...result } = record;
  return { ...result, ...(config ? { targets: { domains: config.domains, processes: config.processes, mode: config.mode }, ca_path: path.join(config.home, 'ca', 'mitmproxy-ca-cert.pem') } : {}) };
}
export async function control(record, route, body) {
  if (!record.control) throw new ReslarkError('SESSION_OFFLINE', 'Session has no running controller', { exitCode: 3 });
  try {
    const response = await fetch(`http://127.0.0.1:${record.control.port}${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { authorization: `Bearer ${record.control.token}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(10000) });
    const result = await response.json();
    if (!response.ok) throw new ReslarkError(result.error?.code || 'CONTROL_ERROR', result.error?.message || 'Session control failed');
    return result;
  } catch (error) {
    if (error instanceof ReslarkError) throw error;
    throw new ReslarkError('SESSION_OFFLINE', 'Session controller is not reachable; use status or recover', { exitCode: 3, retryable: true });
  }
}
export async function status(home, sessionId) {
  const record = await loadSession(home, sessionId);
  if (['starting', 'ready', 'stopping'].includes(record.state)) {
    try { return await control(record, '/status'); }
    catch { return { ...publicSession(record), state: 'interrupted', limitations: [...record.limitations, 'CONTROLLER_UNREACHABLE'] }; }
  }
  return publicSession(record);
}
async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port; await new Promise((resolve) => server.close(resolve)); return port;
}
export async function createSession(home, config, { background = false, onReady } = {}) {
  await requireBackend(config);
  await mkdir(path.join(home, 'starts'));
  let sessionId = id('s');
  const fingerprint = hash(JSON.stringify({ ...config, requestId: undefined }));
  let requestPath;
  if (config.requestId) {
    requestPath = path.join(home, 'starts', `request-${hash(config.requestId)}.json`);
    try { await fs.writeFile(requestPath, JSON.stringify({ session_id: sessionId, fingerprint }), { flag: 'wx', mode: 0o600 }); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const request = await readJSON(requestPath);
      if (request.fingerprint !== fingerprint) fail('IDEMPOTENCY_CONFLICT', 'Request ID was already used with different options');
      for (let attempt = 0; attempt < 300; attempt++) {
        const record = await readJSON(registryPath(home, request.session_id), null);
        if (record && record.state !== 'starting') return publicSession(record);
        await sleep(100);
      }
      fail('START_IN_PROGRESS', 'The matching request is still starting, or its launcher was interrupted', { retryable: true });
    }
  }
  config = { ...config, home, port: config.port || await availablePort() };
  const launch = path.join(home, 'starts', `${sessionId}.json`);
  await atomicJSON(launch, { home, config, session_id: sessionId });
  if (!background) return runDaemon({ home, config, session_id: sessionId }, onReady);
  const log = await fs.open(path.join(home, 'starts', `${sessionId}.log`), 'a', 0o600);
  const child = spawn(process.execPath, [executable, '_daemon', '--config', launch], { detached: true, stdio: ['ignore', log.fd, log.fd], windowsHide: true });
  await log.close();
  let childError; child.on('error', (error) => { childError = error; }); child.unref();
  for (let attempt = 0; attempt < 400; attempt++) {
    if (childError) throw childError;
    const record = await readJSON(registryPath(home, sessionId), null);
    if (record?.state === 'ready') return publicSession(record);
    if (record?.state === 'failed') throw new ReslarkError(record.error?.code || 'SESSION_START_FAILED', record.error?.message || 'Session startup failed', { exitCode: 3, details: { session_id: sessionId } });
    if (child.exitCode !== null) fail('SESSION_START_FAILED', 'Controller exited; inspect its startup log', { exitCode: 3, details: { session_id: sessionId } });
    await sleep(100);
  }
  child.kill('SIGTERM');
  fail('SESSION_START_TIMEOUT', 'Session did not become ready in 40 seconds', { exitCode: 3, details: { session_id: sessionId } });
}

export async function runDaemon(launch, onReady) {
  const { home, config, session_id: sessionId } = launch;
  const store = new Store(home, config, sessionId);
  const graph = new ResourceGraph(store);
  const queue = new DownloadQueue(store, (flow, options) => graph.ingest(flow, options)); graph.queue = queue;
  let backend; let program; let cdp; let server; let proxySnapshot; let stopped; let stopping = false; let tick; let periodicSave;
  let resolveDone; const done = new Promise((resolve) => { resolveDone = resolve; });
  let operations = Promise.resolve();
  const serial = (operation) => { const result = operations.then(operation); operations = result.catch(() => {}); return result; };
  const cleanup = async (reason = 'requested', { drain = true, failure } = {}) => {
    if (stopped) return stopped;
    stopping = true;
    stopped = (async () => {
      clearInterval(tick); clearInterval(periodicSave);
      store.record.state = 'stopping'; store.record.stop_reason = reason;
      const attempt = async (operation) => { try { return await operation(); } catch (error) { failure ||= error; return undefined; } };
      await attempt(() => store.save());
      try { cdp?.close(); } catch { /* Continue restoring the system proxy. */ }
      if (program && program.exitCode === null && program.signalCode === null) {
        program.kill('SIGTERM');
        const force = setTimeout(() => program.kill('SIGKILL'), 5000); force.unref();
        program.once('exit', () => clearTimeout(force));
      }
      try { await backend?.stop(); } catch (error) { failure ||= error; }
      await attempt(() => operations);
      try { await queue.stop(drain, config.drainTimeout); } catch (error) { failure ||= error; }
      await attempt(() => graph.close());
      await attempt(() => fs.rm(path.join(store.state, 'spool'), { recursive: true, force: true }));
      if (proxySnapshot) {
        try {
          const result = await restoreSystemProxy(proxySnapshot, config.port);
          await attempt(() => store.event('system_proxy.restore', result));
          if (result.restored) await fs.rm(path.join(store.state, 'system-proxy.json'), { force: true });
          else store.record.limitations.push('SYSTEM_PROXY_RESTORE_REQUIRES_REVIEW');
        } catch (error) { await attempt(() => store.event('system_proxy.restore_failed', { message: error.message })); store.record.limitations.push('SYSTEM_PROXY_RESTORE_FAILED'); }
      }
      store.record.state = failure ? 'failed' : 'stopped'; store.record.finished_at = now();
      if (failure) store.record.error = asError(failure).toJSON();
      delete store.record.control;
      await attempt(() => store.event(failure ? 'session.failed' : 'session.stopped', { reason, ...(failure ? { error: asError(failure).toJSON() } : {}) }));
      await attempt(() => store.save()); await attempt(() => store.close());
      if (server) await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
      process.off('SIGINT', onInterrupt); process.off('SIGTERM', onTerminate);
      resolveDone(publicSession(store.record));
      return publicSession(store.record);
    })();
    return stopped;
  };
  const onInterrupt = () => { cleanup('signal', { drain: false }).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 4; resolveDone(); }); };
  const onTerminate = onInterrupt;
  try {
    await store.init();
    process.on('SIGINT', onInterrupt); process.on('SIGTERM', onTerminate);
    store.record.controller_pid = process.pid;
    store.record.capabilities = { backend: 'mitmdump', http: true, https: true, http2: true, transparent_process_capture: config.mode === 'local', browser_supplement: Boolean(config.cdp), websocket: true, http3: config.mode === 'local' ? 'backend-dependent' : false };
    store.record.limitations.push('TLS_PINNING_AND_DRM_NOT_BYPASSED');
    if (config.related) store.record.limitations.push('RELATED_MODE_DECRYPTS_ALL_NON_EXCLUDED_TRAFFIC_REACHING_THIS_SESSION');
    if (config.mode === 'regular') store.record.limitations.push('ONLY_PROXY_AWARE_CLIENTS_ARE_CAPTURED');
    if (config.includeChildren) store.record.limitations.push('DESCENDANT_DISCOVERY_IS_POLLED_AND_MAY_MISS_SHORT_LIVED_OR_REPARENTED_PROCESSES');
    await initCert(home, config);
    const originalProcesses = [...config.processes];
    const identities = new Map();
    const updateTargets = async () => {
      const list = await processList();
      const roots = list.filter((item) => originalProcesses.some((target) => /^\d+$/.test(target) ? item.pid === Number(target) : path.basename(item.name).toLowerCase() === target.toLowerCase()));
      const validRoots = roots.filter((item) => {
        if (!identities.has(item.pid)) { identities.set(item.pid, item.identity); return true; }
        return identities.get(item.pid) === item.identity;
      });
      const matched = config.includeChildren ? descendants(list, validRoots.map((item) => item.pid)) : validRoots;
      store.record.matched_processes = matched;
      const targets = matched.map((item) => String(item.pid));
      config.processes = [...(targets.length ? targets : ['2147483647']), `!${process.pid}`];
      await atomicJSON(path.join(store.state, 'targets.json'), config.processes);
    };
    if (config.mode === 'local') await updateTargets();
    backend = await startBackend(store, (message) => serial(async () => {
      if (message.type === 'flow') await graph.ingest(message.flow);
      else if (message.type === 'flow.error') {
        await graph.discard(message.body_path); store.record.counts.errors++;
        await store.event('capture.error', { url: publicURL(message.url), code: 'FLOW_ERROR' });
      } else if (message.type === 'websocket.message') {
        const { url, text, ...details } = message;
        const normalized = normalizeURL(url);
        const source = normalized && [...(graph.byURL.get(normalized) || [])].map((item) => graph.records.get(item)).find((item) => item.selected);
        if (!normalized || !urlAllowed(normalized, config) || (!source && !isRoot(normalized, config))) return;
        await store.event('websocket.message', { ...details, url: publicURL(url) });
        // Message contents may contain credentials; preserve them only in private state.
        const { appendJSON } = await import('./util.js');
        await appendJSON(path.join(store.state, 'websocket.jsonl'), message);
        if (source && text && config.related && source.depth < config.maxDepth) {
          for (const reference of extractReferences(text, normalized, 'application/json').references) {
            if (!urlAllowed(reference.url, config)) continue;
            const target = graph.ensure(reference.url, 'GET', crossOriginHeaders(source.request_headers, normalized, reference.url));
            await graph.link(source, target, reference.relation === 'text-reference' ? 'text-reference' : 'websocket-reference');
            if (config.complete && reference.relation !== 'text-reference') await queue.enqueue(target);
          }
        }
      } else { store.record.counts.errors++; await store.event('backend.warning', { code: message.code || message.type, ...(message.url ? { url: publicURL(message.url) } : {}) }); }
    }));
    backend.exited.then(({ code, signal }) => { if (!stopping) cleanup('backend-exited', { failure: new ReslarkError('BACKEND_EXITED', `mitmdump exited (${code ?? signal})`) }).catch(() => {}); });
    const token = randomBytes(32).toString('hex');
    server = http.createServer(async (request, response) => {
      const expected = Buffer.from(`Bearer ${token}`); const provided = Buffer.from(request.headers.authorization || '');
      const send = (code, value) => { response.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(value)); };
      if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) { send(401, { error: { code: 'UNAUTHORIZED', message: 'Invalid controller token' } }); return; }
      try {
        let body = {};
        if (request.method === 'POST') {
          let text = '';
          for await (const chunk of request) { text += chunk; if (text.length > 65536) throw new ReslarkError('BODY_TOO_LARGE', 'Control request is too large'); }
          body = JSON.parse(text || '{}');
        }
        if (request.url === '/status' && request.method === 'GET') send(200, { ...publicSession(store.record), last_activity: new Date(Math.max(graph.activity, queue.activity)).toISOString(), queue: { pending: queue.pending.length, active: queue.active.size } });
        else if (request.url === '/stop' && request.method === 'POST') { send(202, { session_id: sessionId, state: 'stopping' }); cleanup('requested', { drain: body.drain !== false }).catch(() => {}); }
        else if (request.url === '/download' && request.method === 'POST') {
          if (stopping) throw new ReslarkError('SESSION_STOPPING', 'Session is stopping');
          const resource = graph.records.get(body.resource_id); if (!resource?.selected) throw new ReslarkError('RESOURCE_NOT_FOUND', 'Resource does not exist in this session');
          send(202, await queue.enqueue(resource, { force: body.force }));
        } else send(404, { error: { code: 'NOT_FOUND', message: 'Unknown controller route' } });
      } catch (error) { send(400, { error: asError(error).toJSON() }); }
    });
    server.requestTimeout = 5000; server.headersTimeout = 5000;
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    store.record.control = { port: server.address().port, token };
    store.record.proxy_url = config.mode === 'regular' ? `http://127.0.0.1:${config.port}` : null;
    if (config.systemProxy) {
      proxySnapshot = await getSystemProxy(config.networkService);
      await atomicJSON(path.join(store.state, 'system-proxy.json'), { snapshot: proxySnapshot, port: config.port });
      await setSystemProxy(proxySnapshot, config.port);
    }
    if (config.cdp) cdp = await connectCDP(config.cdp, graph, store);
    store.record.state = 'ready'; await store.save();
    await store.event('session.ready', { proxy_url: store.record.proxy_url });
    if (onReady) await onReady(publicSession(store.record));
    const started = Date.now(); let watching = false;
    tick = setInterval(() => {
      if (stopping || watching) return;
      watching = true;
      (async () => {
        if (queue.error) throw queue.error;
        if (config.mode === 'local') await updateTargets();
        const counts = store.record.counts;
        if (config.duration && Date.now() - started >= config.duration) await cleanup('duration');
        else if (config.maxFiles && counts.files >= config.maxFiles) await cleanup('max-files');
        else if (config.maxBytes && counts.bytes >= config.maxBytes) await cleanup('max-bytes');
        else if (config.idleTimeout && Date.now() - Math.max(started, graph.activity, queue.activity) >= config.idleTimeout && !queue.pending.length && !queue.active.size) await cleanup('idle');
      })().catch((error) => cleanup('watcher-error', { failure: error })).finally(() => { watching = false; });
    }, 250);
    periodicSave = setInterval(() => { store.save().catch((error) => cleanup('storage-error', { failure: error })); }, 1000);
    if (config.command?.length) {
      const log = await fs.open(path.join(store.state, 'program.log'), 'a', 0o600);
      const proxy = store.record.proxy_url;
      program = spawn(config.command[0], config.command.slice(1), { env: { ...process.env, ...(proxy ? { HTTP_PROXY: proxy, HTTPS_PROXY: proxy, ALL_PROXY: proxy, http_proxy: proxy, https_proxy: proxy, all_proxy: proxy, NO_PROXY: '', no_proxy: '', NODE_USE_ENV_PROXY: '1' } : {}), NODE_EXTRA_CA_CERTS: path.join(home, 'ca', 'mitmproxy-ca-cert.pem'), SSL_CERT_FILE: path.join(home, 'ca', 'mitmproxy-ca-cert.pem'), REQUESTS_CA_BUNDLE: path.join(home, 'ca', 'mitmproxy-ca-cert.pem'), CURL_CA_BUNDLE: path.join(home, 'ca', 'mitmproxy-ca-cert.pem') }, stdio: ['ignore', log.fd, log.fd], windowsHide: true });
      await log.close(); store.record.program_pid = program.pid; await store.save();
      program.once('error', (error) => cleanup('program-error', { failure: error }));
      program.once('exit', (code, signal) => {
        store.event('program.exited', { code, signal }).then(() => { if (!stopping) cleanup('program-exited', { failure: code ? new ReslarkError('PROGRAM_EXITED', `Target program exited with code ${code}`) : undefined }); });
      });
    }
    return await done;
  } catch (error) {
    if (!store.lock) throw error;
    await cleanup('startup-error', { drain: false, failure: error });
    throw error;
  }
}

export async function offlineDownload(home, record, resources, { force = false } = {}) {
  const store = new Store(home, record.config, record.session_id); store.record = { ...record, state: 'downloading' };
  // Acquire the original output directory lock without resetting metadata.
  const { jsonLines } = await import('./util.js');
  for await (const event of jsonLines(path.join(record.output_dir, 'events.jsonl'))) store.seq = Math.max(store.seq, event.seq);
  await store.init();
  const graph = new ResourceGraph(store); await graph.restore(await resourcesFor(record, true));
  const queue = new DownloadQueue(store, (flow, options) => graph.ingest(flow, options)); graph.queue = queue;
  try {
    const jobs = [];
    for (const resource of resources) { if (!graph.records.has(resource.id)) await graph.restore([resource]); jobs.push(await queue.enqueue(resource, { force })); }
    await queue.waitIdle();
    return jobs.map((job) => queue.jobs.has(job.id) ? queue.visible(queue.jobs.get(job.id)) : job);
  } finally { await queue.stop(false); await graph.close(); store.record.state = record.state; await store.save(); await store.close(); }
}
