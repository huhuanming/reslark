import { parseArgs } from 'node:util';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { homeDir, loadSession, listSessions, resourcesFor, Store } from './store.js';
import { createSession, runDaemon, status, control, publicSession, offlineDownload } from './session.js';
import { id, now, readJSON, duration, byteSize, integer, jsonLines, sleep, publicURL } from './util.js';
import { normalizeDomain, domainMatches } from './rules.js';
import { ResourceGraph } from './resources.js';
import { DownloadQueue } from './download.js';
import { probe, mitmBinary } from './backend.js';
import { certStatus, initCert, manageCert } from './platform.js';
import { exportSession } from './export.js';
import { recover } from './recover.js';
import { mergeMedia } from './media.js';
import { invalid, fail, ReslarkError } from './errors.js';

const strings = ['home', 'out', 'mode', 'mitmdump', 'port', 'duration', 'idle-timeout', 'max-files', 'max-bytes', 'max-body-bytes', 'max-spool-bytes', 'scan-bytes', 'max-depth', 'max-resources', 'max-pending', 'concurrency', 'retries', 'request-timeout', 'drain-timeout', 'request-id', 'network-service', 'upstream', 'cdp', 'session', 'limit', 'cursor', 'after', 'until', 'count', 'timeout', 'idle', 'format', 'config', 'url', 'ffmpeg', 'probe-url', 'state'];
const booleans = ['help', 'version', 'json', 'background', 'related', 'complete', 'include-children', 'system-proxy', 'system', 'insecure', 'anticache', 'all', 'follow', 'force', 'no-drain', 'allow-network'];
const multiples = ['domain', 'exclude-domain', 'pid', 'process', 'type'];
const options = Object.fromEntries([...strings.map((name) => [name, { type: 'string' }]), ...booleans.map((name) => [name, { type: 'boolean' }]), ...multiples.map((name) => [name, { type: 'string', multiple: true }])]);
const captureOptions = ['out', 'mode', 'mitmdump', 'port', 'duration', 'idle-timeout', 'max-files', 'max-bytes', 'max-body-bytes', 'max-spool-bytes', 'scan-bytes', 'max-depth', 'max-resources', 'max-pending', 'concurrency', 'retries', 'request-timeout', 'drain-timeout', 'request-id', 'network-service', 'upstream', 'cdp', 'background', 'related', 'complete', 'include-children', 'system-proxy', 'insecure', 'anticache', 'all', 'domain', 'exclude-domain', 'pid', 'process', 'type'];
const allowedOptions = {
  capture: captureOptions, run: captureOptions, doctor: ['mitmdump', 'ffmpeg', 'probe-url'], sessions: ['limit', 'cursor'], status: [],
  stop: ['no-drain', 'timeout'], events: ['after', 'limit', 'follow'], resources: ['type', 'domain', 'state', 'limit', 'cursor'], inspect: ['session'],
  download: ['url', 'out', 'session', 'force', 'related', 'complete', 'exclude-domain', 'max-depth', 'max-resources', 'max-pending', 'max-files', 'max-bytes', 'max-body-bytes', 'max-spool-bytes', 'scan-bytes', 'concurrency', 'retries', 'request-timeout', 'upstream', 'insecure'],
  retry: [], wait: ['until', 'timeout', 'idle', 'count'], export: ['format', 'out'], media: ['session', 'out', 'allow-network', 'duration', 'ffmpeg'], cert: ['system', 'mitmdump'], recover: [], _daemon: ['config'],
};
const HELP = `Reslark — AI-friendly resource capture and download with mitmdump

Usage: reslark <command> [options]

  doctor                         Check Node, mitmdump, ffmpeg and CA
  capture --out DIR               Start a capture session
  run --out DIR -- PROGRAM ARGS   Run a proxy-aware program in a session
  sessions                       List sessions
  status SESSION                 Inspect capture and download status
  events SESSION [--follow]       Read JSONL events (--after SEQ)
  resources SESSION              List resources (--type image --limit 100)
  inspect RESOURCE               Inspect a resource and its relationships
  download RESOURCE              Download a discovered resource
  download --url URL --out DIR    Download a URL without mitmdump
  retry SESSION                  Retry failed/incomplete downloads
  wait SESSION                   Wait for --until idle|stopped|files|queue-empty
  stop SESSION                   Stop capture, draining downloads by default
  export SESSION                 Export --format json|har|urls [--out FILE]
  media RESOURCE                 Merge captured HLS/DASH with ffmpeg
  cert init|status|install|uninstall
  recover                        Recover stale locks and owned proxy settings

Capture targets (at least one required):
  --domain HOST                  Repeatable, supports '*.example.com'
  --pid PID / --process NAME     Transparent local capture via mitmdump
  --all                          Explicitly select all traffic reaching proxy
  --exclude-domain HOST          Repeatable hard exclusion
  --include-children             Poll descendant processes in local mode
  --related                      Trace cross-domain asset references
  --complete                     Download missing referenced assets (GET only)
  --type KIND                    Limit saved bodies; metadata is still traced

Session options:
  --background --json            Return after authenticated controller is ready
  --port 0                       Automatic loopback port (default)
  --duration 30s --idle-timeout 5s
  --max-files N --max-bytes 1GiB --max-body-bytes 512MiB
  --max-depth 5 --max-resources 20000 --max-pending 1000
  --concurrency 4 --retries 2 --request-timeout 30s
  --system-proxy [--network-service Wi-Fi]
  --upstream http://127.0.0.1:8080 --cdp http://127.0.0.1:9222
  --request-id KEY                Idempotent capture startup
  --home DIR --mitmdump PATH      Override RESLARK_HOME / RESLARK_MITMDUMP

All result commands support --json. Events are always JSONL.
No npm runtime dependencies. mitmdump is an external capture dependency.
`;

export function captureConfig(values, command = []) {
  const domains = (values.domain || []).map(normalizeDomain);
  const processes = [...(values.pid || []).map((pid) => String(integer(pid, 'pid', { min: 1, max: 2147483647 }))), ...(values.process || [])];
  for (const process of processes) if (!process.trim() || /[,!\x00/\\]/.test(process)) invalid('Process names cannot contain paths, commas, or negation operators');
  const mode = values.mode || (processes.length ? 'local' : 'regular');
  if (!['regular', 'local'].includes(mode)) invalid('Mode must be regular or local');
  if (mode === 'regular' && processes.length) invalid('PID/process targets require local mode');
  if (values['include-children'] && mode !== 'local') invalid('--include-children requires local mode');
  if (mode === 'local' && !processes.length && !command.length) invalid('Local mode requires --pid or --process');
  if (mode === 'local' && command.length && !processes.length) processes.push(path.basename(command[0]));
  if (!domains.length && !processes.length && !values.all && !command.length) invalid('Specify --domain, --pid, --process, or explicitly use --all');
  if (values.all && domains.length) invalid('--all cannot be combined with --domain');
  if (!values.out) invalid('--out is required');
  if (values.complete && !values.related) invalid('--complete requires --related');
  if (values['system-proxy'] && mode !== 'regular') invalid('--system-proxy requires regular mode');
  if (values.upstream) {
    let proxy; try { proxy = new URL(values.upstream); } catch { invalid('Invalid upstream proxy URL'); }
    if (!['http:', 'https:'].includes(proxy.protocol) || proxy.username || proxy.password) invalid('Upstream must be an HTTP(S) proxy URL without embedded credentials');
    if (mode === 'local') invalid('Combining local mode and an upstream proxy is not supported');
  }
  const types = values.type || [];
  for (const type of types) if (!['image', 'video', 'audio', 'manifest', 'font', 'json', 'html', 'script', 'style', 'document', 'other'].includes(type)) invalid(`Unknown resource type: ${type}`);
  return {
    home: homeDir(values.home), out: path.resolve(values.out), domains, exclude: (values['exclude-domain'] || []).map(normalizeDomain), processes, mode,
    related: Boolean(values.related), complete: Boolean(values.complete), types, includeChildren: Boolean(values['include-children']),
    systemProxy: Boolean(values['system-proxy']), networkService: values['network-service'], upstream: values.upstream, cdp: values.cdp,
    mitmdump: values.mitmdump, port: integer(values.port ?? 0, 'port', { max: 65535 }), duration: duration(values.duration), idleTimeout: duration(values['idle-timeout']),
    maxFiles: integer(values['max-files'] ?? 0, 'max-files'), maxBytes: byteSize(values['max-bytes']), maxBodyBytes: byteSize(values['max-body-bytes'], 512 * 1048576), maxSpoolBytes: byteSize(values['max-spool-bytes'], 2 * 1073741824), scanBytes: byteSize(values['scan-bytes'], 2 * 1048576),
    maxDepth: integer(values['max-depth'] ?? 5, 'max-depth', { max: 100 }), maxResources: integer(values['max-resources'] ?? 20000, 'max-resources', { min: 1 }), maxPending: integer(values['max-pending'] ?? 1000, 'max-pending', { min: 1 }),
    concurrency: integer(values.concurrency ?? 4, 'concurrency', { min: 1, max: 64 }), retries: integer(values.retries ?? 2, 'retries', { max: 10 }),
    requestTimeout: duration(values['request-timeout'], 30000), drainTimeout: duration(values['drain-timeout'], 30000), requestId: values['request-id'], insecure: Boolean(values.insecure), anticache: Boolean(values.anticache), command,
  };
}

async function findResource(home, resourceId, sessionId) {
  if (!/^r_[a-f0-9]{20}$/.test(resourceId || '')) invalid('Expected a resource ID (r_...)');
  const records = sessionId ? [await loadSession(home, sessionId)] : await listSessions(home);
  for (const record of records) { const resource = (await resourcesFor(record, true)).find((item) => item.id === resourceId); if (resource) return { record, resource }; }
  fail('RESOURCE_NOT_FOUND', `Resource ${resourceId} does not exist`, { exitCode: 3 });
}
export function paginate(items, values) {
  const cursor = integer(values.cursor ?? 0, 'cursor'); const limit = integer(values.limit ?? 100, 'limit', { min: 1, max: 10000 });
  return { items: items.slice(cursor, cursor + limit), total: items.length, next_cursor: cursor + limit < items.length ? String(cursor + limit) : null };
}
async function directDownload(home, values) {
  let url; try { url = new URL(values.url); } catch { invalid('Invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) invalid('Download URL must be HTTP(S) without embedded credentials');
  const config = captureConfig({ ...values, domain: [url.hostname] });
  const store = new Store(home, config); await store.init();
  const graph = new ResourceGraph(store); const queue = new DownloadQueue(store, (flow, options) => graph.ingest(flow, options)); graph.queue = queue;
  try {
    store.record.state = 'downloading'; await store.save();
    const resource = graph.ensure(url.href, 'GET', {}); resource.selected = true; resource.depth = 0; await graph.persist(resource);
    const job = await queue.enqueue(resource); await queue.waitIdle();
    const result = queue.visible(queue.jobs.get(job.id));
    store.record.state = result.state === 'completed' ? 'stopped' : 'failed'; store.record.finished_at = now();
    await store.save();
    if (result.state !== 'completed') throw new ReslarkError(result.error?.code || 'DOWNLOAD_FAILED', result.error?.message || 'Download failed', { details: { session_id: store.id, download: result } });
    return { session_id: store.id, ...result };
  } finally { await queue.stop(false); await graph.close(); await store.close(); }
}
export async function main(argv = process.argv.slice(2)) {
  const separator = argv.indexOf('--');
  const commandArgs = separator >= 0 ? argv.slice(separator + 1) : [];
  let parsed;
  try { parsed = parseArgs({ args: separator >= 0 ? argv.slice(0, separator) : argv, options, allowPositionals: true, strict: true }); }
  catch (error) { invalid(error.message); }
  const { values, positionals } = parsed; const [command, subject] = positionals;
  const print = (value) => { process.stdout.write(`${JSON.stringify({ schema_version: 1, ...value }, null, values.json ? 0 : 2)}\n`); };
  if (values.version) { print({ name: 'Reslark', package: 'reslark', version: '0.1.0' }); return; }
  if (values.help || !command) { if (values.json) print({ help: HELP }); else process.stdout.write(HELP); return; }
  if (allowedOptions[command]) {
    const allowed = new Set(['home', 'json', 'help', 'version', ...allowedOptions[command]]);
    for (const key of Object.keys(values)) if (!allowed.has(key)) invalid(`--${key} is not supported by ${command}`);
    const noSubject = ['capture', 'run', 'doctor', 'sessions', 'recover', '_daemon'].includes(command) || (command === 'download' && values.url);
    if (positionals.length > (noSubject ? 1 : 2)) invalid(`Unexpected positional arguments for ${command}`);
    if (!noSubject && !subject) invalid(`${command} requires a ${command === 'cert' ? 'subcommand' : 'session or resource ID'}`);
  }
  const home = homeDir(values.home);
  if (command === '_daemon') { if (!values.config) invalid('Missing daemon configuration'); await runDaemon(await readJSON(values.config)); return; }
  if (commandArgs.length && command !== 'run') invalid('Program arguments after -- are only supported by run');
  switch (command) {
    case 'doctor': {
      const backend = await probe(mitmBinary(values)); const media = await probe(values.ffmpeg || process.env.RESLARK_FFMPEG || 'ffmpeg', ['-version']);
      const result = { node: process.version, platform: process.platform, arch: process.arch, mitmdump: backend, ffmpeg: { ...media, version: media.version?.split('\n')[0] }, certificate: await certStatus(home), capabilities: { capture: backend.available, transparent_capture: backend.available ? 'requires platform permissions; verified at session startup' : false, media_merge: media.available } };
      if (values['probe-url']) {
        try { const response = await fetch(values['probe-url'], { signal: AbortSignal.timeout(10000) }); await response.body?.cancel(); result.probe = { reachable: true, status: response.status }; }
        catch { result.probe = { reachable: false }; }
      }
      print(result); if (!backend.available) process.exitCode = 3; return;
    }
    case 'capture': case 'run': {
      if (command === 'run' && !commandArgs.length) invalid('run requires -- PROGRAM [ARGS]');
      const config = captureConfig(values, commandArgs);
      if (values.background) print(await createSession(home, config, { background: true }));
      else { const result = await createSession(home, config, { onReady: async (ready) => print(ready) }); if (result?.state === 'failed') process.exitCode = 4; }
      return;
    }
    case 'sessions': {
      const records = await listSessions(home); const items = [];
      for (const record of records) items.push(await status(home, record.session_id));
      print(paginate(items, values)); return;
    }
    case 'status': print(await status(home, subject)); return;
    case 'stop': {
      const record = await loadSession(home, subject);
      if (!['starting', 'ready', 'stopping'].includes(record.state)) { print(publicSession(record)); return; }
      await control(record, '/stop', { drain: !values['no-drain'] });
      const timeout = duration(values.timeout, record.config.drainTimeout + 15000); const started = Date.now();
      while (Date.now() - started < timeout) {
        const next = await loadSession(home, subject);
        if (!['starting', 'ready', 'stopping'].includes(next.state)) { print(publicSession(next)); return; }
        await sleep(100);
      }
      throw new ReslarkError('WAIT_TIMEOUT', 'Session is still stopping', { exitCode: 5, retryable: true });
    }
    case 'events': {
      const record = await loadSession(home, subject); let after = integer(values.after ?? 0, 'after'); let sent = 0;
      const limit = integer(values.limit ?? (values.follow ? 1000000 : 1000), 'limit', { min: 1 });
      do {
        for await (const event of jsonLines(path.join(record.output_dir, 'events.jsonl'))) if (event.seq > after) { process.stdout.write(`${JSON.stringify(event)}\n`); after = event.seq; if (++sent >= limit) return; }
        if (!values.follow) return;
        const current = await status(home, subject); if (!['ready', 'starting', 'stopping'].includes(current.state)) return;
        await sleep(250);
      } while (true);
    }
    case 'resources': {
      const record = await loadSession(home, subject); let resources = await resourcesFor(record);
      if (values.type?.length) resources = resources.filter((item) => values.type.includes(item.kind));
      if (values.domain?.length) { const domains = values.domain.map(normalizeDomain); resources = resources.filter((item) => domainMatches(new URL(item.url).hostname, domains)); }
      if (values.state) resources = resources.filter((item) => item.state === values.state);
      print(paginate(resources, values)); return;
    }
    case 'inspect': {
      const { record, resource } = await findResource(home, subject, values.session);
      const relations = []; for await (const relation of jsonLines(path.join(record.output_dir, 'relations.jsonl'))) if (relation.from === subject || relation.to === subject) relations.push(relation);
      const visible = (await resourcesFor(record)).find((item) => item.id === resource.id);
      print({ session_id: record.session_id, resource: visible, relations }); return;
    }
    case 'download': {
      if (values.url) { print(await directDownload(home, values)); return; }
      const { record, resource } = await findResource(home, subject, values.session);
      if (record.state === 'ready') print(await control(record, '/download', { resource_id: subject, force: values.force }));
      else print({ downloads: await offlineDownload(home, record, [resource], { force: values.force }) });
      return;
    }
    case 'retry': {
      const record = await loadSession(home, subject); const resources = (await resourcesFor(record, true)).filter((item) => !item.complete && item.state !== 'filtered' && ['GET', 'HEAD'].includes(item.method));
      const jobs = [];
      if (record.state === 'ready') for (const resource of resources) jobs.push(await control(record, '/download', { resource_id: resource.id, force: true }));
      else jobs.push(...await offlineDownload(home, record, resources, { force: true }));
      print({ downloads: jobs }); return;
    }
    case 'wait': {
      const until = values.until || 'idle'; if (!['idle', 'stopped', 'files', 'queue-empty', 'program-exited'].includes(until)) invalid('Unknown wait condition');
      const timeout = duration(values.timeout, 30000); const idle = duration(values.idle, 2000); const count = integer(values.count ?? 1, 'count', { min: 1 });
      const start = Date.now(); let previous; let changed = Date.now();
      while (true) {
        const current = await status(home, subject); const signature = JSON.stringify([current.counts, current.queue, current.last_activity]); if (signature !== previous) { previous = signature; changed = Date.now(); }
        const ended = ['stopped', 'failed', 'interrupted'].includes(current.state); const empty = !(current.queue?.pending || current.queue?.active);
        const matches = until === 'stopped' ? ended : until === 'files' ? current.counts.files >= count : until === 'queue-empty' ? empty : until === 'program-exited' ? current.stop_reason === 'program-exited' : empty && Date.now() - changed >= idle;
        if (matches) { print({ condition: until, ...current }); return; }
        if (ended) throw new ReslarkError('CONDITION_UNREACHABLE', 'Session ended before the requested condition was met', { details: { state: current.state } });
        if (Date.now() - start >= timeout) throw new ReslarkError('WAIT_TIMEOUT', 'Wait condition did not become true', { exitCode: 5, retryable: true });
        await sleep(100);
      }
    }
    case 'export': print(await exportSession(await loadSession(home, subject), values.format, values.out)); return;
    case 'media': {
      const { record } = await findResource(home, subject, values.session);
      print(await mergeMedia(record, subject, { out: values.out, allowNetwork: values['allow-network'], duration: duration(values.duration), ffmpeg: values.ffmpeg })); return;
    }
    case 'cert': {
      if (subject === 'status') print(await certStatus(home));
      else if (subject === 'init') print(await initCert(home, { mitmdump: values.mitmdump }));
      else if (['install', 'uninstall'].includes(subject)) print(await manageCert(home, subject, { system: values.system, mitmdump: values.mitmdump }));
      else invalid('cert requires init, status, install, or uninstall');
      return;
    }
    case 'recover': print({ sessions: await recover(home) }); return;
    default: invalid(`Unknown command: ${command}`);
  }
}
