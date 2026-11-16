import path from 'node:path';
import { promises as fs } from 'node:fs';
import { hash, id, now, publicURL, publicHeaders, safeName, mkdir, normalizeURL, within, fileHash, appendJSON } from './util.js';
import { isRoot, urlAllowed } from './rules.js';
import { crossOriginHeaders } from './network.js';
import { ReslarkError } from './errors.js';

const extensions = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/svg+xml': '.svg', 'video/mp4': '.mp4', 'audio/mpeg': '.mp3', 'application/json': '.json', 'text/html': '.html', 'text/css': '.css', 'application/javascript': '.js', 'text/javascript': '.js', 'application/vnd.apple.mpegurl': '.m3u8', 'application/x-mpegurl': '.m3u8', 'application/dash+xml': '.mpd', 'application/pdf': '.pdf', 'video/mp2t': '.ts' };
export function classify(url, contentType = '') {
  const type = contentType.toLowerCase().split(';')[0].trim();
  const ext = path.posix.extname(new URL(url).pathname).toLowerCase();
  if (/mpegurl|dash\+xml/.test(type) || ['.m3u8', '.mpd'].includes(ext)) return 'manifest';
  if (type.startsWith('image/') || /\.(png|jpe?g|webp|avif|gif|svg|ico|heic)$/.test(ext)) return 'image';
  if (type.startsWith('video/') || /\.(mp4|webm|mov|mkv|flv|ts|m4s)$/.test(ext)) return 'video';
  if (type.startsWith('audio/') || /\.(mp3|m4a|aac|ogg|flac|wav)$/.test(ext)) return 'audio';
  if (type.startsWith('font/') || /\.(woff2?|ttf|otf)$/.test(ext)) return 'font';
  if (type.includes('json')) return 'json';
  if (type.includes('html')) return 'html';
  if (type.includes('javascript') || /\.(m?js)$/.test(ext)) return 'script';
  if (type.includes('css') || ext === '.css') return 'style';
  if (/pdf|officedocument|msword|spreadsheet/.test(type)) return 'document';
  return 'other';
}
export function resourceKey(url, method = 'GET', headers = {}) {
  const normalized = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  return hash(JSON.stringify([method, url, ...['authorization', 'cookie', 'accept', 'accept-language', 'user-agent', 'origin'].map((key) => normalized[key] || '')]));
}
export class ResourceGraph {
  constructor(store) {
    this.store = store; this.config = store.config; this.records = new Map(); this.keys = new Map(); this.byURL = new Map(); this.pendingFlows = new Map(); this.edges = new Set(); this.objects = new Map(); this.activity = Date.now(); this.queue = null;
    this.ingests = Promise.resolve();
  }
  async restore(records) {
    for (const resource of records) {
      this.records.set(resource.id, resource); this.keys.set(resourceKey(resource.url, resource.method, resource.request_headers), resource.id);
      if (!this.byURL.has(resource.url)) this.byURL.set(resource.url, new Set());
      this.byURL.get(resource.url).add(resource.id);
      if (resource.complete && resource.sha256 && resource.path) this.objects.set(resource.sha256, resource.path);
    }
  }
  ensure(url, method, headers, resourceId) {
    const key = resourceKey(url, method, headers);
    const existing = resourceId ? this.records.get(resourceId) : this.records.get(this.keys.get(key));
    if (existing) return existing;
    if (this.records.size >= this.config.maxResources) throw new ReslarkError('RESOURCE_LIMIT', 'Resource metadata limit reached');
    const resource = { id: resourceId || id('r'), url, method, request_headers: headers, selected: false, depth: null, state: 'discovered', first_seen: now(), complete: false, kind: classify(url) };
    this.records.set(resource.id, resource); this.keys.set(key, resource.id);
    if (!this.byURL.has(url)) this.byURL.set(url, new Set());
    this.byURL.get(url).add(resource.id);
    return resource;
  }
  visible(resource) {
    const { request_headers, body_path, references, url, final_url, ...rest } = resource;
    return { ...rest, url: publicURL(url), ...(final_url ? { final_url: publicURL(final_url) } : {}), ...(request_headers ? { request_headers: publicHeaders(request_headers) } : {}) };
  }
  async persist(resource) {
    if (!resource.selected) return;
    this.activity = Date.now(); resource.updated_at = now();
    await this.store.resource(this.visible(resource), resource);
    this.store.record.counts.resources = [...this.records.values()].filter((item) => item.selected).length;
  }
  ingest(flow, options = {}) {
    const result = this.ingests.then(() => this.ingestFlow(flow, options));
    this.ingests = result.catch(() => {});
    return result;
  }
  async ingestFlow(flow, options = {}) {
    flow = { ...flow, request_headers: Object.fromEntries(Object.entries(flow.request_headers || {}).map(([key, value]) => [key.toLowerCase(), value])), response_headers: Object.fromEntries(Object.entries(flow.response_headers || {}).map(([key, value]) => [key.toLowerCase(), value])) };
    const url = normalizeURL(flow.url);
    if (!url || !urlAllowed(url, this.config)) { await this.discard(flow.body_path); return null; }
    if (!this.config.related && !isRoot(url, this.config)) { await this.discard(flow.body_path); return null; }
    const resource = this.ensure(url, flow.method, flow.request_headers, options.resourceId);
    const wasSelected = resource.selected;
    if (isRoot(url, this.config)) { resource.selected = true; resource.depth = 0; resource.selection = 'domain'; }
    if (!resource.selected && this.config.related) {
      for (const header of ['referer', 'origin']) {
        const sourceURL = normalizeURL(flow.request_headers?.[header]);
        const source = sourceURL && [...(this.byURL.get(sourceURL) || [])].map((item) => this.records.get(item)).find((item) => item.selected);
        if (source && source.depth < this.config.maxDepth) { await this.link(source, resource, `${header}-header`); break; }
        if (sourceURL && isRoot(sourceURL, this.config)) {
          const root = this.ensure(sourceURL, 'GET', {}); root.selected = true; root.depth = 0;
          await this.persist(root); await this.link(root, resource, `${header}-header`); break;
        }
      }
    }
    if (!resource.selected) {
      const previous = this.pendingFlows.get(resource.id); if (previous) await this.discard(previous.body_path);
      this.pendingFlows.set(resource.id, flow);
      if (this.pendingFlows.size > this.config.maxPending) {
        const [oldId, oldFlow] = this.pendingFlows.entries().next().value;
        this.pendingFlows.delete(oldId); await this.discard(oldFlow.body_path);
        await this.store.event('capture.omitted', { code: 'PENDING_RESOURCE_LIMIT', resource_id: oldId });
      }
      return null;
    }
    if (!wasSelected) await this.store.event('resource.discovered', { resource_id: resource.id, url: publicURL(url), kind: resource.kind });
    await this.accept(resource, flow);
    return resource;
  }
  async link(source, target, relation) {
    if (!this.config.related || source.depth >= this.config.maxDepth || !urlAllowed(target.url, this.config)) return;
    const key = `${source.id}:${target.id}:${relation}`;
    if (!this.edges.has(key)) {
      this.edges.add(key);
      await this.store.relation({ from: source.id, to: target.id, relation, evidence: ['referer-header', 'origin-header', 'text-reference'].includes(relation) ? 'inferred' : 'explicit', time: now() });
    }
    const newlySelected = !target.selected;
    target.selected = true; target.depth = Math.min(target.depth ?? Infinity, source.depth + 1); target.selection ||= relation;
    if (newlySelected) {
      await this.persist(target);
      await this.store.event('resource.discovered', { resource_id: target.id, url: publicURL(target.url), kind: target.kind });
      const pending = this.pendingFlows.get(target.id);
      if (pending) { this.pendingFlows.delete(target.id); await this.accept(target, pending); }
    }
  }
  async accept(resource, flow) {
    const previousComplete = resource.complete ? { ...resource } : null;
    const headers = Object.fromEntries(Object.entries(flow.response_headers || {}).filter(([, value]) => value !== undefined));
    const mime = (headers['content-type'] || '').split(';')[0];
    Object.assign(resource, { status: flow.status, http_version: flow.http_version, response_headers: publicHeaders(headers), content_type: mime, content_encoding: headers['content-encoding'] || 'identity', kind: classify(resource.url, mime), bytes: flow.bytes, observed_bytes: flow.observed_bytes, sha256: flow.sha256, content_range: headers['content-range'], limitations: flow.limitations || [], started_at: flow.started_at, finished_at: flow.finished_at, final_url: flow.final_url });
    const success = flow.status >= 200 && flow.status < 300 && flow.status !== 204 && resource.method !== 'HEAD';
    const fullRange = /^bytes 0-(\d+)\/(\d+)$/.exec(headers['content-range'] || '');
    const rangeComplete = flow.status !== 206 || (fullRange && Number(fullRange[1]) + 1 === Number(fullRange[2]) && flow.bytes === Number(fullRange[2]));
    resource.complete = Boolean(success && !flow.truncated && rangeComplete);
    resource.state = resource.complete ? 'captured' : success ? 'partial' : flow.status === 304 ? 'cache-miss' : 'observed';
    if (flow.truncated) resource.limitations.push('BODY_CAPTURE_TRUNCATED');
    const selectedType = !this.config.types.length || this.config.types.includes(resource.kind);
    if (flow.body_path && success && selectedType) {
      if (!within(path.join(this.store.state, 'spool'), flow.body_path)) throw new ReslarkError('INVALID_SPOOL_PATH', 'Backend returned a path outside the spool');
      const exists = await fs.stat(flow.body_path).catch(() => null);
      if (exists) {
        if ((this.config.maxFiles && this.store.record.counts.files >= this.config.maxFiles) || (this.config.maxBytes && this.store.record.counts.bytes + flow.bytes > this.config.maxBytes)) {
          resource.complete = false; resource.state = 'omitted'; resource.limitations.push('SESSION_STORAGE_LIMIT');
          await this.discard(flow.body_path);
        } else {
          const duplicate = resource.complete && this.objects.get(flow.sha256);
          if (duplicate && await fs.stat(path.join(this.store.out, duplicate)).catch(() => null)) { resource.path = duplicate; await this.discard(flow.body_path); }
          else {
            const url = new URL(resource.url);
            let name;
            try { name = safeName(decodeURIComponent(path.posix.basename(url.pathname))); } catch { name = 'resource'; }
            if (!path.extname(name)) name += extensions[mime] || '.bin';
            const directory = path.join(this.store.out, resource.kind === 'manifest' ? 'manifests' : 'files', safeName(url.hostname));
            await mkdir(directory);
            const destination = path.join(directory, `${resource.id}-${flow.sha256?.slice(0, 10) || id('f')}-${name}${resource.complete ? '' : '.partial'}`);
            // link is exclusive, so even a user-created file is never overwritten.
            try {
              try { await fs.link(flow.body_path, destination); }
              catch (error) { if (!['EXDEV', 'EPERM', 'ENOTSUP', 'EOPNOTSUPP'].includes(error.code)) throw error; await fs.copyFile(flow.body_path, destination, fs.constants.COPYFILE_EXCL); }
            } catch (error) { if (error.code !== 'EEXIST') throw error; if (await fileHash(destination) !== flow.sha256) throw new ReslarkError('FILE_CONFLICT', 'An existing output file has different contents'); }
            await this.discard(flow.body_path);
            resource.path = path.relative(this.store.out, destination);
            if (resource.complete) this.objects.set(flow.sha256, resource.path);
            this.store.record.counts.files++; this.store.record.counts.bytes += flow.bytes;
          }
        }
      } else { resource.complete = false; resource.state = 'unavailable'; resource.limitations.push('CAPTURE_BODY_MISSING'); }
    } else {
      await this.discard(flow.body_path);
      if (!selectedType) { resource.complete = false; resource.state = 'filtered'; }
    }
    const request = { id: flow.flow_id || id('q'), resource_id: resource.id, url: publicURL(resource.url), method: resource.method, status: flow.status, bytes: flow.bytes, complete: resource.complete, path: resource.path, sha256: flow.sha256, time: now(), content_range: resource.content_range };
    await this.store.serial(async () => {
      await appendJSON(path.join(this.store.out, 'requests.jsonl'), request);
      await appendJSON(path.join(this.store.state, 'requests.jsonl'), { ...request, url: resource.url, request_headers: resource.request_headers });
    });
    // A subsequent cache validation or range request does not erase a known full object.
    if (previousComplete && !resource.complete) {
      const lastResponse = { status: resource.status, state: resource.state, content_range: resource.content_range, limitations: resource.limitations };
      Object.assign(resource, previousComplete, { last_response: lastResponse });
    }
    await this.persist(resource);
    await this.store.event(resource.complete ? 'resource.saved' : 'resource.observed', { resource_id: resource.id, kind: resource.kind, state: resource.state, path: resource.path });
    if (this.config.related) {
      for (const reference of flow.references || []) {
        const url = normalizeURL(reference.url, resource.url);
        if (!url || !urlAllowed(url, this.config) || resource.depth >= this.config.maxDepth) continue;
        const inherited = crossOriginHeaders(resource.request_headers || {}, resource.url, url);
        const target = this.ensure(url, 'GET', inherited);
        await this.link(resource, target, reference.relation);
        // Other request variants remain distinct, but explicit URL evidence can select them.
        for (const candidateId of this.byURL.get(url) || []) {
          const candidate = this.records.get(candidateId);
          if (!candidate.selected) await this.link(resource, candidate, reference.relation);
        }
        if (this.config.complete && !target.complete && !['dash-base', 'text-reference'].includes(reference.relation)) await this.queue?.enqueue(target);
      }
      // Streamed downloads are scanned separately by the media backend; no JS is executed.
    }
    if (this.config.complete && resource.state === 'partial' && resource.method === 'GET' && !flow.downloaded) await this.queue?.enqueue(resource);
  }
  async discard(file) { if (file && within(path.join(this.store.state, 'spool'), file)) await fs.rm(file, { force: true }); }
  async close() { await this.ingests; for (const flow of this.pendingFlows.values()) await this.discard(flow.body_path); this.pendingFlows.clear(); }
}
