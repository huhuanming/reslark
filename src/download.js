import path from 'node:path';
import { promises as fs, createWriteStream } from 'node:fs';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { id, now, mkdir, readJSON, atomicJSON, sleep, fileHash, publicURL } from './util.js';
import { requestViaProxy, downloadHeaders, crossOriginHeaders } from './network.js';
import { ReslarkError, asError } from './errors.js';
import { urlAllowed } from './rules.js';
import { scanBody } from './scan.js';

export class DownloadQueue {
  constructor(store, consume) {
    this.store = store; this.consume = consume; this.pending = []; this.active = new Map(); this.jobs = new Map(); this.stopping = false;
    this.activity = Date.now();
  }
  async enqueue(resource, { force = false } = {}) {
    if (!['GET', 'HEAD'].includes(resource.method || 'GET')) throw new ReslarkError('UNSAFE_REPLAY', 'Only GET/HEAD resources can be downloaded');
    if (!urlAllowed(resource.url, this.store.config)) throw new ReslarkError('DOMAIN_EXCLUDED', 'Resource is excluded by the session rules');
    if (this.pending.length >= this.store.config.maxPending) throw new ReslarkError('QUEUE_FULL', 'Download queue limit reached');
    const existing = [...this.jobs.values()].find((job) => job.resource_id === resource.id && ['queued', 'running'].includes(job.state));
    if (existing) return this.visible(existing);
    if (!force && resource.complete && resource.path) return { resource_id: resource.id, state: 'completed', path: resource.path };
    const job = { id: id('d'), resource_id: resource.id, url: resource.url, headers: resource.request_headers || {}, state: 'queued', created_at: now(), attempt: 0 };
    this.jobs.set(job.id, job); this.pending.push(job);
    await this.persist(job); this.pump();
    return this.visible(job);
  }
  visible(job) { const { headers, url, ...rest } = job; return { ...rest, url: publicURL(url) }; }
  async persist(job) {
    this.activity = Date.now();
    await this.store.download(this.visible(job));
    await atomicJSON(path.join(this.store.state, 'tasks', `${job.id}.json`), job);
    await this.store.event(`download.${job.state}`, this.visible(job));
  }
  pump() {
    while (!this.stopping && this.active.size < this.store.config.concurrency && this.pending.length) {
      const job = this.pending.shift();
      const controller = new AbortController();
      const promise = this.perform(job, controller.signal).catch(async (error) => {
        job.state = this.stopping ? 'cancelled' : 'failed'; job.error = asError(error).toJSON(); job.finished_at = now();
        await this.persist(job);
      }).catch((error) => { this.error ||= error; this.stopping = true; }).finally(() => { this.active.delete(job.id); this.pump(); });
      this.active.set(job.id, { controller, promise });
    }
  }
  async perform(job, signal) {
    job.state = 'running'; await this.persist(job);
    let lastError;
    for (let attempt = 0; attempt <= this.store.config.retries; attempt++) {
      if (signal.aborted) throw signal.reason;
      job.attempt++; await this.persist(job);
      try {
        const flow = await this.fetch(job, signal);
        const resource = await this.consume(flow, { resourceId: job.resource_id });
        if (!resource?.complete) throw new ReslarkError('DOWNLOAD_INCOMPLETE', 'Response was saved as partial or unavailable; inspect resource metadata');
        job.state = 'completed'; job.path = resource.path; job.bytes = resource.bytes; job.finished_at = now();
        await this.persist(job); return;
      } catch (error) {
        lastError = error;
        if (signal.aborted || error.retryable === false || attempt === this.store.config.retries) throw error;
        await sleep(Math.min(10000, 500 * 2 ** attempt), undefined, { signal });
      }
    }
    throw lastError;
  }
  async fetch(job, signal) {
    const directory = path.join(this.store.state, 'downloads'); await mkdir(directory);
    // Stable across retry commands and daemon restarts, without combining variants.
    const partial = path.join(directory, `${job.resource_id}.part`);
    const checkpoint = `${partial}.json`;
    let saved = await readJSON(checkpoint, {});
    let offset = (await fs.stat(partial).catch(() => ({ size: 0 }))).size;
    let url = job.url;
    let headers = downloadHeaders(job.headers);
    if (offset && (saved.etag || saved.last_modified) && saved.url === url && !saved.content_encoding) {
      headers.range = `bytes=${offset}-`; headers['if-range'] = saved.etag || saved.last_modified;
    } else { offset = 0; await fs.rm(partial, { force: true }); }
    let response;
    for (let redirect = 0; redirect <= 10; redirect++) {
      if (!urlAllowed(url, this.store.config)) throw new ReslarkError('DOMAIN_EXCLUDED', 'Redirect destination is excluded');
      response = await requestViaProxy(url, this.store.config.upstream, { headers, signal, timeout: this.store.config.requestTimeout, insecure: this.store.config.insecure });
      if (![301, 302, 303, 307, 308].includes(response.statusCode)) break;
      response.resume();
      if (!response.headers.location || redirect === 10) throw new ReslarkError('REDIRECT_LIMIT', 'Missing redirect location or too many redirects');
      const next = new URL(response.headers.location, url).href;
      if (!['http:', 'https:'].includes(new URL(next).protocol)) throw new ReslarkError('INVALID_REDIRECT', 'Only HTTP(S) redirects are supported');
      headers = crossOriginHeaders(headers, url, next); url = next;
    }
    const status = response.statusCode;
    if (status < 200 || status >= 300) {
      response.resume();
      throw new ReslarkError('HTTP_ERROR', `Resource returned HTTP ${status}`, { retryable: status === 408 || status === 429 || status >= 500, details: { status } });
    }
    let total = Number(response.headers['content-length']) || null;
    if (status === 206) {
      const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers['content-range'] || '');
      if (!range || Number(range[1]) !== offset || Number(range[2]) !== Number(range[3]) - 1 || (offset && saved.etag && response.headers.etag && saved.etag !== response.headers.etag)) {
        response.destroy(); await fs.rm(partial, { force: true }); await fs.rm(checkpoint, { force: true });
        throw new ReslarkError('INVALID_CONTENT_RANGE', 'Server returned an unexpected range; partial download was discarded', { retryable: true });
      }
      total = Number(range[3]);
    } else offset = 0;
    if (total && total > this.store.config.maxBodyBytes) { response.destroy(); throw new ReslarkError('BODY_LIMIT', 'Resource exceeds max-body-bytes'); }
    saved = { url: job.url, etag: response.headers.etag?.startsWith('W/') ? undefined : response.headers.etag, last_modified: response.headers['last-modified'], content_encoding: response.headers['content-encoding'] };
    await atomicJSON(checkpoint, saved);
    let bytes = offset;
    const meter = new Transform({ transform: (chunk, _encoding, callback) => {
      bytes += chunk.length;
      if (bytes > this.store.config.maxBodyBytes || (this.store.config.maxBytes && this.store.record.counts.bytes + bytes > this.store.config.maxBytes)) callback(new ReslarkError('BYTE_LIMIT', 'Download byte limit reached'));
      else callback(null, chunk);
    } });
    await pipeline(response, meter, createWriteStream(partial, { flags: offset ? 'a' : 'w', mode: 0o600 }), { signal });
    if (total && bytes !== total) throw new ReslarkError('CONTENT_LENGTH_MISMATCH', 'Downloaded size does not match response length', { retryable: true });
    const spool = path.join(this.store.state, 'spool', `${job.id}.part`);
    await fs.rename(partial, spool); await fs.rm(checkpoint, { force: true });
    const scanned = await scanBody(spool, url, response.headers, this.store.config.scanBytes);
    return { flow_id: job.id, url: job.url, final_url: url, method: 'GET', request_headers: job.headers, response_headers: { ...response.headers, 'content-length': String(bytes), 'content-range': undefined }, status: 200, started_at: Date.now() / 1000, finished_at: Date.now() / 1000, body_path: spool, bytes, observed_bytes: bytes, sha256: await fileHash(spool), truncated: false, ...scanned, downloaded: true };
  }
  async waitIdle(timeout = 0) {
    const start = Date.now();
    while (this.pending.length || this.active.size) {
      if (this.error) throw this.error;
      if (timeout && Date.now() - start >= timeout) throw new ReslarkError('WAIT_TIMEOUT', 'Download queue did not drain in time', { exitCode: 5, retryable: true });
      await sleep(50);
    }
    if (this.error) throw this.error;
  }
  async stop(drain = true, timeout = 30000) {
    if (drain) {
      try { await this.waitIdle(timeout); return; } catch (error) { if (error.code !== 'WAIT_TIMEOUT') throw error; }
    }
    this.stopping = true;
    for (const job of this.pending.splice(0)) { job.state = 'cancelled'; await this.persist(job); }
    for (const { controller } of this.active.values()) controller.abort(new ReslarkError('DOWNLOAD_CANCELLED', 'Session stopped'));
    await Promise.allSettled([...this.active.values()].map((entry) => entry.promise));
  }
}
