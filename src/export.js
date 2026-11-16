import path from 'node:path';
import { resourcesFor } from './store.js';
import { jsonLines, publicURL, atomicJSON } from './util.js';
import { invalid } from './errors.js';

export async function exportSession(record, format = 'json', destination) {
  const resources = await resourcesFor(record);
  const relations = []; for await (const relation of jsonLines(path.join(record.output_dir, 'relations.jsonl'))) relations.push(relation);
  let result;
  if (format === 'json') result = { schema_version: 1, session_id: record.session_id, resources, relations };
  else if (format === 'har') {
    result = { log: { version: '1.2', creator: { name: 'Reslark', version: '0.1.0' }, entries: resources.filter((item) => item.status).map((item) => ({
      startedDateTime: item.started_at ? new Date(item.started_at * 1000).toISOString() : item.first_seen,
      time: Math.max(0, ((item.finished_at || 0) - (item.started_at || 0)) * 1000),
      request: { method: item.method, url: item.url, httpVersion: item.http_version || 'HTTP/1.1', headers: Object.entries(item.request_headers || {}).map(([name, value]) => ({ name, value })), queryString: [...new URL(item.url).searchParams].map(([name, value]) => ({ name, value })), cookies: [], headersSize: -1, bodySize: -1 },
      response: { status: item.status, statusText: '', httpVersion: item.http_version || 'HTTP/1.1', headers: Object.entries(item.response_headers || {}).map(([name, value]) => ({ name, value })), cookies: [], content: { size: item.bytes || 0, mimeType: item.content_type || 'application/octet-stream', comment: 'Body is stored separately; credentials are redacted' }, redirectURL: item.response_headers?.location || '', headersSize: -1, bodySize: item.bytes || 0 },
      cache: {}, timings: { send: 0, wait: 0, receive: 0 }, _reslark: { resource_id: item.id, path: item.path, complete: item.complete },
    })) } };
  } else if (format === 'urls') result = { urls: [...new Set(resources.map((item) => publicURL(item.url)))] };
  else invalid('Export format must be json, har, or urls');
  if (destination) { await atomicJSON(path.resolve(destination), result); return { path: path.resolve(destination), format, resources: resources.length }; }
  return result;
}
