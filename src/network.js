import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { ReslarkError } from './errors.js';

const hop = /^(host|connection|proxy-connection|proxy-authorization|keep-alive|transfer-encoding|upgrade|te|trailer|content-length)$/i;
export function downloadHeaders(headers = {}) {
  return { ...Object.fromEntries(Object.entries(headers).filter(([key]) => !hop.test(key) && !/^(range|if-range|if-none-match|if-modified-since|accept-encoding)$/i.test(key))), 'accept-encoding': 'identity' };
}
export function crossOriginHeaders(headers, from, to) {
  if (new URL(from).origin === new URL(to).origin) return { ...headers };
  return Object.fromEntries(Object.entries(headers).filter(([key]) => /^(accept|accept-language|accept-encoding|user-agent|range|if-range|cache-control|pragma)$/i.test(key)));
}
export function requestURL(raw, { headers = {}, signal, timeout = 30000, insecure = false } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(raw);
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, { method: 'GET', headers, signal, rejectUnauthorized: !insecure, agent: false }, resolve);
    request.setTimeout(timeout, () => request.destroy(new ReslarkError('NETWORK_TIMEOUT', 'Resource request timed out', { retryable: true })));
    request.once('error', reject);
    request.end();
  });
}
export function requestViaProxy(raw, proxy, options = {}) {
  if (!proxy) return requestURL(raw, options);
  const url = new URL(raw);
  const server = new URL(proxy);
  const transport = server.protocol === 'https:' ? https : http;
  const proxyHeaders = server.username ? { 'proxy-authorization': `Basic ${Buffer.from(`${decodeURIComponent(server.username)}:${decodeURIComponent(server.password)}`).toString('base64')}` } : {};
  if (url.protocol === 'http:') {
    return new Promise((resolve, reject) => {
      const request = transport.request(server, { method: 'GET', path: url.href, headers: { ...options.headers, host: url.host, ...proxyHeaders }, signal: options.signal, agent: false }, resolve);
      request.setTimeout(options.timeout || 30000, () => request.destroy(new ReslarkError('NETWORK_TIMEOUT', 'Proxy request timed out', { retryable: true })));
      request.once('error', reject); request.end();
    });
  }
  return new Promise((resolve, reject) => {
    const tunnel = transport.request(server, { method: 'CONNECT', path: `${url.hostname}:${url.port || 443}`, headers: { host: url.host, ...proxyHeaders }, signal: options.signal, agent: false });
    tunnel.setTimeout(options.timeout || 30000, () => tunnel.destroy(new Error('Proxy CONNECT timed out')));
    tunnel.once('error', reject);
    tunnel.once('connect', (response, socket, head) => {
      if (response.statusCode !== 200) { socket.destroy(); reject(new ReslarkError('UPSTREAM_PROXY_ERROR', `Proxy CONNECT returned ${response.statusCode}`)); return; }
      if (head.length) socket.unshift(head);
      tunnel.setTimeout(0);
      const agent = new https.Agent({ keepAlive: false });
      agent.createConnection = () => tls.connect({ socket, host: url.hostname, servername: isIP(url.hostname) ? undefined : url.hostname, rejectUnauthorized: !options.insecure });
      const request = https.request(url, { method: 'GET', headers: options.headers, signal: options.signal, agent }, (result) => {
        result.once('close', () => agent.destroy()); resolve(result);
      });
      request.setTimeout(options.timeout || 30000, () => request.destroy(new Error('Resource request timed out')));
      request.once('error', (error) => { agent.destroy(); reject(error); }); request.end();
    });
    tunnel.end();
  });
}
