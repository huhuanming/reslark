import { promises as fs } from 'node:fs';
import { gunzipSync, inflateSync, brotliDecompressSync } from 'node:zlib';
import { normalizeURL } from './util.js';

const entities = (text) => text.replace(/&(?:amp|quot|apos|lt|gt);|&#(?:x[0-9a-f]+|\d+);/gi, (value) => {
  if (value.startsWith('&#')) { const number = value[2].toLowerCase() === 'x' ? parseInt(value.slice(3), 16) : parseInt(value.slice(2), 10); return number <= 0x10ffff ? String.fromCodePoint(number) : '\ufffd'; }
  return { '&amp;': '&', '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>' }[value.toLowerCase()] || value;
});
export function extractReferences(text, base, mime) {
  const references = new Map(); const limitations = [];
  const add = (raw, relation, origin = base) => { const url = normalizeURL(entities(raw), origin); if (url && url !== base && references.size < 10000) references.set(url, { url, relation }); };
  if (/json/i.test(mime)) {
    const visit = (value, depth = 0) => {
      if (depth > 40) return;
      if (typeof value === 'string' && /^(https?:\/\/|\/)/.test(value)) add(value, 'json-reference');
      else if (Array.isArray(value)) value.slice(0, 10000).forEach((item) => visit(item, depth + 1));
      else if (value && typeof value === 'object') Object.values(value).forEach((item) => visit(item, depth + 1));
    };
    try { visit(JSON.parse(text)); } catch { limitations.push('JSON_REFERENCE_PARSE_FAILED'); }
  }
  if (/html/i.test(mime)) {
    let documentBase = base;
    const tags = text.matchAll(/<([a-z][\w:-]*)\b((?:[^<>"']|"[^"]*"|'[^']*')*)>/gi);
    for (const [, tag, body] of tags) {
      const attrs = Object.fromEntries([...body.matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)].map(([, key, a, b, c]) => [key.toLowerCase(), a ?? b ?? c ?? '']));
      if (tag.toLowerCase() === 'base' && attrs.href) documentBase = normalizeURL(entities(attrs.href), base) || base;
      for (const key of ['src', 'poster', 'data-src']) if (attrs[key]) add(attrs[key], 'html-reference', documentBase);
      if (/^(link|image|use)$/i.test(tag) && (attrs.href || attrs['xlink:href'])) add(attrs.href || attrs['xlink:href'], 'html-reference', documentBase);
      for (const candidate of (attrs.srcset || '').split(',')) if (candidate.trim()) add(candidate.trim().split(/\s+/)[0], 'html-srcset', documentBase);
    }
  }
  if (/css|html/i.test(mime)) {
    for (const [, value] of text.matchAll(/url\(\s*['"]?([^)'"\s]+)/gi)) add(value, 'css-reference');
    for (const [, value] of text.matchAll(/@import\s+['"]([^'"]+)/gi)) add(value, 'css-import');
  }
  if (/mpegurl/i.test(mime) || text.trimStart().startsWith('#EXTM3U')) {
    for (const line of text.split(/\r?\n/)) {
      if (line.trim() && !line.trim().startsWith('#')) add(line.trim(), 'hls-reference');
      for (const [, value] of line.matchAll(/URI="([^"]+)"/g)) add(value, 'hls-reference');
    }
    if (/SAMPLE-AES|KEYFORMAT=/.test(text)) limitations.push('ENCRYPTED_MEDIA_MAY_REQUIRE_DRM');
  }
  if (/dash\+xml/i.test(mime) || /<MPD\b/.test(text)) {
    let documentBase = base;
    const baseMatch = /<BaseURL[^>]*>([^<]+)<\/BaseURL>/i.exec(text);
    if (baseMatch) { documentBase = normalizeURL(entities(baseMatch[1]), base) || base; add(documentBase, 'dash-base'); }
    for (const [, , value] of text.matchAll(/\b(media|sourceURL|initialization)\s*=\s*['"]([^'"]+)['"]/g)) {
      if (value.includes('$')) limitations.push('DASH_TEMPLATE_REQUIRES_MEDIA_BACKEND');
      else add(value, 'dash-reference', documentBase);
    }
    if (/<ContentProtection\b/.test(text)) limitations.push('DASH_CONTENT_PROTECTION');
  }
  for (const match of entities(text.replaceAll('\\/', '/')).matchAll(/https?:\/\/[^\s"'<>\\`]+/g)) if (!references.has(normalizeURL(match[0], base))) add(match[0].replace(/[,);]+$/, ''), 'text-reference');
  return { references: [...references.values()], limitations: [...new Set(limitations)] };
}
export async function scanBody(file, url, headers, limit) {
  const mime = headers['content-type'] || '';
  if (!/text\/|json|javascript|xml|mpegurl/i.test(mime)) return { references: [], limitations: [] };
  const handle = await fs.open(file, 'r');
  try {
    const size = (await handle.stat()).size;
    const data = Buffer.alloc(Math.min(size, limit)); await handle.read(data, 0, data.length, 0);
    const decode = { gzip: gunzipSync, deflate: inflateSync, br: brotliDecompressSync }[headers['content-encoding']];
    const decoded = decode ? decode(data, { maxOutputLength: limit }) : data;
    const result = extractReferences(decoded.toString('utf8'), url, mime);
    if (size > limit) result.limitations.push('REFERENCE_SCAN_TRUNCATED');
    return result;
  } catch { return { references: [], limitations: ['CONTENT_DECODE_OR_SCAN_FAILED'] }; }
  finally { await handle.close(); }
}
