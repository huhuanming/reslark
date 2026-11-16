import { domainToASCII } from 'node:url';
import { invalid } from './errors.js';

export function normalizeDomain(value) {
  let raw = value.trim().toLowerCase().replace(/\.$/, '');
  const wildcard = raw.startsWith('*.');
  if (wildcard) raw = raw.slice(2);
  const ascii = domainToASCII(raw);
  if (!ascii || /[/:\s?#@*]/.test(ascii)) invalid(`Expected a hostname, not a URL: ${value}`);
  return `${wildcard ? '*.' : ''}${ascii}`;
}
export function domainMatches(hostname, rules) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  return rules.some((rule) => rule.startsWith('*.') ? host === rule.slice(2) || host.endsWith(`.${rule.slice(2)}`) : host === rule);
}
export function urlAllowed(url, config) {
  try { return !domainMatches(new URL(url).hostname, config.exclude || []); } catch { return false; }
}
export function isRoot(url, config) {
  if (!urlAllowed(url, config)) return false;
  return !config.domains.length || domainMatches(new URL(url).hostname, config.domains);
}
export function hostRegex(domains) {
  return domains.map((domain) => {
    const wildcard = domain.startsWith('*.');
    const host = (wildcard ? domain.slice(2) : domain).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return `^(?:${wildcard ? '(?:[^.]+\\.)*' : ''}${host})(?::[0-9]+)?$`;
  });
}
