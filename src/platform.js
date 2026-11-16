import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { spawn } from 'node:child_process';
import { exec, requireBackend, addonPath, probe } from './backend.js';
import { atomicJSON, mkdir, readJSON, now } from './util.js';
import { ReslarkError, fail } from './errors.js';

export async function certStatus(home) {
  const file = path.join(home, 'ca', 'mitmproxy-ca-cert.pem');
  try {
    const cert = new X509Certificate(await fs.readFile(file));
    return { available: true, path: file, fingerprint256: cert.fingerprint256, fingerprint: cert.fingerprint, valid_from: cert.validFrom, valid_to: cert.validTo, expired: Date.parse(cert.validTo) < Date.now(), trust: 'application-specific; use doctor --probe-url to verify the target client' };
  } catch (error) { if (error.code === 'ENOENT') return { available: false, path: file }; throw error; }
}
export async function initCert(home, config = {}) {
  const existing = await certStatus(home); if (existing.available) return existing;
  const binary = await requireBackend(config); const directory = path.join(home, 'ca'); await mkdir(directory);
  const child = spawn(binary, ['-q', '-n', '-s', addonPath, '--set', `confdir=${directory}`], { env: { ...process.env, RESLARK_CERT_ONLY: '1', PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  child.stdout.resume(); let errorText = ''; child.stderr.on('data', (data) => { errorText = (errorText + data).slice(-2000); });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill(); reject(new ReslarkError('CERT_INIT_TIMEOUT', 'CA generation timed out')); }, 30000);
    child.once('error', (error) => { clearTimeout(timeout); reject(error); });
    child.once('exit', (code) => { clearTimeout(timeout); code === 0 ? resolve() : reject(new ReslarkError('CERT_INIT_FAILED', `CA generation failed: ${errorText}`)); });
  });
  await fs.chmod(path.join(directory, 'mitmproxy-ca.pem'), 0o600);
  return certStatus(home);
}
export async function manageCert(home, action, { system = false, mitmdump } = {}) {
  const certificate = action === 'install' ? await initCert(home, { mitmdump }) : await certStatus(home);
  if (!certificate.available) fail('CERT_NOT_FOUND', 'Run reslark cert init first', { exitCode: 3 });
  const tracking = path.join(home, 'certificate-install.json');
  if (process.platform === 'darwin') {
    const keychain = system ? '/Library/Keychains/System.keychain' : path.join(os.homedir(), 'Library/Keychains/login.keychain-db');
    if (action === 'install') await exec('security', ['add-trusted-cert', ...(system ? ['-d'] : []), '-r', 'trustRoot', '-k', keychain, certificate.path]);
    else await exec('security', ['delete-certificate', '-Z', certificate.fingerprint.replaceAll(':', ''), keychain]);
  } else if (process.platform === 'win32') {
    await exec('certutil', [...(system ? [] : ['-user']), ...(action === 'install' ? ['-addstore', 'Root', certificate.path] : ['-delstore', 'Root', certificate.fingerprint.replaceAll(':', '')])]);
  } else if (process.platform === 'linux') {
    if (!system) fail('SYSTEM_SCOPE_REQUIRED', 'Linux trust installation requires --system and administrator privileges. Applications may instead use the PEM path.', { exitCode: 3 });
    const available = await probe('update-ca-certificates', ['--help']);
    if (!available.available) fail('TRUST_TOOL_UNAVAILABLE', 'This Linux trust-store layout is unsupported; import the PEM into your application', { exitCode: 3 });
    const destination = path.join('/usr/local/share/ca-certificates', `reslark-${certificate.fingerprint256.replaceAll(':', '').slice(0, 16)}.crt`);
    if (action === 'install') await fs.copyFile(certificate.path, destination, fs.constants.COPYFILE_EXCL).catch((error) => { if (error.code !== 'EEXIST') throw error; });
    else await fs.rm(destination, { force: true });
    await exec('update-ca-certificates', []);
  } else fail('PLATFORM_UNSUPPORTED', 'Certificate management is unavailable on this platform', { exitCode: 3 });
  await atomicJSON(tracking, { action, system, fingerprint256: certificate.fingerprint256, time: now() });
  return { ...certificate, action, system };
}

function parseMacProxy(text) {
  const values = Object.fromEntries(text.trim().split('\n').map((line) => { const index = line.indexOf(':'); return [line.slice(0, index).trim(), line.slice(index + 1).trim()]; }));
  return { enabled: values.Enabled === 'Yes', server: values.Server || '', port: Number(values.Port) || 0, authenticated: values['Authenticated Proxy Enabled'] === '1' };
}
export async function getSystemProxy(service) {
  if (process.platform === 'darwin') {
    if (!service) fail('SERVICE_REQUIRED', 'macOS --system-proxy requires --network-service (for example Wi-Fi)', { exitCode: 2 });
    const web = parseMacProxy((await exec('networksetup', ['-getwebproxy', service])).stdout);
    const secure = parseMacProxy((await exec('networksetup', ['-getsecurewebproxy', service])).stdout);
    if (web.authenticated || secure.authenticated) fail('AUTHENTICATED_PROXY', 'Cannot safely restore authenticated system proxies; use explicit proxy mode');
    return { platform: 'darwin', service, web, secure };
  }
  if (process.platform === 'win32') {
    const script = "$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; @{enable=$p.ProxyEnable;server=$p.ProxyServer;override=$p.ProxyOverride} | ConvertTo-Json -Compress";
    return { platform: 'win32', ...JSON.parse((await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script])).stdout) };
  }
  if (process.platform === 'linux') {
    const get = async (key) => (await exec('gsettings', ['get', 'org.gnome.system.proxy', key])).stdout.trim();
    const sub = async (scheme, key) => (await exec('gsettings', ['get', `org.gnome.system.proxy.${scheme}`, key])).stdout.trim();
    return { platform: 'linux', mode: await get('mode'), web: { host: await sub('http', 'host'), port: await sub('http', 'port') }, secure: { host: await sub('https', 'host'), port: await sub('https', 'port') } };
  }
  fail('PLATFORM_UNSUPPORTED', 'System proxy management is unavailable', { exitCode: 3 });
}
export async function setSystemProxy(snapshot, port) {
  if (snapshot.platform === 'darwin') {
    for (const type of ['web', 'secureweb']) await exec('networksetup', [`-set${type}proxy`, snapshot.service, '127.0.0.1', String(port)]);
  } else if (snapshot.platform === 'win32') {
    await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; Set-ItemProperty $k ProxyServer '127.0.0.1:${port}'; Set-ItemProperty $k ProxyEnable 1`]);
    await refreshWindowsProxy();
  } else {
    for (const scheme of ['http', 'https']) {
      await exec('gsettings', ['set', `org.gnome.system.proxy.${scheme}`, 'host', '127.0.0.1']);
      await exec('gsettings', ['set', `org.gnome.system.proxy.${scheme}`, 'port', String(port)]);
    }
    await exec('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'manual']);
  }
}
async function refreshWindowsProxy() {
  // WinINet SETTINGS_CHANGED + REFRESH, per Microsoft's option-flags reference.
  const script = `Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class ReslarkProxyRefresh { [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int length); }'; [void][ReslarkProxyRefresh]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0); [void][ReslarkProxyRefresh]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)`;
  await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
}
export async function restoreSystemProxy(snapshot, port) {
  const current = await getSystemProxy(snapshot.service);
  const conflicts = [];
  if (snapshot.platform === 'darwin') {
    for (const [type, key, original] of [['web', 'web', snapshot.web], ['secureweb', 'secure', snapshot.secure]]) {
      const value = current[key];
      if (JSON.stringify(value) === JSON.stringify(original)) continue;
      if (value.server !== '127.0.0.1' || value.port !== port || !value.enabled) { conflicts.push(key); continue; }
      if (original.server && original.port) await exec('networksetup', [`-set${type}proxy`, snapshot.service, original.server, String(original.port)]);
      await exec('networksetup', [`-set${type}proxystate`, snapshot.service, original.enabled ? 'on' : 'off']);
    }
  } else if (snapshot.platform === 'win32') {
    if (current.server === snapshot.server && current.enable === snapshot.enable) return { restored: true };
    if (current.server !== `127.0.0.1:${port}` || (current.enable !== 1 && current.enable !== snapshot.enable)) return { restored: false, reason: 'SETTINGS_CHANGED' };
    const encoded = Buffer.from(JSON.stringify(snapshot)).toString('base64');
    const script = `$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json; $k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; foreach($n in @('ProxyServer','ProxyEnable')) { $v=switch($n){'ProxyServer'{$p.server};'ProxyEnable'{$p.enable}}; if($null -eq $v){Remove-ItemProperty $k $n -ErrorAction SilentlyContinue}else{Set-ItemProperty $k $n $v} }`;
    await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
    await refreshWindowsProxy();
  } else {
    for (const [scheme, key, original] of [['http', 'web', snapshot.web], ['https', 'secure', snapshot.secure]]) {
      const value = current[key];
      if (value.host === original.host && value.port === original.port) continue;
      if (value.host !== "'127.0.0.1'" || Number(value.port) !== port) { conflicts.push(scheme); continue; }
      await exec('gsettings', ['set', `org.gnome.system.proxy.${scheme}`, 'host', original.host]);
      await exec('gsettings', ['set', `org.gnome.system.proxy.${scheme}`, 'port', original.port]);
    }
    if (current.mode === "'manual'" && !conflicts.length) await exec('gsettings', ['set', 'org.gnome.system.proxy', 'mode', snapshot.mode]);
    else if (current.mode !== snapshot.mode) conflicts.push('mode');
  }
  return conflicts.length ? { restored: false, reason: 'SETTINGS_CHANGED', conflicts } : { restored: true };
}
export async function processList() {
  if (process.platform === 'win32') {
    const output = (await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CreationDate | ConvertTo-Json -Compress'])).stdout;
    const list = JSON.parse(output || '[]');
    return (Array.isArray(list) ? list : [list]).map((item) => ({ pid: item.ProcessId, ppid: item.ParentProcessId, name: item.Name, identity: String(item.CreationDate) }));
  }
  const output = (await exec('ps', ['-axo', 'pid=,ppid=,lstart=,comm='])).stdout;
  return output.trim().split('\n').map((line) => {
    const match = /^\s*(\d+)\s+(\d+)\s+(.{24})\s+(.+)$/.exec(line);
    return match ? { pid: Number(match[1]), ppid: Number(match[2]), identity: match[3], name: match[4] } : null;
  }).filter(Boolean);
}
export function descendants(list, roots) {
  const selected = new Set(roots.map(Number)); let changed = true;
  while (changed) { changed = false; for (const item of list) if (selected.has(item.ppid) && !selected.has(item.pid)) { selected.add(item.pid); changed = true; } }
  return list.filter((item) => selected.has(item.pid));
}
