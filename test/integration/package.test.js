import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
test('npm tarball installs without dependencies and its bundled addon starts a real capture', { skip: !process.env.RESLARK_MITMDUMP, timeout: 45000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'reslark-package-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const packed = JSON.parse((await exec('npm', ['pack', '--json', '--pack-destination', directory], { cwd: root })).stdout)[0];
  assert.ok(packed.files.some((item) => item.path === 'addon/reslark.py'));
  assert.equal(packed.files.some((item) => /__pycache__|\.pyc$|\.tools|\.state/.test(item.path)), false);
  const installed = path.join(directory, 'installed');
  await exec('npm', ['install', '--prefix', installed, '--ignore-scripts', '--no-audit', '--no-fund', path.join(directory, packed.filename)]);
  const executable = path.join(installed, 'node_modules/reslark/bin/reslark.js');
  const cli = async (...args) => JSON.parse((await exec(process.execPath, [executable, ...args, '--home', path.join(directory, 'home'), '--json'], { timeout: 35000 })).stdout);
  assert.equal((await cli('--version')).package, 'reslark');
  const session = await cli('capture', '--domain', 'example.com', '--out', path.join(directory, 'out'), '--background');
  t.after(() => cli('stop', session.session_id, '--no-drain').catch(() => {}));
  assert.equal(session.state, 'ready'); assert.equal((await cli('stop', session.session_id)).state, 'stopped');
});
