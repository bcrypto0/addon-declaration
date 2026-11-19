import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'addon-declare.js');
const run = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'recheck-'));
const file = (name, text) => {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, text);
  return p;
};

test('a member repeated in the page wrapper gives no digest, so a swapped list cannot verify', () => {
  const good = file('good.json', '{"tools":[{"name":"good"}]}');
  const swapped = file('swapped.json', '{"tools":[{"name":"evil"}],"tools":[{"name":"good"}]}');
  const ok = run(['tool-set-digest', good, '--json']);
  assert.equal(ok.status, 0);
  const bad = run(['tool-set-digest', swapped]);
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr + bad.stdout, /outside the tools array/);
  const envelope = file('env.json', '{"jsonrpc":"2.0","id":1,"id":2,"result":{"tools":[{"name":"good"}]}}');
  assert.notEqual(run(['tool-set-digest', envelope]).status, 0);
});

test('a member repeated inside a tool is still read as that document says, and reported', () => {
  const inside = file('inside.json', '{"tools":[{"name":"a","description":"x","description":"y"}]}');
  const r = run(['tool-set-digest', inside, '--json']);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).repeatedMembers, 1);
});

test('init: key material with a short prefix or suffix in --name or --version is refused and not echoed', () => {
  const K = 'ab12'.repeat(16);
  const tools = file('t.json', '{"tools":[{"name":"a"}]}');
  for (const args of [['--name', 'com.example/k-' + K, '--version', '1'], ['--name', 'com.example/' + K + '_x', '--version', '1'], ['--name', 'com.example/a', '--version', 'v' + K]]) {
    const r = run(['init', ...args, '--tools', tools, '--method', 'http', '--out', path.join(tmp, 'o.json')]);
    assert.equal(r.status, 1);
    assert.ok(!(r.stdout + r.stderr).includes(K));
    assert.ok(!fs.existsSync(path.join(tmp, 'o.json')));
  }
});
