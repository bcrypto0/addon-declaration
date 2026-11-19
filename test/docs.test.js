// Keeps SPEC.md, README.md and the CLI help in step with the code.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { STATES, declarationHash, parseDeclarationText } from '../lib/declaration.js';
import { HELP, parseArgs, COMMAND_FLAGS, LISTING_STATES, PREPARE_STATES } from '../lib/cli.js';
import { toolsHashFromText, toolsHash } from '../lib/tools.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';
import { makeKey, TOOLS } from '../testlib/helpers.js';

const read = (p) => fs.readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const SPEC = read('SPEC.md');
const README = read('README.md');
const BSL = String.fromCharCode(92);

// Line ends are normalized first: a Windows checkout with core.autocrlf gives
// CRLF files, and a pattern that needs LF would then find no block at all.
function codeBlocks(md) {
  return [...md.replace(/\r\n/g, '\n').matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map((m) => m[1]);
}

// Every documented command line: the words after "addon-declare.js".
function documentedCommands(md) {
  const out = [];
  for (const block of codeBlocks(md)) {
    for (const line of block.split('\n')) {
      const at = line.indexOf('addon-declare.js ');
      if (at >= 0) out.push(line.slice(at + 'addon-declare.js '.length).trim().split(/\s+/));
    }
  }
  return out;
}

test('README and SPEC commands are single lines (they paste into PowerShell)', () => {
  for (const [name, md] of [['README.md', README], ['SPEC.md', SPEC], ['README.md with CRLF', README.replace(/\r?\n/g, '\r\n')]]) {
    const blocks = codeBlocks(md);
    assert.ok(blocks.length >= 3, `${name}: found ${blocks.length} code blocks`);
    for (const block of blocks) {
      for (const line of block.split('\n')) {
        if (!line.includes('addon-declare')) continue;
        assert.ok(!line.trimEnd().endsWith(BSL) && !line.trimEnd().endsWith('`'), `${name}: continuation in "${line}"`);
      }
    }
  }
});

test('every command in README and SPEC uses a command and flags the CLI knows', () => {
  const cmds = [...documentedCommands(README), ...documentedCommands(SPEC)];
  assert.ok(cmds.length >= 6, `found ${cmds.length} commands`);
  for (const [cmd, ...rest] of cmds) {
    assert.ok(['hash-tools', 'tool-set-digest', 'hash-declaration', 'init', 'sign', 'verify', 'check-listing', 'prepare'].includes(cmd), `unknown command ${cmd}`);
    assert.doesNotThrow(() => parseArgs(rest), `${cmd} ${rest.join(' ')}`);
  }
});

// The rows "| `state` | code |" of the verify table of section 11, and of the
// listing check table that follows it.
const LISTING_TABLE = '| Listing check state |';
function stateRows(md) {
  return Object.fromEntries([...md.matchAll(/^\| `([a-z_]+)` \| (\d+) \|/gm)].map((m) => [m[1], Number(m[2])]));
}

test('result states and exit codes agree across code, SPEC, README and help', () => {
  const s = SPEC.replace(/\r\n/g, '\n');
  const at = s.indexOf(LISTING_TABLE);
  assert.ok(at > 0, 'SPEC has the listing check table');
  assert.deepEqual(stateRows(s.slice(0, at)), { ...STATES });
  for (const [state, code] of Object.entries(STATES)) {
    assert.ok(README.includes(`${code} ${state}`), `README lists ${code} ${state}`);
    assert.ok(HELP.includes(`${code} ${state}`), `help lists ${code} ${state}`);
  }
});

test('check-listing states and exit codes agree across code, SPEC, README and help', () => {
  const s = SPEC.replace(/\r\n/g, '\n');
  const table = s.slice(s.indexOf(LISTING_TABLE), s.indexOf('Display guidance'));
  const own = Object.fromEntries(Object.entries(LISTING_STATES).filter(([k]) => !Object.hasOwn(STATES, k)));
  assert.deepEqual(stateRows(table), own);
  for (const [state, code] of Object.entries(STATES)) if (state !== 'valid') assert.equal(LISTING_STATES[state], code, `${state} keeps the exit code of verify`);
  const readme = README.replace(/\r\n/g, '\n');
  for (const [state, code] of Object.entries(own)) {
    assert.ok(readme.includes(`| ${code} | \`${state}\` |`), `README table lists ${code} ${state}`);
    assert.ok(HELP.replace(/\s+/g, ' ').includes(`${code} ${state}`), `help lists ${code} ${state}`);
  }
  // The live example line sits in the README section near the top.
  const top = section(README, '## Check a listing by name', '## Five minute path');
  assert.deepEqual(documentedCommands(top), [['check-listing', 'com.rtlpdf/arabic-pdf', '--fetch-tools']]);
});

test('prepare states and exit codes agree across code, README and help; its README section reads plainly', () => {
  const readme = README.replace(/\r\n/g, '\n');
  for (const [state, code] of Object.entries(PREPARE_STATES)) {
    assert.ok(readme.includes(`| ${code} | \`${state}\` |`), `README table lists ${code} ${state}`);
    assert.ok(HELP.replace(/\s+/g, ' ').includes(`${code} ${state}`), `help lists ${code} ${state}`);
  }
  const top = section(README, '## Publish a declaration in one command', '## Check a listing by name');
  assert.ok(README.indexOf('## Publish a declaration in one command') < README.indexOf('## Five minute path'), 'the one command section comes before the manual steps');
  assert.deepEqual(documentedCommands(top), [['prepare', 'com.example/weather', '--for-version', '1.4.1', '--key-env', 'MCP_PRIVATE_KEY']]);
  const prose = top.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, '');
  assert.ok(!/[‒-―−]/.test(prose), 'a dash character');
  assert.ok(!/\s-\s|\s--\s/.test(prose), 'a hyphen used as a dash');
  assert.ok(!/\b(never|guaranteed|safe|trusted|secure)\b/i.test(prose), 'a barred word');
});

test('SPEC section 8a and the README listing section: no dash punctuation and none of the barred words', () => {
  const parts = [section(SPEC, '## 8a.', '## 9.'), section(SPEC, 'T18.', '## 13.'), section(SPEC, 'Result states of a listing check', 'Display guidance'), section(README, '## Check a listing by name', '## Five minute path')];
  for (const p of parts) {
    const prose = p.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, '');
    assert.ok(!/[‒-―−]/.test(prose), 'a dash character');
    assert.ok(!/\s-\s|\s--\s/.test(prose), 'a hyphen used as a dash');
    assert.ok(!/\bguaranteed\b/i.test(prose), 'a promise word');
  }
});

// Review round 3 (18 November 2026).

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const BIN = path.join(ROOT, 'bin', 'addon-declare.js');

function section(md, from, to) {
  const s = md.replace(/\r\n/g, '\n');
  const a = s.indexOf(from);
  assert.ok(a >= 0, `section ${from}`);
  const b = to ? s.indexOf(to, a) : s.length;
  return s.slice(a, b < 0 ? s.length : b);
}

test('every documented flag belongs to the command it is given to, and HELP lists it', () => {
  const cmds = [...documentedCommands(README), ...documentedCommands(SPEC)];
  for (const [cmd, ...rest] of cmds) {
    for (const a of rest) {
      if (!a.startsWith('--')) continue;
      const name = a.slice(2).split('=')[0];
      assert.ok(COMMAND_FLAGS[cmd].includes(name), `--${name} is not an option of ${cmd} (in "${cmd} ${rest.join(' ')}")`);
    }
  }
  for (const [cmd, flags] of Object.entries(COMMAND_FLAGS)) {
    const at = HELP.indexOf(`\n  ${cmd} `) >= 0 ? HELP.indexOf(`\n  ${cmd} `) : HELP.indexOf(`\n  ${cmd}\n`);
    assert.ok(at >= 0, `HELP has a section for ${cmd}`);
    const next = HELP.slice(at + 1).search(/\n  [a-z]/);
    const text = next < 0 ? HELP.slice(at) : HELP.slice(at, at + 1 + next);
    for (const flag of flags) assert.ok(text.includes(`--${flag}`), `HELP lists --${flag} under ${cmd}`);
  }
});

test('the README five minute path runs as written, with a throwaway key kept outside the working folder', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-docs-'));
  try {
    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    const k = makeKey('ed25519');
    fs.writeFileSync(path.join(repo, 'server.json'), JSON.stringify({ name: 'com.example/weather', version: '1.4.0', remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }] }));
    fs.writeFileSync(path.join(repo, 'tools.json'), JSON.stringify({ jsonrpc: '2.0', id: 1, result: TOOLS }));
    const steps = documentedCommands(section(README, '## Five minute path', '## Checking a declaration'));
    assert.ok(steps.length >= 4, `found ${steps.length} steps`);
    assert.deepEqual([...new Set(steps.map((s) => s[0]))], ['init', 'sign', 'verify']);
    // Offline checks on the file the steps wrote (the live lookup and the example need other inputs).
    const checks = documentedCommands(section(README, '## Checking a declaration', '## Tests')).filter((c) => c.includes('--pubkey') && !c.some((a) => a.startsWith('examples/')));
    assert.ok(checks.length >= 1);
    const env = { ...process.env };
    let keyFileSeen = false;
    for (const [cmd, ...rest] of [...steps, ...checks]) {
      const args = [cmd, ...rest];
      const kf = rest.indexOf('--key-file');
      if (kf >= 0) {
        const p = path.resolve(repo, rest[kf + 1]);
        assert.ok(path.relative(repo, p).startsWith('..'), `README keeps the key file ${rest[kf + 1]} inside the working folder`);
        assert.ok(!path.relative(tmp, p).startsWith('..'), 'the test writes only under its temp folder');
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, k.pem);
        keyFileSeen = true;
      }
      const ke = rest.indexOf('--key-env');
      if (ke >= 0) env[rest[ke + 1]] = k.hex;
      const pk = rest.indexOf('--pubkey');
      if (pk >= 0) fs.writeFileSync(path.resolve(repo, rest[pk + 1]), k.record + '\n');
      else if (cmd === 'verify') args.push('--pubkey', k.record); // in place of the live lookup
      const r = spawnSync(process.execPath, [BIN, ...args], { cwd: repo, env, encoding: 'utf8' });
      assert.equal(r.status, 0, `${args.join(' ')}\n${r.stdout}${r.stderr}`);
      for (const s of k.secretStrings) assert.ok(!r.stdout.includes(s) && !r.stderr.includes(s), `key material in the output of ${cmd}`);
    }
    assert.ok(keyFileSeen, 'the README shows the --key-file form');
    assert.equal(JSON.parse(fs.readFileSync(path.join(repo, 'declaration.json'), 'utf8')).key.id, k.loaded.public.id);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('the documented example commands run from this folder and exit 0', () => {
  const cmds = [...documentedCommands(README), ...documentedCommands(SPEC)].filter((c) => c.some((a) => a.startsWith('examples/')));
  assert.ok(cmds.length >= 2);
  for (const args of cmds) {
    const r = spawnSync(process.execPath, [BIN, ...args], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(r.status, 0, `${args.join(' ')}\n${r.stdout}${r.stderr}`);
  }
});

test('the sample workflow tells publishers to keep pages apart, not to join them', () => {
  const wf = read('examples/workflows/sign-declaration.yml');
  assert.ok(!/concatenat/i.test(wf), 'concatenated pages fail the strict parser');
  assert.match(wf, /each page as its own file/);
  assert.match(wf, /server sent events/);
  assert.match(read('action/action.yml'), /one path per line/);
});

// The "Create and sign" script of the action, run with bash when a bash that
// reads this machine's paths is available (Git Bash on Windows, any bash elsewhere).
function actionScript(stepName) {
  const lines = read('action/action.yml').replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  assert.ok(start >= 0, stepName);
  const runAt = lines.findIndex((l, n) => n > start && /^\s+run: \|$/.test(l));
  const indent = lines[runAt].search(/\S/);
  const body = [];
  for (const l of lines.slice(runAt + 1)) {
    if (l.trim() !== '' && l.search(/\S/) <= indent) break;
    body.push(l.slice(indent + 2));
  }
  return body.join('\n');
}

test('the action passes one --tools per listed page, in order', (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-action-'));
  try {
    const probe = path.join(tmp, 'probe');
    fs.writeFileSync(probe, 'x');
    const bash = spawnSync('bash', ['-c', 'test -f "$0"', probe], { encoding: 'utf8' });
    if (bash.status !== 0) return t.skip('no bash that reads this machine\'s paths');
    const [t1, t2] = TOOLS.tools;
    fs.writeFileSync(path.join(tmp, 'tools-1.json'), JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [t1], nextCursor: 'c' } }));
    fs.writeFileSync(path.join(tmp, 'tools-2.json'), JSON.stringify({ jsonrpc: '2.0', id: 2, result: { tools: [t2] } }));
    fs.writeFileSync(path.join(tmp, 'server.json'), JSON.stringify({ name: 'com.example/weather', version: '1.4.0' }));
    const k = makeKey('ed25519');
    const env = {
      ...process.env,
      ADDON_DECLARE_KEY: k.hex,
      CLI: BIN,
      IN_TOOLS: '  tools-1.json\r\ntools-2.json\n\n',
      IN_CONTACT: 'mailto:security@example.com',
      IN_SERVER: 'server.json',
      IN_DOMAIN: '',
      IN_METHOD: 'dns',
      IN_PAYMENT: '',
      IN_PREVIOUS: '',
      IN_DAYS: '180',
      IN_OUT: 'declaration.json',
      RUNNER_TEMP: tmp,
      GITHUB_OUTPUT: path.join(tmp, 'github-output.txt'),
    };
    // The input's default (0.2), an empty format (the CLI default, also 0.2), and 0.1.
    for (const [IN_FORMAT, want] of [['0.2', '0.2'], ['', '0.2'], ['0.1', '0.1']]) {
      const r = spawnSync('bash', ['-c', actionScript('Create and sign')], { cwd: tmp, env: { ...env, IN_FORMAT }, encoding: 'utf8' });
      assert.equal(r.status, 0, r.stdout + r.stderr);
      const decl = JSON.parse(fs.readFileSync(path.join(tmp, 'declaration.json'), 'utf8'));
      assert.equal(decl.spec, `addon-declaration/${want}`);
      if (want === '0.1') assert.equal(decl.toolsHash, toolsHash(TOOLS));
      else {
        const d = toolSetDigestsFromPages([fs.readFileSync(path.join(tmp, 'tools-1.json')), fs.readFileSync(path.join(tmp, 'tools-2.json'))]);
        assert.deepEqual(decl.toolSetDigest, { spec: 'mcp-tool-set-digest/1', contract: d.contract.digest, extras: d.extras.digest });
      }
      assert.match(fs.readFileSync(env.GITHUB_OUTPUT, 'utf8'), /^hash=sha256:[0-9a-f]{64}$/m);
      for (const s of k.secretStrings) assert.ok(!r.stdout.includes(s) && !r.stderr.includes(s));
    }
    // Format 0.2 without a contact; format 0.1 needs one.
    const noContact = spawnSync('bash', ['-c', actionScript('Create and sign')], { cwd: tmp, env: { ...env, IN_FORMAT: '0.2', IN_CONTACT: '' }, encoding: 'utf8' });
    assert.equal(noContact.status, 0, noContact.stdout + noContact.stderr);
    assert.equal(JSON.parse(fs.readFileSync(path.join(tmp, 'declaration.json'), 'utf8')).contact, undefined);
    const noContact01 = spawnSync('bash', ['-c', actionScript('Create and sign')], { cwd: tmp, env: { ...env, IN_FORMAT: '0.1', IN_CONTACT: '' }, encoding: 'utf8' });
    assert.notEqual(noContact01.status, 0);
    assert.match(noContact01.stderr, /give --contact/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('the worked example in SPEC matches the example files', () => {
  const decl = parseDeclarationText(read('examples/declaration.example.json'));
  assert.ok(SPEC.includes(`Its declaration hash is \`${declarationHash(decl)}\``));
  assert.ok(SPEC.includes(`\`toolsHash\`: \`${toolsHashFromText(read('examples/tools.example.json'))}\``));
});

test('the mcp-tool-set-digest/1 digests quoted in SPEC and README match the example file', () => {
  const r = toolSetDigestsFromPages([read('examples/tools.example.json')]);
  assert.ok(SPEC.includes(`contract digest \`${r.contract.digest}\` and the extras digest \`${r.extras.digest}\``));
  assert.ok(README.replace(/\r\n/g, '\n').includes(`contract digest: ${r.contract.digest}\nextras digest: ${r.extras.digest}\n`));
  assert.match(section(SPEC, '## 4a.', '## 5.'), /NON NORMATIVE/);
});

test('format 0.2: the worked example in SPEC section 17 matches the example files', () => {
  const decl = parseDeclarationText(read('examples/declaration-0.2.example.json'));
  assert.equal(decl.spec, 'addon-declaration/0.2');
  const s17 = section(SPEC, '## 17.');
  assert.ok(s17.includes(`Its declaration hash is \`${declarationHash(decl)}\``));
  const r = toolSetDigestsFromPages([read('examples/tools.example.json')]);
  assert.deepEqual(decl.toolSetDigest, { spec: 'mcp-tool-set-digest/1', contract: r.contract.digest, extras: r.extras.digest });
  assert.ok(s17.includes(`contract digest \`${r.contract.digest}\` and the extras digest \`${r.extras.digest}\``));
  assert.ok(read('examples/example-key-0.2.txt').includes(`p=`));
  // The 0.1 example is untouched and still the one section 15 describes.
  assert.equal(parseDeclarationText(read('examples/declaration.example.json')).spec, 'addon-declaration/0.1');
});

test('SPEC and README prose added for format 0.2: no dash punctuation and none of the barred words', () => {
  const parts = [section(SPEC, '# Add on Declaration Spec', '## 1.'), section(SPEC, '## 4a.', '## 5.'), section(SPEC, '## 17.'), README];
  for (const p of parts) {
    const prose = p.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, '');
    assert.ok(!/[‒-―−]/.test(prose), 'a dash character');
    assert.ok(!/\s-\s|\s--\s/.test(prose), 'a hyphen used as a dash');
    assert.ok(!/\bguaranteed\b/i.test(prose), 'a promise word');
  }
  assert.match(SPEC, /^# Add on Declaration Spec v0\.2 \(draft\)$/m);
});

test('SPEC and README prose: no dash punctuation and none of the barred words in the sections changed for review round 4', () => {
  const parts = [section(SPEC, '## 4a.', '## 5.'), section(README, '## Comparing with mcp-tool-set-digest/1', '## Tests')];
  for (const p of parts) {
    const prose = p.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, '');
    assert.ok(!/[‒-―−]/.test(prose), 'a dash character');
    assert.ok(!/\s-\s|\s--\s/.test(prose), 'a hyphen used as a dash');
    assert.ok(!/\bguaranteed\b/i.test(prose), 'a promise word');
  }
});
