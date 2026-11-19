// addon-declare CLI logic. bin/addon-declare.js is a thin wrapper; tests call
// main() directly with their own output streams, environment and key lookups.

import fs from 'node:fs';
import net from 'node:net';
import { parseStrict, decodeUtf8Strict } from './jcs.js';
import { toolsHashFromPages } from './tools.js';
import { toolSetDigestsFromPages, InputError, TOOL_SET_DIGEST_ID } from './tool-set-digest.js';
import { loadPrivateKey, parsePublicKeyText, proofRecord, KeyError } from './keys.js';
import {
  SPEC_ID_01,
  SPEC_ID_02,
  SPEC_IDS,
  DEFAULT_SPEC_ID,
  validate,
  ordered,
  reverseDomain,
  declarationHash,
  declarationPaths,
  parseDeclarationText,
  signDeclaration,
  verifyDeclarationText,
  parseTime,
  namespaceProblem,
  isHttpsUrl,
  UNSAFE_CHARS_SOURCE,
  DeclarationError,
  GITHUB_OUT_OF_SCOPE,
} from './declaration.js';
import { keysFromDns, keysFromHttp, dnsResolverFor } from './resolve.js';

export const EXIT_USAGE = 1;

export const HELP = `addon-declare (Declaration Spec v0.2 draft: writes addon-declaration/0.2 by
default, and signs, hashes and verifies both 0.2 and 0.1 declarations, each
by the format its "spec" member names)

Commands
  hash-tools <tools.json> [<page2.json> ...]
      Print the tools hash of a tools/list result (or a bare array of tools).
      For a server that paginates, give every page in order, one file each.
      Each file holds the JSON text of one page; a response that arrived as
      server sent events is saved without the "event:" and "data:" framing.
  tool-set-digest <tools.json> [<page2.json> ...] [--json]
      Print the contract digest and the extras digest of mcp-tool-set-digest/1
      (github.com/alexar76/mcp-tool-set-digest), for comparison with tools
      that use them. They are in general not the tools hash
      (SPEC.md section 4a). Pages as for hash-tools; the last page must not
      carry nextCursor. Input rules are that document's (README.md): repeated
      member names keep the last value and large integers are rounded; a note
      reports repeated member names and tool names that repeat. Exit 0 when
      both are known (an extras digest of null counts), 2 when either has no
      digest (a TSD code is printed), 1 for usage or file errors.
  hash-declaration <declaration.json>
      Print the declaration hash of a signed declaration (0.1 or 0.2), the
      value a later declaration puts in "previous".
  init --name <ns/name> --version <v> [--format 0.2|0.1] [--contact <uri>]
       (--tools <tools.json> | --contract-digest <d> --extras-digest <d|null> | --tools-hash <h>)
       [--server-json <server.json>] [--domain <d>] [--method dns|http]
       [--payment <payment.json>] [--previous <signed declaration.json>]
       [--issued-at <YYYY-MM-DDTHH:MM:SSZ>] [--expires-in-days <n>] [--out <file>]
      Write an unsigned declaration. --server-json fills name, version and remotes.
      --tools may be repeated, one file per tools/list page, in order.
      --format 0.2 (the default) writes the two mcp-tool-set-digest/1 digests
      of the tool list in "toolSetDigest", computed from --tools, or taken
      from --contract-digest and --extras-digest (each the "digest" value
      tool-set-digest prints, "sha256-" and base64; --extras-digest null when
      no tool has extras); --contact is optional. With --tools, a list in
      which two tools share a name or an object repeats a member name is
      refused, as MCP and format 0.1 refuse it.
      --format 0.1 writes "toolsHash" from --tools or --tools-hash and needs
      --contact. A line on stderr says which format was written. --previous
      may name a 0.1 or 0.2 declaration for a 0.2 one, and only a 0.1
      declaration for a 0.1 one.
  sign <unsigned.json> (--key-file <path> | --key-env <VARIABLE_NAME>) [--out <file>]
      Sign with the same private key used for the registry's dns or http login
      (PEM, or the hex form given to mcp-publisher), or with a declaration only
      key. --key-env takes the name of a variable, not the key. The key stays
      on this machine; keep a key file outside the repository.
  verify <declaration.json> [--pubkey <file or "v=MCPv1; ..." record>] [--dns] [--http]
         [--dns-server <ip>] [--tools <tools.json>] [--previous <declaration.json>]
         [--format 0.1|0.2] [--now <YYYY-MM-DDTHH:MM:SSZ>] [--json]
      Checks a 0.1 or a 0.2 declaration by the format its "spec" names, and
      says which ("format:" line, "format" in --json). --format (given once)
      accepts only that format; a declaration of the other is malformed
      (exit 2) with "formatAccepted": false in --json. Once a publisher has
      moved to 0.2, give --format 0.2 so an older 0.1 file is not accepted.
      Without --pubkey the key is looked up by the method named in the
      declaration (key.method). --dns or --http must match that method.
      With --pubkey nothing is fetched (a "v=MCPv1; k=...; p=..." record,
      such as the line sign prints, or a file holding it). --tools: for 0.1
      the tools hash is compared; for 0.2 the contract and extras digests of
      mcp-tool-set-digest/1 are computed and compared one by one, and the
      output says which one differs ("toolSetDigest.differs" in --json) or
      could not be computed ("toolSetDigest.noDigest"). An extras only
      difference means the names, descriptions and schemas are as that
      document reads them (a description that is not a string, or an
      inputSchema or outputSchema that is not an object, is not covered;
      SPEC.md 17.8) and a member such as title, annotations, icons or _meta
      changed. Tool names that repeat and repeated member names are reported
      (toolSetDigest.repeatedNames and repeatedMembers).
      With --previous, --json output has a "chain" object; chain.keyChanged
      true means the link crosses a change of key and does not show that the
      same holder signed both; chain.previousFormat names the earlier format.

Exit codes for verify
  0 valid, 1 usage or file error, 2 malformed, 3 invalid_signature, 4 key_not_found,
  5 expired, 6 not_yet_valid, 7 name_domain_mismatch, 8 tools_hash_mismatch,
  9 chain_mismatch, 10 key_lookup_failed
`;

export class UsageError extends Error {
  constructor(message, lines) {
    super(message);
    this.name = 'UsageError';
    this.lines = lines;
  }
}

// Text from input files reaches the terminal only through esc(): the unsafe
// characters of SPEC.md section 3 (control, format and bidirectional
// characters, line and paragraph separators, tag characters, lone surrogates)
// become \\u escapes, one per UTF-16 code unit, so a file cannot move the
// cursor, hide text or reorder what is shown.
const TERMINAL_UNSAFE = new RegExp(UNSAFE_CHARS_SOURCE, 'gu');
const escapeUnits = (c) => [...Array(c.length).keys()].map((n) => '\\u' + c.charCodeAt(n).toString(16).padStart(4, '0')).join('');
export function esc(s) {
  return String(s).replace(TERMINAL_UNSAFE, escapeUnits);
}

// --json output: JSON.stringify escapes only C0, so the same characters are
// escaped after it. They can occur only inside JSON strings, and a \\u escape
// there decodes to the same string, so the output stays valid JSON.
export function jsonOut(value) {
  // The line feeds are the pretty printing; inside strings JSON.stringify has escaped them already.
  return JSON.stringify(value, null, 2).replace(TERMINAL_UNSAFE, (c) => (c === '\n' ? c : escapeUnits(c)));
}

// Values that look like key material rather than a path, a name or an option.
function looksLikeKey(s) {
  s = String(s);
  const base64Like = /^[A-Za-z0-9+/_-]{40,}={0,2}$/.test(s) && /[0-9]/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s);
  return /^[0-9a-fA-F:\s]{32,}$/.test(s) || s.includes('-----BEGIN') || s.length > 128 || base64Like;
}

// Every argument value echoed in a message goes through shown(), so a key
// pasted in the wrong place does not reach the terminal or a CI log.
export function shown(v) {
  return looksLikeKey(v) ? '<value hidden: it looks like key material>' : String(v);
}

const VALUE_FLAGS = new Set([
  'name', 'version', 'tools', 'tools-hash', 'contact', 'server-json', 'domain', 'method', 'payment', 'previous',
  'issued-at', 'expires-in-days', 'out', 'key-file', 'key-env', 'pubkey', 'dns-server', 'now',
  'format', 'contract-digest', 'extras-digest',
]);
const BOOL_FLAGS = new Set(['dns', 'http', 'json', 'help']);
// Flags that may be given more than once; their value is a list.
const REPEAT_FLAGS = new Set(['tools']);
export const FLAGS = Object.freeze({ value: VALUE_FLAGS, bool: BOOL_FLAGS, repeat: REPEAT_FLAGS });

// The options each command takes, as HELP lists them (--help is accepted by all).
// A known option given to the wrong command is a usage error, so a mistyped
// step fails with a message instead of being ignored.
export const COMMAND_FLAGS = Object.freeze({
  'hash-tools': Object.freeze([]),
  'tool-set-digest': Object.freeze(['json']),
  'hash-declaration': Object.freeze([]),
  init: Object.freeze(['name', 'version', 'format', 'tools', 'contract-digest', 'extras-digest', 'tools-hash', 'contact', 'server-json', 'domain', 'method', 'payment', 'previous', 'issued-at', 'expires-in-days', 'out']),
  sign: Object.freeze(['key-file', 'key-env', 'out']),
  verify: Object.freeze(['pubkey', 'dns', 'http', 'dns-server', 'tools', 'previous', 'format', 'now', 'json']),
});

function checkCommandFlags(cmd, flags) {
  const allowed = COMMAND_FLAGS[cmd];
  if (!allowed) return;
  for (const name of Object.keys(flags)) {
    if (name !== 'help' && !allowed.includes(name)) throw new UsageError(`--${name} is not an option of ${cmd}${allowed.length ? ` (it takes ${allowed.map((x) => '--' + x).join(', ')})` : ' (it takes file arguments only)'}`);
  }
}

// A file path given to --out must not be key material: the path is echoed and
// becomes a file name. Each path segment is checked with and without its
// extension, and PEM text anywhere.
// A key inside a longer value (key-<hex>.json, k-<hex>, <base64>.signed.json).
function holdsKeyRun(v) {
  const s = String(v);
  return /[0-9a-fA-F]{64,}/.test(s) || (s.match(/[A-Za-z0-9+_-]{40,}/g) || []).some((m) => /[0-9]/.test(m) && /[A-Z]/.test(m) && /[a-z]/.test(m));
}

function checkOutPath(p) {
  if (p === undefined) return;
  const s = String(p);
  if (holdsKeyRun(s) || s.includes('-----BEGIN') || s.split(/[\\/]/).some((seg) => looksLikeKey(seg) || looksLikeKey(seg.replace(/\.[A-Za-z0-9]{1,8}$/, '')))) {
    throw new UsageError('--out looks like key material, not a file path; give the path of the file to write (nothing was written)');
  }
}

// Accepts "--flag value" and "--flag=value".
export function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    // PEM private key text starts with dashes, so it would be read as an option
    // name and echoed. It is refused here, before any message can repeat it.
    if (/PRIVATE KEY|-----BEGIN [A-Z ]*KEY/.test(a) && /PRIVATE/.test(a)) {
      throw new UsageError('an argument holds private key text; pass the key with --key-env <VARIABLE NAME> or --key-file <path> (nothing was written)');
    }
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const eq = a.indexOf('=');
    const name = eq < 0 ? a.slice(2) : a.slice(2, eq);
    let value;
    if (BOOL_FLAGS.has(name)) {
      if (eq >= 0) throw new UsageError(`--${name} takes no value`);
      flags[name] = true;
      continue;
    }
    if (!VALUE_FLAGS.has(name)) throw new UsageError(`unknown option --${shown(name)}`);
    if (eq >= 0) value = a.slice(eq + 1);
    else {
      if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`);
      value = argv[++i];
    }
    if (REPEAT_FLAGS.has(name)) (flags[name] ||= []).push(value);
    // A second value would silently replace the first, which for a flag such
    // as verify --format would widen or change what the check accepts.
    else if (Object.hasOwn(flags, name)) throw new UsageError(`--${name} was given more than once; give it once`);
    else flags[name] = value;
  }
  return { positional, flags };
}

function readBytes(path, what) {
  try {
    return fs.readFileSync(path);
  } catch (e) {
    throw new UsageError(`cannot read ${what} ${shown(path)} (${e.code || 'error'})`);
  }
}

function decode(bytes, what) {
  try {
    return decodeUtf8Strict(bytes);
  } catch (e) {
    throw new UsageError(`${what}: ${e.message}`);
  }
}

function readJson(path, what) {
  const text = decode(readBytes(path, what), what);
  try {
    return parseStrict(text);
  } catch (e) {
    throw new UsageError(`${what} ${shown(path)} is not valid JSON: ${e.message}`);
  }
}

function one(positional, what) {
  if (positional.length !== 1) throw new UsageError(`expected exactly one ${what}`);
  return positional[0];
}

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// paths: one file per tools/list page, in order.
function toolsHashOf(paths) {
  const pages = paths.map((p) => readBytes(p, 'tools file'));
  try {
    return toolsHashFromPages(pages);
  } catch (e) {
    throw new UsageError(`tools file: ${e.message}`);
  }
}

function readDecl(path) {
  const bytes = readBytes(path, 'declaration');
  try {
    return parseDeclarationText(bytes);
  } catch (e) {
    throw new UsageError(`declaration ${shown(path)}: ${e.message}`);
  }
}

// A signed declaration that passes section 3, for "previous" and hash-declaration.
// unsignedHint: what to do when the file is not signed yet.
function readSignedDecl(path, what, unsignedHint) {
  const decl = readDecl(path);
  const problems = validate(decl);
  if (problems.length) {
    if (decl && typeof decl === 'object' && !Object.hasOwn(decl, 'signature')) {
      throw new UsageError(`${what} ${shown(path)} is not signed; ${unsignedHint}`);
    }
    throw new UsageError(`${what} ${shown(path)} is not a valid signed declaration:`, problems);
  }
  return decl;
}

function cmdHashTools({ positional }, io) {
  if (positional.length === 0) throw new UsageError('expected one tools file, or one per page');
  io.stdout.write(toolsHashOf(positional) + '\n');
  return 0;
}

export const EXIT_NO_DIGEST = 2;

function cmdToolSetDigest({ positional, flags }, io) {
  if (positional.length === 0) throw new UsageError('expected one tools file, or one per page');
  const pages = positional.map((p) => readBytes(p, 'tools file'));
  let r;
  try {
    r = toolSetDigestsFromPages(pages);
  } catch (e) {
    if (e instanceof InputError) throw new UsageError(`tools file: ${e.message}`);
    throw e;
  }
  const show = (d) => {
    if (d.error) return { error: d.error, detail: d.detail };
    if (d.digest === null) return { digest: null };
    return { digest: d.digest, hex: d.hex };
  };
  const failed = Boolean(r.contract.error || r.extras.error);
  if (flags.json) {
    io.stdout.write(jsonOut({ profile: TOOL_SET_DIGEST_ID, contract: show(r.contract), extras: show(r.extras), notes: r.notes, repeatedMembers: r.repeatedMembers, repeatedNames: r.repeatedNames }) + '\n');
  } else {
    const line = (label, d) => {
      if (d.error) return `${label}: none, ${d.error} (${esc(d.detail)})`;
      if (d.digest === null) return `${label}: null (no tool has extras)`;
      return `${label}: ${d.digest}`;
    };
    const lines = [TOOL_SET_DIGEST_ID, line('contract digest', r.contract), line('extras digest', r.extras)];
    for (const n of r.notes) lines.push(`note: ${esc(n)}`);
    io.stdout.write(lines.join('\n') + '\n');
  }
  return failed ? EXIT_NO_DIGEST : 0;
}

function cmdHashDeclaration({ positional }, io) {
  const path = one(positional, 'declaration file');
  const decl = readSignedDecl(path, 'declaration', 'the declaration hash is taken of a signed declaration: run sign on it first, then hash-declaration on the signed output');
  io.stdout.write(declarationHash(decl) + '\n');
  return 0;
}

// Inputs init needs, by format.
const FLAG_FOR_FIELD = {
  [SPEC_ID_01]: {
    name: '--name (or --server-json with a "name")',
    version: '--version (or --server-json with a "version")',
    toolsHash: '--tools or --tools-hash',
    contact: '--contact',
  },
  [SPEC_ID_02]: {
    name: '--name (or --server-json with a "name")',
    version: '--version (or --server-json with a "version")',
    toolSetDigest: '--tools, or --contract-digest and --extras-digest',
  },
};

// "--format 0.1" or "0.2" (the full spec id is accepted too) to a spec id.
function formatFlag(v, cmd) {
  const byShort = { '0.1': SPEC_ID_01, '0.2': SPEC_ID_02 };
  if (Object.hasOwn(byShort, v)) return byShort[v];
  if (SPEC_IDS.includes(v)) return v;
  throw new UsageError(`--format of ${cmd} must be 0.1 or 0.2, not ${shown(v)}`);
}

// The two digests of mcp-tool-set-digest/1 for init --format 0.2 --tools.
function toolSetDigestOf(paths, io) {
  const pages = paths.map((p) => readBytes(p, 'tools file'));
  let r;
  try {
    r = toolSetDigestsFromPages(pages);
  } catch (e) {
    if (e instanceof InputError) throw new UsageError(`tools file: ${e.message}`);
    throw e;
  }
  const missing = ['contract', 'extras'].filter((k) => r[k].error).map((k) => `the tool list has no ${k} digest under ${TOOL_SET_DIGEST_ID}: ${r[k].error} (${r[k].detail})`);
  if (missing.length) throw new UsageError(`a declaration in format ${SPEC_ID_02} needs both digests of its tool list:`, missing);
  // The publisher controls the list, so input the digests read in only one of
  // several ways is refused here (SPEC.md T17), as format 0.1 refuses it. A
  // verifier stays lenient, as mcp-tool-set-digest/1 requires, and reports it.
  const ambiguous = [];
  for (const { name, count } of r.repeatedNames) ambiguous.push(`tool name "${name}" appears ${count} times; MCP requires unique tool names, and the digests group extras by name, so which of these tools carries title or annotations would not be pinned`);
  if (r.repeatedMembers) ambiguous.push(`${r.repeatedMembers} repeated member name${r.repeatedMembers === 1 ? '' : 's'} in the tools/list page; a client whose JSON parser keeps the first value, or refuses the list, would read other tool definitions than the signed digests pin`);
  if (ambiguous.length) throw new UsageError('tools file: the list cannot be signed as it is; fix the server so its tools/list has unique tool names and no repeated member names, then save the list again:', ambiguous);
  for (const n of r.notes) io.stderr.write(esc(`note: ${n}`) + '\n');
  return { spec: TOOL_SET_DIGEST_ID, contract: r.contract.digest, extras: r.extras.digest };
}

// The canonical form of u when it differs from u only by what WHATWG
// serialization does to a plain URL: a lowercase scheme and host, a dropped
// :443, and a path of "/" added to a bare origin. null for any other difference.
export function plainCanonicalForm(u) {
  if (typeof u !== 'string' || !/^https:\/\//i.test(u)) return null;
  const m = /^https:\/\/([^/?#]*)([\s\S]*)$/i.exec(u);
  const [, authority, rest] = m;
  if (authority.includes('@')) return null;
  const c = 'https://' + authority.toLowerCase().replace(/:443$/, '') + (rest === '' || rest[0] === '?' || rest[0] === '#' ? '/' + rest : rest);
  if (!isHttpsUrl(c)) return null;
  try {
    return new URL(u).href === c ? c : null;
  } catch {
    return null;
  }
}

function remotesFromServerJson(s, io) {
  if (!Array.isArray(s.remotes) || s.remotes.length === 0) return undefined;
  const problems = [];
  let canonicalHint = false;
  const out = s.remotes.map((r, n) => {
    let url = r && r.url;
    if (r && (r.variables !== undefined || (typeof url === 'string' && /[{}]/.test(url)))) {
      problems.push(`server.json remotes[${n}] is a URL template ({...} or "variables"); a declaration names concrete URLs only`);
    } else if (typeof url !== 'string' || !/^https:\/\//i.test(url)) {
      problems.push(`server.json remotes[${n}].url is not an https URL; a declaration accepts https remotes only`);
    } else if (hasUserinfo(url)) {
      // Checked before the canonical form, so the URL (and its password) is not repeated.
      problems.push(`server.json remotes[${n}].url carries a user name or password; a declared remote URL must not (SPEC.md section 3, https URL rule c). Remove it from the URL in server.json and pass credentials another way (the URL is not repeated here)`);
    } else if (!isHttpsUrl(url)) {
      const c = plainCanonicalForm(url);
      if (c) {
        io.stderr.write(esc(`note: server.json remotes[${n}].url ${url} is declared in its canonical form ${c}; clients compare remotes after WHATWG URL serialization (SPEC.md section 11)`) + '\n');
        url = c;
      } else {
        problems.push(`server.json remotes[${n}].url is not in canonical form; write it in server.json as ${safeHref(url)} if that is the endpoint you mean`);
        canonicalHint = true;
      }
    }
    if (r && r.headers !== undefined) io.stderr.write(esc(`note: server.json remotes[${n}] has headers; the declaration does not cover headers`) + '\n');
    return { type: r && r.type, url };
  });
  if (problems.length) {
    if (!canonicalHint || problems.length > 1) problems.push('to declare without these remotes, run init with --name and --version instead of --server-json');
    throw new UsageError('server.json remotes cannot be declared:', problems);
  }
  return out;
}

// userinfo in the authority as written, or as a WHATWG parser reads it.
function hasUserinfo(u) {
  const m = /^https:\/\/([^/?#\\]*)/i.exec(u);
  if (m && m[1].includes('@')) return true;
  try {
    const x = new URL(u);
    return x.username !== '' || x.password !== '';
  } catch {
    return false;
  }
}

// The WHATWG serialization, without any userinfo, for a hint in a message.
function safeHref(u) {
  try {
    const x = new URL(u);
    x.username = '';
    x.password = '';
    return x.href;
  } catch {
    return 'a valid https URL';
  }
}

function cmdInit({ positional, flags }, io) {
  if (positional.length) throw new UsageError('init takes no file argument');
  checkOutPath(flags.out);
  if (flags.version !== undefined && (looksLikeKey(flags.version) || holdsKeyRun(flags.version))) {
    throw new UsageError('--version looks like key material (a long hex, base64 or PEM value), so it is not written into the declaration; if it really is the version, put it in server.json and use --server-json');
  }
  // The name is signed and served publicly too; each part is screened as --version is.
  if (flags.name !== undefined && (holdsKeyRun(flags.name) || String(flags.name).split(/[/.]/).some((part) => looksLikeKey(part)))) {
    throw new UsageError('--name looks like it holds key material (a long hex, base64 or PEM value), so it is not written into the declaration; give the server name as registered, such as com.example/weather (if it really is the name, put it in server.json and use --server-json)');
  }
  const spec = flags.format === undefined ? DEFAULT_SPEC_ID : formatFlag(flags.format, 'init');
  if (spec === SPEC_ID_01 && (flags['contract-digest'] !== undefined || flags['extras-digest'] !== undefined)) {
    throw new UsageError(`--contract-digest and --extras-digest are for --format 0.2; a declaration in format ${SPEC_ID_01} carries a tools hash (--tools or --tools-hash)`);
  }
  if (spec === SPEC_ID_02 && flags['tools-hash'] !== undefined) {
    throw new UsageError(`--tools-hash is the tools hash of ${SPEC_ID_01}; a declaration in format ${SPEC_ID_02} carries the two digests of ${TOOL_SET_DIGEST_ID}: give --tools, or --contract-digest and --extras-digest (or --format 0.1 for the earlier format)`);
  }
  const decl = { spec };
  if (flags['server-json']) {
    const s = readJson(flags['server-json'], 'server.json');
    if (typeof s.name === 'string') decl.name = s.name;
    if (typeof s.version === 'string') decl.version = s.version;
    const remotes = remotesFromServerJson(s, io);
    if (remotes) decl.remotes = remotes;
  }
  if (flags.name) decl.name = flags.name;
  if (flags.version) decl.version = flags.version;
  if (typeof decl.name === 'string') {
    const ns = decl.name.split('/')[0].toLowerCase();
    if (ns === 'io.github' || ns.startsWith('io.github.')) throw new UsageError(`${GITHUB_OUT_OF_SCOPE}; a declaration needs a domain namespace such as com.example/weather`);
  }
  if (spec === SPEC_ID_01) {
    if (flags.tools && flags['tools-hash']) throw new UsageError('give --tools or --tools-hash, not both');
    if (flags.tools) decl.toolsHash = toolsHashOf(flags.tools);
    else if (flags['tools-hash']) decl.toolsHash = flags['tools-hash'];
  } else {
    const c = flags['contract-digest'];
    const x = flags['extras-digest'];
    if (flags.tools && (c !== undefined || x !== undefined)) throw new UsageError('give --tools, or --contract-digest and --extras-digest, not both');
    if ((c === undefined) !== (x === undefined)) throw new UsageError('give both --contract-digest and --extras-digest (--extras-digest null when no tool has a member outside name, description, inputSchema and outputSchema)');
    if (flags.tools) decl.toolSetDigest = toolSetDigestOf(flags.tools, io);
    else if (c !== undefined) {
      decl.toolSetDigest = { spec: TOOL_SET_DIGEST_ID, contract: c, extras: x === 'null' ? null : x };
    }
  }
  if (flags.payment) {
    const pay = readJson(flags.payment, 'payment file');
    decl.payment = Array.isArray(pay) ? pay : [pay];
  }
  if (flags.contact) decl.contact = flags.contact;
  if (flags['issued-at'] !== undefined && parseTime(flags['issued-at']) === null) throw new UsageError('--issued-at must be YYYY-MM-DDTHH:MM:SSZ (UTC, a real date)');
  decl.issuedAt = flags['issued-at'] || nowIso();
  if (flags['expires-in-days'] !== undefined) {
    const days = Number(flags['expires-in-days']);
    if (!Number.isInteger(days) || days < 1 || days > 3660) throw new UsageError('--expires-in-days must be a whole number from 1 to 3660');
    decl.expiresAt = new Date(parseTime(decl.issuedAt) + days * 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  const need = FLAG_FOR_FIELD[spec];
  const missing = Object.keys(need).filter((k) => decl[k] === undefined);
  if (missing.length) throw new UsageError('missing input:', missing.map((k) => `give ${need[k]}`));
  if (flags.previous) {
    const prev = readSignedDecl(flags.previous, 'previous declaration', 'pass the signed declaration of the previous release, not the unsigned file');
    if (prev.name !== decl.name) throw new UsageError(`previous declaration is for "${prev.name}", not "${decl.name}"; pass the signed declaration of the previous release of this server`);
    if (SPEC_IDS.indexOf(prev.spec) > SPEC_IDS.indexOf(spec)) throw new UsageError(`previous declaration is in format ${prev.spec}; a declaration in format ${spec} cannot follow it (a link back to an earlier format is refused, SPEC.md section 17.5)`);
    decl.previous = declarationHash(prev);
  }
  const method = flags.method || 'dns';
  let domain = flags.domain;
  if (!domain && typeof decl.name === 'string') domain = reverseDomain(decl.name.split('/')[0].toLowerCase());
  decl.key = { method, domain };

  const out = ordered(decl);
  const problems = validate(out, { unsigned: true });
  if (problems.length) throw new UsageError('the declaration would be invalid:', problems);
  const nsProblem = namespaceProblem(out.name, domain, method);
  if (nsProblem) throw new UsageError(`the key domain cannot prove this name: ${nsProblem}`);
  writeOut(io, flags.out, JSON.stringify(out, null, 2) + '\n');
  io.stderr.write(`format: ${spec}${flags.format === undefined ? ' (the default; --format 0.1 writes the earlier format)' : ''}\n`);
  // The form of a digest cannot show where the value came from, so say what happens to it.
  if (flags['contract-digest'] !== undefined) io.stderr.write('note: --contract-digest and --extras-digest are written, signed and published exactly as given, and nothing checks them against a tool list; --tools computes them from the list itself and is preferred\n');
  if (flags.out) io.stderr.write(esc(`wrote unsigned declaration to ${shown(flags.out)}`) + '\n');
  return 0;
}

function writeOut(io, path, text) {
  if (!path) return io.stdout.write(text);
  try {
    fs.writeFileSync(path, text, { encoding: 'utf8' });
  } catch (e) {
    throw new UsageError(`cannot write --out ${shown(path)} (${e.code || 'error'})${e.code === 'ENOENT' ? '; does the folder exist?' : ''}`);
  }
}

function cmdSign({ positional, flags }, io) {
  const path = one(positional, 'unsigned declaration file');
  if (!!flags['key-file'] === !!flags['key-env']) throw new UsageError('give exactly one of --key-file or --key-env');
  checkOutPath(flags.out);
  let keyText;
  if (flags['key-file']) {
    // The path is not repeated: a key pasted in place of a path would be printed.
    let bytes;
    try {
      bytes = fs.readFileSync(flags['key-file']);
    } catch (e) {
      throw new UsageError(`cannot read the file given to --key-file (${e.code || 'error'}); --key-file takes a path to the key file`);
    }
    keyText = decode(bytes, 'key file');
  } else {
    const name = flags['key-env'];
    if (looksLikeKey(name) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new UsageError('--key-env takes the NAME of an environment variable, not the key itself');
    keyText = io.env[name];
    if (!keyText) throw new UsageError(`environment variable ${name} is empty or not set`);
  }
  let loaded;
  try {
    loaded = loadPrivateKey(keyText);
  } catch (e) {
    // Only our own KeyError text is shown; it does not contain key material.
    throw new UsageError(`private key: ${e instanceof KeyError ? e.message : 'could not be read'}`);
  } finally {
    keyText = undefined;
  }
  const unsigned = readDecl(path);
  let signed;
  try {
    signed = signDeclaration(unsigned, loaded);
  } catch (e) {
    throw new UsageError(`cannot sign: ${e.message}`);
  }
  writeOut(io, flags.out, JSON.stringify(signed, null, 2) + '\n');
  const paths = declarationPaths(signed);
  const lines = [
    `signed ${signed.name} ${signed.version} with ${loaded.alg} key ${loaded.public.id}`,
    `format: ${signed.spec}`,
    `declaration hash: ${declarationHash(signed)}`,
    `this key must be published as: ${proofRecord(loaded.public)}`,
    signed.key.method === 'dns' ? `  (TXT record at ${signed.key.domain})` : `  (https://${signed.key.domain}/.well-known/mcp-registry-auth)`,
  ];
  if (signed.key.method === 'dns') lines.push(`  or, for a declaration only key that cannot log in to the registry: ${proofRecord(loaded.public, 'addon')}`);
  lines.push(`serve it at: ${paths.byHash}`, `         and: ${paths.version}`, `         and: ${paths.latest} (if it is the newest)`);
  if (flags.out) lines.push(`wrote ${shown(flags.out)}`);
  io.stderr.write(lines.map(esc).join('\n') + '\n');
  return 0;
}

function looksUnsigned(bytes) {
  try {
    const d = parseDeclarationText(bytes);
    return d !== null && typeof d === 'object' && !Array.isArray(d) && !Object.hasOwn(d, 'signature');
  } catch {
    return false;
  }
}

function declaredMethod(bytes) {
  try {
    const d = parseDeclarationText(bytes);
    return d && d.key && (d.key.method === 'http' || d.key.method === 'dns') ? d.key.method : null;
  } catch {
    return null;
  }
}

async function cmdVerify({ positional, flags }, io) {
  const path = one(positional, 'declaration file');
  const bytes = readBytes(path, 'declaration');
  const sources = ['pubkey', 'dns', 'http'].filter((k) => flags[k]);
  if (sources.length > 1) throw new UsageError('give at most one of --pubkey, --dns, --http');
  if (flags['dns-server'] !== undefined && !net.isIP(flags['dns-server'])) throw new UsageError('--dns-server must be an IP address');

  let keySource;
  if (flags.pubkey) {
    const v = flags.pubkey;
    let keyText;
    if (fs.existsSync(v)) keyText = decode(readBytes(v, 'public key'), 'public key file');
    else if (/v=(MCPv1|ADKv1);/.test(v) || v.includes('-----BEGIN')) keyText = v;
    else throw new UsageError(`public key file not found: ${shown(v)}`);
    try {
      keySource = { kind: 'offline', keys: parsePublicKeyText(keyText) };
    } catch (e) {
      throw new UsageError(`--pubkey: ${e.message}`);
    }
  } else {
    const declared = declaredMethod(bytes);
    const asked = flags.dns ? 'dns' : flags.http ? 'http' : null;
    if (asked && declared && asked !== declared) throw new UsageError(`the declaration names key.method "${declared}"; the key is looked up by that method, so use --${declared} or neither`);
    const kind = declared || asked || 'dns'; // a malformed file is reported by the verifier
    const d = io.deps;
    const resolver = kind === 'dns' ? d.dnsResolverFor(flags['dns-server']) : undefined;
    keySource = { kind, lookup: (domain) => (kind === 'dns' ? d.keysFromDns(domain, { resolver }) : d.keysFromHttp(domain)) };
  }

  let now = Date.now();
  if (flags.now) {
    now = parseTime(flags.now);
    if (now === null) throw new UsageError('--now must be YYYY-MM-DDTHH:MM:SSZ');
  }
  const toolsText = flags.tools ? flags.tools.map((p) => readBytes(p, 'tools file')) : undefined;
  const previousText = flags.previous ? readBytes(flags.previous, 'previous declaration') : undefined;
  const formats = flags.format === undefined ? undefined : [formatFlag(flags.format, 'verify')];

  let r;
  try {
    r = await verifyDeclarationText(bytes, { keySource, now, toolsText, previousText, formats });
  } catch (e) {
    if (e instanceof DeclarationError) throw new UsageError(e.message);
    throw e;
  }
  if (r.state === 'malformed' && looksUnsigned(bytes)) r.reasons.push('this file looks unsigned (no "signature"); run sign on it first, then verify the signed output');
  if (flags.json) {
    io.stdout.write(jsonOut({ state: r.state, exitCode: r.exitCode, reasons: r.reasons, ...r.details }) + '\n');
  } else {
    const D = r.details;
    const lines = [`${r.state}${D.name ? `: ${esc(D.name)} ${esc(D.version)}` : ''}`];
    for (const x of r.reasons) lines.push(`  reason: ${esc(x)}`);
    if (D.format) lines.push(`  format: ${D.format}`);
    if (D.toolSetDigest) {
      const T = D.toolSetDigest;
      const word = (d) => (d.result === 'no_digest' ? `no digest${d.code ? ` (${d.code})` : ''}` : d.result);
      lines.push(`  tool set digest: contract ${word(T.contract)}, extras ${word(T.extras)}${T.comparable ? '' : ' (could not be compared)'}`);
      for (const n of T.notes || []) lines.push(`  note: ${esc(n)}`);
    }
    if (D.keySource) lines.push(`  key source: ${esc(D.keySource)}`);
    if (D.keyId) lines.push(`  key: ${esc(D.alg)} ${esc(D.keyId)}${D.keyRecord ? ` (${D.keyRecord})` : ''}`);
    for (const x of D.checked) lines.push(`  checked: ${esc(x)}`);
    for (const x of D.notChecked) lines.push(`  not checked: ${esc(x)}`);
    for (const x of [...(D.keyNotes || []), ...(D.notes || [])]) lines.push(`  note: ${esc(x)}`);
    if (r.state === 'valid') lines.push('  meaning: the holder of the named key signed this content. It does not show that the server is safe or that it behaves as declared.');
    io.stdout.write(lines.join('\n') + '\n');
  }
  return r.exitCode;
}

export const DEFAULT_DEPS = Object.freeze({ keysFromDns, keysFromHttp, dnsResolverFor });

// io: { stdout, stderr, env, deps } (deps: key lookup functions, replaceable in tests)
export async function main(argv, io = {}) {
  io = { stdout: process.stdout, stderr: process.stderr, env: process.env, ...io, deps: { ...DEFAULT_DEPS, ...(io.deps || {}) } };
  try {
    const [cmd, ...rest] = argv;
    if (!cmd || cmd === 'help' || cmd === '--help') {
      io.stdout.write(HELP);
      return cmd ? 0 : EXIT_USAGE;
    }
    const args = parseArgs(rest);
    if (args.flags.help) {
      io.stdout.write(HELP);
      return 0;
    }
    checkCommandFlags(cmd, args.flags);
    switch (cmd) {
      case 'hash-tools':
        return cmdHashTools(args, io);
      case 'tool-set-digest':
        return cmdToolSetDigest(args, io);
      case 'hash-declaration':
        return cmdHashDeclaration(args, io);
      case 'init':
        return cmdInit(args, io);
      case 'sign':
        return cmdSign(args, io);
      case 'verify':
        return await cmdVerify(args, io);
      default:
        throw new UsageError(`unknown command ${shown(cmd)}`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      io.stderr.write(`addon-declare: ${esc(e.message)}\n`);
      for (const l of e.lines || []) io.stderr.write(`  ${esc(l)}\n`);
    } else io.stderr.write(`addon-declare: unexpected error: ${esc(e && e.message)}\n`);
    return EXIT_USAGE;
  }
}

