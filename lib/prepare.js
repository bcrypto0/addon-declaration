// prepare: the publisher side in one command. For a server already listed in
// the official MCP Registry under a domain namespace, it reads the listing,
// finds the key record that registry login reads, reads the tool list, links
// the declaration the publisher's site already serves, builds and signs a
// format 0.2 declaration, checks the result offline (also as check-listing
// would read it after publishing) and writes the files to upload into one
// output folder. It publishes nothing and writes nothing outside that folder.
//
// Network access goes through the request and key lookup functions given (the
// hardened fetch and key lookups of resolve.js by default); nothing here opens
// a socket itself. The private key is passed in already loaded and is used
// only to sign; nothing here prints or stores it.

import fs from 'node:fs';
import path from 'node:path';
import { decodeUtf8Strict, parseStrict } from './jcs.js';
import {
  SPEC_ID_02,
  GITHUB_OUT_OF_SCOPE,
  MAX_DECLARATION_BYTES,
  UNSAFE_CHARS_SOURCE,
  DeclarationError,
  declarationHash,
  encodePathSegment,
  formatOf,
  isHttpsUrl,
  isValidDomain,
  namespaceProblem,
  ordered,
  parseDeclarationText,
  parseTime,
  reverseDomain,
  signDeclaration,
  validate,
  verifyDeclarationText,
} from './declaration.js';
import { checkListing, walkHistory, pointerHosts, DEFAULT_REGISTRY, REGISTRY_SERVER_PATH, MAX_REGISTRY_RESPONSE, MAX_CHAIN_LINKS, PUBLISHER_META_KEY, OFFICIAL_META_KEY, POINTER_MEMBER, clip } from './listing.js';
import { fetchToolsList, describe } from './mcp-client.js';
import { httpsRequest, hostWithoutAddress } from './resolve.js';
import { proofRecord } from './keys.js';
import { looksLikeKey, holdsKeyRun, holdsSplitKey } from './keylike.js';
import { toolSetDigestsFromPages, InputError, TOOL_SET_DIGEST_ID } from './tool-set-digest.js';
import { HISTOR_MEMBER, HISTOR_URL, HISTOR_DOC, HISTOR_MAX_SETS, historToolSetsMember, historMemberProblems, mergeHistorMember } from './histor-tool-sets.js';

// Result states of prepare and their exit codes. 0 and 1 keep their meaning
// across the commands; every other number is new and used by no other command
// (verify uses 2 to 10, check-listing 2 to 22).
// A host taken from a listing is data from outside. Inside a command a person
// may paste into a shell it is printed only when it is plain lower case
// letters, digits, dots and hyphens; otherwise a placeholder stands in.
function hostForCommand(host) {
  return /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(String(host)) ? host : '<that host>';
}

export const PREPARE_STATES = Object.freeze({
  prepared: 0,
  prepared_unsigned: 0,
  listing_not_found: 23,
  namespace_not_domain: 24,
  registry_read_failed: 25,
  key_record_not_found: 26,
  key_record_lookup_failed: 27,
  version_not_usable: 28,
  remotes_not_declarable: 29,
  tools_unavailable: 30,
  key_mismatch: 31,
  output_folder_not_empty: 32,
  pointer_too_large: 33,
  self_check_failed: 34,
  previous_unreadable: 35,
  previous_not_linkable: 36,
});

export const DEFAULT_OUT = 'addon-declaration-out';
export const DEFAULT_EXPIRES_IN_DAYS = 180;
// The registry keeps the publisher metadata block up to this many bytes of JSON (SPEC.md section 2).
export const MAX_PUBLISHER_META_BYTES = 4096;
// A folder with more entries than this is reported as not empty without a full listing.
const MAX_LISTED_FILES = 2000;
// --now this far from the machine clock gets a note.
const CLOCK_SKEW_MS = 5 * 60 * 1000;
// What an earlier prepare run writes into the output folder; --force replaces these.
const OWNED_TOP = ['declaration.unsigned.json', 'pointer.json', 'NEXT_STEPS.txt'];
const OWNED_SITE = 'site/.well-known/addon-declaration/';
const HASH_RE = /^sha256:[0-9a-f]{64}$/;

const STEP_LABELS = ['listing', 'key record', 'version', 'tools', 'previous declaration', 'declaration', 'signing', 'output', 'check'];

// A problem with the inputs (a usage error for the CLI).
export class PrepareError extends Error {
  constructor(message, lines) {
    super(message);
    this.name = 'PrepareError';
    this.lines = lines;
  }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// The "when" a HISTOR member gives for a digest, or null.
const existingSetWhen = (member, digest) => {
  const s = isObj(member) && Array.isArray(member.sets) ? member.sets.find((x) => isObj(x) && x.digest === digest) : undefined;
  return s && typeof s.when === 'string' ? s.when : null;
};
// The notes for a HISTOR member already in the listing or the server.json
// given (m: the result of mergeHistorMember).
function historMergeNotes(m, source, would) {
  const head = `${source} already has a "${HISTOR_MEMBER}" member`;
  if (m.action === 'replaced') return [`${head}; ${m.leftOut[0]}, and ${would ? 'pointer.json would replace' : 'pointer.json replaces'} it with the one built from the tool list signed here (--histor-tool-sets)`];
  const n = m.keptSets.length;
  const keeps = n ? `the ${n === 1 ? 'other set' : `${n} other sets`} HISTOR reads from it (${m.keptSets.join(', ')})` : 'no other set (it names none HISTOR reads besides the one signed here)';
  const notes = [`${head}; ${would ? 'pointer.json would merge' : 'pointer.json merges'} the set signed here into it as its first set (--histor-tool-sets) and keeps ${keeps}${m.url !== undefined ? ' and its "url"' : ''}${m.keptWhen ? ', with the "when" it gives for the digest signed here' : ''}, so HISTOR marks none of them withdrawn`];
  if (m.urlRefused) notes.push(`the "url" of that member is kept as it is, although HISTOR does not read it: ${m.urlRefused}`);
  if (m.leftOut.length) notes.push(`${would ? 'pointer.json would leave out' : 'pointer.json leaves out'} what HISTOR does not read from that member: ${m.leftOut.join('; ')}`);
  return notes;
}
const errMessage = (e) => (e && typeof e.message === 'string' ? e.message : 'the request failed');
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

// Text written into the files a publisher reads (NEXT_STEPS.txt, pointer.json)
// goes through escText: the unsafe characters of SPEC.md section 3 become \u
// escapes, one per UTF-16 code unit, as in the terminal output. Line feeds stay.
const UNSAFE_G = new RegExp(UNSAFE_CHARS_SOURCE, 'gu');
const escapeUnits = (c) => [...Array(c.length).keys()].map((n) => '\\u' + c.charCodeAt(n).toString(16).padStart(4, '0')).join('');
export function escText(s) {
  return String(s).replace(UNSAFE_G, (c) => (c === '\n' ? c : escapeUnits(c)));
}

// ---- shared with init (lib/cli.js) ----

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

// The remotes of a server.json (or of a listing, which holds a server.json) as
// a declaration names them. Returns { remotes, problems, notes, canonicalHint };
// remotes is undefined when there are none. label names the source in messages.
// fromListing: the remotes of a published listing, which cannot change. A
// client compares a listing remote after WHATWG serialization (SPEC.md section
// 11, "Comparing remotes"), so its serialization is declared when it is an
// https URL a declaration accepts.
export function declarableRemotes(list, label = 'server.json', { fromListing = false } = {}) {
  const out = { remotes: undefined, problems: [], notes: [], canonicalHint: false };
  if (!Array.isArray(list) || list.length === 0) return out;
  out.remotes = list.map((r, n) => {
    let url = r && r.url;
    if (r && (r.variables !== undefined || (typeof url === 'string' && /[{}]/.test(url)))) {
      out.problems.push(`${label} remotes[${n}] is a URL template ({...} or "variables"); a declaration names concrete URLs only`);
    } else if (typeof url !== 'string' || !/^https:\/\//i.test(url)) {
      out.problems.push(`${label} remotes[${n}].url is not an https URL; a declaration accepts https remotes only`);
    } else if (hasUserinfo(url)) {
      // Checked before the canonical form, so the URL (and its password) is not repeated.
      out.problems.push(`${label} remotes[${n}].url carries a user name or password; a declared remote URL must not (SPEC.md section 3, https URL rule c). Remove it from the URL in server.json and pass credentials another way (the URL is not repeated here)`);
    } else if (!isHttpsUrl(url)) {
      const c = plainCanonicalForm(url);
      const href = safeHref(url);
      if (c) {
        out.notes.push(`${label} remotes[${n}].url ${url} is declared in its canonical form ${c}; clients compare remotes after WHATWG URL serialization (SPEC.md section 11)`);
        url = c;
      } else if (fromListing && isHttpsUrl(href)) {
        out.notes.push(`${label} remotes[${n}].url ${clip(url, 300)} is declared as ${href}, its WHATWG URL serialization, which is the form check-listing compares (SPEC.md section 11); a later server.json can name it in that form`);
        url = href;
      } else if (url.length > 2048 || href.length > 2048) {
        out.problems.push(`${label} remotes[${n}].url is longer than 2048 characters, the limit for a declared URL (SPEC.md section 3)`);
      } else {
        out.problems.push(`${label} remotes[${n}].url is not in canonical form; write it in server.json as ${href} if that is the endpoint you mean`);
        out.canonicalHint = true;
      }
    }
    if (r && r.headers !== undefined) out.notes.push(`${label} remotes[${n}] has headers; the declaration does not cover headers`);
    if (r && (r.variables !== undefined || (typeof r.url === 'string' && /[{}]/.test(r.url)))) out.template = true;
    return { type: r && r.type, url };
  });
  return out;
}

// The two digests of mcp-tool-set-digest/1 of a tool list the publisher signs.
// Returns { value, notes } or { problem: { message, lines } }.
export function digestsForSigning(pages) {
  let r;
  try {
    r = toolSetDigestsFromPages(pages);
  } catch (e) {
    if (e instanceof InputError) return { problem: { message: `tools file: ${e.message}` } };
    throw e;
  }
  const missing = ['contract', 'extras'].filter((k) => r[k].error).map((k) => `the tool list has no ${k} digest under ${TOOL_SET_DIGEST_ID}: ${r[k].error} (${r[k].detail})`);
  if (missing.length) return { problem: { message: `a declaration in format ${SPEC_ID_02} needs both digests of its tool list:`, lines: missing } };
  // The publisher controls the list, so input the digests read in only one of
  // several ways is refused here (SPEC.md T17), as format 0.1 refuses it. A
  // verifier stays lenient, as mcp-tool-set-digest/1 requires, and reports it.
  const ambiguous = [];
  for (const { name, count } of r.repeatedNames) ambiguous.push(`tool name "${name}" appears ${count} times; MCP requires unique tool names, and the digests group extras by name, so which of these tools carries title or annotations would not be pinned`);
  if (r.repeatedMembers) ambiguous.push(`${r.repeatedMembers} repeated member name${r.repeatedMembers === 1 ? '' : 's'} in the tools/list page; a client whose JSON parser keeps the first value, or refuses the list, would read other tool definitions than the signed digests pin`);
  if (ambiguous.length) return { problem: { message: 'tools file: the list cannot be signed as it is; fix the server so its tools/list has unique tool names and no repeated member names, then save the list again:', lines: ambiguous } };
  return { value: { spec: TOOL_SET_DIGEST_ID, contract: r.contract.digest, extras: r.extras.digest }, notes: r.notes, toolCount: r.toolCount };
}

// ---- --tools-header-env ----

// A header the publisher's own remote needs before it answers tools/list
// (Authorization, X-API-KEY, ...). The name is given on the command line, the
// value only through an environment variable; prepare sends it to the
// streamable-http remote of the listing only, over https, and does not print
// or write it.
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;
// Headers the MCP client or the HTTP layer sets itself, and hop by hop headers.
const RESERVED_HEADERS = new Set(['host', 'content-length', 'content-type', 'accept', 'accept-encoding', 'transfer-encoding', 'connection', 'keep-alive', 'upgrade', 'te', 'trailer', 'expect', 'user-agent', 'mcp-protocol-version', 'mcp-method', 'mcp-session-id', 'last-event-id']);
export const MAX_TOOLS_HEADER_VALUE = 8192;

// Why a header name cannot be used, or null. The name is not repeated, since a
// value pasted in its place would be shown.
export function toolsHeaderNameProblem(name) {
  if (typeof name !== 'string' || looksLikeKey(name) || holdsKeyRun(name) || holdsSplitKey(name)) return 'the header name looks like key material or a token; give the NAME of the header (such as Authorization) and put its value in the environment variable';
  if (!HEADER_NAME_RE.test(name)) return 'the header name must be 1 to 64 letters, digits or the characters of an HTTP token (such as Authorization or X-API-KEY)';
  const low = name.toLowerCase();
  if (RESERVED_HEADERS.has(low) || low.startsWith('proxy-')) return 'that header is set by prepare itself or by the HTTP connection, so it cannot be given';
  return null;
}

// The value to send (surrounding white space, such as the line feed a file
// ends with, is dropped), or { problem }. The value is not repeated.
export function toolsHeaderValue(raw) {
  if (typeof raw !== 'string') return { problem: 'is not set' };
  const v = raw.trim();
  if (v === '') return { problem: 'is empty' };
  if (v.length > MAX_TOOLS_HEADER_VALUE) return { problem: `holds more than ${MAX_TOOLS_HEADER_VALUE} characters` };
  if (/[^\t\x20-\x7e\x80-\xff]/.test(v)) return { problem: 'holds a line break, a control character or a character outside Latin-1, which an HTTP header cannot carry' };
  return { value: v };
}

// The header names a listing declares for a remote (server.json remotes[n].headers),
// when they can be used with --tools-header-env. The names come from outside
// data and are printed inside a suggested command line, so only letters,
// digits and "-" are taken (an HTTP token may also hold characters a shell
// reads, such as ` $ | &).
function declaredHeaderNames(remote) {
  const hs = remote && Array.isArray(remote.headers) ? remote.headers : [];
  return [...new Set(hs.map((h) => (isObj(h) && typeof h.name === 'string' ? h.name : null)).filter((n) => n !== null && /^[A-Za-z0-9-]{1,64}$/.test(n) && toolsHeaderNameProblem(n) === null))].slice(0, 4);
}

// Hides the values of --tools-header-env in text that came from the server
// (a server may repeat a credential in an error message, and the client cuts
// long messages, so a cut part is hidden too). A value or word of 8 or more
// characters is hidden where it appears whole, and every run of 16 or more
// characters taken from such a value is hidden as well. A shorter value is
// not treated as a secret (see the note in prepare). Returns a function of a string.
export const MIN_HIDDEN_VALUE = 8;
const HIDE_WINDOW = 16;
export function headerValueHider(values) {
  const whole = [...new Set(values.flatMap((v) => [v, ...v.split(/\s+/)]).filter((p) => p.length >= MIN_HIDDEN_VALUE))];
  const windows = new Set();
  for (const v of values) for (let i = 0; i + HIDE_WINDOW <= v.length; i++) windows.add(v.slice(i, i + HIDE_WINDOW));
  if (!whole.length) return (s) => s;
  return (s) => {
    if (typeof s !== 'string' || s === '') return s;
    const marks = new Uint8Array(s.length);
    let any = false;
    for (const w of whole) {
      for (let at = s.indexOf(w); at !== -1; at = s.indexOf(w, at + 1)) {
        marks.fill(1, at, at + w.length);
        any = true;
      }
    }
    for (let i = 0; i + HIDE_WINDOW <= s.length; i++) {
      if (windows.has(s.slice(i, i + HIDE_WINDOW))) {
        marks.fill(1, i, i + HIDE_WINDOW);
        any = true;
      }
    }
    if (!any) return s;
    let out = '';
    for (let i = 0; i < s.length; ) {
      if (!marks[i]) {
        out += s[i++];
        continue;
      }
      while (i < s.length && marks[i]) i++;
      out += '<header value hidden>';
    }
    return out;
  };
}

// Whether a host is the domain a namespace names or a host under it.
function hostInNamespace(host, nsDomain) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  return h === nsDomain || h.endsWith(`.${nsDomain}`);
}

// ---- versions ----

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

// Semantic version precedence (semver.org 2.0.0, section 11): -1, 0 or 1, or
// null when the order cannot be decided (either is not a semantic version, or
// the two differ only in build metadata, which has no precedence).
export function compareVersions(a, b) {
  const x = typeof a === 'string' ? SEMVER_RE.exec(a) : null;
  const y = typeof b === 'string' ? SEMVER_RE.exec(b) : null;
  if (!x || !y) return null;
  const num = (p, q) => {
    const m = BigInt(p);
    const n = BigInt(q);
    return m === n ? 0 : m < n ? -1 : 1;
  };
  for (let i = 1; i <= 3; i++) {
    const c = num(x[i], y[i]);
    if (c) return c;
  }
  const pa = x[4];
  const pb = y[4];
  if (pa !== undefined || pb !== undefined) {
    // A version with a prerelease comes before the same version without one.
    if (pa === undefined) return 1;
    if (pb === undefined) return -1;
    const A = pa.split('.');
    const B = pb.split('.');
    for (let i = 0; i < Math.max(A.length, B.length); i++) {
      if (i >= A.length) return -1;
      if (i >= B.length) return 1;
      const na = /^\d+$/.test(A[i]);
      const nb = /^\d+$/.test(B[i]);
      if (na && nb) {
        const c = num(A[i], B[i]);
        if (c) return c;
      } else if (na) return -1;
      else if (nb) return 1;
      else if (A[i] !== B[i]) return A[i] < B[i] ? -1 : 1;
    }
  }
  return a === b ? 0 : null;
}

// ---- local files ----

// Path segments this command writes must give the same name on every system:
// no trailing dot or space (Windows drops them) and no device name such as CON.
export function segmentProblem(seg) {
  if (seg === '' || seg === '.' || seg === '..') return 'it is empty or a dot segment';
  if (/[. ]$/.test(seg)) return 'it ends with a dot or a space, which Windows drops from file names';
  if (/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i.test(seg)) return 'it is a device name on Windows (such as CON or NUL)';
  if (/[<>:"|?*\\/\x00-\x1f]/.test(seg)) return 'it holds a character that cannot be part of a file name';
  return null;
}

// Every file under dir (relative, "/" separated), without following links.
// A symbolic link or junction is listed in links and not entered.
function listFiles(dir) {
  const files = [];
  const links = [];
  const walk = (rel) => {
    if (files.length >= MAX_LISTED_FILES) return;
    let entries;
    try {
      entries = fs.readdirSync(path.join(dir, rel), { withFileTypes: true });
    } catch (e) {
      throw new PrepareError(`cannot read the output folder (${e.code || 'error'})`);
    }
    for (const e of entries) {
      if (files.length >= MAX_LISTED_FILES) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) {
        links.push(r);
        files.push(r);
      } else if (e.isDirectory()) walk(r);
      else files.push(r);
    }
  };
  walk('');
  return { files, links };
}

function inspectFolder(dir) {
  let st;
  try {
    st = fs.statSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT') return { exists: false, files: [], links: [] };
    throw new PrepareError(`cannot read the output folder (${e.code || 'error'})`);
  }
  if (!st.isDirectory()) throw new PrepareError('--out names a file, not a folder; give a folder (it is made if it does not exist)');
  return { exists: true, ...listFiles(dir) };
}

// The files of a signed set an earlier prepare run wrote: only a signed run writes these.
const inSignedSet = (f) => f === 'pointer.json' || f === 'NEXT_STEPS.txt' || f.startsWith(OWNED_SITE);

// The reason a folder cannot be written into, or null. signing: this run signs.
// A run that does not sign (no key, or a dry run) writes only
// declaration.unsigned.json, so it does not remove a signed set, also with --force.
function folderRefusal(folder, outDir, force, signing) {
  if (folder.links.length) {
    return `the output folder ${outDir} holds ${plural(folder.links.length, 'symbolic link or junction', 'symbolic links or junctions')} (such as ${folder.links.slice(0, 3).map((x) => clip(x, 120)).join(', ')}); prepare does not write into a folder that holds links, also with --force, because a file could land outside the folder. Give another --out`;
  }
  const signedSet = signing ? [] : folder.files.filter(inSignedSet);
  if (signedSet.length) {
    return `the output folder ${outDir} holds a signed set from an earlier prepare run (${plural(signedSet.length, 'file')}, such as ${signedSet.slice(0, 3).map((x) => clip(x, 120)).join(', ')}); a run without a key option, or with --dry-run, writes only declaration.unsigned.json and does not remove signed files, also with --force. Give another --out for this run`;
  }
  if (folder.files.length && !force) {
    return `the output folder ${outDir} already holds ${plural(folder.files.length, 'file')}${folder.files.length >= MAX_LISTED_FILES ? ' or more' : ''}; give another --out, or --force to replace what an earlier prepare run wrote there (other files are left as they are)`;
  }
  return null;
}

// Removes the empty folders under dir/rel, deepest first (links are not entered).
function removeEmptyFolders(dir, rel) {
  const full = path.join(dir, ...rel.split('/').filter(Boolean));
  let st;
  try {
    st = fs.lstatSync(full);
  } catch {
    return;
  }
  if (!st.isDirectory()) return;
  for (const e of fs.readdirSync(full, { withFileTypes: true })) if (e.isDirectory()) removeEmptyFolders(dir, `${rel}/${e.name}`);
  if (fs.readdirSync(full).length === 0) fs.rmdirSync(full);
}

// Writes list ([{ path, text }]) into outDir as one step: every file is first
// written into a staging folder inside outDir, and moved into place only when
// all of them were written. With force, the files an earlier prepare run wrote
// (OWNED_TOP and everything under OWNED_SITE) that this run does not write are
// removed, so the folder holds one consistent set; a run that does not sign is
// refused when the folder holds a signed set (folderRefusal). Returns
// { removed, left } or { refused }.
function commitFiles(outDir, list, force, signing) {
  const folder = inspectFolder(outDir);
  const refused = folderRefusal(folder, outDir, force, signing);
  if (refused) return { refused };
  const created = !folder.exists;
  let root;
  let stage;
  try {
    fs.mkdirSync(outDir, { recursive: true });
    root = fs.realpathSync(outDir);
    stage = fs.mkdtempSync(path.join(root, '.prepare-'));
  } catch (e) {
    throw new PrepareError(`cannot write into the output folder (${e.code || 'error'}); nothing was written`);
  }
  const inside = (base, rel) => {
    const full = path.resolve(base, ...rel.split('/'));
    if (!full.startsWith(base + path.sep)) throw new PrepareError('an output path would leave the output folder; nothing was written');
    return full;
  };
  try {
    for (const f of list) {
      const full = inside(stage, f.path);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, f.text, { encoding: 'utf8', flag: 'wx' });
    }
  } catch (e) {
    fs.rmSync(stage, { recursive: true, force: true });
    if (created) fs.rmSync(root, { recursive: true, force: true });
    if (e instanceof PrepareError) throw e;
    throw new PrepareError(`cannot write into the output folder (${e.code || 'error'}); nothing was written into it`);
  }
  const written = new Set(list.map((f) => f.path));
  const owned = (f) => OWNED_TOP.includes(f) || f.startsWith(OWNED_SITE);
  const removed = folder.files.filter((f) => owned(f) && !written.has(f));
  const left = folder.files.filter((f) => !owned(f) && !written.has(f));
  try {
    for (const f of removed) fs.rmSync(inside(root, f), { force: true });
    if (removed.length) {
      removeEmptyFolders(root, OWNED_SITE.replace(/\/$/, ''));
      for (const rel of ['site/.well-known', 'site']) {
        const full = path.join(root, ...rel.split('/'));
        try {
          if (fs.lstatSync(full).isDirectory() && fs.readdirSync(full).length === 0) fs.rmdirSync(full);
        } catch {
          // absent: nothing to remove
        }
      }
    }
    for (const f of list) {
      const dst = inside(root, f.path);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.renameSync(inside(stage, f.path), dst);
    }
  } catch (e) {
    throw new PrepareError(`cannot move the files into the output folder (${e.code || 'error'}); the folder may hold a partial set, so run prepare again with --force`);
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
  return { removed, left };
}

// A command argument as a shell reads it.
function arg(s) {
  return /^[A-Za-z0-9._+~/:-]+$/.test(s) ? s : `"${s.replace(/"/g, '\\"')}"`;
}

// The check-listing command to run once the files are served (and, for a new
// version, once it is published). --registry is named when it is not the default.
export function checkListingCommand(name, version, fetchTools, registryBaseUrl) {
  const reg = registryBaseUrl && registryBaseUrl !== DEFAULT_REGISTRY ? ` --registry ${arg(registryBaseUrl)}` : '';
  return `node bin/addon-declare.js check-listing ${arg(name)} --version ${arg(version)}${fetchTools ? ' --fetch-tools' : ''}${reg}`;
}

const remoteWords = (remotes) => (remotes && remotes.length ? remotes.map((r) => `${r.type} ${r.url}`).join(', ') : 'no remote');

function nextStepsText(x) {
  const L = [];
  const authLine = x.toolsHeaders ? '   The tool list was read with --tools-header-env. check-listing --fetch-tools sends no credentials, so for a remote that asks for authorization it reports the tool list as not checked (the state and exit code stay as above). To compare the list too, save the tools/list result of the published version as tools.json and run the same command with --tools tools.json in place of --fetch-tools.' : null;
  L.push(`Next steps for ${x.name} version ${x.forVersion}`);
  L.push(`Declaration hash: ${x.hash}`);
  L.push('Nothing has been uploaded or published yet. Do these steps in order.');
  L.push('');
  L.push(`1. Upload these files to ${x.host}. Serve each one at the URL shown, with HTTP status 200, no redirect, and the header Content-Type: application/json.`);
  for (const f of x.uploads) {
    L.push(`   ${f.path}`);
    L.push(`     to ${f.url}`);
  }
  L.push('   Keep every by-hash file you upload, also after later releases: the history of your declarations is read from them. The versions and latest.json files are replaced by later declarations.');
  if (!x.writeLatest) L.push(`   No latest.json was written (${x.latestWhy}); leave the latest.json you serve as it is${x.mode === 'pointer' ? `, and once the registry marks ${x.forVersion} as the latest version, serve a copy of versions/${encodePathSegment(x.forVersion)}.json as latest.json` : ''}.`);
  L.push(`   To check an upload, open ${x.uploads[0].url} in a browser: it must show the same text as the local file.`);
  if (x.folderWarning) {
    const w = x.folderWarning;
    L.push(w.result === 'redirect'
      ? `   When prepare ran, ${w.url} answered with a permanent redirect. check-listing follows no redirect, and a browser follows one without showing it, so stop that redirect for the folder of these files before the next step, and check each URL with a request that does not follow redirects, such as curl -sI ${x.uploads[0].url}: the first line must show status 200, and no Location line may follow. While the redirect is there, check-listing reports declaration_unreachable.`
      : `   When prepare ran, ${w.host} had no address in DNS. Give it an address and serve these files there before the next step, then check each URL with a request that does not follow redirects, such as curl -sI ${x.uploads[0].url}: the first line must show status 200, and no Location line may follow. Until then, check-listing reports declaration_unreachable.`);
  }
  if (x.mode === 'pointer') {
    L.push(`2. Edit the server.json of version ${x.forVersion} as follows, then publish it.`);
    L.push(`   a. Set "version" to "${x.forVersion}".`);
    L.push(`   b. Set _meta["${PUBLISHER_META_KEY}"] to the object of that name in pointer.json: replace the object as a whole, do not merge into it.${x.carried.length ? ` It already holds the other members of that object in ${x.metaSource} (${x.carried.map((k) => JSON.stringify(clip(k, 80))).join(', ')}).` : ''}${x.fromListing ? ` pointer.json was built from the listing of ${x.listedVersion}; if the server.json of ${x.forVersion} has other members in that object, run prepare again with --server-json <that server.json> and --force, so pointer.json keeps them.` : ''}`);
    if (x.histor) {
      const s = x.histor.value.sets[0];
      const m = x.histor.merge;
      const how = m.action === 'replaced' ? `; it replaces the member of that name in ${x.metaSource}, which HISTOR reads nothing from` : m.action === 'merged' ? `; it is the member of that name in ${x.metaSource} with this set added first` : '';
      const kept = m.action !== 'merged' ? '' : ` It also keeps ${m.keptSets.length ? `the ${plural(m.keptSets.length, 'other set')} that member declares` : 'no other set'}${m.url !== undefined ? ' and its "url"' : ''}${m.keptWhen ? ', and the "when" that member gives for this digest' : ''}, so HISTOR marks none of them withdrawn.`;
      L.push(`      That object also holds the member "${HISTOR_MEMBER}" (--histor-tool-sets was given${how}). It is read by HISTOR, a third party watcher of MCP servers (${HISTOR_URL}), in the format HISTOR defines (${HISTOR_DOC}). It states "mtl": "1" and, as its first tool set, the contract digest of ${TOOL_SET_DIGEST_ID} that the declaration signs, ${s.digest}${s.count !== undefined ? `, with ${plural(s.count, 'tool')}` : ''}.${kept}`);
      L.push('      HISTOR uses the member for tool sets it has not observed itself, such as a list given with --tools from another configuration; a set it already observes shows only on the server page.');
      L.push('      The member is not signed and is not part of the declaration: it is a statement by the publisher, and HISTOR shows it as such. The signed declaration is what shows who made the statement about the tool list. check-listing prints whether a listing carries the member, and its result does not depend on it.');
    }
    if (x.fromListing) {
      L.push(`   c. Keep "remotes" exactly as listed for ${x.listedVersion}: ${remoteWords(x.remotes)}. The declaration names these remotes, and check-listing reports listing_mismatch for a version whose remotes differ, which cannot be fixed once that version is published. If ${x.forVersion} uses other remotes, run prepare again with --server-json <the server.json of ${x.forVersion}> and --force.`);
    } else {
      L.push(`   c. Keep "remotes" as in the server.json given to prepare: ${remoteWords(x.remotes)}. The declaration names these remotes, and check-listing reports listing_mismatch for a version whose remotes differ.`);
    }
    L.push(`   d. ${x.toolsFrom} Version ${x.forVersion} must answer tools/list with that same list, or check-listing --fetch-tools reports tools_hash_mismatch after publishing. If ${x.forVersion} changes the tools, run prepare again with --tools <the tools/list result of the ${x.forVersion} build> and --force.`);
    L.push('   Then publish it with the usual publisher tool:');
    L.push('   mcp-publisher publish');
    L.push(`3. When the registry lists version ${x.forVersion}, run:`);
    L.push(`   ${x.checkCommand}`);
    L.push('   It should print "verified" and exit with code 0.');
    if (authLine) L.push(authLine);
  } else {
    L.push(`2. The listing of ${x.forVersion} stays as it is (a published version cannot change). When the files are served, run:`);
    L.push(`   ${x.checkCommand}`);
    L.push(`   It should print "verified_newer_declaration" and exit with code 11: the declaration the listing names is checked first, and this one is found through versions/${encodePathSegment(x.forVersion)}.json and latest.json because its history leads back to it under the same key.`);
    if (authLine) L.push(authLine);
  }
  for (const n of x.timeNotes) L.push(`Note: ${n}.`);
  L.push('');
  L.push(`Do not upload declaration.unsigned.json${x.mode === 'pointer' ? ', pointer.json' : ''} or this file.`);
  L.push('bin/addon-declare.js is in the addon-declaration folder; put its path in front of it, as README.md shows.');
  return escText(L.join('\n') + '\n');
}

// options:
//   name, listingVersion ("latest" by default), registry ({ base, loopback })
//   method: "dns" or "http" (the key record method), or undefined for http then dns
//   forVersion, noPointer, noPrevious (pointer mode: read and name no previous declaration)
//   historToolSets (pointer mode: pointer.json also carries the HISTOR tool sets
//     member, lib/histor-tool-sets.js); historToolSetsMember: its builder, replaceable in tests
//   toolsPages: tool list pages given as files (bytes), or undefined to read the remote
//   serverJson: the parsed server.json of the version to publish, or undefined
//   contact, payment (array), expiresInDays
//   key: a loaded private key (keys.js loadPrivateKey), or undefined
//   dryRun, outDir, force, now (epoch milliseconds), clock (the machine clock, for a note on --now)
//   request (the hardened fetch), keyLookup: (method, domain) => { keys, notes, error, transient }
//   hostLookup: (host) => { noAddress, detail } (resolve.js hostWithoutAddress),
//     asked when latest.json could not be fetched because the system lookup
//     found no address for its host
//   toolsHeaders: [{ name, value, variable }] (--tools-header-env), sent with
//     tools/list to the streamable-http remote of the listing only; the values
//     are not printed, written or kept in the report
//   fetchToolsList: replaceable in tests
// Returns { state, exitCode, reasons, report }. Throws PrepareError for input problems.
export async function prepare(o) {
  const { name, listingVersion = 'latest', registry, method, forVersion, noPointer = false, noPrevious = false, toolsPages, serverJson, contact, payment, expiresInDays = DEFAULT_EXPIRES_IN_DAYS, key, dryRun = false, outDir = DEFAULT_OUT, force = false, now = Date.now(), clock = Date.now, request = httpsRequest, keyLookup, hostLookup = (h) => hostWithoutAddress(h), toolsHeaders = [], toolsHeaderHost } = o;
  if (toolsHeaders.length && toolsPages) throw new PrepareError('give --tools-header-env or --tools, not both: with --tools the remote is not read; nothing was read or written');
  if (toolsHeaderHost !== undefined && !toolsHeaders.length) throw new PrepareError('--tools-header-host names the host that may receive the headers of --tools-header-env, so it is given only with --tools-header-env; nothing was read or written');
  // The header values are hidden in the text that came from the server (error
  // messages and notes of the tools/list read), where a server may repeat a
  // credential. The rest of the output is prepare's own text and is left as it is.
  const hideText = headerValueHider(toolsHeaders.map((h) => h.value));
  // The variable named after "=", or a description when cli.js did not repeat it.
  const varWords = (h) => h.variable || `the variable given for ${h.name}`;
  const readTools = o.fetchToolsList || fetchToolsList;
  const historOn = Boolean(o.historToolSets);
  const buildHistor = o.historToolSetsMember || historToolSetsMember;
  const signing = Boolean(key) && !dryRun;
  if (noPointer && noPrevious) throw new PrepareError('--no-previous cannot be given with --no-pointer: a declaration without a pointer is found only when it follows the declaration check-listing puts in force; nothing was read or written');
  if (noPointer && historOn) throw new PrepareError(`--histor-tool-sets cannot be given with --no-pointer: the member goes into pointer.json, the publisher metadata of the new version's server.json, and --no-pointer writes no pointer.json; nothing was read or written`);
  const report = {
    name,
    forVersion: forVersion ?? null,
    mode: forVersion === undefined ? null : noPointer ? 'no_pointer' : 'pointer',
    signed: false,
    dryRun: Boolean(dryRun),
    out: outDir,
    steps: [],
    listing: { name, requestedVersion: listingVersion, registry: registry.base, url: null, version: null, publishedAt: null, registryStatus: null, isLatest: null, remoteCount: null, latestVersion: null },
    keyRecord: null,
    signingKey: key ? { alg: key.alg, id: key.public.id, matches: null } : null,
    tools: null,
    previous: null,
    declaration: null,
    pointer: null,
    // Present only with --histor-tool-sets, so the output without it stays as it was.
    ...(historOn ? { historToolSets: null } : {}),
    files: [],
    verify: null,
    preview: null,
    checkCommand: null,
    fetched: [],
    notes: [],
  };
  const steps = new Map();
  const step = (n, result, line) => steps.set(n, { step: n, label: STEP_LABELS[n - 1], result, line });
  const finish = (state, reasons = []) => {
    for (let n = 1; n <= STEP_LABELS.length; n++) if (!steps.has(n)) step(n, 'not_run', `not run (stopped at ${state})`);
    report.steps = [...steps.values()].sort((a, b) => a.step - b.step);
    return { state, exitCode: PREPARE_STATES[state], reasons, report };
  };

  // Names written as folders and files must give the same names everywhere.
  const slash = name.indexOf('/');
  const nsPart = name.slice(0, slash);
  const serverPart = name.slice(slash + 1);
  const versionFile = forVersion === undefined ? null : `${encodePathSegment(forVersion)}.json`;
  for (const [what, seg] of [['the namespace', nsPart], ['the server name', serverPart], ['the version file name', versionFile]]) {
    const p = seg === null ? null : segmentProblem(seg);
    if (p) throw new PrepareError(`${what} cannot be written as a file or folder name (${p}); nothing was read or written`);
  }

  // 3, before anything is read: the version the declaration is for.
  const versionWhy = 'A published version cannot change in the registry, and the pointer to a declaration lives in server.json, so a pointer can only be added in a new listing version';
  if (forVersion === undefined) {
    step(3, 'failed', 'no --for-version given; nothing was read');
    return finish('version_not_usable', [
      `give --for-version <version>, the version you are about to publish. ${versionWhy}: the declaration is made for that version, and its pointer goes into that version's server.json. Nothing was read`,
      `to declare the version already listed without a pointer, give that version (check-listing ${name} prints it) as --for-version together with --no-pointer: check-listing then finds the declaration through versions/<version>.json and latest.json, and only when the listing already points to a declaration that the new one follows under the same key`,
    ]);
  }

  // The output folder is checked next, so a refusal costs no request.
  const folder = inspectFolder(outDir);
  const refusal = folderRefusal(folder, outDir, force, signing);
  if (refusal) {
    step(8, 'failed', `the output folder cannot be written into (${folder.links.length ? 'it holds a link' : plural(folder.files.length, 'file')}); nothing was read or written`);
    return finish('output_folder_not_empty', [refusal]);
  }

  // Notes on --now against the machine clock.
  const timeNotes = [];
  const machine = clock();
  if (now > machine + CLOCK_SKEW_MS) timeNotes.push(`--now (${iso(now)}) is later than this machine's clock (${iso(machine)}): the declaration is issued at ${iso(now)}, and until then verify and check-listing give not_yet_valid for it`);
  else if (now < machine - 86400000) timeNotes.push(`--now (${iso(now)}) is earlier than this machine's clock (${iso(machine)}): the declaration expires ${plural(expiresInDays, 'day')} after ${iso(now)}, sooner than ${plural(expiresInDays, 'day')} from today`);
  report.notes.push(...timeNotes);

  // Every network read goes through here, and is listed; a GET is read once.
  const cache = new Map();
  const net = (purpose) => async (url, opts = {}) => {
    const m = opts.method || 'GET';
    if (m === 'GET' && cache.has(url)) return cache.get(url);
    const entry = { purpose, method: m, url, status: null };
    if (m === 'POST' && typeof opts.body === 'string') {
      try {
        const b = JSON.parse(opts.body);
        if (isObj(b) && typeof b.method === 'string') entry.rpc = b.method;
      } catch {
        // not JSON: no method to name
      }
    } else if (m === 'DELETE') entry.rpc = 'session end';
    report.fetched.push(entry);
    try {
      const res = await request(url, opts);
      entry.status = res.status;
      if (m === 'GET') {
        entry.bytes = res.body.length;
        cache.set(url, res);
      }
      return res;
    } catch (e) {
      entry.error = purpose === 'mcp' ? hideText(errMessage(e)) : errMessage(e);
      if (e && e.refused) entry.refused = true;
      throw e;
    }
  };
  // One key lookup per method and domain, listed with the requests.
  const lookups = new Map();
  const lookupEntries = new Map();
  const lookup = (m, domain) => {
    const id = `${m} ${domain}`;
    if (!lookups.has(id)) {
      const entry = m === 'http'
        ? { purpose: 'key lookup (http)', method: 'GET', url: `https://${domain}/.well-known/mcp-registry-auth`, status: null }
        : { purpose: 'key lookup (dns)', method: 'TXT', url: `dns:${domain} (TXT)`, domain, status: null };
      report.fetched.push(entry);
      lookupEntries.set(id, entry);
      lookups.set(
        id,
        Promise.resolve()
          .then(() => keyLookup(m, domain))
          .then(
            (r) => {
              const out = { keys: Array.isArray(r && r.keys) ? r.keys : [], notes: Array.isArray(r && r.notes) ? r.notes : [], ...(r && r.error ? { error: String(r.error) } : {}), ...(r && r.error && r.transient === true ? { transient: true } : {}) };
              if (r && Number.isInteger(r.status)) entry.status = r.status;
              if (out.error) entry.error = out.error;
              else if (m === 'dns') entry.answered = true;
              return out;
            },
            (e) => {
              entry.error = errMessage(e);
              return { keys: [], notes: [], error: entry.error };
            },
          ),
      );
    }
    return lookups.get(id);
  };
  // The keys a location publishes that its method reads (http reads only MCPv1 records, SPEC.md section 9).
  const keysAt = async (m, d) => {
    const r = await lookup(m, d);
    return { ...r, keys: r.keys.filter((k) => m !== 'http' || k.record !== 'addon') };
  };
  const where = (m, d) => (m === 'http' ? `https://${d}/.well-known/mcp-registry-auth` : `the TXT records of ${d}`);

  // A registry listing, read strictly. Returns { server, official } or { failed: { state, line, reason } }.
  const readListing = async (version, purpose) => {
    const url = `${registry.base}${REGISTRY_SERVER_PATH}/${encodePathSegment(name)}/versions/${encodePathSegment(version)}`;
    const asked = version === 'latest' ? `the latest version of ${name}` : `${name} version ${version}`;
    let res;
    try {
      res = await net(purpose)(url, { method: 'GET', headers: { Accept: 'application/json' }, maxBytes: MAX_REGISTRY_RESPONSE, allowLoopbackHttp: registry.loopback });
    } catch (e) {
      return { url, failed: { state: 'registry_read_failed', line: `could not read ${url}`, reason: e && e.tooLarge ? `the registry answer for ${asked} is larger than ${MAX_REGISTRY_RESPONSE} bytes` : `the request to the registry failed: ${errMessage(e)}` } };
    }
    if (res.status === 404) return { url, status: 404, failed: { state: 'listing_not_found', line: `the registry has no listing for ${asked} (HTTP 404)`, reason: `the registry answered HTTP 404 for ${asked}. prepare makes a declaration for a server the registry already lists, and reads its remotes from that listing: publish the server once with the usual publisher tool (mcp-publisher publish), or check the name and --listing-version` } };
    if (res.status !== 200) return { url, status: res.status, failed: { state: 'registry_read_failed', line: `the registry answered HTTP ${res.status}`, reason: `the registry answered HTTP ${res.status}${res.status >= 300 && res.status < 400 ? ', a redirect, which is not followed' : ''} for ${asked}` } };
    let body;
    try {
      body = parseStrict(decodeUtf8Strict(res.body));
    } catch (e) {
      return { url, status: 200, failed: { state: 'registry_read_failed', line: 'the registry answer is not strict JSON', reason: `the registry answer is not strict JSON (${e.message}); the base URL may not be a registry API` } };
    }
    const server = isObj(body) ? body.server : undefined;
    const invalid = (why) => ({ url, status: 200, failed: { state: 'registry_read_failed', line: 'the registry answer is not a listing for this name', reason: why } });
    if (!isObj(server)) return invalid('the registry answer has no "server" object');
    if (server.name !== name) return invalid(`the registry answered for another server name (${typeof server.name === 'string' ? JSON.stringify(clip(server.name)) : 'none'}), not ${name}`);
    if (typeof server.version !== 'string' || server.version.length === 0) return invalid('the registry answer has no server version');
    if (version !== 'latest' && server.version !== version) return invalid(`the registry answered for version ${JSON.stringify(clip(server.version))}, not ${JSON.stringify(version)}`);
    const official = isObj(body._meta) && isObj(body._meta[OFFICIAL_META_KEY]) ? body._meta[OFFICIAL_META_KEY] : {};
    return { url, status: 200, server, official };
  };

  // 1. The namespace and the listing.
  const ns = nsPart.toLowerCase();
  if (ns === 'io.github' || ns.startsWith('io.github.')) {
    step(1, 'failed', 'not read: the name is in a GitHub account namespace, not a domain namespace');
    return finish('namespace_not_domain', [`${GITHUB_OUT_OF_SCOPE}. A declaration is signed with the key of a domain namespace (such as com.example/weather) and checked against the key record that domain publishes, so no declaration can be made for this name; nothing was read`]);
  }
  const nsDomain = reverseDomain(ns);
  if (!isValidDomain(nsDomain)) {
    step(1, 'failed', 'not read: the namespace names no domain');
    return finish('namespace_not_domain', [`the namespace "${ns}" names no domain the registry accepts for a key (${nsDomain} is not a lowercase domain name of two or more labels, or it is refused, as github.io is). A declaration is checked against the key record of the domain the namespace names, so no declaration can be made for this name; nothing was read`]);
  }
  const first = await readListing(listingVersion, 'registry listing');
  report.listing.url = first.url;
  if (first.failed) {
    step(1, 'failed', first.failed.line);
    return finish(first.failed.state, [first.failed.reason]);
  }
  const listed = first.server;
  const official = first.official;
  const str = (v) => (typeof v === 'string' ? v : null);
  Object.assign(report.listing, {
    version: listed.version,
    publishedAt: str(official.publishedAt),
    registryStatus: str(official.status),
    isLatest: typeof official.isLatest === 'boolean' ? official.isLatest : null,
    remoteCount: Array.isArray(listed.remotes) ? listed.remotes.length : 0,
  });
  const bits = [`published ${clip(report.listing.publishedAt ?? 'unknown')}`, `status ${clip(report.listing.registryStatus ?? 'unknown')}`];
  if (report.listing.isLatest) bits.push('latest');
  step(1, 'ok', `read ${name} ${clip(listed.version)} from ${first.url} (${bits.join(', ')})`);
  if (report.listing.registryStatus !== null && report.listing.registryStatus !== 'active') report.notes.push(`the registry marks the listed version ${clip(report.listing.registryStatus)}`);

  // 2. The key record that registry login reads: at the domain the namespace
  // names (--method, else http, then dns), then by dns at each parent domain of
  // two or more labels, whose dns key covers the sub namespace (SPEC.md section 11 step 2).
  const parents = pointerHosts(ns).filter((h) => h !== nsDomain);
  const locations = [...(method ? [method] : ['http', 'dns']).map((m) => ({ method: m, domain: nsDomain })), ...(method === 'http' ? [] : parents.map((d) => ({ method: 'dns', domain: d })))];
  const tried = [];
  let found = null;
  for (const loc of locations) {
    const r = await keysAt(loc.method, loc.domain);
    tried.push({ method: loc.method, domain: loc.domain, location: where(loc.method, loc.domain), found: r.keys.length, error: r.error ?? null, transient: Boolean(r.transient), notes: r.notes });
    if (r.keys.length) {
      found = { method: loc.method, domain: loc.domain, location: where(loc.method, loc.domain), keys: r.keys };
      break;
    }
  }
  const keyRows = (keys) => keys.map((k) => ({ alg: k.alg, id: k.id, kind: k.record === 'addon' ? 'ADKv1' : 'MCPv1', record: proofRecord(k, k.record === 'addon' ? 'addon' : 'mcp') }));
  const setKeyRecord = () => {
    report.keyRecord = { method: found ? found.method : null, domain: found ? found.domain : null, location: found ? found.location : null, keys: found ? keyRows(found.keys) : [], tried: tried.map(({ method: m, domain: d, location, found: n, error }) => ({ method: m, domain: d, location, found: n, error })) };
  };
  setKeyRecord();
  if (!found) {
    const failed = tried.filter((t) => t.error);
    const lines = tried.map((t) => `${t.method} at ${t.domain}: ${t.error ? `the lookup failed (${t.error})` : `no usable record at ${t.location}${t.notes.length ? ` (${t.notes.join('; ')})` : ''}`}`);
    step(2, 'failed', `no key record found (${tried.map((t) => `${t.method} at ${t.domain}`).join(', then ')} tried)`);
    if (failed.length) {
      const transient = failed.filter((t) => t.transient);
      const last = transient.length
        ? `the DNS query ${transient.map((t) => `for ${t.domain}`).join(' and ')} timed out or got SERVFAIL from the resolver, also when it was sent a second time. That says nothing about the record: a run a few minutes later may get an answer, so run prepare again. To ask another resolver, give --dns-server <IP address of a resolver you choose>`
        : 'a lookup could not be completed, so nothing is known about the record there; run prepare again later';
      return finish('key_record_lookup_failed', [...lines, last]);
    }
    return finish('key_record_not_found', [
      ...lines,
      `prepare signs with the private key you use for registry login, and a declaration is checked against the public record that login reads: a line "v=MCPv1; k=<alg>; p=<public key>" in https://${nsDomain}/.well-known/mcp-registry-auth (mcp-publisher login http) or a TXT record at ${nsDomain} (mcp-publisher login dns)${parents.length ? `; for a sub namespace a TXT record at a parent domain (${parents.join(' or ')}) is accepted too, because a dns key covers the namespaces under it` : ''}. Publish that record, the same one the registry reads at login, then run prepare again`,
    ]);
  }
  const keyWords = (k) => `${k.alg} ${k.id}`;
  const parentWords = (d) => (d !== nsDomain ? ` (a parent of ${nsDomain}; a dns key there covers the sub namespace)` : '');
  step(2, 'ok', `found by the ${found.method} method at ${found.location}${parentWords(found.domain)}: ${found.keys.map((k) => `${keyWords(k)} (${k.record === 'addon' ? 'ADKv1, declaration only key' : 'MCPv1'})`).join(', ')}${tried.length > 1 ? ` (tried first: ${tried.slice(0, -1).map((t) => `${t.method} at ${t.domain}, ${t.error ? 'no usable answer' : 'no record'}`).join('; ')})` : ''}`);
  // A location tried before the one that answered is not a failure of this
  // run: its request line says so, and a note says why it gave no key.
  for (const t of tried.slice(0, -1)) {
    if (!t.error) continue;
    const e = lookupEntries.get(`${t.method} ${t.domain}`);
    if (e) e.superseded = true;
    report.notes.push(`the ${t.method} key lookup at ${t.domain} gave no usable answer (${t.error}); the key was then found by the ${found.method} method at ${found.location}, so this does not affect the declaration`);
  }

  // The private key is checked against the published record before anything else is read.
  if (signing) {
    const match = found.keys.find((k) => k.alg === key.alg && k.id === key.public.id);
    report.signingKey.matches = Boolean(match);
    if (!match) {
      const other = found.method === 'http' ? 'dns' : 'http';
      step(7, 'failed', `the private key given belongs to ${key.alg} ${key.public.id}, which is not a published record; nothing was signed`);
      return finish('key_mismatch', [
        `the public key of the private key given is ${key.alg} ${key.public.id}, whose record is "${proofRecord(key.public)}"; ${found.location} publishes ${found.keys.map((k) => `${keyWords(k)} ("${proofRecord(k, k.record === 'addon' ? 'addon' : 'mcp')}")`).join(', ')}. A declaration signed with this key would not verify (key_not_found), so nothing was signed or written. Give the private key of the published record${method ? '' : `, or --method ${other} if your key is published by the ${other} method`}`,
      ]);
    }
  }

  // 3. The version the declaration is for, and whether it gets latest.json
  // (the newest declaration of the newest version, SPEC.md section 8).
  let latestVersion = null;
  let latestRead = null;
  if (listingVersion === 'latest' && report.listing.isLatest !== false) latestVersion = listed.version;
  else {
    const lr = await readListing('latest', 'registry listing (latest)');
    if (lr.failed) latestRead = lr.failed.reason;
    else if (lr.official.isLatest === false) latestRead = `the registry answered the request for "latest" with ${clip(lr.server.version)}, which it does not mark as the latest`;
    else latestVersion = lr.server.version;
  }
  report.listing.latestVersion = latestVersion;
  let writeLatest = true;
  let latestWhy = null;
  const noLatest = (why) => {
    writeLatest = false;
    latestWhy = why;
    report.notes.push(`no latest.json is written: ${why}; latest.json holds the newest declaration of the newest version`);
  };
  if (noPointer) {
    if (forVersion !== listed.version) {
      step(3, 'failed', `--no-pointer declares the version already listed, ${clip(listed.version)}, not ${forVersion}`);
      return finish('version_not_usable', [`--no-pointer makes a declaration for the version the listing already has (${clip(listed.version)}), found next to the one the listing names; for the new version ${forVersion}, leave out --no-pointer so the declaration gets a pointer in its server.json`]);
    }
    if (latestVersion === null) noLatest(`the latest version could not be read from the registry${latestRead ? ` (${latestRead})` : ''}`);
    else if (latestVersion !== forVersion) noLatest(`the registry marks ${clip(latestVersion)} as the latest version, not ${forVersion}`);
    step(3, 'ok', `the declaration is for ${forVersion}, the version already listed, with no pointer: check-listing finds it through versions/${versionFile}${writeLatest ? ' and latest.json' : ''}, after the declaration the listing names`);
  } else {
    if (forVersion === listed.version) {
      step(3, 'failed', `${forVersion} is the version already listed`);
      return finish('version_not_usable', [
        `${forVersion} is the version the registry already lists. ${versionWhy}. Give the version you are about to publish as --for-version`,
        `or, to declare ${forVersion} as it is listed, add --no-pointer: the declaration is then found through versions/${versionFile} and latest.json, and only when the listing already points to a declaration that the new one follows under the same key`,
      ]);
    }
    // The new version must not be published yet.
    const vr = await readListing(forVersion, 'registry listing of --for-version');
    if (vr.status === 200 && !vr.failed) {
      step(3, 'failed', `${forVersion} is already published in the registry`);
      return finish('version_not_usable', [`the registry already lists ${name} ${forVersion} (HTTP 200 for ${vr.url}). ${versionWhy}. Give a version that is not published yet`]);
    }
    if (vr.status !== 404) report.notes.push(`could not check whether ${forVersion} is already published (${vr.failed ? vr.failed.reason : 'unexpected answer'}); a version that is already published cannot take a pointer`);
    if (latestVersion === null) noLatest(`the latest version could not be read from the registry${latestRead ? ` (${latestRead})` : ''}`);
    else {
      const c = compareVersions(forVersion, latestVersion);
      if (c === -1 || c === 0) noLatest(`${forVersion} comes before the latest listed version ${clip(latestVersion)} in semantic version order, so the registry will not mark it as the latest`);
      else if (c === null) noLatest(`the order of ${forVersion} and the latest listed version ${clip(latestVersion)} cannot be decided, because they are not both semantic versions`);
    }
    step(3, 'ok', `the declaration is for the new version ${forVersion}${vr.status === 404 ? ' (not in the registry yet)' : ''}; its pointer goes into the server.json of ${forVersion}, because a published version cannot change`);
  }

  // The remotes the declaration names: those of server.json for the new
  // version when given, else those of the listing.
  const remoteLabel = serverJson ? 'server.json' : 'the listing';
  const R = declarableRemotes(serverJson ? serverJson.remotes : listed.remotes, remoteLabel, { fromListing: !serverJson });
  if (R.remotes) {
    if (R.remotes.length > 16) R.problems.push(`${remoteLabel} names ${R.remotes.length} remotes; a declaration names at most 16`);
    R.remotes.forEach((r, n) => {
      if (r.type !== 'streamable-http' && r.type !== 'sse') R.problems.push(`${remoteLabel} remotes[${n}].type is ${describe(r.type)}; a declaration names streamable-http and sse remotes only`);
    });
  }
  if (R.problems.length) {
    step(6, 'failed', `the remotes of ${remoteLabel} cannot be declared`);
    const advice = noPointer
      ? 'a declaration must name the same remotes as the listing, or check-listing reports listing_mismatch, and the listed version cannot change: publish a new version with a remote a declaration can name, and run prepare for it with --server-json'
      : 'a declaration must name the same remotes as the listing, or check-listing reports listing_mismatch: fix the remote in the server.json of the new version and give that file with --server-json';
    // A URL template is a rule of format 0.2, not something to fix in the URL: say what can be done.
    const template = !R.template ? [] : [
      `a remote that is a URL template cannot be declared in format ${SPEC_ID_02}: a declaration names the concrete URLs a client connects to, and a template names none until its variables are filled in`,
      noPointer
        ? `the listed version keeps its template remote, so no declaration can be made for it. If your server has a concrete endpoint (such as https://mcp.example.com/mcp), publish a new version whose server.json names that URL in "remotes" (no {...} and no "variables"), and run prepare for that version with --server-json <that server.json>`
        : serverJson
          ? 'if your server has a concrete endpoint (such as https://mcp.example.com/mcp), name that URL in "remotes" of the server.json given (no {...} and no "variables"); the version you publish must list that same URL, or check-listing reports listing_mismatch'
          : `if your server has a concrete endpoint (such as https://mcp.example.com/mcp), name that URL in "remotes" of the server.json of ${forVersion} (no {...} and no "variables") and give that file with --server-json <server.json>; ${forVersion} must then be published with that same URL, or check-listing reports listing_mismatch. If every user fills in their own URL, there is no concrete remote to declare`,
    ];
    const otherProblems = R.problems.some((p) => !p.includes('is a URL template'));
    return finish('remotes_not_declarable', [...R.problems, ...template, ...(template.length && !otherProblems ? [] : [advice])]);
  }
  report.notes.push(...R.notes);
  const remotes = R.remotes;
  if (!noPointer && !serverJson) report.notes.push(`the declaration names the remotes of the listing of ${clip(listed.version)} (${remoteWords(remotes)}); the server.json of ${forVersion} must name exactly these, or check-listing reports listing_mismatch after publishing, which cannot be fixed for that version. If they change, give --server-json with the server.json of ${forVersion}`);

  // 4. The tool list.
  let pages;
  if (toolsPages) {
    pages = toolsPages;
    report.tools = { source: 'files', pages: pages.length };
  } else {
    const remote = (remotes || []).find((r) => r.type === 'streamable-http');
    if (!remote) {
      step(4, 'failed', 'no streamable-http remote to read tools/list from');
      return finish('tools_unavailable', [`${remoteLabel} names no streamable-http remote to read tools/list from; save the tools/list result of this build as tools.json (one file per page) and give --tools tools.json`]);
    }
    // --tools-header-env: the headers go only to a streamable-http remote the
    // listing names (the remote of a --server-json that the listing does not
    // name gets none), over https, and fetchToolsList follows no redirect.
    // The listing is outside data (a mistyped name, or a --registry that is
    // not the official one, gives a listing the publisher did not write), so
    // the remote host must also be the domain the namespace names or a host
    // under it, and the listing must come from the official registry (or a
    // loopback one); otherwise the publisher names the host with
    // --tools-header-host.
    const headerNames = toolsHeaders.map((h) => h.name);
    let remoteHost = null;
    let isHttps = false;
    try {
      const u = new URL(remote.url);
      isHttps = u.protocol === 'https:';
      remoteHost = u.hostname.toLowerCase();
    } catch {
      isHttps = false;
    }
    const officialRegistry = registry.loopback || registry.base === DEFAULT_REGISTRY;
    // Why the host needs --tools-header-host, or null.
    const hostNeedsOptIn = remoteHost === null ? null : !hostInNamespace(remoteHost, nsDomain) ? `${remoteHost} is not ${nsDomain} (the domain the namespace names) or a host under it` : !officialRegistry ? `the listing was read from ${registry.base}, not from the official registry (${DEFAULT_REGISTRY})` : null;
    if (toolsHeaders.length) {
      const listedRemotes = declarableRemotes(listed.remotes, 'the listing', { fromListing: true }).remotes || [];
      const inListing = listedRemotes.some((r) => r.type === 'streamable-http' && r.url === remote.url);
      if (!inListing || !isHttps) {
        report.tools = { source: 'remote', remote: remote.url, pages: 0, headers: headerNames, error: 'the headers were not sent' };
        step(4, 'failed', `the headers of --tools-header-env were not sent to ${remote.url}, a remote the listing of ${clip(listed.version)} does not name`);
        return finish('tools_unavailable', [
          `--tools-header-env sends its headers only to a streamable-http remote that the listing of ${clip(listed.version)} names, over https; the remote to read here, ${remote.url} (from ${remoteLabel}), is not one of them (the listing names ${remoteWords(listedRemotes)}), so nothing was sent to it`,
          'save the tools/list result of the new build as tools.json (the "result" object or the whole JSON-RPC response, as the server sent it, without "data:" framing; one file per page) and give --tools tools.json',
        ]);
      }
      if (hostNeedsOptIn && toolsHeaderHost !== remoteHost) {
        report.tools = { source: 'remote', remote: remote.url, pages: 0, headers: headerNames, error: 'the headers were not sent' };
        step(4, 'failed', `the headers of --tools-header-env were not sent to ${remote.url}: ${hostNeedsOptIn}`);
        return finish('tools_unavailable', [
          `the listing names the remote ${remote.url}, and ${hostNeedsOptIn}${toolsHeaderHost !== undefined ? `; --tools-header-host names another host (${toolsHeaderHost})` : ''}. A listing is data from outside (a mistyped server name or another registry gives a listing someone else wrote), so prepare sends your credentials to such a host only when you name it, and nothing was sent`,
          `if ${remoteHost} is your server, run prepare again with --tools-header-host ${hostForCommand(remoteHost)} as well; or save the tools/list result of this build as tools.json (one file per page) and give --tools tools.json`,
        ]);
      }
    }
    const shortValues = toolsHeaders.filter((h) => h.value.length < MIN_HIDDEN_VALUE);
    if (shortValues.length) report.notes.push(`the value of ${shortValues.map((h) => h.name).join(', ')} has fewer than ${MIN_HIDDEN_VALUE} characters, so it is read as a setting, not a secret, and messages from the server are shown as they came`);
    try {
      const got = await readTools(remote.url, { request: net('mcp'), ...(toolsHeaders.length ? { headers: Object.fromEntries(toolsHeaders.map((h) => [h.name, h.value])), redact: hideText } : {}) });
      pages = got.pages;
      report.tools = { source: 'remote', remote: remote.url, protocolVersion: got.protocolVersion, era: got.era, session: got.session, pages: got.pages.length, notes: (got.notes || []).map((n) => hideText(n)), ...(toolsHeaders.length ? { headers: headerNames } : {}) };
      if (toolsHeaders.length) {
        report.notes.push(`--tools-header-env: ${headerNames.join(', ')} (the value${headerNames.length === 1 ? '' : 's'} from ${toolsHeaders.map(varWords).join(', ')}, not shown) ${headerNames.length === 1 ? 'was' : 'were'} sent with the requests to ${remote.url} only, over https; the tool list read with ${headerNames.length === 1 ? 'it' : 'them'} is the one signed`);
      }
    } catch (e) {
      const auth = e && e.kind === 'authorization';
      // 401, or 403 (with or without a Bearer challenge): the server wants the caller to show who it is.
      const refusedBy = (Array.isArray(e && e.requests) ? e.requests : []).find((x) => x && (x.status === 401 || x.status === 403));
      // The server's own text, with the header values hidden.
      const em = hideText(errMessage(e));
      report.tools = { source: 'remote', remote: remote.url, pages: 0, error: em, ...(toolsHeaders.length ? { headers: headerNames } : {}) };
      step(4, 'failed', auth || refusedBy ? `${remote.url} asked for authorization${refusedBy ? ` (HTTP ${refusedBy.status})` : ''}` : `the tool list could not be read from ${remote.url}`);
      const saveLine = 'or save the tools/list result of this build as tools.json (the "result" object or the whole JSON-RPC response, as the server sent it, without "data:" framing; one file per page, in order) and give --tools tools.json';
      const save = 'save the tools/list result of this build as tools.json (one file per page, as the server sent it) and give --tools tools.json';
      if (auth || refusedBy) {
        const status = refusedBy ? `HTTP ${refusedBy.status}` : 'a request for authorization';
        if (toolsHeaders.length) {
          return finish('tools_unavailable', [
            `the remote ${remote.url} (from ${remoteLabel}) answered with ${status} also with the header${headerNames.length === 1 ? '' : 's'} ${headerNames.join(', ')} sent from ${toolsHeaders.map(varWords).join(', ')} (${em}), so it asked for authorization again`,
            `check that ${toolsHeaders.map(varWords).join(' and ')} ${toolsHeaders.length === 1 ? 'holds' : 'hold'} the whole header value the server expects (for Authorization usually "Bearer <token>", with a token that is still valid), and that the header name is the one the server reads; then run prepare again`,
            saveLine,
          ]);
        }
        const declared = declaredHeaderNames((serverJson ? serverJson.remotes : listed.remotes || []).find((r) => isObj(r) && r.type === 'streamable-http'));
        const names = declared.length ? declared : ['Authorization'];
        const example = names.map((n) => `--tools-header-env "${n}=MCP_TOOLS_${n === 'Authorization' ? 'AUTH' : 'HEADER'}"`).slice(0, 1)[0];
        const hostWords = hostNeedsOptIn ? ` Since ${hostNeedsOptIn}, also give --tools-header-host ${hostForCommand(remoteHost)} once you have checked that it is your server.` : '';
        return finish('tools_unavailable', [
          `the remote ${remote.url} (from ${remoteLabel}) answered tools/list with ${status}, so it asked for authorization${auth && refusedBy ? '' : ` (${em})`}; prepare sends no credentials unless you name them`,
          `if this is your server, let prepare read it with your own credentials: put the header value in an environment variable and name the header and the variable, for example ${example}${names[0] === 'Authorization' ? ' with MCP_TOOLS_AUTH set to "Bearer <your token>"' : ` with MCP_TOOLS_HEADER set to the value of ${names[0]}`}${declared.length ? ` (${remoteLabel} declares the header${declared.length === 1 ? '' : 's'} ${declared.join(', ')} for this remote)` : ''}. The option can be given once per header. The value is sent only to ${remote.url}, over https, and is not printed or written.${hostWords}`,
          saveLine,
        ]);
      }
      return finish('tools_unavailable', [`the tool list could not be read from ${remote.url} (from ${remoteLabel}): ${em}; ${save}`]);
    }
    if (!noPointer) report.notes.push(`the tool list was read from the server running now at ${remote.url}; version ${forVersion} must answer tools/list with the same list, so if it changes the tools, give --tools with the tools/list result of that build instead`);
  }
  const digests = digestsForSigning(pages);
  if (digests.problem) {
    step(4, 'failed', 'the tool list cannot be signed');
    return finish('tools_unavailable', [digests.problem.message.replace(/^tools file: /, 'tool list: '), ...(digests.problem.lines || [])]);
  }
  report.tools = { ...report.tools, contract: digests.value.contract, extras: digests.value.extras };
  report.notes.push(...digests.notes);
  const T = report.tools;
  const toolSource = T.source === 'files'
    ? `${plural(T.pages, 'page')} given with --tools`
    : `read ${plural(T.pages, 'page')} of tools/list from ${T.remote} (MCP protocol version ${T.protocolVersion}, ${T.era === 'modern' ? 'no session' : `initialize flow${T.session ? ', with a session' : ''}`})`;
  step(4, 'ok', `${toolSource}; contract digest ${T.contract}, extras digest ${T.extras ?? 'null (no tool has extras)'}`);

  // The HISTOR tool sets member (--histor-tool-sets), from the digest signed here.
  // A member of that name in the listing (or the server.json given) is merged
  // with it, not replaced: HISTOR marks withdrawn a set the member stops naming.
  let histor = null;
  let historMerge = null;
  if (historOn) {
    const h = buildHistor(digests.value.contract, digests.toolCount);
    if (h.problem) throw new PrepareError(`--histor-tool-sets: ${h.problem}; nothing was signed or written`);
    const srcMeta = serverJson ? serverJson._meta : listed._meta;
    const srcBlock = isObj(srcMeta) && isObj(srcMeta[PUBLISHER_META_KEY]) ? srcMeta[PUBLISHER_META_KEY] : null;
    const srcName = serverJson ? 'the server.json given' : `the listing of ${clip(listed.version)}`;
    historMerge = mergeHistorMember(h.value, srcBlock && Object.hasOwn(srcBlock, HISTOR_MEMBER) ? srcBlock[HISTOR_MEMBER] : undefined, name);
    if (historMerge.overflow.length) {
      throw new PrepareError(`--histor-tool-sets: ${srcName} already has a "${HISTOR_MEMBER}" member with ${plural(historMerge.keptSets.length + historMerge.overflow.length, 'set')} HISTOR reads, and HISTOR reads at most ${HISTOR_MAX_SETS} there. Adding the set signed here would drop these sets, which HISTOR would then mark withdrawn:`, [
        ...historMerge.overflow.map((d) => {
          const w = existingSetWhen(srcBlock[HISTOR_MEMBER], d);
          return w === null ? d : `${d} (when: ${JSON.stringify(clip(w, 200))})`;
        }),
        `Remove a set from the member${serverJson ? ' in the server.json given' : ' (give the server.json of the new version with --server-json)'}, or move sets into the file its "url" names, then run prepare again; nothing was signed or written`,
      ]);
    }
    histor = historMerge.value;
    report.historToolSets = {
      member: HISTOR_MEMBER,
      value: histor,
      bytes: Buffer.byteLength(JSON.stringify(histor), 'utf8'),
      existing: historMerge.action === 'added' ? null : { source: srcName, action: historMerge.action, keptSets: historMerge.keptSets, keptWhen: historMerge.keptWhen, keptUrl: historMerge.url === undefined ? null : historMerge.url, urlRefused: historMerge.urlRefused, leftOut: historMerge.leftOut },
      toolCount: digests.toolCount,
      check: null,
      problems: [],
      watcher: HISTOR_URL,
      definedBy: HISTOR_DOC,
    };
    report.notes.push(...h.notes);
  }

  // 5. The declaration this one follows.
  const folderFor = (host) => `https://${host}/.well-known/addon-declaration/${name}/`;
  let host = found.domain; // where the files are served
  let prev = null; // { hash, bytes, decl, source }
  // What latest.json answered when it was read as "no previous declaration"
  // because of a redirect or a host with no address: NEXT_STEPS.txt says so.
  let folderWarning = null; // { result, url }
  // Moves the key location to that of the previous declaration when the same
  // key is published there, so the link does not cross a change of key location.
  // want: the key ids that must be published there (the signing key, or for an
  // unsigned run the key the new declaration would be signed with).
  const followKeyLocation = async (d, want) => {
    const loc = d.key;
    if (loc.method === found.method && loc.domain === found.domain) return true;
    if (method && method !== loc.method) return false;
    if (namespaceProblem(name, loc.domain, loc.method)) return false;
    const r = await keysAt(loc.method, loc.domain);
    if (!r.keys.some((k) => want.includes(k.id))) return false;
    report.notes.push(`the key location follows the previous declaration: the ${loc.method} method at ${loc.domain}, where the same key is published, in place of the ${found.method} method at ${found.domain}, so the link does not cross a change of key location`);
    found = { method: loc.method, domain: loc.domain, location: where(loc.method, loc.domain), keys: r.keys };
    setKeyRecord();
    return true;
  };
  if (noPointer) {
    // As check-listing reads the listing today: the declaration in force is the one to follow.
    const cl = await checkListing({ name, version: listingVersion, registry, now, request: net('check-listing read'), keyLookup: lookup });
    const R2 = cl.report;
    const fromCache = (url) => (cache.get(url) || {}).body;
    let source = null;
    if (cl.state === 'verified' || (cl.state === 'expired' && R2.declaration && R2.declaration.state === 'expired')) source = { url: R2.pointer.url, hash: R2.pointer.hash, what: 'the declaration the listing names' };
    else if (cl.state === 'verified_newer_declaration' && R2.inForce) source = { url: R2.inForce.url, hash: R2.inForce.hash, what: `the newer declaration in force (${R2.inForce.source})` };
    if (!source || !fromCache(source.url)) {
      step(5, 'failed', `check-listing on the listing gives ${cl.state}`);
      const why = cl.state === 'no_declaration'
        ? 'the listing names no declaration, so check-listing stops at no_declaration and reads no other file; a declaration for this version cannot be found that way. Give a new --for-version without --no-pointer, so the new version carries a pointer'
        : `a declaration found through versions/<version>.json and latest.json is put in force only after the declaration the listing names verifies (or has only expired), and check-listing on this listing gives ${cl.state}${cl.reasons.length ? `: ${clip(cl.reasons.join('; '), 400)}` : ''}`;
      return finish('version_not_usable', [why]);
    }
    const bytes = fromCache(source.url);
    const d = parseDeclarationText(bytes);
    prev = { hash: source.hash, bytes, decl: d };
    // check-listing reads newer declarations in the folder of the pointer URL.
    host = new URL(R2.pointer.url).hostname;
    report.previous = { source: source.url, hash: source.hash, format: d.spec, version: d.version, state: cl.state === 'expired' ? 'expired' : 'valid', linked: true, checkListingState: cl.state };
    if (signing && (d.key.alg !== key.alg || d.key.id !== key.public.id)) {
      step(5, 'failed', `${source.what} is signed under another key`);
      return finish('version_not_usable', [`${source.what} is signed under ${d.key.alg} ${d.key.id}, and the private key given is ${key.alg} ${key.public.id}; check-listing sets a newer declaration aside when its history crosses a change of key (SPEC.md section 10), so this one would not be put in force. Sign with the key of ${source.what}, or publish a new version with a pointer`]);
    }
    if (!(await followKeyLocation(d, [signing ? key.public.id : d.key.id]))) {
      step(5, 'failed', `${source.what} is signed by the ${d.key.method} method at ${d.key.domain}, another key location`);
      return finish('version_not_usable', [`${source.what} names its key by the ${d.key.method} method at ${d.key.domain}, and this run would sign by the ${found.method} method at ${found.domain}; check-listing sets a newer declaration aside when its history crosses a change of key location (SPEC.md section 8a), so this one would not be put in force. ${method && method !== d.key.method ? `Leave out --method, or give --method ${d.key.method}` : `Publish the same key by the ${d.key.method} method at ${d.key.domain}, or publish a new version with a pointer`}`]);
    }
    if (!signing && found.keys.every((k) => k.id !== d.key.id)) report.notes.push(`${source.what} is signed under ${d.key.alg} ${d.key.id}, which is not among the published records; check-listing puts the new declaration in force only when it is signed under that same key`);
    step(5, 'ok', `${source.what}, ${source.hash} (${d.spec}${cl.state === 'expired' ? ', expired' : ''}), is followed: check-listing gives ${cl.state} today, and the new declaration names it as previous`);
  } else if (noPrevious) {
    // The publisher accepts a fresh start: nothing is read, and no previous is named.
    report.previous = { source: null, hash: null, linked: false, result: 'not_read', reason: '--no-previous' };
    step(5, 'skipped', '--no-previous was given: no previous declaration is read, and the new declaration names none');
    report.notes.push('--no-previous was given: the new declaration names no previous, so its history starts here, and verifiers see no link to a declaration before it');
  } else {
    const latestUrl = `${folderFor(host)}latest.json`;
    const listedWords = `the declaration the listing of ${clip(listed.version)} names`;
    const readDecl = async (purpose, url) => {
      try {
        return { res: await net(purpose)(url, { method: 'GET', headers: { Accept: 'application/json' }, maxBytes: MAX_DECLARATION_BYTES }) };
      } catch (e) {
        return { error: e && e.tooLarge ? `larger than ${MAX_DECLARATION_BYTES} bytes` : errMessage(e), cause: isObj(e) || e instanceof Error ? e : {} };
      }
    };
    // The pointer in the listing, and whether check-listing would fetch the declaration it names.
    const pm = isObj(listed._meta) && isObj(listed._meta[PUBLISHER_META_KEY]) ? listed._meta[PUBLISHER_META_KEY][POINTER_MEMBER] : undefined;
    // A listing that names no declaration (no pointer member at all): an answer
    // at latest.json that is definitely not a declaration means that there is
    // no previous declaration (see the latest.json read below).
    const namesNone = pm === undefined;
    const unreadable = (what, why) => {
      step(5, 'failed', `${what}: ${why}`);
      return finish('previous_unreadable', [
        `${what} ${why}. The new declaration would name no previous, and once its pointer is in a published version that gap in the history stays; run prepare again when it can be read`,
        ...(namesNone && what === latestUrl ? [`the listing of ${clip(listed.version)} names no declaration. If you have not served a declaration at ${latestUrl} before, give --no-previous to make this the first one`] : []),
      ]);
    };
    const pointerOk = pm !== undefined && isObj(pm) && typeof pm.url === 'string' && typeof pm.hash === 'string' && HASH_RE.test(pm.hash) && isHttpsUrl(pm.url) && pointerHosts(ns).includes(new URL(pm.url).hostname) && pm.url === `${folderFor(new URL(pm.url).hostname)}by-hash/${pm.hash.slice('sha256:'.length)}.json`;
    // Candidates in order: latest.json, then the declaration the listing names.
    // The first one that can be linked is the previous declaration, except
    // when both can be linked and differ: then the one that follows the other
    // is linked (decided by walking their "previous" links), and two that do
    // not follow one another stop the run.
    let linked = null; // { candidate, ex }
    let ancestry = null; // what was decided between latest.json and the named declaration
    const notLinked = []; // { what, source, hash, result, reason }
    const examine = async (candidate) => {
      const ex = await examinePrevious(candidate.bytes, candidate.expectHash);
      if (ex.lookupFailed) {
        step(5, 'failed', `the key lookup for ${candidate.what} could not be completed`);
        return { stop: finish('key_record_lookup_failed', [`the key lookup for ${candidate.what} (the ${ex.decl.key.method} method at ${ex.decl.key.domain}) could not be completed: ${clip(ex.reason)}. Without it the declaration cannot be checked before it is linked as previous; run prepare again later`]) };
      }
      if (!ex.linked) {
        notLinked.push({ what: candidate.what, source: candidate.source, hash: ex.hash ?? null, result: ex.result, reason: ex.reason });
        report.notes.push(`${candidate.what} is not linked as previous: ${ex.reason}`);
      }
      return { ex };
    };
    // Reads and examines the declaration the listing names. Returns { stop } or { ex } (ex null when it is not served).
    const examinePointer = async () => {
      const P = await readDecl('declaration named by the listing', pm.url);
      if (P.error) return { stop: unreadable(pm.url, `could not be read (${P.error})`) };
      if (P.res.status === 200) {
        const r = await examine({ bytes: P.res.body, source: pm.url, what: listedWords, expectHash: pm.hash });
        return r.stop ? r : { ex: r.ex, candidate: { bytes: P.res.body, source: pm.url, what: listedWords } };
      }
      if (P.res.status !== 404 && P.res.status !== 410) return { stop: unreadable(pm.url, `answered HTTP ${P.res.status}`) };
      const reason = `it is not served at ${pm.url} (HTTP ${P.res.status})`;
      notLinked.push({ what: listedWords, source: pm.url, hash: pm.hash, result: 'absent', reason });
      report.notes.push(`${listedWords} is not served at ${pm.url} (HTTP ${P.res.status})`);
      return { ex: null };
    };
    // When the listing names no declaration, these answers at latest.json are
    // read as "no previous declaration" (firstWhy), because a declaration
    // check-listing reads cannot be behind them: a permanent redirect (301, 308;
    // check-listing follows no redirect) to a place outside the declaration
    // folders, a 404 or 410, a body over the 16384 bytes a declaration may
    // have (with status 200, 404, 410, 301 or 308), a body that is not a
    // declaration (as before), and a host that has no address in DNS, which
    // the name servers confirm (an ENOTFOUND from the system lookup alone can
    // be a resolver outage). The listing read is the newest version only: a
    // publisher whose newest version was published without the pointer an
    // earlier version carried has a history, and a WAF page, a redirect or a
    // spoofed DNS answer at latest.json must not start a second one. So before
    // any of the new answers is taken as "no previous declaration", the
    // registry's list of versions of this name is read once, and a version
    // that names a declaration stops the run. A timeout, a connection or TLS
    // error, a 5xx, a temporary redirect (302, 303, 307), a permanent redirect
    // into a declaration folder and any other status stay
    // previous_unreadable. A listing that names a declaration (also a
    // malformed pointer) keeps the rules it had.
    const permanentRedirect = (s) => s === 301 || s === 308;
    let firstWhy = null; // { result, seen }
    // A permanent redirect into a declaration folder (this one on any host, or
    // a by-hash file) may lead to a declaration the publisher serves there, so
    // it is not read as "no previous declaration". Returns a finished result, or null.
    const redirectIntoFolder = (status, loc) => {
      if (loc === null) return null;
      let target;
      try {
        target = new URL(loc, latestUrl);
      } catch {
        step(5, 'failed', `${latestUrl}: answered HTTP ${status}, a permanent redirect to a Location that is not a URL`);
        return finish('previous_unreadable', [`${latestUrl} answered HTTP ${status}, a permanent redirect to a Location that is not a URL (${clip(loc, 200)}), so prepare cannot tell where it leads. Serve latest.json with HTTP status 200 and no redirect and run prepare again; if no declaration was served there before, give --no-previous to make this the first one`]);
      }
      let decoded = target.pathname;
      try {
        decoded = decodeURIComponent(target.pathname);
      } catch {
        decoded = target.pathname;
      }
      const inFolder = [target.pathname, decoded].some((p) => p.toLowerCase().startsWith('/.well-known/addon-declaration/'));
      if (!inFolder) return null;
      step(5, 'failed', `${latestUrl}: answered HTTP ${status}, a permanent redirect into a declaration folder (${clip(target.href, 200)})`);
      return finish('previous_unreadable', [
        `${latestUrl} answered HTTP ${status}, a permanent redirect to ${clip(target.href, 200)}, which is inside a declaration folder, so a declaration may be served behind it. check-listing follows no redirect, so it reads no declaration at latest.json, and prepare does not follow one either`,
        `serve latest.json itself with HTTP status 200 and no redirect (a copy of your newest declaration) and run prepare again, so the new declaration follows it; if no declaration was served there before, give --no-previous to make this the first one`,
      ]);
    };
    // Reads the registry's list of versions of this name. Returns { versions }
    // when no version names a declaration, or { stop }.
    const historyCheck = async () => {
      const url = `${registry.base}${REGISTRY_SERVER_PATH}/${encodePathSegment(name)}/versions`;
      const unsure = (why) => {
        step(5, 'failed', `latest.json answered ${firstWhy.seen}; the registry's list of versions of ${name} could not be read (${why})`);
        return finish('previous_unreadable', [
          `${latestUrl} answered ${firstWhy.seen}, and the listing of ${clip(listed.version)} names no declaration. Before that is taken as no previous declaration, prepare reads the registry's list of versions of ${name} (${url}), since an earlier version may name a declaration that the newest one dropped, and that list could not be read: ${why}`,
          `run prepare again later; if no version of ${name} was published with a pointer to a declaration and no declaration was served at ${latestUrl}, give --no-previous to make this the first one`,
        ]);
      };
      let res;
      try {
        res = await net('registry list of versions')(url, { method: 'GET', headers: { Accept: 'application/json' }, maxBytes: MAX_REGISTRY_RESPONSE, allowLoopbackHttp: registry.loopback });
      } catch (e) {
        return { stop: unsure(e && e.tooLarge ? `the answer is larger than ${MAX_REGISTRY_RESPONSE} bytes` : `the request failed: ${errMessage(e)}`) };
      }
      if (res.status !== 200) return { stop: unsure(`the registry answered HTTP ${res.status}`) };
      let body;
      try {
        body = parseStrict(decodeUtf8Strict(res.body));
      } catch {
        return { stop: unsure('the answer is not strict JSON') };
      }
      const list = isObj(body) && Array.isArray(body.servers) ? body.servers : null;
      if (!list) return { stop: unsure('the answer has no "servers" list') };
      if (isObj(body.metadata) && typeof body.metadata.nextCursor === 'string' && body.metadata.nextCursor !== '') return { stop: unsure('the list has more than one page, and prepare reads one') };
      const entries = list.map((x) => (isObj(x) && isObj(x.server) ? x.server : null));
      if (entries.some((s) => s === null || s.name !== name)) return { stop: unsure(`an entry of the list is not a listing of ${name}`) };
      if (!entries.some((s) => s.version === listed.version)) return { stop: unsure(`the list does not hold the listed version ${clip(listed.version)}`) };
      const named = entries.filter((s) => isObj(s._meta) && isObj(s._meta[PUBLISHER_META_KEY]) && s._meta[PUBLISHER_META_KEY][POINTER_MEMBER] !== undefined);
      if (named.length) {
        const versions = named.map((s) => (typeof s.version === 'string' ? clip(s.version) : '(no version)'));
        const p0 = named[0]._meta[PUBLISHER_META_KEY][POINTER_MEMBER];
        const where0 = isObj(p0) && typeof p0.url === 'string' ? ` (${clip(p0.url, 200)})` : '';
        report.previous = { source: url, hash: null, linked: false, result: 'not_linkable', reason: `latest.json answered ${firstWhy.seen}; the registry lists ${versions.length === 1 ? 'a version' : 'versions'} of ${name} that ${versions.length === 1 ? 'names' : 'name'} a declaration (${versions.slice(0, 8).join(', ')})` };
        step(5, 'failed', `latest.json answered ${firstWhy.seen}, and the registry lists ${versions.length === 1 ? 'version' : 'versions'} ${versions.slice(0, 8).join(', ')} of ${name} with a pointer to a declaration`);
        return {
          stop: finish('previous_not_linkable', [
            `${latestUrl} answered ${firstWhy.seen}, and the listing of ${clip(listed.version)} names no declaration, but ${versions.length === 1 ? 'version' : 'versions'} ${versions.slice(0, 8).join(', ')} of ${name} ${versions.length === 1 ? 'names' : 'name'} one${where0}: a history of declarations exists, and the newest version was published without its pointer`,
            `the new declaration would name no previous, and once its pointer is in a published version that gap in the history stays. Serve your newest declaration at ${latestUrl} with HTTP status 200 and no redirect (and at its by-hash URL) and run prepare again, so the new one follows it, or give --no-previous to start a new history on purpose`,
          ]),
        };
      }
      return { versions: entries.length, url };
    };
    // Where the publisher serves the files of this run, said when latest.json held no declaration.
    const serveThere = (result) => `The files this run writes for upload are to be served in ${folderFor(host)}, each with HTTP status 200 and no redirect${result === 'redirect' ? ', so that redirect has to stop for these paths' : result === 'host_not_found' ? `, so ${host} needs an address in DNS first` : (result === 'too_large' || result === 'body') && writeLatest ? '; the latest.json of this run replaces what is served there now' : ''}. If you served a declaration at that address before, do not use the files of this run: serve that declaration there again and run prepare again, so the new one follows it`;
    const L5 = await readDecl('existing latest.json', latestUrl);
    if (L5.error) {
      const c = L5.cause || {};
      if (namesNone && c.tooLarge && (c.status === 200 || c.status === 404 || c.status === 410 || permanentRedirect(c.status))) {
        if (permanentRedirect(c.status)) {
          const stop = redirectIntoFolder(c.status, typeof c.location === 'string' ? c.location : null);
          if (stop) return stop;
        }
        firstWhy = { result: c.status === 200 ? 'too_large' : permanentRedirect(c.status) ? 'redirect' : 'absent', seen: `HTTP ${c.status} with a body larger than ${MAX_DECLARATION_BYTES} bytes, the most a declaration may have, so it is not a declaration` };
      } else if (namesNone && c.hostLookupCode === 'ENOTFOUND') {
        const entry = { purpose: 'host address check (dns)', method: 'A/AAAA', url: `dns:${host} (A, AAAA)`, domain: host, status: null };
        report.fetched.push(entry);
        let h;
        try {
          h = await hostLookup(host);
        } catch (e) {
          h = { noAddress: false, detail: `the name servers could not be asked (${errMessage(e)})` };
        }
        if (h && h.noAddress === true) {
          entry.answered = true;
          firstWhy = { result: 'host_not_found', seen: `nothing: the host ${host} has no address in DNS (the system lookup gave ENOTFOUND, and ${h && h.detail ? h.detail : 'the name servers gave no address'})` };
        } else {
          entry.error = h && h.detail ? h.detail : 'no answer';
          return unreadable(latestUrl, `could not be read (${L5.error}; ${entry.error}, so the host may have an address and this may be a passing fault)`);
        }
      } else return unreadable(latestUrl, `could not be read (${L5.error})`);
    } else if (namesNone && permanentRedirect(L5.res.status)) {
      const loc = L5.res.headers && typeof L5.res.headers.location === 'string' ? L5.res.headers.location : null;
      const stop = redirectIntoFolder(L5.res.status, loc);
      if (stop) return stop;
      firstWhy = { result: 'redirect', seen: `HTTP ${L5.res.status}, a permanent redirect${loc ? ` to ${clip(loc, 200)}` : ''}, which check-listing does not follow, so no declaration is read there` };
    }
    if (firstWhy) {
      const h = await historyCheck();
      if (h.stop) return h.stop;
      firstWhy.versions = h.versions;
      if (firstWhy.result === 'redirect' || firstWhy.result === 'host_not_found') folderWarning = { result: firstWhy.result, url: latestUrl, host };
    }
    const latestAbsent = !L5.error && (L5.res.status === 404 || L5.res.status === 410);
    if (firstWhy) {
      // nothing more to read at latest.json
    } else if (L5.res.status === 200) {
      const latestCandidate = { bytes: L5.res.body, source: latestUrl, what: 'latest.json' };
      const r = await examine(latestCandidate);
      if (r.stop) return r.stop;
      if (r.ex.linked) linked = { candidate: latestCandidate, ex: r.ex };
    } else if (!latestAbsent) return unreadable(latestUrl, `answered HTTP ${L5.res.status}`);
    if (linked && pointerOk && linked.ex.hash !== pm.hash) {
      // latest.json can be linked, and the listing names another declaration:
      // the one that follows the other is the newer, and is linked.
      const L = linked;
      const P = await examinePointer();
      if (P.stop) return P.stop;
      const pointerWhy = P.ex ? P.ex.reason : notLinked[notLinked.length - 1].reason;
      if (!P.ex || !P.ex.linked) {
        report.previous = { source: pm.url, hash: null, linked: false, result: 'not_linkable', reason: `${listedWords}: ${pointerWhy}`, tried: notLinked, latest: { source: latestUrl, hash: L.ex.hash } };
        step(5, 'failed', `latest.json holds ${L.ex.hash}, and ${listedWords}, ${pm.hash}, cannot be linked as previous (read: ${latestUrl}, ${pm.url})`);
        return finish('previous_not_linkable', [
          `latest.json (${latestUrl}) holds ${L.ex.hash}, which could be linked, but the listing of ${clip(listed.version)} names another declaration, ${pm.hash}`,
          `${listedWords} (${pm.url}) cannot be linked as previous: ${pointerWhy}`,
          `without the declaration the listing names, prepare cannot tell whether latest.json follows it, and linking latest.json alone could leave the history the listing names behind. Serve ${listedWords} at its by-hash URL and run prepare again, or give --no-previous to start a new history on purpose`,
        ]);
      }
      const A = { hash: L.ex.hash, bytes: L.candidate.bytes, decl: L.ex.decl, url: latestUrl };
      const B = { hash: pm.hash, bytes: P.candidate.bytes, decl: P.ex.decl, url: pm.url };
      const rel = await historyBetween(A, B, folderFor(host), folderFor(new URL(pm.url).hostname));
      if (rel.unreadable) return unreadable(rel.unreadable.url, rel.unreadable.why);
      const readWords = [latestUrl, pm.url, ...rel.read].join(', ');
      ancestry = { latest: A.hash, named: B.hash, relation: rel.relation, read: [latestUrl, pm.url, ...rel.read] };
      if (rel.relation === 'latest_follows') {
        ancestry.words = `latest.json follows ${listedWords} (${pm.hash}) in ${plural(rel.links, 'link')} (read: ${readWords})`;
      } else if (rel.relation === 'named_follows') {
        linked = { candidate: P.candidate, ex: P.ex };
        ancestry.words = `${listedWords} follows latest.json (${A.hash}) in ${plural(rel.links, 'link')}, so latest.json is behind (read: ${readWords})`;
        report.notes.push(`latest.json (${latestUrl}) is behind: it holds ${A.hash}, and ${listedWords}, ${pm.hash}, follows it, so the new declaration follows the one the listing names${writeLatest ? ', and the latest.json written by this run replaces it' : '; this run writes no latest.json, so it stays behind until a later declaration replaces it'}`);
      } else {
        report.previous = { source: pm.url, hash: null, linked: false, result: 'not_linkable', reason: 'latest.json and the declaration the listing names do not follow one another', tried: notLinked, ancestry };
        step(5, 'failed', `latest.json holds ${A.hash} and ${listedWords} is ${pm.hash}, and neither follows the other within ${MAX_CHAIN_LINKS} links (read: ${readWords})`);
        return finish('previous_not_linkable', [
          `latest.json (${latestUrl}) holds ${A.hash}: ${rel.why.latest}`,
          `${listedWords} (${pm.url}) is ${pm.hash}: ${rel.why.named}`,
          `the two declarations do not follow one another within ${MAX_CHAIN_LINKS} links (a fork in the history, or a history longer than prepare reads), so linking either one would leave the other history behind. Serve at latest.json a declaration that follows the one the listing names (or the one the listing names itself) and run prepare again, or give --no-previous to start a new history on purpose`,
        ]);
      }
    } else if (!linked && pm !== undefined) {
      // latest.json is absent or cannot be linked: the declaration the pointer of the listing names is the next candidate.
      if (!pointerOk) report.notes.push(`the pointer in the listing of ${clip(listed.version)} is not a by-hash URL check-listing would fetch, so it is not read`);
      else {
        const P = await examinePointer();
        if (P.stop) return P.stop;
        if (P.ex && P.ex.linked) linked = { candidate: P.candidate, ex: P.ex };
      }
    }
    if (linked) {
      const { candidate, ex } = linked;
      prev = { hash: ex.hash, bytes: candidate.bytes, decl: ex.decl };
      report.previous = { source: candidate.source, hash: ex.hash, format: ex.decl.spec, version: ex.decl.version, state: ex.state, linked: true, signatureChecked: ex.state !== 'key_not_found', ...(ancestry ? { ancestry: { latest: ancestry.latest, named: ancestry.named, relation: ancestry.relation, read: ancestry.read } } : {}) };
      const how = ex.state === 'expired' ? 'has expired but verifies' : ex.state === 'valid' ? 'verifies' : 'is linked without a signature check, because its key is not published now';
      step(5, 'ok', `${candidate.what} holds ${ex.hash} (${ex.decl.spec}, version ${clip(ex.decl.version)}), which ${how}${ex.state === 'key_not_found' ? '' : ' with the published key'}; the new declaration names it as previous${notLinked.length ? ` (${notLinked.map((x) => x.what).join(', ')} could not be linked)` : ''}${ancestry ? `; ${ancestry.words}` : ''}`);
      if (ex.state === 'expired') report.notes.push(`the declaration in ${candidate.what} expired at ${ex.decl.expiresAt}; it is still linked as previous, which keeps the history`);
      if (ex.state === 'key_not_found') report.notes.push(`${candidate.what} is signed under ${ex.decl.key.alg} ${ex.decl.key.id} (the ${ex.decl.key.method} method at ${ex.decl.key.domain}), which is not published now, as after a rotation (SPEC.md section 10); it parses, names this server and was issued before now, so it is linked as previous and its signature is not checked (SPEC.md section 7). Verifiers report the link as a change of key`);
      await followKeyLocation(ex.decl, signing ? [key.public.id] : found.keys.map((k) => k.id));
      if (ex.decl.key.method !== found.method || ex.decl.key.domain !== found.domain) report.notes.push(`the previous declaration names its key by the ${ex.decl.key.method} method at ${ex.decl.key.domain}, the new one by the ${found.method} method at ${found.domain}${method ? ` (--method ${method} was given)` : ''}: the link crosses a change of key location, which verifiers report, and check-listing does not put a newer declaration in force across it`);
      if (signing && (ex.decl.key.alg !== key.alg || ex.decl.key.id !== key.public.id)) report.notes.push(`the previous declaration is signed under ${ex.decl.key.alg} ${ex.decl.key.id}, the new one under ${key.alg} ${key.public.id}: the link crosses a change of key, which verifiers report (SPEC.md section 10)`);
    } else if (pointerOk) {
      // The listing names a declaration and nothing can be linked: a new
      // declaration with no previous would cut the history, so the run stops.
      report.previous = { source: pm.url, hash: null, linked: false, result: 'not_linkable', reason: notLinked.map((x) => `${x.what}: ${x.reason}`).join('; '), tried: notLinked };
      step(5, 'failed', `the listing names a declaration, and ${latestAbsent ? `latest.json is absent (HTTP ${L5.res.status}) and ` : ''}${notLinked.map((x) => x.what).join(' and ')} cannot be linked as previous`);
      return finish('previous_not_linkable', [
        ...(latestAbsent ? [`latest.json (${latestUrl}) is absent (HTTP ${L5.res.status})`] : []),
        ...notLinked.map((x) => `${x.what} (${x.source}) cannot be linked as previous: ${x.reason}`),
        `the listing of ${clip(listed.version)} names a declaration, so the new one would follow it; with no previous the history ends there, and once the new pointer is in a published version that gap stays. Serve ${listedWords} at its by-hash URL (or a declaration for this server that verifies at latest.json) and run prepare again, or give --no-previous to start a new history on purpose`,
      ]);
    } else if (firstWhy) {
      report.previous = { source: latestUrl, hash: null, linked: false, result: firstWhy.result, reason: firstWhy.seen };
      const listWords = `the registry lists ${plural(firstWhy.versions, 'version')} of ${name}, and none names a declaration`;
      step(5, 'ok', `latest.json answered ${firstWhy.seen}; the listing names no declaration and ${listWords}, so there is no previous declaration, and the new declaration names none`);
      report.notes.push(`${latestUrl} answered ${firstWhy.seen}. The listing of ${clip(listed.version)} names no declaration and ${listWords}, so this run makes the first declaration for this server. ${serveThere(firstWhy.result)}`);
    } else if (notLinked.length) {
      const x = notLinked[0];
      if (namesNone && x.source === latestUrl) {
        // A declaration for this name that fails its checks (a signature that
        // does not verify, issued later than now, ...) is not "no previous
        // declaration": one is there, so the run stops.
        if (x.result !== 'invalid') {
          report.previous = { source: x.source, hash: x.hash, linked: false, result: x.result, reason: x.reason };
          step(5, 'failed', `latest.json holds a declaration for ${name} that cannot be linked as previous (${x.reason})`);
          return finish('previous_not_linkable', [
            `${latestUrl} holds a declaration for ${name}${x.hash ? `, ${x.hash},` : ''} that cannot be linked as previous: ${x.reason}`,
            `the listing of ${clip(listed.version)} names no declaration, but a declaration for this server is served there, so the new one would leave it behind. Serve a declaration for ${name} that verifies at latest.json (or wait until its issuedAt has passed, or check the clock and --now) and run prepare again, or give --no-previous to start a new history on purpose`,
          ]);
        }
        // A body cut short (a close delimited answer that ended early) can
        // look like a file that is not a declaration although it began as one.
        const head = Buffer.isBuffer(L5.res.body) ? L5.res.body.toString('utf8').replace(/^﻿/, '').trimStart() : '';
        if (!x.hash && x.reason.startsWith('not a declaration:') && head.startsWith('{') && /"spec"\s*:\s*"addon-declaration\//.test(head)) {
          return unreadable(latestUrl, `answered HTTP 200 with a body that begins as a declaration but does not parse (${x.reason}), as when an answer is cut short`);
        }
      }
      report.previous = { source: x.source, hash: x.hash, linked: false, result: x.result, reason: x.reason };
      step(5, 'ok', `${x.what} holds a file that is not linked (${x.reason})${pm !== undefined ? ', and the pointer in the listing is not one check-listing would fetch' : ', and the listing names no declaration'}; the new declaration names no previous`);
      if (namesNone && x.source === latestUrl) report.notes.push(`${latestUrl} answered HTTP 200 with a file that is not linked as previous (${x.reason}). The listing of ${clip(listed.version)} names no declaration, so this run makes the first declaration for this server. ${serveThere('body')}`);
    } else {
      report.previous = { source: latestUrl, hash: null, linked: false, result: 'absent', reason: `HTTP ${L5.res.status}` };
      step(5, 'ok', `latest.json is absent (HTTP ${L5.res.status})${pm !== undefined ? ', and the pointer in the listing is not one check-listing would fetch' : ' and the listing names no declaration'}; the new declaration names no previous`);
      if (namesNone) report.notes.push(`${latestUrl} answered HTTP ${L5.res.status}. The listing of ${clip(listed.version)} names no declaration, so this run makes the first declaration for this server. ${serveThere('absent')}`);
    }
  }
  const folderUrl = folderFor(host);
  // The history is read from by-hash files (SPEC.md section 8), so the
  // previous declaration has to be served at its own by-hash path too.
  const siteRel = `site/.well-known/addon-declaration/${nsPart}/${serverPart}/`;
  const extraUploads = [];
  if (prev) {
    const pHex = prev.hash.slice('sha256:'.length);
    const pUrl = `${folderUrl}by-hash/${pHex}.json`;
    let pr = null;
    let perr = null;
    try {
      pr = await net('previous declaration (by hash)')(pUrl, { method: 'GET', headers: { Accept: 'application/json' }, maxBytes: MAX_DECLARATION_BYTES });
    } catch (e) {
      perr = e && e.tooLarge ? `larger than ${MAX_DECLARATION_BYTES} bytes` : errMessage(e);
    }
    if (pr && pr.status === 200) {
      let same = false;
      try {
        same = declarationHash(parseDeclarationText(pr.body)) === prev.hash;
      } catch {
        same = false;
      }
      if (!same) report.notes.push(`${pUrl} serves another file than the declaration ${prev.hash}; serve that declaration there, because the history is read from the by-hash files`);
    } else if (pr && (pr.status === 404 || pr.status === 410)) {
      extraUploads.push({ path: `${siteRel}by-hash/${pHex}.json`, url: pUrl, bytes: Buffer.from(prev.bytes) });
      report.notes.push(`the previous declaration ${prev.hash} is not served at its by-hash path (HTTP ${pr.status}); a copy of it is written with the files to upload, because the history is read from the by-hash files`);
    } else {
      report.notes.push(`could not check that the previous declaration is served at ${pUrl} (${perr || `HTTP ${pr.status}`}); serve it there, because the history is read from the by-hash files`);
    }
  }
  if (prev) {
    if (Array.isArray(prev.decl.payment) && !payment) report.notes.push('the previous declaration declares payment and this one does not; give --payment to declare it again');
    if (typeof prev.decl.contact === 'string' && !contact) report.notes.push('the previous declaration names a contact and this one does not; give --contact to name it again');
  }

  // Decides whether a declaration served at latest.json (or named by the
  // listing) can be linked. expectHash: the hash it must have, when known.
  async function examinePrevious(bytes, expectHash) {
    let d;
    try {
      d = parseDeclarationText(bytes);
    } catch (e) {
      return { linked: false, result: 'invalid', reason: `not a declaration: ${clip(e.message)}` };
    }
    if (!formatOf(d)) return { linked: false, result: 'invalid', reason: 'its "spec" names no declaration format' };
    const problems = validate(d);
    if (problems.length) return { linked: false, result: 'invalid', reason: `not a valid declaration: ${clip(problems.join('; '))}` };
    const hash = declarationHash(d);
    if (expectHash && hash !== expectHash) return { linked: false, result: 'not_the_named_one', hash, reason: `its declaration hash is ${hash}, not ${expectHash}, the hash the listing names` };
    if (d.name !== name) return { linked: false, result: 'invalid', hash, reason: `it is for ${clip(d.name)}, not ${name}` };
    if (parseTime(d.issuedAt) > now) return { linked: false, result: 'not_yet_valid', hash, reason: `it was issued at ${d.issuedAt}, later than now, and a declaration cannot follow a later one` };
    const v = await verifyDeclarationText(bytes, { keySource: { kind: d.key.method, lookup: (dom) => lookup(d.key.method, dom) }, now });
    if (v.state === 'valid' || v.state === 'expired' || v.state === 'key_not_found') return { linked: true, state: v.state, hash, decl: d };
    if (v.state === 'key_lookup_failed') return { lookupFailed: true, decl: d, reason: v.reasons.join('; ') };
    return { linked: false, result: v.state, hash, reason: `it gives ${v.state}${v.reasons.length ? `: ${clip(v.reasons.join('; '))}` : ''}` };
  }

  // Which of two linkable declarations follows the other: A is the one at
  // latest.json, B the one the listing names. Direct links are seen without a
  // request; otherwise the "previous" links of A, then of B, are walked
  // through by-hash files (walkHistory, as check-listing walks them), at most
  // MAX_CHAIN_LINKS links each, and each file is read once. Returns
  // { relation: 'latest_follows' | 'named_follows', links, read },
  // { relation: 'none', why: { latest, named }, read }, or
  // { unreadable: { url, why }, read } on a network error or an HTTP status
  // other than 200, 404 and 410.
  async function historyBetween(A, B, folderA, folderB) {
    if (A.decl.previous === B.hash) return { relation: 'latest_follows', links: 1, read: [] };
    if (B.decl.previous === A.hash) return { relation: 'named_follows', links: 1, read: [] };
    const known = new Map([[A.hash, A.bytes], [B.hash, B.bytes]]);
    const read = [];
    const fetchByHash = async (url) => {
      read.push(url);
      try {
        return { res: await net('earlier declaration (by hash)')(url, { method: 'GET', headers: { Accept: 'application/json' }, maxBytes: MAX_DECLARATION_BYTES }) };
      } catch (e) {
        return { error: e };
      }
    };
    const why = {};
    // An unreadable file on one walk stops the run only when the other walk
    // finds no relation either: the walk that settles the question may not
    // need that file at all.
    let unreadable = null;
    const walks = [
      { from: A, to: B, folder: folderA, relation: 'latest_follows', key: 'latest', toWords: 'the declaration the listing names' },
      { from: B, to: A, folder: folderB, relation: 'named_follows', key: 'named', toWords: 'the declaration at latest.json' },
    ];
    for (const x of walks) {
      const w = await walkHistory({ start: x.from, target: x.to.hash, folder: x.folder, name, known, fetch: fetchByHash, targetWords: x.toWords });
      if (w.steps) return { relation: x.relation, links: w.steps.length, read };
      const c = w.cause;
      if (c && c.error && !c.error.tooLarge) unreadable = unreadable || { url: c.url, why: `could not be read (${errMessage(c.error)})` };
      else if (c && c.status !== undefined && c.status !== 404 && c.status !== 410) unreadable = unreadable || { url: c.url, why: `answered HTTP ${c.status}` };
      why[x.key] = w.walk.reason;
    }
    if (unreadable) return { unreadable, read };
    return { relation: 'none', why, read };
  }

  // 6. The unsigned declaration.
  const issuedAt = iso(now);
  const expiresAt = iso(parseTime(issuedAt) + expiresInDays * 86400000);
  const unsigned = ordered({
    spec: SPEC_ID_02,
    name,
    version: forVersion,
    toolSetDigest: digests.value,
    ...(remotes ? { remotes } : {}),
    ...(payment ? { payment } : {}),
    ...(contact ? { contact } : {}),
    issuedAt,
    expiresAt,
    ...(prev ? { previous: prev.hash } : {}),
    key: { method: found.method, domain: found.domain },
  });
  const problems = validate(unsigned, { unsigned: true });
  if (problems.length) throw new PrepareError('the declaration would be invalid:', problems);
  const nsProblem = namespaceProblem(name, found.domain, found.method);
  if (nsProblem) throw new PrepareError(`the key domain cannot prove this name: ${nsProblem}`);
  const unsignedText = JSON.stringify(unsigned, null, 2) + '\n';
  report.declaration = { format: SPEC_ID_02, version: forVersion, issuedAt, expiresAt, key: { method: found.method, domain: found.domain }, remotes: remotes ? remotes.map((r) => r.url) : [], payment: payment || [], contact: contact ?? null, previous: prev ? prev.hash : null, hash: null };
  const payWords = payment ? `, payment ${plural(payment.length, 'entry', 'entries')} (${payment.map((p) => `network ${p.network}, asset ${p.asset}, payTo ${p.payTo}, amount ${p.amount}`).join('; ')})` : '';
  step(6, 'ok', `built ${SPEC_ID_02} for ${name} ${forVersion}: ${remotes ? `remotes ${remotes.map((r) => r.url).join(', ')}` : 'no remotes'}${payWords}, issued ${issuedAt}, expires ${expiresAt} (${plural(expiresInDays, 'day')})${prev ? `, previous ${prev.hash}` : ''}${contact ? `, contact ${contact}` : ''}, key by the ${found.method} method at ${found.domain}`);
  if (!remotes) report.notes.push(`${remoteLabel} names no remote, so the declaration declares none`);

  // The pointer block for server.json (pointer mode), with a placeholder hash
  // until the declaration is signed: its size does not depend on the hash.
  // would: true when no pointer.json is written (no signing in this run).
  const pointerFor = (hash, would = false) => {
    const url = `${folderUrl}by-hash/${hash.slice('sha256:'.length)}.json`;
    const meta = serverJson ? serverJson._meta : listed._meta;
    const metaSource = serverJson ? 'the server.json given' : `the listing of ${clip(listed.version)}`;
    const notes = [];
    let existing = {};
    if (isObj(meta) && meta[PUBLISHER_META_KEY] !== undefined) {
      if (isObj(meta[PUBLISHER_META_KEY])) existing = meta[PUBLISHER_META_KEY];
      else notes.push(`the publisher metadata of ${metaSource} is not a JSON object, so ${would ? 'pointer.json would hold' : 'pointer.json holds'} only the pointer`);
    } else if (meta !== undefined && !isObj(meta)) notes.push(`the "_meta" of ${metaSource} is not a JSON object, so ${would ? 'pointer.json would hold' : 'pointer.json holds'} only the pointer`);
    // Members are defined, not assigned, so a member named "__proto__" stays data.
    const block = {};
    const put = (k, v) => Object.defineProperty(block, k, { value: v, enumerable: true, writable: true, configurable: true });
    const carried = [];
    let replaced = false;
    let historThere = false;
    for (const k of Object.keys(existing)) {
      if (k === POINTER_MEMBER) {
        replaced = true;
        put(k, { url, hash });
      } else if (histor && k === HISTOR_MEMBER) {
        historThere = true;
        put(k, histor);
      } else {
        carried.push(k);
        put(k, existing[k]);
      }
    }
    if (!replaced) put(POINTER_MEMBER, { url, hash });
    if (histor && !historThere) put(HISTOR_MEMBER, histor);
    if (replaced) notes.push(`${metaSource} already has an "${POINTER_MEMBER}" member; ${would ? 'pointer.json would replace' : 'pointer.json replaces'} it with the new pointer`);
    if (historThere) notes.push(...historMergeNotes(historMerge, metaSource, would));
    if (carried.length) notes.push(`${would ? 'pointer.json would keep' : 'pointer.json keeps'} the other publisher metadata members of ${metaSource}: ${carried.map((k) => JSON.stringify(clip(k, 80))).join(', ')}`);
    const bytes = Buffer.byteLength(JSON.stringify(block), 'utf8');
    return { meta: { [PUBLISHER_META_KEY]: block }, url, hash, bytes, limit: MAX_PUBLISHER_META_BYTES, carried, notes, metaSource };
  };
  const tooLarge = (p) => {
    step(8, 'failed', `the publisher metadata block would be ${p.bytes} bytes; nothing was written`);
    const own = Buffer.byteLength(JSON.stringify({ [POINTER_MEMBER]: { url: p.url, hash: p.hash } }), 'utf8');
    const historWords = histor ? `, the "${HISTOR_MEMBER}" member (--histor-tool-sets) about ${Buffer.byteLength(JSON.stringify({ [HISTOR_MEMBER]: histor }), 'utf8')} bytes` : '';
    return finish('pointer_too_large', [
      `the publisher metadata block for server.json (_meta["${PUBLISHER_META_KEY}"]) would be ${p.bytes} bytes of JSON; the registry keeps at most ${MAX_PUBLISHER_META_BYTES} bytes there (SPEC.md section 2). The pointer alone takes about ${own} bytes${historWords}${p.carried.length ? `, and the block carries ${plural(p.carried.length, 'other member')} of ${p.metaSource}; make them smaller or move them out${histor ? ', or leave out --histor-tool-sets' : ''}, then run prepare again` : `; the server name is too long for a pointer${histor ? ' and that member' : ''}`}`,
    ]);
  };

  // Writes the files, or stops when the folder changed since the start.
  const write = (list) => {
    const c = commitFiles(outDir, list, force, signing);
    if (c.refused) return c;
    if (c.removed.length) report.notes.push(`--force removed ${plural(c.removed.length, 'file')} an earlier prepare run wrote into the output folder and this run does not (such as ${c.removed.slice(0, 3).map((x) => clip(x, 120)).join(', ')}), so the folder holds one consistent set`);
    if (c.left.length) report.notes.push(`the output folder also holds ${plural(c.left.length, 'file')} this run did not write (such as ${c.left.slice(0, 3).map((x) => clip(x, 120)).join(', ')}); they are left as they are and are not part of this declaration`);
    return c;
  };
  const folderChanged = (c) => {
    step(8, 'failed', 'the output folder changed while prepare ran; nothing was written');
    return finish('output_folder_not_empty', [c.refused]);
  };

  // 7. Signing (or, without a key, what signing would do).
  const afterWhat = noPointer ? 'the upload' : 'publishing';
  if (!signing) {
    // The declaration hash does not cover the signature, so it is known once the key is.
    const candidates = noPointer && prev ? [{ alg: prev.decl.key.alg, id: prev.decl.key.id }] : [...new Map(found.keys.map((k) => [`${k.alg} ${k.id}`, { alg: k.alg, id: k.id }])).values()];
    const predicted = candidates.length === 1 ? declarationHash({ ...unsigned, key: { ...unsigned.key, alg: candidates[0].alg, id: candidates[0].id } }) : null;
    report.declaration.predictedHash = predicted;
    if (!noPointer) {
      const p = pointerFor(predicted || `sha256:${'0'.repeat(64)}`, true);
      report.pointer = { meta: predicted ? p.meta : null, bytes: p.bytes, limit: p.limit, carried: p.carried, predicted: Boolean(predicted) };
      report.notes.push(...p.notes);
      if (p.bytes > MAX_PUBLISHER_META_BYTES) return tooLarge(p);
      if (histor) report.notes.push(`--histor-tool-sets: pointer.json would also hold _meta["${PUBLISHER_META_KEY}"]["${HISTOR_MEMBER}"] = ${JSON.stringify(histor)}, the member HISTOR, a third party watcher (${HISTOR_URL}), reads; its first set names the contract digest the declaration would sign, and the block would be ${p.bytes} of ${MAX_PUBLISHER_META_BYTES} bytes. The member is not signed; pointer.json is written when the declaration is signed`);
    }
    const how = dryRun ? 'not signed (dry run)' : 'not signed (no --key-file or --key-env)';
    const keyText = candidates.length === 1 ? `${candidates[0].alg} ${candidates[0].id}` : `one of the published records (${candidates.map((c) => `${c.alg} ${c.id}`).join(', ')})`;
    step(7, 'skipped', `${how}. With --key-file <path> or --key-env <NAME>${dryRun ? ' and no --dry-run' : ''} it would check that the private key belongs to ${keyText}, sign, verify the result offline and against a check-listing run on the listing as it will be after ${afterWhat}, and write the files to upload${predicted ? `; signing declaration.unsigned.json with that key gives the declaration hash ${predicted}` : ''}`);
    const c = write([{ path: 'declaration.unsigned.json', text: unsignedText }]);
    if (c.refused) return folderChanged(c);
    report.files = [{ path: 'declaration.unsigned.json', upload: false }];
    step(8, 'ok', `wrote declaration.unsigned.json into ${outDir}; the files to upload are written when the declaration is signed. The signed run needs --force for this folder (or another --out), because the folder is no longer empty`);
    step(9, 'skipped', 'not run (nothing was signed)');
    return finish('prepared_unsigned', []);
  }

  let signed;
  try {
    signed = signDeclaration(unsigned, key);
  } catch (e) {
    if (e instanceof DeclarationError) throw new PrepareError(`cannot sign: ${e.message}`);
    throw e;
  }
  const hash = declarationHash(signed);
  const hex = hash.slice('sha256:'.length);
  const signedText = JSON.stringify(signed, null, 2) + '\n';
  const signedBytes = Buffer.from(signedText, 'utf8');
  report.signed = true;
  report.declaration.hash = hash;
  step(7, 'ok', `signed with ${key.alg} ${key.public.id}, the key of the published record; declaration hash ${hash}`);

  let pointer = null;
  if (!noPointer) {
    pointer = pointerFor(hash);
    report.pointer = { meta: pointer.meta, bytes: pointer.bytes, limit: pointer.limit, carried: pointer.carried, predicted: false };
    report.notes.push(...pointer.notes);
    if (pointer.bytes > MAX_PUBLISHER_META_BYTES) return tooLarge(pointer);
  }

  // The files and where each is served (SPEC.md section 8).
  const uploads = [
    { path: `${siteRel}by-hash/${hex}.json`, url: `${folderUrl}by-hash/${hex}.json`, bytes: signedBytes },
    { path: `${siteRel}versions/${versionFile}`, url: `${folderUrl}versions/${versionFile}`, bytes: signedBytes },
    ...(writeLatest ? [{ path: `${siteRel}latest.json`, url: `${folderUrl}latest.json`, bytes: signedBytes }] : []),
    ...extraUploads,
  ];

  // 9. The checks, before anything is written: offline against the published
  // record, and check-listing on the listing as it will read after publishing,
  // with every answer served from memory (nothing is fetched).
  const v = await verifyDeclarationText(signedBytes, { keySource: { kind: 'offline', keys: found.keys }, now, toolsText: pages, ...(prev ? { previousText: prev.bytes } : {}), formats: [SPEC_ID_02] });
  report.verify = { state: v.state, reasons: v.reasons, checked: v.details.checked, notChecked: v.details.notChecked };
  const mem = new Map(cache);
  for (const f of uploads) mem.set(f.url, { status: 200, headers: { 'content-type': 'application/json' }, body: f.bytes });
  let previewVersion = listingVersion;
  if (!noPointer) {
    previewVersion = forVersion;
    const base = serverJson ? serverJson : listed;
    const newServer = { ...base, version: forVersion, _meta: { ...(isObj(base._meta) ? base._meta : {}), ...pointer.meta } };
    // Without --server-json the new version is assumed to keep the listed remotes.
    if (!serverJson) newServer.remotes = listed.remotes;
    const previewUrl = `${registry.base}${REGISTRY_SERVER_PATH}/${encodePathSegment(name)}/versions/${encodePathSegment(forVersion)}`;
    mem.set(previewUrl, { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ server: newServer, _meta: { [OFFICIAL_META_KEY]: { status: 'active', publishedAt: issuedAt, isLatest: writeLatest } } }), 'utf8') });
  }
  const memRequest = async (url) => mem.get(url) || { status: 404, headers: {}, body: Buffer.alloc(0) };
  const memLookup = async (m, d) => (lookups.has(`${m} ${d}`) ? lookups.get(`${m} ${d}`) : { keys: [], notes: [], error: `no ${m} key lookup for ${d} was made in this run` });
  const pv = await checkListing({ name, version: previewVersion, registry, now, request: memRequest, keyLookup: memLookup, toolsPages: pages });
  const expected = noPointer ? 'verified_newer_declaration' : 'verified';
  report.preview = { state: pv.state, exitCode: pv.exitCode, expected, inForce: pv.report.inForce ? pv.report.inForce.hash : null, assumed: !noPointer && !serverJson ? 'the server.json of the new version names the remotes of the listing' : null, reasons: pv.reasons, notes: pv.report.notes };
  const previewOk = pv.state === expected && pv.report.inForce && pv.report.inForce.hash === hash;
  // The HISTOR member in pointer.json: read under HISTOR's rules, and its
  // digests equal to the contract digest of the signed declaration.
  let historProblems = [];
  if (histor) {
    historProblems = historMemberProblems(pointer.meta[PUBLISHER_META_KEY][HISTOR_MEMBER], parseStrict(signedText).toolSetDigest, digests.toolCount, historMerge.carried);
    report.historToolSets.check = historProblems.length ? 'failed' : 'passed';
    report.historToolSets.problems = historProblems;
  }
  if (v.state !== 'valid' || !previewOk || historProblems.length) {
    step(9, 'failed', `${v.state !== 'valid' ? `the signed declaration gives ${v.state} offline` : 'the signed declaration verifies offline'}; check-listing on the listing as it will be after ${afterWhat} gives ${pv.state}${previewOk ? '' : `, not ${expected} with this declaration in force`}${histor ? `; the "${HISTOR_MEMBER}" member ${historProblems.length ? 'does not match the signed declaration' : 'matches the signed declaration'}` : ''}; nothing was written`);
    return finish('self_check_failed', [...(v.state !== 'valid' ? v.reasons.map((x) => `offline: ${x}`) : []), ...(!previewOk ? [...pv.reasons.map((x) => `check-listing: ${x}`), ...pv.report.notes.map((x) => `check-listing note: ${x}`)] : []), ...historProblems.map((x) => `${HISTOR_MEMBER}: ${x}`)]);
  }

  // 8. The output folder.
  const fetchTools = Boolean((remotes || []).find((r) => r.type === 'streamable-http'));
  report.checkCommand = checkListingCommand(name, forVersion, fetchTools, registry.base);
  const toolsFrom = T.source === 'files' ? `The tool list signed is the one given with --tools (${plural(T.pages, 'page')}).` : `The tool list signed was read from ${T.remote}, the server running now.`;
  const files = [
    ...uploads.map(({ path: p, url, bytes }) => ({ path: p, url, text: bytes, upload: true, contentType: 'application/json' })),
    { path: 'declaration.unsigned.json', text: unsignedText, upload: false },
    ...(pointer ? [{ path: 'pointer.json', text: escText(JSON.stringify({ _meta: pointer.meta }, null, 2) + '\n'), upload: false }] : []),
    {
      path: 'NEXT_STEPS.txt',
      text: nextStepsText({ name, forVersion, mode: noPointer ? 'no_pointer' : 'pointer', hash, host, uploads, writeLatest, latestWhy, checkCommand: report.checkCommand, metaSource: pointer ? pointer.metaSource : null, carried: pointer ? pointer.carried : [], histor: histor ? { value: histor, merge: historMerge } : null, fromListing: !serverJson, listedVersion: clip(listed.version), remotes, toolsFrom, timeNotes, toolsHeaders: toolsHeaders.length > 0, folderWarning }),
      upload: false,
    },
  ];
  const c = write(files);
  if (c.refused) return folderChanged(c);
  report.files = files.map(({ path: p, url, upload, contentType }) => ({ path: p, ...(url ? { url } : {}), upload, ...(contentType ? { contentType } : {}) }));
  step(8, 'ok', `wrote ${plural(files.length, 'file')} into ${outDir}: ${uploads.length} to upload (${uploads.map((f) => f.path.slice(siteRel.length)).join(', ')} under ${siteRel}, Content-Type application/json${extraUploads.length ? '; the previous declaration is among them because the site does not serve it at its by-hash path' : ''}), declaration.unsigned.json, ${pointer ? `pointer.json (${pointer.bytes} of ${MAX_PUBLISHER_META_BYTES} bytes${histor ? `, with the "${HISTOR_MEMBER}" member` : ''}), ` : ''}NEXT_STEPS.txt`);
  step(9, 'ok', `the signed declaration verifies offline against the published record${prev ? ', with its previous declaration' : ''} and the tool list; check-listing on the listing as it will be after ${afterWhat} gives ${pv.state} (exit code ${pv.exitCode}) with this declaration in force, with every answer served from memory${!noPointer && !serverJson ? `, assuming the server.json of ${forVersion} names the remotes of the listing and the server answers with the tool list read here` : ''}${histor ? `; the "${HISTOR_MEMBER}" member in pointer.json names ${histor.sets[0].digest}, equal to the contract digest the declaration signs${histor.sets[0].count !== undefined ? `, with the count of ${plural(digests.toolCount, 'tool')} signed` : ''}${historMerge.keptSets.length ? `, and keeps ${plural(historMerge.keptSets.length, 'other set')} from ${pointer.metaSource}` : ''} (the member itself is not signed)` : ''}`);
  return finish('prepared', []);
}
