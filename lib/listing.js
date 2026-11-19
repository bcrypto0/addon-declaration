// check-listing: the client side of SPEC.md section 8a in one step. Read one
// registry listing by name and version, find the declaration pointer in its
// publisher metadata, fetch the declaration it names under the fetch rules of
// section 8a, check it against the listing, verify it as "verify" does, look
// for a newer declaration for the same version that chains back to it, and run
// the tool check of the declaration in force.
//
// Network access goes through the request function given (the hardened fetch
// of resolve.js by default) and the key lookup function given; nothing here
// opens a socket itself.

import { decodeUtf8Strict, parseStrict } from './jcs.js';
import {
  STATES,
  GITHUB_OUT_OF_SCOPE,
  MAX_DECLARATION_BYTES,
  declarationHash,
  encodePathSegment,
  formatOf,
  isHttpsUrl,
  isValidDomain,
  parseDeclarationText,
  reverseDomain,
  validate,
  verifyDeclarationText,
  UNSAFE_CHARS_RE,
} from './declaration.js';
import { httpsRequest, HTTP_ATTEMPT_TIMEOUT_MS, HTTP_OVERALL_TIMEOUT_MS } from './resolve.js';
import { fetchToolsList, McpFetchError } from './mcp-client.js';
import { urlHoldsKey } from './keylike.js';
import { HISTOR_MEMBER, readHistorMember, compareHistorDigests } from './histor-tool-sets.js';

export const DEFAULT_REGISTRY = 'https://registry.modelcontextprotocol.io';
// The documented get by name and version endpoint of the registry API
// (docs/reference/api/openapi.yaml, GET /v0.1/servers/{serverName}/versions/{version}).
export const REGISTRY_SERVER_PATH = '/v0.1/servers';
export const PUBLISHER_META_KEY = 'io.modelcontextprotocol.registry/publisher-provided';
export const OFFICIAL_META_KEY = 'io.modelcontextprotocol.registry/official';
export const POINTER_MEMBER = 'addonDeclaration';
export const MAX_REGISTRY_RESPONSE = 262144;
// Links walked from a newer declaration back to the one the listing names.
export const MAX_CHAIN_LINKS = 8;
// One limit for every read of a check other than the tools fetch, which has
// its own (mcp-client.js). Each request is also bounded on its own.
export const OVERALL_TIMEOUT_MS = 90000;
// Strings from the listing shown in text are cut to this many characters.
export const MAX_SHOWN_CHARS = 200;

// Result states of check-listing and their exit codes. The verify states other
// than "valid" are passed through with the exit codes of verify.
const PASSED_THROUGH = Object.fromEntries(Object.entries(STATES).filter(([s]) => s !== 'valid'));
export const LISTING_STATES = Object.freeze({
  verified: 0,
  ...PASSED_THROUGH,
  verified_newer_declaration: 11,
  no_declaration: 12,
  pointer_malformed: 13,
  pointer_refused: 14,
  namespace_out_of_scope: 15,
  declaration_unreachable: 16,
  declaration_not_the_named_one: 17,
  listing_mismatch: 18,
  tools_fetch_failed: 19,
  registry_not_found: 20,
  registry_unreachable: 21,
  registry_response_invalid: 22,
});

// The steps of SPEC.md section 8a in order. A check that stops lists every
// later step in notChecked, with the state it stopped at.
const STEPS = Object.freeze([
  'the registry listing',
  'the declaration pointer',
  'the declaration the listing names (fetch and hash)',
  'name, version and remotes against the listing',
  'key lookup, signature and time window of the declaration the listing names',
  'newer declarations for this version (versions/<version>.json and latest.json were not read)',
]);
const STEP = Object.freeze({ listing: 0, pointer: 1, fetch: 2, match: 3, verify: 4, newer: 5 });

const NAME_RE = /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/;
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export const clip = (s, n = MAX_SHOWN_CHARS) => (s.length > n ? s.slice(0, n) + '...' : s);

export function isServerName(s) {
  return typeof s === 'string' && s.length >= 3 && s.length <= 200 && NAME_RE.test(s) && !s.split('/').some((p) => p === '.' || p === '..');
}

// A version as given to --version: what a declaration accepts (SPEC.md section
// 3), or "latest". "." and ".." are refused: as a path segment they would be
// resolved away and the request would reach another endpoint of the registry.
export function isVersionArgument(s) {
  return typeof s === 'string' && [...s].length >= 1 && [...s].length <= 255 && !UNSAFE_CHARS_RE.test(s) && s !== '.' && s !== '..';
}

// --registry: https with no user name, password, query or fragment; or
// http://127.0.0.1:<port> or http://localhost:<port> (for local test doubles).
// Returns { base, loopback } or throws an Error saying why.
export function registryBase(s) {
  // The base URL is sent with every registry request and shown in the output,
  // so a key pasted into it in a common form is stopped here, before any
  // request, and not repeated (a best effort check, see keylike.js).
  if (urlHoldsKey(s)) throw new Error('--registry looks like it holds key material (a long hex run, also cut in pieces, a base64 key as one path segment, or PEM text), so it is not used or sent anywhere; give the base URL of the registry, such as https://registry.modelcontextprotocol.io');
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error('--registry must be a URL such as https://registry.modelcontextprotocol.io');
  }
  if (u.username || u.password) throw new Error('--registry must not carry a user name or password');
  if (u.search || u.hash || /[?#]/.test(s)) throw new Error('--registry must not carry a query or a fragment');
  let loopback = false;
  if (u.protocol === 'http:') {
    if (!['127.0.0.1', 'localhost'].includes(u.hostname) || u.port === '') throw new Error('--registry must be an https URL; plain http is accepted only as http://127.0.0.1:<port> or http://localhost:<port>');
    loopback = true;
  } else if (u.protocol !== 'https:') throw new Error('--registry must be an https URL');
  return { base: (u.origin + u.pathname).replace(/\/+$/, ''), loopback };
}

// The domains whose key can prove a namespace (SPEC.md section 11 step 2): the
// reversed namespace itself (dns or http) and each parent of it with at least
// two labels (dns only). A pointer may point to one of these hosts only.
export function pointerHosts(namespace) {
  const d = reverseDomain(namespace.toLowerCase());
  const labels = d.split('.');
  const out = [];
  for (let i = 0; i <= labels.length - 2; i++) {
    const h = labels.slice(i).join('.');
    if (isValidDomain(h)) out.push(h);
  }
  return out;
}

// The URL as it may be shown: no user name or password, never more than 300 characters.
export function shownUrl(u) {
  if (typeof u !== 'string') return String(u);
  let s = u;
  try {
    const x = new URL(u);
    if (x.username || x.password) {
      x.username = '';
      x.password = '';
      s = x.href + ' (user name and password removed)';
    }
  } catch {
    // shown as given, escaped by the caller
  }
  return s.length > 300 ? s.slice(0, 300) + '...' : s;
}

// A listing remote in the canonical form a declaration uses (SPEC.md section
// 11, "Comparing remotes"), or null with a reason when it cannot be one.
function listingRemote(r) {
  if (!isObj(r)) return { key: null, why: 'not an object' };
  const type = typeof r.type === 'string' ? r.type : null;
  const url = r.url;
  if (typeof url !== 'string') return { type, key: null, why: 'url is not a string' };
  if (/[{}]/.test(url) || r.variables !== undefined) return { type, url: shownUrl(url), key: null, why: 'a URL template, which a declaration cannot name' };
  let x;
  try {
    x = new URL(url);
  } catch {
    return { type, url: shownUrl(url), key: null, why: 'not a URL' };
  }
  if (x.protocol !== 'https:') return { type, url: shownUrl(url), key: null, why: 'not https' };
  if (x.username || x.password) return { type, url: shownUrl(url), key: null, why: 'carries a user name or password' };
  return { type, url: x.href, key: `${type} ${x.href}`, written: x.href === url ? undefined : shownUrl(url) };
}

// Compares the listing's remotes with a declaration's, both ways.
export function compareRemotes(listingRemotes, declaredRemotes) {
  const listing = (Array.isArray(listingRemotes) ? listingRemotes : []).map(listingRemote);
  const declared = (Array.isArray(declaredRemotes) ? declaredRemotes : []).map((r) => ({ type: r.type, url: r.url, key: `${r.type} ${r.url}` }));
  const dkeys = new Set(declared.map((r) => r.key));
  const lkeys = new Set(listing.filter((r) => r.key).map((r) => r.key));
  const onlyInListing = listing.filter((r) => !r.key || !dkeys.has(r.key));
  const onlyInDeclaration = declared.filter((r) => !lkeys.has(r.key));
  const listed = Array.isArray(listingRemotes) ? listingRemotes.length : 0;
  return {
    listing: listing.map(({ type, url, why, written }) => ({ type, url: url ?? null, ...(why ? { problem: why } : {}), ...(written ? { written } : {}) })),
    declared: declared.map(({ type, url }) => ({ type, url })),
    match: onlyInListing.length === 0 && onlyInDeclaration.length === 0,
    onlyInListing: onlyInListing.map(({ type, url, why }) => ({ type: type ?? null, url: url ?? null, ...(why ? { problem: why } : {}) })),
    onlyInDeclaration: onlyInDeclaration.map(({ type, url }) => ({ type, url })),
    listingCount: listed,
  };
}

function remoteReasons(cmp, which) {
  const out = [];
  for (const r of cmp.onlyInListing) out.push(`the listing names remote ${r.type ?? '(no type)'} ${r.url ?? '(no url)'}${r.problem ? ` (${r.problem})` : ''}, which ${which} does not declare; the registry does not check remotes, and a client connects to the listing's remote`);
  for (const r of cmp.onlyInDeclaration) out.push(`${which} declares remote ${r.type} ${r.url}, which the listing does not name`);
  return out;
}

// Walks the "previous" links of a declaration back through the by-hash files
// of folder (https://<host>/.well-known/addon-declaration/<name>/) until one
// names target, at most maxLinks links. Each file read is checked to be the
// declaration with the hash asked for, valid under section 3 and for name;
// signatures are not checked here. Used by check-listing (newer declarations)
// and by prepare (which of two declarations follows the other).
//   start: { hash, bytes, decl, url }; target: a declaration hash
//   known: a Map of hash to bytes already read (filled with each file read)
//   fetch: (url) => { res } or { error }, as the get of checkListing
//   targetWords: how the reasons name target
// Returns { steps } (start first, target not included) or { walk: { result,
// reason }, cause } where cause, when a by-hash read ended the walk, is
// { url, status } or { url, error } (error: the Error the fetch gave).
export async function walkHistory({ start, target, folder, name, known = new Map(), fetch, maxLinks = MAX_CHAIN_LINKS, targetWords = 'the declaration the listing names' }) {
  const folderPath = new URL(folder).pathname;
  const steps = [start];
  let cur = start.decl;
  for (;;) {
    const last = steps[steps.length - 1].hash;
    if (!Object.hasOwn(cur, 'previous')) return { walk: { result: 'not_chained', reason: `its history ends at ${last} without reaching ${targetWords}` } };
    // Checked before the value is used, so a URL is built only from 64 hex digits.
    if (typeof cur.previous !== 'string' || !HASH_RE.test(cur.previous)) return { walk: { result: 'not_chained', reason: `${last} names a "previous" that is not a declaration hash` } };
    if (cur.previous === target) return { steps };
    if (steps.some((s) => s.hash === cur.previous)) return { walk: { result: 'not_chained', reason: `its history loops back to ${cur.previous}` } };
    if (steps.length >= maxLinks) return { walk: { result: 'not_chained', reason: `its history does not reach ${targetWords} within ${maxLinks} links` } };
    const prevHash = cur.previous;
    const purl = `${folder}by-hash/${prevHash.slice('sha256:'.length)}.json`;
    if (!new URL(purl).pathname.startsWith(`${folderPath}by-hash/`)) return { walk: { result: 'not_chained', reason: `the by-hash path for ${prevHash} leaves the folder of the declaration` } };
    let pbytes = known.get(prevHash);
    if (!pbytes) {
      const B = await fetch(purl);
      if (B.error) return { walk: { result: 'unreachable', reason: `the earlier declaration ${prevHash} could not be fetched from its by-hash path (${B.error.tooLarge ? `larger than ${MAX_DECLARATION_BYTES} bytes` : B.error.message})` }, cause: { url: purl, error: B.error } };
      if (B.res.status !== 200) return { walk: { result: 'not_chained', reason: `the earlier declaration ${prevHash} could not be fetched from its by-hash path (HTTP ${B.res.status})` }, cause: { url: purl, status: B.res.status } };
      pbytes = B.res.body;
    }
    let pd;
    try {
      pd = parseDeclarationText(pbytes);
    } catch (e) {
      return { walk: { result: 'not_chained', reason: `the by-hash file for ${prevHash} is not a declaration (${e.message})` } };
    }
    if (!formatOf(pd) || declarationHash(pd) !== prevHash) return { walk: { result: 'not_chained', reason: `the by-hash file for ${prevHash} is not the declaration with that hash` } };
    // Nothing of an earlier declaration is used before it passes section 3.
    const problems = validate(pd);
    if (problems.length) return { walk: { result: 'not_chained', reason: `the by-hash file for ${prevHash} is not a valid declaration: ${clip(problems.join('; '))}` } };
    if (pd.name !== name) return { walk: { result: 'not_chained', reason: `the by-hash file for ${prevHash} is for ${pd.name}, not ${name}` } };
    known.set(prevHash, pbytes);
    steps.push({ hash: prevHash, bytes: pbytes, decl: pd, url: purl });
    cur = pd;
  }
}

// options:
//   name, version ("latest" by default), registry ({ base, loopback })
//   toolsPages: tool list pages given as files (bytes), or undefined
//   fetchTools: true to read the tool list from the declared remote
//   now: epoch milliseconds
//   request: the hardened fetch (resolve.js httpsRequest)
//   keyLookup: (method, domain) => Promise<{ keys, notes, error }>, used by verify
//   fetchToolsList: replaceable in tests
//   overallTimeoutMs: the limit for every read other than the tools fetch
// Returns { state, exitCode, reasons, report }.
export async function checkListing(options) {
  const { name, version = 'latest', registry = registryBase(DEFAULT_REGISTRY), toolsPages, fetchTools = false, now = Date.now(), request = httpsRequest, keyLookup, overallTimeoutMs = OVERALL_TIMEOUT_MS } = options;
  const readTools = options.fetchToolsList || fetchToolsList;
  const toolFlag = Boolean(toolsPages) || fetchTools;
  const deadline = Date.now() + overallTimeoutMs;
  const timeLimit = `the overall time limit of ${overallTimeoutMs / 1000} seconds for the reads of this check ran out`;
  const report = {
    listing: { name, requestedVersion: version, registry: registry.base, url: null, version: null, publishedAt: null, registryStatus: null, isLatest: null, remoteCount: null },
    pointer: null,
    fetched: [],
    declaration: null,
    newer: [],
    newerSetAside: false,
    inForce: null,
    chain: [],
    remotes: null,
    remotesInForce: null,
    tools: { check: 'not_run', reason: null },
    checked: [],
    notChecked: [],
    notes: [],
    // For information only: the HISTOR tool sets member of the listing, or
    // null when the listing has none. No state depends on it.
    historToolSets: null,
  };
  // The step of section 8a the check is at; a stop lists every later one as not checked.
  let reached = -1;
  let newerPaths = null;
  let finalDecl = null; // the declaration in force, once it verified
  const done = (state, reasons) => {
    const H = report.historToolSets;
    if (H) {
      if (finalDecl) {
        H.matches = compareHistorDigests(H.digests, finalDecl.toolSetDigest);
        H.comparedWith = H.matches === null ? null : report.inForce.hash;
      }
      // Why nothing was compared, when nothing was.
      if (H.matches === null) {
        H.notCompared = H.digests.length === 0 ? 'it names no digest in the form HISTOR reads'
          : !finalDecl ? `the check stopped at ${state}, before a declaration in force verified`
            : 'the declaration in force has no contract digest';
      }
    }
    for (let i = reached + 1; i < STEPS.length; i++) {
      const text = i === STEP.newer && newerPaths ? `newer declarations for this version (${newerPaths.join(' and ')} were not read)` : STEPS[i];
      report.notChecked.push(`${text} (the check stopped at ${state})`);
    }
    const T = report.tools;
    if (T.check === 'not_run') {
      T.reason = toolFlag ? `the check stopped at ${state}, before the tool check` : 'give --tools or --fetch-tools to compare the tool list with the declaration in force';
      report.notChecked.push(`tools (${T.reason})`);
    } else if (T.check === 'not_checked' || T.check === 'failed') {
      report.notChecked.push(`tools (${T.reason})`);
    } else if (T.result === 'not_reached') {
      report.notChecked.push(`tools (the check stopped at ${state}, before the tool check)`);
    }
    return { state, exitCode: LISTING_STATES[state], reasons, report };
  };

  const ns = name.split('/')[0].toLowerCase();
  if (ns === 'io.github' || ns.startsWith('io.github.')) {
    return done('namespace_out_of_scope', [`${GITHUB_OUT_OF_SCOPE}; no declaration can prove such a name, so nothing was fetched`]);
  }

  async function get(purpose, url, opts = {}) {
    const entry = { purpose, method: 'GET', url, status: null };
    report.fetched.push(entry);
    const left = deadline - Date.now();
    if (left <= 0) {
      entry.error = timeLimit;
      return { error: Object.assign(new Error(timeLimit), { timeLimit: true }) };
    }
    try {
      const res = await request(url, { method: 'GET', headers: { Accept: 'application/json' }, attemptTimeoutMs: Math.min(HTTP_ATTEMPT_TIMEOUT_MS, left), overallTimeoutMs: Math.min(HTTP_OVERALL_TIMEOUT_MS, left), ...opts });
      entry.status = res.status;
      entry.bytes = res.body.length;
      return { res };
    } catch (e) {
      entry.error = e && typeof e.message === 'string' ? e.message : 'the request failed';
      if (e && e.refused) entry.refused = true;
      return { error: e };
    }
  }

  // 1. The listing.
  reached = STEP.listing;
  const listingUrl = `${registry.base}${REGISTRY_SERVER_PATH}/${encodePathSegment(name)}/versions/${encodePathSegment(version)}`;
  report.listing.url = listingUrl;
  const asked = version === 'latest' ? `the latest version of ${name}` : `${name} version ${version}`;
  const L = await get('registry listing', listingUrl, { maxBytes: MAX_REGISTRY_RESPONSE, allowLoopbackHttp: registry.loopback });
  if (L.error) {
    if (L.error.tooLarge) return done('registry_unreachable', [`the registry answer for ${asked} is larger than ${MAX_REGISTRY_RESPONSE} bytes`]);
    return done('registry_unreachable', [`the request to the registry failed: ${L.error.message}`]);
  }
  if (L.res.status === 404) return done('registry_not_found', [`the registry answered HTTP 404 for ${asked}`]);
  if (L.res.status !== 200) {
    const why = L.res.status >= 300 && L.res.status < 400 ? ', a redirect, which is not followed' : '';
    return done('registry_unreachable', [`the registry answered HTTP ${L.res.status}${why} for ${asked}`]);
  }
  let body;
  try {
    body = parseStrict(decodeUtf8Strict(L.res.body));
  } catch (e) {
    return done('registry_response_invalid', [`the registry answer is not strict JSON (${e.message}); the base URL may not be a registry API`]);
  }
  const server = isObj(body) ? body.server : undefined;
  if (!isObj(server)) return done('registry_response_invalid', ['the registry answer has no "server" object']);
  const quoted = (v) => JSON.stringify(clip(v));
  if (server.name !== name) return done('registry_response_invalid', [`the registry answered for another server name (${typeof server.name === 'string' ? quoted(server.name) : 'none'}), not ${name}`]);
  if (typeof server.version !== 'string' || server.version.length === 0) return done('registry_response_invalid', ['the registry answer has no server version']);
  if (version !== 'latest' && server.version !== version) return done('registry_response_invalid', [`the registry answered for version ${quoted(server.version)}, not ${quoted(version)}`]);
  report.listing.version = server.version;
  const official = isObj(body._meta) && isObj(body._meta[OFFICIAL_META_KEY]) ? body._meta[OFFICIAL_META_KEY] : {};
  const str = (v) => (typeof v === 'string' ? v : null);
  report.listing.publishedAt = str(official.publishedAt);
  report.listing.registryStatus = str(official.status);
  report.listing.isLatest = typeof official.isLatest === 'boolean' ? official.isLatest : null;
  report.listing.remoteCount = Array.isArray(server.remotes) ? server.remotes.length : 0;
  if (report.listing.registryStatus !== null && report.listing.registryStatus !== 'active') report.notes.push(`the registry marks this version ${clip(report.listing.registryStatus)}; the check goes on, and the state does not reflect it`);
  if (version === 'latest' && report.listing.isLatest === false) report.notes.push('the registry answered the request for "latest" with a version that is not marked latest');
  newerPaths = [`versions/${encodePathSegment(server.version)}.json`, 'latest.json'];

  // 2. The pointer.
  reached = STEP.pointer;
  const meta = server._meta;
  if (meta === undefined || (isObj(meta) && meta[PUBLISHER_META_KEY] === undefined)) {
    return done('no_declaration', [`the listing has no publisher metadata (${PUBLISHER_META_KEY}), so it names no declaration`]);
  }
  if (!isObj(meta) || !isObj(meta[PUBLISHER_META_KEY])) return done('pointer_malformed', [`the listing's server._meta or its "${PUBLISHER_META_KEY}" member is present and not a JSON object`]);
  if (Object.hasOwn(meta[PUBLISHER_META_KEY], HISTOR_MEMBER)) {
    // What HISTOR takes from it, with the url bound to the namespace of the listed name.
    const h = readHistorMember(meta[PUBLISHER_META_KEY][HISTOR_MEMBER], typeof server.name === 'string' ? server.name : '');
    report.historToolSets = { member: HISTOR_MEMBER, readable: h.readable, problem: h.problem === null ? null : clip(h.problem, 600), mtl: h.mtl === null ? null : clip(h.mtl, 40), sets: h.sets, digests: h.digests, url: h.url === null ? null : shownUrl(h.url), urlRefused: h.urlRefused === null ? null : clip(h.urlRefused, 300), skipped: h.skipped.slice(0, 16).map((x) => clip(x, 200)), comparedWith: null, matches: null, notCompared: null };
  }
  const p = meta[PUBLISHER_META_KEY][POINTER_MEMBER];
  if (p === undefined) return done('no_declaration', [`the listing's publisher metadata has no "${POINTER_MEMBER}" member, so it names no declaration`]);
  const pointerProblems = [];
  if (!isObj(p)) pointerProblems.push(`"${POINTER_MEMBER}" is not a JSON object`);
  else {
    for (const k of Object.keys(p)) if (k !== 'url' && k !== 'hash') pointerProblems.push(`"${POINTER_MEMBER}" has the member "${clip(k, 80)}"; a pointer has exactly "url" and "hash"`);
    if (typeof p.url !== 'string') pointerProblems.push(`"${POINTER_MEMBER}.url" is missing or not a string`);
    if (typeof p.hash !== 'string' || !HASH_RE.test(p.hash)) pointerProblems.push(`"${POINTER_MEMBER}.hash" must be "sha256:" followed by 64 lowercase hex digits`);
  }
  if (pointerProblems.length) {
    if (isObj(p)) report.pointer = { url: typeof p.url === 'string' ? shownUrl(p.url) : null, hash: typeof p.hash === 'string' ? p.hash.slice(0, 80) : null };
    return done('pointer_malformed', pointerProblems);
  }
  report.pointer = { url: shownUrl(p.url), hash: p.hash };

  // The fetch rules (SPEC.md section 8a).
  const hex = p.hash.slice('sha256:'.length);
  const hosts = pointerHosts(ns);
  const path = `/.well-known/addon-declaration/${name}/by-hash/${hex}.json`;
  const refused = [];
  let host = null;
  if (!isHttpsUrl(p.url)) refused.push('the pointer URL is not an https URL in canonical form without a user name or password (SPEC.md section 3)');
  else {
    const u = new URL(p.url);
    host = u.hostname;
    if (hosts.length === 0) refused.push(`the namespace "${ns}" does not name a domain, so no host may serve its declaration`);
    else if (!hosts.includes(host)) refused.push(`the pointer URL is on ${host}; for the namespace "${ns}" a declaration is fetched only from ${hosts.join(' or ')}`);
    if (p.url !== `https://${host}${path}`) refused.push(`the pointer URL must be exactly https://<host>${path} (the by-hash path of SPEC.md section 8 for this name and hash, with no port, query or fragment)`);
  }
  if (refused.length) return done('pointer_refused', refused);

  // 3. The declaration the listing names.
  reached = STEP.fetch;
  const D = await get('declaration named by the listing', p.url, { maxBytes: MAX_DECLARATION_BYTES });
  if (D.error) {
    if (D.error.tooLarge) return done('declaration_not_the_named_one', [`the pointer URL served more than ${MAX_DECLARATION_BYTES} bytes, the size limit of a declaration, so it does not serve the named declaration`]);
    return done('declaration_unreachable', [`the declaration could not be fetched: ${D.error.message}`]);
  }
  if (D.res.status !== 200) {
    const why = D.res.status >= 300 && D.res.status < 400 ? ' (a redirect, which is not followed)' : '';
    return done('declaration_unreachable', [`the pointer URL answered HTTP ${D.res.status}${why}`]);
  }
  const pointerBytes = D.res.body;
  let decl;
  try {
    decl = parseDeclarationText(pointerBytes);
  } catch (e) {
    return done('declaration_not_the_named_one', [`the pointer URL serves a file that is not a declaration (${e.message}), so it is not the one the listing names`]);
  }
  if (!formatOf(decl)) return done('declaration_not_the_named_one', ['the pointer URL serves a JSON file whose "spec" names no declaration format, so it is not the one the listing names']);
  const gotHash = declarationHash(decl);
  report.declaration = { url: shownUrl(p.url), hash: gotHash, format: decl.spec };
  if (gotHash !== p.hash) return done('declaration_not_the_named_one', [`the pointer URL serves a declaration whose hash is ${gotHash}, not ${p.hash}: the served file is not the one the listing names`]);
  report.checked.push('the served declaration is the one the listing names (its declaration hash equals the pointer hash)');

  // One key lookup per method and domain, listed with what was fetched.
  const lookups = new Map();
  const lookupKey = (method, domain) => {
    const id = `${method} ${domain}`;
    if (!lookups.has(id)) {
      const entry = method === 'http'
        ? { purpose: 'key lookup (http)', method: 'GET', url: `https://${domain}/.well-known/mcp-registry-auth`, status: null }
        : { purpose: 'key lookup (dns)', method: 'TXT', url: `dns:${domain} (TXT)`, domain, status: null };
      report.fetched.push(entry);
      if (deadline - Date.now() <= 0) {
        entry.error = timeLimit;
        lookups.set(id, Promise.resolve({ keys: [], notes: [], error: timeLimit }));
      } else {
        lookups.set(
          id,
          Promise.resolve(keyLookup(method, domain)).then((r) => {
            if (r && Number.isInteger(r.status)) entry.status = r.status;
            if (r && r.error) entry.error = r.error;
            else if (method === 'dns') entry.answered = true;
            return r;
          }),
        );
      }
    }
    return lookups.get(id);
  };
  // A file that breaks the rules of its format is reported as verify reports it.
  const verifyOpts = (d, extra = {}) => ({ keySource: { kind: d.key.method, lookup: (domain) => lookupKey(d.key.method, domain) }, now, ...extra });
  if (validate(decl).length) {
    const r = await verifyDeclarationText(pointerBytes, { keySource: { kind: 'offline', keys: [] }, now });
    report.declaration.state = r.state;
    report.declaration.verify = r.details;
    return done(r.state, r.reasons);
  }

  // 4. Against the listing.
  reached = STEP.match;
  const mismatch = [];
  if (decl.name !== name) mismatch.push(`the declaration is for ${decl.name}, the listing for ${name}`);
  if (decl.version !== server.version) mismatch.push(`the declaration is for version ${decl.version}, the listing for version ${clip(server.version)}`);
  const pointerRemotes = compareRemotes(server.remotes, decl.remotes);
  report.remotes = pointerRemotes;
  if (mismatch.length === 0 && !pointerRemotes.match) mismatch.push(...remoteReasons(pointerRemotes, 'the declaration'));
  if (mismatch.length) return done('listing_mismatch', mismatch);
  report.checked.push('the listing name and version equal the declaration\'s');
  report.checked.push(pointerRemotes.listingCount === 0 ? 'the listing names no remote and the declaration declares none' : `the listing's remotes equal the declared remotes (${pointerRemotes.declared.map((r) => r.url).join(', ')})`);

  // 5. Verify, as verify does, with a live key lookup by the declared method.
  // A declaration the listing names that fails only its time window (it has
  // expired, or is not valid yet) can still be followed by a newer one for the
  // same version under the same key (SPEC.md section 8a, "Newer declarations").
  reached = STEP.verify;
  const pv = await verifyDeclarationText(pointerBytes, verifyOpts(decl));
  report.declaration.state = pv.state;
  report.declaration.verify = pv.details;
  const pointerTimeOnly = pv.state === 'expired' || pv.state === 'not_yet_valid';
  if (pv.state !== 'valid' && !pointerTimeOnly) return done(pv.state, pv.reasons);

  // 6. Newer declarations for the same version, next to the by-hash file.
  reached = STEP.newer;
  const folderPath = `/.well-known/addon-declaration/${name}/`;
  const folder = `https://${host}${folderPath}`;
  const byHash = new Map([[p.hash, pointerBytes]]);
  const candidates = [];

  // Walks "previous" from a candidate back to the pointer hash.
  const walkBack = (c, d, bytes) => walkHistory({ start: { hash: c.hash, bytes, decl: d, url: c.url }, target: p.hash, folder, name, known: byHash, fetch: (url) => get('earlier declaration (by hash)', url, { maxBytes: MAX_DECLARATION_BYTES }) });

  // Reads one candidate file and decides what it is. Fills c.
  async function examine(c) {
    const R = await get(`newer declaration (${c.path})`, c.url, { maxBytes: MAX_DECLARATION_BYTES });
    if (R.error) {
      c.result = 'unreachable';
      c.reason = R.error.tooLarge ? `larger than ${MAX_DECLARATION_BYTES} bytes` : R.error.message;
      return;
    }
    c.status = R.res.status;
    if (R.res.status !== 200) {
      c.result = R.res.status === 404 || R.res.status === 410 ? 'absent' : 'unreachable';
      c.reason = `HTTP ${R.res.status}${R.res.status >= 300 && R.res.status < 400 ? ' (a redirect, which is not followed)' : ''}`;
      return;
    }
    let d;
    try {
      d = parseDeclarationText(R.res.body);
    } catch (e) {
      c.result = 'invalid';
      c.reason = `not a declaration: ${e.message}`;
      return;
    }
    if (!formatOf(d) || validate(d).length) {
      c.result = 'invalid';
      c.reason = `not a valid declaration: ${formatOf(d) ? clip(validate(d).join('; ')) : 'its "spec" names no declaration format'}`;
      return;
    }
    c.hash = declarationHash(d);
    c.format = d.spec;
    if (c.hash === p.hash) {
      c.result = 'same_as_pointer';
      return;
    }
    if (d.name !== name) {
      c.result = 'invalid';
      c.reason = `it is for ${d.name}, not ${name}`;
      return;
    }
    if (d.version !== server.version) {
      c.result = 'other_version';
      c.reason = `it is for version ${d.version}, not ${clip(server.version)}`;
      return;
    }
    const dup = candidates.find((x) => x.hash === c.hash);
    if (dup) {
      c.result = dup.result;
      c.reason = `the same declaration as ${dup.path}`;
      c.sameAs = dup.path;
      return;
    }
    const w = await walkBack(c, d, R.res.body);
    if (w.walk) {
      Object.assign(c, w.walk);
      return;
    }
    const steps = w.steps;
    // Every link is verified as verify does, each with the declaration it
    // follows. Only the newest is checked against the clock: the ones between
    // it and the declaration the listing names were superseded by it.
    steps.push({ hash: p.hash, bytes: pointerBytes, decl, url: p.url });
    c.links = steps.length - 1;
    for (let i = 0; i < steps.length - 1; i++) {
      const s = steps[i];
      const r = await verifyDeclarationText(s.bytes, verifyOpts(s.decl, { previousText: steps[i + 1].bytes, ...(i > 0 ? { checkTime: false } : {}) }));
      if (r.state !== 'valid') {
        const timeOnly = i === 0 && (r.state === 'expired' || r.state === 'not_yet_valid');
        Object.assign(c, { result: timeOnly ? r.state : 'invalid', reason: `${s.hash} gives ${r.state}: ${clip(r.reasons.join('; '))}`, state: r.state });
        return;
      }
      // A link across a change of key is not accepted as continuity (SPEC.md section 10).
      if (r.details.chain && (r.details.chain.keyChanged || r.details.chain.keyLocationChanged)) {
        Object.assign(c, { result: 'key_changed', reason: `the link from ${s.hash} to ${steps[i + 1].hash} crosses a change of key${r.details.chain.keyLocationChanged ? ' or key location' : ''}; a chain link does not show that the same holder signed both, so the newer declaration is not put in force` });
        return;
      }
    }
    c.result = 'chained';
    c.chain = steps.map((s) => ({ hash: s.hash, format: s.decl.spec, issuedAt: s.decl.issuedAt, url: shownUrl(s.url) }));
    c.steps = steps;
    candidates.push(c);
  }

  for (const rel of newerPaths) {
    const c = { path: rel, url: folder + rel, status: null, result: null };
    report.newer.push(c);
    try {
      await examine(c);
    } catch (e) {
      // One bad file never aborts the check: it is set aside.
      c.result = 'invalid';
      c.reason = `it could not be checked (${e && typeof e.message === 'string' ? clip(e.message) : 'unexpected error'})`;
      delete c.steps;
    }
  }

  // Of the chained candidates, the newest: one whose history holds the other.
  let inForce = null;
  if (candidates.length === 1) inForce = candidates[0];
  else if (candidates.length > 1) {
    const [a, b] = candidates;
    if (a.chain.some((x) => x.hash === b.hash)) inForce = a;
    else if (b.chain.some((x) => x.hash === a.hash)) inForce = b;
    else {
      inForce = a;
      report.notes.push(`${a.path} and ${b.path} hold two newer declarations that do not follow one another (a fork in the history); the one at ${a.path} is used`);
    }
  }
  const forceSteps = inForce ? inForce.steps : null;
  for (const c of report.newer) {
    if (c.result === 'chained') c.result = c === inForce ? 'in_force' : 'superseded';
    if (c.sameAs && inForce && c.hash === inForce.hash) c.result = 'in_force';
    delete c.steps;
  }
  // A valid declaration for this version that was not put in force is "set
  // aside" (newerSetAside in --json), and each one gets a note with its reason.
  const SET_ASIDE = ['not_chained', 'key_changed', 'invalid', 'expired', 'not_yet_valid', 'unreachable'];
  for (const c of report.newer) {
    if (!SET_ASIDE.includes(c.result)) continue;
    if (c.hash) {
      report.newerSetAside = true;
      report.notes.push(`${c.path} holds another declaration for this version that was not put in force: ${c.reason}`);
    } else if (c.result === 'invalid') report.notes.push(`${c.path} holds a file that is not a valid declaration: ${c.reason}`);
    else report.notes.push(`${c.path} could not be read: ${c.reason}`);
  }

  if (pointerTimeOnly && !inForce) return done(pv.state, pv.reasons);

  let forceBytes = pointerBytes;
  let forceDecl = decl;
  let forcePrev;
  if (inForce) {
    forceBytes = forceSteps[0].bytes;
    forceDecl = forceSteps[0].decl;
    forcePrev = forceSteps[1].bytes;
    report.chain = inForce.chain;
    report.inForce = { source: inForce.path, url: inForce.url, hash: inForce.hash, format: forceDecl.spec, state: null };
    // The newer declaration is the publisher's signed statement about the
    // remotes now; one that differs from the listing is a mismatch, not set aside.
    const cmp = compareRemotes(server.remotes, forceDecl.remotes);
    report.remotesInForce = cmp;
    if (!cmp.match) {
      for (const c of report.newer) if (c.result === 'in_force') c.result = 'remotes_differ';
      return done('listing_mismatch', remoteReasons(cmp, `the newer declaration at ${inForce.path}`));
    }
    report.checked.push(`a newer declaration for this version (${inForce.path}) follows the one the listing names in ${inForce.links} link${inForce.links === 1 ? '' : 's'} under the same key, and declares the same remotes`);
    if (pointerTimeOnly) report.notes.push(`the declaration the listing names ${pv.state === 'expired' ? `expired at ${decl.expiresAt}` : `is not valid yet (issued at ${decl.issuedAt})`}; a newer declaration for this version that follows it under the same key is in force`);
  } else {
    report.inForce = { source: 'pointer', url: shownUrl(p.url), hash: p.hash, format: decl.spec, state: null };
    report.chain = [{ hash: p.hash, format: decl.spec, issuedAt: decl.issuedAt, url: shownUrl(p.url) }];
  }

  // 7. The tool check of the declaration in force.
  let pages = toolsPages;
  let toolsFailure = null;
  if (pages) report.tools = { check: 'run', source: 'files', pages: pages.length };
  else if (fetchTools) {
    const remote = (forceDecl.remotes || []).find((r) => r.type === 'streamable-http');
    if (!remote) {
      report.tools = { check: 'not_checked', source: 'remote', reason: 'the declaration in force names no streamable-http remote to read the tool list from' };
    } else {
      report.tools = { check: 'run', source: 'remote', remote: remote.url, protocolVersion: null, era: null, pages: 0, requests: [] };
      const keyDomain = forceDecl.key.domain;
      const rhost = new URL(remote.url).hostname;
      if (rhost !== keyDomain && !rhost.endsWith('.' + keyDomain)) report.tools.notes = [`the remote host ${rhost} is not ${keyDomain} or below it; a declaration can name an endpoint on another party's host (SPEC.md section 13)`];
      const listRequests = () => {
        for (const r of report.tools.requests) report.fetched.push({ purpose: `mcp ${r.method}`, method: r.httpMethod, rpc: r.method, url: r.url, status: r.status, ...(r.error ? { error: r.error } : {}) });
      };
      try {
        const got = await readTools(remote.url, { request });
        pages = got.pages;
        Object.assign(report.tools, { protocolVersion: got.protocolVersion, era: got.era, session: got.session, pages: got.pages.length, requests: got.requests });
        if (got.notes.length) report.tools.notes = [...(report.tools.notes || []), ...got.notes];
        listRequests();
      } catch (e0) {
        // Any error of the tools fetch is a failed fetch (or a request for
        // authorization), never an unexpected error of the command.
        const e = e0 instanceof McpFetchError ? e0 : Object.assign(new McpFetchError(`the tools fetch failed: ${e0 && typeof e0.message === 'string' ? e0.message : 'unknown error'}`), { requests: e0 && Array.isArray(e0.requests) ? e0.requests : [] });
        report.tools.requests = Array.isArray(e.requests) ? e.requests : [];
        if (e.notes && e.notes.length) report.tools.notes = [...(report.tools.notes || []), ...e.notes];
        listRequests();
        report.tools.reason = e.message;
        if (e.kind === 'authorization') report.tools.check = 'not_checked';
        else {
          report.tools.check = 'failed';
          toolsFailure = [`the tool list could not be read from ${remote.url}: ${e.message}`];
        }
      }
    }
  }

  // The declaration in force is verified as verify does (again for a newer one,
  // now with the tool list); on a failed tools fetch it is verified without one.
  const fr = await verifyDeclarationText(forceBytes, verifyOpts(forceDecl, { ...(pages ? { toolsText: pages } : {}), ...(forcePrev ? { previousText: forcePrev } : {}) }));
  report.inForce.state = fr.state;
  report.inForce.verify = fr.details;
  if (pages) report.tools.result = fr.state === 'valid' ? 'match' : fr.state === 'tools_hash_mismatch' ? 'mismatch' : 'not_reached';
  if (fr.state !== 'valid') return done(fr.state, fr.reasons);
  finalDecl = forceDecl;
  if (toolsFailure) return done('tools_fetch_failed', toolsFailure);
  return done(inForce ? 'verified_newer_declaration' : 'verified', []);
}
