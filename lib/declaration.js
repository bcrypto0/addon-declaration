// Declaration Spec: field rules, signing input, declaration hash, and the
// verification procedure, for both formats: addon-declaration/0.1 (sections 3
// to 15 of SPEC.md) and addon-declaration/0.2 (section 17, which lists only its
// differences from 0.1). Every rule reads the format from the "spec" member;
// a 0.1 declaration goes through exactly the 0.1 rules. Network access is not
// done here; the caller passes a key lookup function (see resolve.js) or
// offline keys.

import crypto from 'node:crypto';
import { canonicalize, parseStrict, hasLoneSurrogate, decodeUtf8Strict } from './jcs.js';
import { ALGS, SIG_LEN, decodeBase64Strict, verifyBytes, signBytes } from './keys.js';
import { toolsHashFromText, toolsHashFromPages } from './tools.js';
import { toolSetDigestsFromPages, InputError as ToolSetInputError, TOOL_SET_DIGEST_ID } from './tool-set-digest.js';

// SPEC_ID stays the 0.1 identifier, as before; the 0.2 one is SPEC_ID_02.
export const SPEC_ID = 'addon-declaration/0.1';
export const SPEC_ID_01 = SPEC_ID;
export const SPEC_ID_02 = 'addon-declaration/0.2';
// In format order: a declaration may follow one of the same or an earlier format only.
export const SPEC_IDS = Object.freeze([SPEC_ID_01, SPEC_ID_02]);
// What init writes when no --format is given.
export const DEFAULT_SPEC_ID = SPEC_ID_02;
export const CLOCK_SKEW_SECONDS = 300;
export const MAX_DECLARATION_BYTES = 16384;

export const STATES = Object.freeze({
  valid: 0,
  malformed: 2,
  invalid_signature: 3,
  key_not_found: 4,
  expired: 5,
  not_yet_valid: 6,
  name_domain_mismatch: 7,
  tools_hash_mismatch: 8,
  chain_mismatch: 9,
  key_lookup_failed: 10,
});

// Member order for files we write; covers both formats (a file holds the
// members of its own format only, which validate() checks).
const TOP_ORDER = ['spec', 'name', 'version', 'toolsHash', 'toolSetDigest', 'remotes', 'payment', 'contact', 'issuedAt', 'expiresAt', 'previous', 'key', 'signature'];
// Format 0.1 (unchanged).
const MEMBERS_01 = TOP_ORDER.filter((k) => k !== 'toolSetDigest');
export const REQUIRED = Object.freeze(['spec', 'name', 'version', 'toolsHash', 'contact', 'issuedAt', 'key']);
// Format 0.2: toolSetDigest in place of toolsHash, and contact optional.
const MEMBERS_02 = TOP_ORDER.filter((k) => k !== 'toolsHash');
export const REQUIRED_02 = Object.freeze(['spec', 'name', 'version', 'toolSetDigest', 'issuedAt', 'key']);
const FORMAT_RULES = {
  [SPEC_ID_01]: { members: MEMBERS_01, required: REQUIRED, other: 'toolSetDigest', otherIn: SPEC_ID_02 },
  [SPEC_ID_02]: { members: MEMBERS_02, required: REQUIRED_02, other: 'toolsHash', otherIn: SPEC_ID_01 },
};
const TOOL_SET_DIGEST_FIELDS = ['spec', 'contract', 'extras'];
// mcp-tool-set-digest/1 writes a digest as "sha256-" and the standard padded
// base64 of the 32 hash bytes (44 characters). A declaration accepts only that
// form, and only its canonical text, so each digest has one byte representation.
const TSD_DIGEST_RE = /^sha256-[A-Za-z0-9+/]{43}=$/;
const KEY_FIELDS = ['method', 'domain', 'alg', 'id'];
const REMOTE_FIELDS = ['type', 'url'];
const PAYMENT_FIELDS = ['network', 'asset', 'payTo', 'amount', 'tool'];

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const NAME_RE = /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CAIP2_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const TOKEN_RE = /^[\x21-\x7e]{1,128}$/;
const AMOUNT_RE = /^(0|[1-9][0-9]{0,77})$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// RFC 3986 characters: unreserved, reserved and "%" (checked for triplets below).
const URI_CHARS_RE = /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/;
const MAILTO_RE = /^mailto:[A-Za-z0-9._+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
// "Unsafe" characters (SPEC.md section 3): Unicode general categories Cc
// (C0, DEL, C1) and Cf (format characters: the bidirectional controls, zero
// width characters, U+00AD, U+FEFF, tag characters and the rest), the line and
// paragraph separators (Zl, Zp), private use (Co) and unassigned (Cn) code
// points, the noncharacters, every Default_Ignorable_Code_Point (this adds the
// variation selectors U+FE00 to U+FE0F and U+E0100 to U+E01EF, which can carry
// hidden bytes, the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0, U+034F,
// U+17B4, U+17B5, U+180B to U+180F and U+E0000 to U+E0FFF), the whole tag block
// U+E0000 to U+E007F, and lone surrogates (Cs, which a /u regex sees only when
// unpaired).
export const UNSAFE_CHARS_SOURCE =
  '[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}\\p{Co}\\p{Cn}\\p{Noncharacter_Code_Point}\\p{Default_Ignorable_Code_Point}\\u{E0000}-\\u{E007F}]|\\p{Cs}';
export const UNSAFE_CHARS_RE = new RegExp(UNSAFE_CHARS_SOURCE, 'u');

export const GITHUB_OUT_OF_SCOPE = 'GitHub account namespaces (io.github.*) have no domain key and are out of scope in formats 0.1 and 0.2';

export class DeclarationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeclarationError';
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function safeText(s) {
  return !UNSAFE_CHARS_RE.test(s) && !hasLoneSurrogate(s);
}

// Length in Unicode code points, as JSON Schema maxLength counts it.
function codePoints(s) {
  return [...s].length;
}

export function parseTime(s) {
  if (typeof s !== 'string' || !TIME_RE.test(s)) return null;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return null;
  // Rejects dates such as 2026-02-30 that Date would roll over, and leap seconds (:60).
  if (d.toISOString() !== s.replace('Z', '.000Z')) return null;
  return d.getTime();
}

export function isValidDomain(d) {
  if (typeof d !== 'string' || d.length > 253 || d !== d.toLowerCase()) return false;
  const labels = d.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => LABEL_RE.test(l))) return false;
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return false; // IPv4 literal or numeric TLD
  // The registry refuses github.io and its subdomains for domain authentication.
  if (d === 'github.io' || d.endsWith('.github.io')) return false;
  return true;
}

export function reverseDomain(d) {
  return d.split('.').reverse().join('.');
}

// SPEC.md section 3, "https URL": RFC 3986 characters only, scheme https, no
// userinfo, and the text equals its WHATWG URL serialization (lowercase host,
// explicit path, no default port, no backslashes or other parser fixups).
export function isHttpsUrl(u) {
  if (typeof u !== 'string' || u.length > 2048 || !u.startsWith('https://')) return false;
  if (!URI_CHARS_RE.test(u) || /%(?![0-9A-Fa-f]{2})/.test(u)) return false;
  let x;
  try {
    x = new URL(u);
  } catch {
    return false;
  }
  return x.protocol === 'https:' && x.hostname.length > 0 && x.username === '' && x.password === '' && x.href === u;
}

export function isContact(c) {
  if (typeof c !== 'string' || c.length > 256) return false;
  if (c.startsWith('mailto:')) return MAILTO_RE.test(c);
  return isHttpsUrl(c);
}

// One digest of mcp-tool-set-digest/1 in the only form a declaration accepts.
export function isToolSetDigestValue(s) {
  if (typeof s !== 'string' || !TSD_DIGEST_RE.test(s)) return false;
  const b64 = s.slice('sha256-'.length);
  const bytes = Buffer.from(b64, 'base64');
  return bytes.length === 32 && bytes.toString('base64') === b64;
}

// The format of a parsed declaration: its "spec" when that names a known
// format, else null.
export function formatOf(decl) {
  return isPlainObject(decl) && SPEC_IDS.includes(decl.spec) ? decl.spec : null;
}

function toolSetDigestProblems(t) {
  const p = [];
  const shape = 'toolSetDigest must be an object with exactly "spec", "contract" and "extras"';
  if (!isPlainObject(t)) return [shape];
  for (const k of Object.keys(t)) if (!TOOL_SET_DIGEST_FIELDS.includes(k)) p.push(`toolSetDigest has unknown field "${k}"`);
  for (const k of TOOL_SET_DIGEST_FIELDS) if (!Object.hasOwn(t, k)) p.push(`toolSetDigest is missing "${k}"${k === 'extras' ? ' (write null when no tool has a member outside name, description, inputSchema and outputSchema)' : ''}`);
  if (Object.hasOwn(t, 'spec') && t.spec !== TOOL_SET_DIGEST_ID) p.push(`toolSetDigest.spec must be "${TOOL_SET_DIGEST_ID}"`);
  const want = '"sha256-" followed by the standard padded base64 of 32 bytes (44 characters, canonical), the "digest" value the tool-set-digest command prints (not its "hex" value)';
  const form = (what, v) => {
    if (typeof v === 'string' && /^sha256:[0-9a-fA-F]{64}$/.test(v)) return `${what} is in the sha256:<hex> form, which a declaration refuses; write it as ${want}`;
    if (typeof v === 'string' && v.startsWith('sha256-')) {
      const b = v.slice('sha256-'.length);
      if (/[-_]/.test(b) && /^[A-Za-z0-9_-]+=*$/.test(b)) return `${what} uses the base64url alphabet ("-" and "_"), which a declaration refuses; write it as ${want}, with "+" and "/"`;
      if (b.length === 43 && /^[A-Za-z0-9+/]+$/.test(b)) return `${what} has no "=" padding, which a declaration requires; write it as ${want}`;
      if (/^[A-Za-z0-9+/]{43}=$/.test(b)) return `${what} is not canonical base64 (the unused bits of its last character are not zero); write it as ${want}`;
    }
    return `${what} must be ${want}`;
  };
  if (Object.hasOwn(t, 'contract') && !isToolSetDigestValue(t.contract)) p.push(form('toolSetDigest.contract', t.contract));
  if (Object.hasOwn(t, 'extras') && t.extras !== null && !isToolSetDigestValue(t.extras)) p.push(form('toolSetDigest.extras', t.extras) + ', or null');
  return p;
}

// Returns a list of problems; empty means the object follows the field rules.
// unsigned: true allows key.alg, key.id and signature to be absent (the state
// before `sign`), and requires signature to be absent.
// The rules are those of the format named by "spec". An object whose "spec" is
// missing or names no known format is checked against the 0.1 member list, as
// before format 0.2 existed, after the "spec" problem itself.
export function validate(decl, { unsigned = false } = {}) {
  const p = [];
  if (!isPlainObject(decl)) return ['declaration is not a JSON object'];
  const format = formatOf(decl) || SPEC_ID_01;
  const rules = FORMAT_RULES[format];
  for (const k of Object.keys(decl)) {
    if (rules.members.includes(k)) continue;
    if (k === rules.other && formatOf(decl)) p.push(`"${k}" is a member of ${rules.otherIn}, not of ${format}; ${format === SPEC_ID_02 ? 'a 0.2 declaration carries "toolSetDigest" in place of "toolsHash"' : 'a 0.1 declaration carries "toolsHash"'}`);
    else p.push(`unknown field "${k}"`);
  }
  for (const k of rules.required) if (!Object.hasOwn(decl, k)) p.push(`missing field "${k}"`);
  if (unsigned) {
    if (Object.hasOwn(decl, 'signature')) p.push('an unsigned declaration must not carry "signature"');
  } else if (!Object.hasOwn(decl, 'signature')) {
    p.push('missing field "signature"');
  }

  if (Object.hasOwn(decl, 'spec') && !SPEC_IDS.includes(decl.spec)) p.push(`spec must be "${SPEC_ID_01}" or "${SPEC_ID_02}"`);
  if (format === SPEC_ID_02 && Object.hasOwn(decl, 'toolSetDigest')) p.push(...toolSetDigestProblems(decl.toolSetDigest));
  if (Object.hasOwn(decl, 'name')) {
    const n = decl.name;
    if (typeof n !== 'string' || n.length < 3 || n.length > 200 || !NAME_RE.test(n)) p.push('name must match the registry server name rule (namespace/name, 3 to 200 chars)');
    // "." and ".." would be dot segments in the section 8 paths.
    else if (n.split('/').some((part) => part === '.' || part === '..')) p.push('name must not use "." or ".." as the namespace or the server part');
  }
  if (Object.hasOwn(decl, 'version')) {
    const v = decl.version;
    if (typeof v !== 'string' || !safeText(v) || codePoints(v) < 1 || codePoints(v) > 255) p.push('version must be a string of 1 to 255 code points without unsafe characters (control, format, bidirectional, separator, invisible, variation selector, private use, unassigned or noncharacter code points; SPEC.md section 3)');
  }
  if (format === SPEC_ID_01 && Object.hasOwn(decl, 'toolsHash') && (typeof decl.toolsHash !== 'string' || !HASH_RE.test(decl.toolsHash))) p.push('toolsHash must be "sha256:" followed by 64 lowercase hex digits');

  if (Object.hasOwn(decl, 'remotes')) {
    const r = decl.remotes;
    if (!Array.isArray(r) || r.length < 1 || r.length > 16) p.push('remotes must be an array of 1 to 16 entries');
    else
      r.forEach((e, n) => {
        if (!isPlainObject(e)) return p.push(`remotes[${n}] is not an object`);
        for (const k of Object.keys(e)) if (!REMOTE_FIELDS.includes(k)) p.push(`remotes[${n}] unknown field "${k}"`);
        if (e.type !== 'streamable-http' && e.type !== 'sse') p.push(`remotes[${n}].type must be "streamable-http" or "sse"`);
        if (!isHttpsUrl(e.url)) p.push(`remotes[${n}].url must be an https URL in canonical form, without userinfo or template variables, at most 2048 characters`);
      });
  }

  if (Object.hasOwn(decl, 'payment')) {
    const pay = decl.payment;
    if (!Array.isArray(pay) || pay.length < 1 || pay.length > 16) p.push('payment must be an array of 1 to 16 entries');
    else
      pay.forEach((e, n) => {
        if (!isPlainObject(e)) return p.push(`payment[${n}] is not an object`);
        for (const k of Object.keys(e)) if (!PAYMENT_FIELDS.includes(k)) p.push(`payment[${n}] unknown field "${k}"`);
        if (typeof e.network !== 'string' || !CAIP2_RE.test(e.network)) p.push(`payment[${n}].network must be a CAIP-2 chain id such as "eip155:8453"`);
        if (typeof e.asset !== 'string' || !TOKEN_RE.test(e.asset)) p.push(`payment[${n}].asset must be 1 to 128 printable ASCII characters without spaces`);
        // x402 v2 writes a fiat price as an ISO 4217 code in "asset"; fiat is out of scope in 0.1 and 0.2.
        else if (/^[A-Z]{3}$/.test(e.asset)) p.push(`payment[${n}].asset looks like an ISO 4217 currency code; prices in fiat currency are out of scope in formats 0.1 and 0.2 (name the token's on chain identifier)`);
        if (typeof e.payTo !== 'string' || !TOKEN_RE.test(e.payTo)) p.push(`payment[${n}].payTo must be 1 to 128 printable ASCII characters without spaces`);
        if (typeof e.amount !== 'string' || !AMOUNT_RE.test(e.amount)) p.push(`payment[${n}].amount must be a base 10 integer string of at most 78 digits in the asset's smallest unit`);
        if (Object.hasOwn(e, 'tool') && (typeof e.tool !== 'string' || e.tool.length < 1 || e.tool.length > 128 || !safeText(e.tool))) p.push(`payment[${n}].tool must be a tool name of 1 to 128 characters without unsafe characters (control, format, bidirectional, separator, invisible, variation selector, private use, unassigned or noncharacter code points; SPEC.md section 3)`);
      });
  }

  if (Object.hasOwn(decl, 'contact') && !isContact(decl.contact)) p.push('contact must be a mailto: address or an https URL in canonical form, at most 256 characters');

  let issued = null;
  if (Object.hasOwn(decl, 'issuedAt')) {
    issued = parseTime(decl.issuedAt);
    if (issued === null) p.push('issuedAt must be UTC in the form YYYY-MM-DDTHH:MM:SSZ');
  }
  if (Object.hasOwn(decl, 'expiresAt')) {
    const exp = parseTime(decl.expiresAt);
    if (exp === null) p.push('expiresAt must be UTC in the form YYYY-MM-DDTHH:MM:SSZ');
    else if (issued !== null && exp <= issued) p.push('expiresAt must be later than issuedAt');
  }
  if (Object.hasOwn(decl, 'previous') && (typeof decl.previous !== 'string' || !HASH_RE.test(decl.previous))) p.push('previous must be "sha256:" followed by 64 lowercase hex digits');

  if (Object.hasOwn(decl, 'key')) {
    const k = decl.key;
    if (!isPlainObject(k)) p.push('key must be an object');
    else {
      for (const f of Object.keys(k)) if (!KEY_FIELDS.includes(f)) p.push(`key has unknown field "${f}"`);
      if (k.method !== 'dns' && k.method !== 'http') p.push('key.method must be "dns" or "http"');
      if (!isValidDomain(k.domain)) p.push('key.domain must be a lowercase domain name with at least two labels');
      const needAlgId = !unsigned || Object.hasOwn(k, 'alg') || Object.hasOwn(k, 'id');
      if (needAlgId) {
        if (!ALGS.includes(k.alg)) p.push('key.alg must be "ed25519" or "ecdsap384"');
        if (typeof k.id !== 'string' || !HASH_RE.test(k.id)) p.push('key.id must be "sha256:" followed by 64 lowercase hex digits');
      }
    }
  }

  if (!unsigned && Object.hasOwn(decl, 'signature')) {
    const sig = decodeBase64Strict(decl.signature);
    if (!sig) p.push('signature must be standard padded base64');
    else if (isPlainObject(decl.key) && ALGS.includes(decl.key.alg) && sig.length !== SIG_LEN[decl.key.alg]) p.push(`signature must be ${SIG_LEN[decl.key.alg]} bytes for ${decl.key.alg}`);
  }
  return p;
}

// Fixed member order for files we write. The order has no effect on the
// signature, which covers the canonical form.
export function ordered(decl) {
  const out = {};
  for (const k of TOP_ORDER) if (Object.hasOwn(decl, k)) out[k] = decl[k];
  if (isPlainObject(decl.key)) {
    const key = {};
    for (const k of KEY_FIELDS) if (Object.hasOwn(decl.key, k)) key[k] = decl.key[k];
    out.key = key;
  }
  if (isPlainObject(decl.toolSetDigest)) {
    // Known members first; any other member is kept (validate() reports it).
    const t = {};
    for (const k of TOOL_SET_DIGEST_FIELDS) if (Object.hasOwn(decl.toolSetDigest, k)) t[k] = decl.toolSetDigest[k];
    for (const k of Object.keys(decl.toolSetDigest)) if (!Object.hasOwn(t, k)) t[k] = decl.toolSetDigest[k];
    out.toolSetDigest = t;
  }
  return out;
}

// The exact bytes that are signed: the ASCII spec id, one LF byte, then the
// UTF-8 RFC 8785 form of the declaration with the "signature" member removed.
// The spec id is the declaration's own "spec" member, so the prefix always
// equals it: a signature made under one format cannot be read as one made
// under the other. For a 0.1 declaration this is "addon-declaration/0.1", as
// it has always been. An object whose "spec" names no known format has no
// signing input.
export function signingInput(decl) {
  const spec = formatOf(decl);
  if (!spec) throw new DeclarationError(`no signing input: "spec" must be "${SPEC_ID_01}" or "${SPEC_ID_02}"`);
  const body = {};
  for (const k of Object.keys(decl)) if (k !== 'signature') body[k] = decl[k];
  return Buffer.concat([Buffer.from(spec + '\n', 'ascii'), Buffer.from(canonicalize(body), 'utf8')]);
}

// Declaration hash, used by "previous". Covers the signing input, so it does
// not depend on the signature bytes (ECDSA signatures are malleable).
export function declarationHash(decl) {
  return 'sha256:' + crypto.createHash('sha256').update(signingInput(decl)).digest('hex');
}

// input: the file bytes (Buffer) or a string. The size limit is on the bytes;
// bytes that are not valid UTF-8 are refused.
export function parseDeclarationText(input) {
  const size = typeof input === 'string' ? Buffer.byteLength(input, 'utf8') : input.length;
  if (size > MAX_DECLARATION_BYTES) throw new DeclarationError(`declaration is larger than ${MAX_DECLARATION_BYTES} bytes`);
  return parseStrict(decodeUtf8Strict(input));
}

// Applies the namespace rule of the registry's authentication method:
//   http: a key at https://D/.well-known/mcp-registry-auth proves only the
//         namespace reverse(D)
//   dns:  a TXT key at D proves reverse(D) and every namespace that starts with
//         reverse(D) + "." (the registry grants "<reverse(D)>.*")
export function nameMatchesDomain(name, domain, method) {
  const ns = name.split('/')[0].toLowerCase();
  const rev = reverseDomain(domain);
  if (ns === rev) return true;
  return method === 'dns' && ns.startsWith(rev + '.');
}

// null when the key domain and method can prove the namespace of name, or the
// reason the verifier gives for name_domain_mismatch.
export function namespaceProblem(name, domain, method) {
  const ns = name.split('/')[0].toLowerCase();
  if (ns === 'io.github' || ns.startsWith('io.github.')) return GITHUB_OUT_OF_SCOPE;
  if (nameMatchesDomain(name, domain, method)) return null;
  const why =
    method === 'http'
      ? 'an http key proves only the exact namespace; a key on a parent domain works only with the dns method'
      : 'a dns key proves its own namespace and the namespaces that start with it';
  return `namespace "${ns}" is not covered by ${method === 'http' ? 'an' : 'a'} ${method} key at ${domain} (${why})`;
}

// Where a declaration is served (SPEC.md section 8). Path segments use
// percent encoding of every byte outside the RFC 3986 unreserved set.
export function encodePathSegment(s) {
  let out = '';
  for (const b of Buffer.from(s, 'utf8')) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9\-._~]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

export function declarationPaths(decl) {
  const base = `https://${decl.key.domain}/.well-known/addon-declaration/${decl.name}`;
  return {
    byHash: `${base}/by-hash/${declarationHash(decl).slice('sha256:'.length)}.json`,
    version: `${base}/versions/${encodePathSegment(decl.version)}.json`,
    latest: `${base}/latest.json`,
  };
}

export function signDeclaration(unsignedDecl, loadedKey) {
  if (!isPlainObject(unsignedDecl) || !isPlainObject(unsignedDecl.key)) throw new DeclarationError('declaration and its "key" must be JSON objects');
  const merged = { ...unsignedDecl, key: { ...unsignedDecl.key, alg: loadedKey.alg, id: loadedKey.public.id } };
  delete merged.signature;
  const problems = validate(merged, { unsigned: true });
  if (problems.length) throw new DeclarationError(problems.join('; '));
  // Refuse what the verifier would report as name_domain_mismatch.
  const nsProblem = namespaceProblem(merged.name, merged.key.domain, merged.key.method);
  if (nsProblem) throw new DeclarationError(nsProblem);
  const decl = ordered(merged);
  const input = signingInput(decl);
  const sig = signBytes(loadedKey.alg, loadedKey.privateKey, input);
  if (!verifyBytes(loadedKey.public, input, sig)) throw new DeclarationError('self check failed: the new signature does not verify');
  const signed = ordered({ ...decl, signature: sig.toString('base64') });
  const size = Buffer.byteLength(JSON.stringify(signed, null, 2) + '\n', 'utf8');
  if (size > MAX_DECLARATION_BYTES) throw new DeclarationError(`the signed declaration would be ${size} bytes; the limit is ${MAX_DECLARATION_BYTES}`);
  return signed;
}

function result(state, reasons, details) {
  return { state, exitCode: STATES[state], reasons, details };
}

function normalizeNow(now) {
  if (now === undefined) return Date.now();
  if (now instanceof Date) now = now.getTime();
  if (typeof now !== 'number' || !Number.isFinite(now)) throw new TypeError('options.now must be epoch milliseconds (a finite number) or a valid Date');
  return now;
}

// options:
//   keySource: { kind: 'offline', keys } or { kind: 'dns'|'http', lookup: async (domain) => ({ keys, notes, error }) }
//              A live lookup must use the method the declaration names in key.method;
//              a different kind throws (SPEC.md section 9).
//   now: epoch milliseconds or a Date; the current time when absent. Anything else throws.
//   toolsText: optional text or bytes of the tool list the verifier received, or
//              an array of them, one per tools/list page in order
//   toolsHash: optional tools hash already computed by the caller (format 0.1 only;
//              a 0.2 declaration is checked against the tool list itself)
//   previousText: optional text of the declaration this one says it follows
//   formats: optional list of the formats (spec ids) this check accepts; all
//            known formats when absent. A declaration of another format is
//            malformed for this check. It applies to the declaration checked,
//            not to the earlier one of a link check (section 17).
//   checkTime: false skips step 5 (the time window) and lists it as not
//            checked. check-listing uses it only for the declarations between
//            the newest one and the one a listing names (SPEC.md section 8a).
export async function verifyDeclarationText(text, options) {
  const { keySource, toolsHash, toolsText, previousText } = options;
  const now = normalizeNow(options.now);
  const formats = options.formats === undefined ? SPEC_IDS : options.formats;
  if (!Array.isArray(formats) || formats.length === 0 || !formats.every((f) => SPEC_IDS.includes(f))) throw new TypeError(`options.formats must be a nonempty list of ${SPEC_IDS.join(', ')}`);
  const details = { checked: [], notChecked: [] };

  let decl;
  try {
    decl = parseDeclarationText(text);
  } catch (e) {
    return result('malformed', [e.message], details);
  }
  const format = formatOf(decl);
  // The format whose rules were applied, reported even when they failed.
  // formatAccepted tells a refusal by the format setting of this check (the
  // file may be a well formed declaration) apart from a broken file.
  if (format) {
    details.format = format;
    details.formatAccepted = formats.includes(format);
  }
  if (format && !formats.includes(format)) return result('malformed', [`format ${format} is not accepted by this check (accepted: ${formats.join(', ')}); the file was not checked further, so it may be a well formed declaration of that format`], details);
  const problems = validate(decl);
  if (problems.length) return result('malformed', problems, details);
  if (format === SPEC_ID_02 && toolsHash !== undefined) throw new DeclarationError(`a tools hash cannot check a declaration in format ${SPEC_ID_02}, which carries the two digests of ${TOOL_SET_DIGEST_ID}; give the tool list`);
  details.name = decl.name;
  details.version = decl.version;
  details.keyId = decl.key.id;
  details.alg = decl.key.alg;
  details.declarationHash = declarationHash(decl);

  if (keySource.kind !== 'offline' && keySource.kind !== decl.key.method) {
    throw new DeclarationError(`the declaration names key.method "${decl.key.method}"; look the key up by that method, not by ${keySource.kind}`);
  }

  // key.method is signed and decides the namespace rule, for live and offline checks alike.
  const method = decl.key.method;
  const nsProblem = namespaceProblem(decl.name, decl.key.domain, method);
  if (nsProblem) return result('name_domain_mismatch', [nsProblem], details);
  details.checked.push(`name: namespace covered by ${method === 'http' ? 'an' : 'a'} ${method} key at ${decl.key.domain}`);

  let candidates;
  if (keySource.kind === 'offline') {
    candidates = keySource.keys;
    details.keySource = 'offline: supplied by the person running the check; publication at the domain was not checked';
  } else {
    details.keySource = method === 'dns' ? `dns: TXT record at ${decl.key.domain}` : `http: https://${decl.key.domain}/.well-known/mcp-registry-auth`;
    const found = await keySource.lookup(decl.key.domain);
    if (found.error) return result('key_lookup_failed', [found.error, ...(found.notes || [])], details);
    candidates = found.keys;
    if (found.notes && found.notes.length) details.keyNotes = found.notes;
  }
  // The http method reads only MCPv1 records (section 9), so an ADKv1 record
  // cannot stand for an http key offline either.
  const usable = method === 'http' ? candidates.filter((k) => k.record !== 'addon') : candidates;
  const pub = usable.find((k) => k.alg === decl.key.alg && k.id === decl.key.id);
  if (!pub) {
    const reasons = [`no ${decl.key.alg} key with id ${decl.key.id} among ${candidates.length} key(s) from ${keySource.kind === 'offline' ? 'the supplied key' : details.keySource}`];
    if (usable.length !== candidates.length && candidates.some((k) => k.alg === decl.key.alg && k.id === decl.key.id)) reasons.push('the matching key is a v=ADKv1 record, which the http method does not read');
    return result('key_not_found', [...reasons, ...(details.keyNotes || [])], details);
  }
  if (pub.record) details.keyRecord = pub.record === 'addon' ? 'ADKv1 record, declaration only key' : 'MCPv1 record, registry login key';

  const sig = decodeBase64Strict(decl.signature);
  if (!verifyBytes(pub, signingInput(decl), sig)) return result('invalid_signature', ['the signature does not match the declaration content and key'], details);
  details.checked.push('signature');

  if (options.checkTime === false) {
    details.notChecked.push('time window (an earlier declaration on a history; only the newest one is checked against the clock)');
  } else {
    const issued = parseTime(decl.issuedAt);
    if (issued > now + CLOCK_SKEW_SECONDS * 1000) return result('not_yet_valid', [`issuedAt ${decl.issuedAt} is in the future`], details);
    if (Object.hasOwn(decl, 'expiresAt') && parseTime(decl.expiresAt) <= now) return result('expired', [`expired at ${decl.expiresAt}`], details);
    details.checked.push('time window');
  }

  // Step 6 failed: step 7 is not run, and the output says so (section 11).
  const toolsFailed = (reasons) => {
    if (previousText !== undefined) details.notChecked.push('chain link (not run: the check stopped at the tool check)');
    else if (Object.hasOwn(decl, 'previous')) details.notChecked.push('chain link (previous declaration not given)');
    else details.notChecked.push('chain link (this declaration names no previous declaration)');
    return result('tools_hash_mismatch', reasons, details);
  };

  if (format === SPEC_ID_02) {
    if (toolsText !== undefined) {
      const cmp = compareToolSetDigest(decl.toolSetDigest, toolsText);
      details.toolSetDigest = cmp.summary;
      if (cmp.reasons.length) return toolsFailed(cmp.reasons);
      const ambiguous = cmp.summary.repeatedMembers > 0 || cmp.summary.repeatedNames.length > 0;
      details.checked.push(`tool set digest (${TOOL_SET_DIGEST_ID}): contract and extras${ambiguous ? '; the list repeats a tool name or a member name, which the digests read in only one of several ways (see the notes)' : ''}`);
    } else {
      details.notChecked.push('tool set digest (no tool list given)');
    }
  } else {
    let computed = toolsHash;
    if (toolsText !== undefined) {
      try {
        computed = Array.isArray(toolsText) ? toolsHashFromPages(toolsText) : toolsHashFromText(toolsText);
      } catch (e) {
        return toolsFailed([`the received tool list is invalid, so it cannot match the declared one: ${e.message}`]);
      }
    }
    if (computed !== undefined) {
      if (computed !== decl.toolsHash) return toolsFailed([`declared ${decl.toolsHash}, computed ${computed}`]);
      details.checked.push('tools hash');
    } else {
      details.notChecked.push('tools hash (no tool list given)');
    }
  }

  if (previousText !== undefined) {
    const link = checkChain(decl, previousText, pub, candidates);
    if (link.reasons.length) return result('chain_mismatch', link.reasons, details);
    details.checked.push(...link.checked);
    details.notChecked.push(...link.notChecked);
    if (link.notes.length) details.notes = link.notes;
    details.chain = link.chain;
  } else if (Object.hasOwn(decl, 'previous')) {
    details.notChecked.push('chain link (previous declaration not given)');
  } else {
    details.notChecked.push('chain link (this declaration names no previous declaration)');
  }

  return result('valid', [], details);
}

// Step 6 for format 0.2 (SPEC.md section 17): the two digests of
// mcp-tool-set-digest/1 computed from the received list, under that
// document's input rules, compared one by one with the declared ones.
// toolsText: the text or bytes of the list, or an array of them, one per page.
// Returns { reasons, summary }; reasons nonempty means tools_hash_mismatch.
// summary.contract and summary.extras are each { result, declared, computed }
// with result "match", "mismatch" or "no_digest" (then also code, the TSD
// error code, or null when the list cannot be read at all, and detail).
// summary.differs names the digests whose result is "mismatch" (a computed
// value that differs from the declared one); summary.noDigest names those whose
// result is "no_digest" (the list could not be compared for that digest, which
// is not evidence of a change); summary.comparable is false when noDigest is
// not empty. summary.repeatedMembers (a count) and summary.repeatedNames (a
// list of { name, count }) report the input that the digests read in only one
// of several possible ways (SPEC.md T17); both are null when the list could not
// be read. summary.notes says the same in words.
export function compareToolSetDigest(declared, toolsText) {
  const pages = Array.isArray(toolsText) ? toolsText : [toolsText];
  let r;
  try {
    r = toolSetDigestsFromPages(pages);
  } catch (e) {
    if (!(e instanceof ToolSetInputError)) throw e;
    const none = (kind) => ({ result: 'no_digest', declared: declared[kind], computed: null, code: null, detail: e.message });
    const summary = { spec: TOOL_SET_DIGEST_ID, contract: none('contract'), extras: none('extras'), differs: [], noDigest: ['contract', 'extras'], comparable: false, repeatedMembers: null, repeatedNames: null };
    return { summary, reasons: [`the received tool list could not be compared with the declared digests: it cannot be read under ${TOOL_SET_DIGEST_ID} (${e.message}), so it has neither digest. This is not evidence that the tools changed; the check fails closed`] };
  }
  const shown = (v) => (v === null ? 'null (no tool has extras)' : v);
  const summary = { spec: TOOL_SET_DIGEST_ID };
  for (const kind of ['contract', 'extras']) {
    const got = r[kind];
    if (got.error) summary[kind] = { result: 'no_digest', declared: declared[kind], computed: null, code: got.error, detail: got.detail };
    else summary[kind] = { result: got.digest === declared[kind] ? 'match' : 'mismatch', declared: declared[kind], computed: got.digest };
  }
  summary.differs = ['contract', 'extras'].filter((k) => summary[k].result === 'mismatch');
  summary.noDigest = ['contract', 'extras'].filter((k) => summary[k].result === 'no_digest');
  summary.comparable = summary.noDigest.length === 0;
  summary.repeatedMembers = r.repeatedMembers;
  summary.repeatedNames = r.repeatedNames;
  if (r.notes.length) summary.notes = r.notes;
  const reasons = [];
  const c = summary.contract;
  const x = summary.extras;
  const notCompared = (kind, d) =>
    `the ${kind} digest could not be computed from the received tool list under ${TOOL_SET_DIGEST_ID} (${d.code}: ${d.detail})${d.code === 'TSD-PAGE' ? '; the list given to the verifier is incomplete' : ''}, so it could not be compared with the declared one. This is not evidence that the tools changed; the check fails closed`;
  if (c.result === 'mismatch') reasons.push(`the contract digest differs: declared ${c.declared}, computed ${c.computed}. A tool was added, removed or renamed, or a description, inputSchema or outputSchema changed: the tools a model calls are not the declared ones`);
  if (c.result === 'no_digest') reasons.push(notCompared('contract', c));
  if (x.result === 'mismatch') {
    const only = c.result === 'match' ? 'only the extras digest differs (the contract digest matches)' : c.result === 'mismatch' ? 'the extras digest differs too' : 'the extras digest differs';
    reasons.push(`${only}: declared ${shown(x.declared)}, computed ${shown(x.computed)}. A member other than name, description, inputSchema and outputSchema changed, such as title, annotations, icons or _meta`);
  }
  if (x.result === 'no_digest') reasons.push(notCompared('extras', x));
  return { summary, reasons };
}

// Labels of the link entry in "checked". A link across a key change gets its
// own wording, so a program cannot read it as the same holder (SPEC.md section 7).
export const CHAIN_LINK_SAME_KEY = 'chain link to previous declaration';
export const CHAIN_LINK_KEY_CHANGED = 'chain link (hash, name and order only; the key changed, so this does not show continuity)';

// The link check (SPEC.md section 7). A link shows only what the newer signer
// chose to point at. The earlier signature is checked if the key it
// names is at hand: the same key as this declaration's, or another key among
// the candidate keys. A history that key did not sign fails. When the key
// changed, the link says nothing about who signed the earlier declaration;
// that is reported in chain.keyChanged and as a note, and when the earlier key
// is not at hand the earlier signature has to be checked on its own (its key
// may have been rotated out).
// pub: the key that verified decl, when known. candidates: the other keys the
// verifier was given or looked up (offline keys, or the records found live).
// Returns { reasons, notes, checked, notChecked, chain }; reasons nonempty means chain_mismatch.
export function checkChain(decl, previousText, pub, candidates = []) {
  const out = { reasons: [], notes: [], checked: [], notChecked: [], chain: null };
  let prev;
  try {
    prev = parseDeclarationText(previousText);
  } catch (e) {
    out.reasons.push(`previous declaration is not valid JSON: ${e.message}`);
    return out;
  }
  const problems = validate(prev);
  if (problems.length) {
    out.reasons.push(`previous declaration is malformed: ${problems.join('; ')}`);
    if (isPlainObject(prev) && !Object.hasOwn(prev, 'signature')) out.reasons.push('the previous declaration looks unsigned (no "signature"); give the signed declaration it follows, not the unsigned file');
    return out;
  }
  // A declaration may follow one of its own format or an earlier one (0.2 after
  // 0.1 is the upgrade path); going back to an earlier format is refused.
  if (SPEC_IDS.indexOf(prev.spec) > SPEC_IDS.indexOf(decl.spec)) out.reasons.push(`a declaration in format ${decl.spec} cannot follow one in format ${prev.spec}: a link back to an earlier format is refused (SPEC.md section 17.5)`);
  if (!Object.hasOwn(decl, 'previous')) out.reasons.push('this declaration has no "previous" field');
  else if (decl.previous !== declarationHash(prev)) out.reasons.push(`"previous" is ${decl.previous} but the given declaration hashes to ${declarationHash(prev)}`);
  if (prev.name !== decl.name) out.reasons.push(`name changed from "${prev.name}" to "${decl.name}"`);
  if (parseTime(prev.issuedAt) > parseTime(decl.issuedAt)) out.reasons.push('previous declaration was issued later than this one');
  if (out.reasons.length) return out;

  const sameKey = prev.key.alg === decl.key.alg && prev.key.id === decl.key.id;
  const matches = (k) => k && k.alg === prev.key.alg && k.id === prev.key.id;
  let prevPub = null;
  if (sameKey) prevPub = matches(pub) ? pub : null;
  // The record kind rule of section 9 applies to the earlier key's own method.
  else prevPub = (candidates || []).find((k) => matches(k) && !(prev.key.method === 'http' && k.record === 'addon')) || null;

  if (prevPub) {
    if (!verifyBytes(prevPub, signingInput(prev), decodeBase64Strict(prev.signature))) {
      out.reasons.push(
        sameKey
          ? 'the previous declaration names the same key, but its signature does not verify with that key'
          : `the previous declaration names ${prev.key.alg} key ${prev.key.id}, which is among the keys given, but its signature does not verify with that key`,
      );
      return out;
    }
  }
  const locationChanged = prev.key.method !== decl.key.method || prev.key.domain !== decl.key.domain;
  out.chain = {
    previous: decl.previous,
    keyChanged: !sameKey,
    previousKey: { method: prev.key.method, domain: prev.key.domain, alg: prev.key.alg, id: prev.key.id },
    previousSignature: prevPub ? 'checked' : 'not_checked',
    keyLocationChanged: locationChanged,
    previousFormat: prev.spec,
  };
  out.checked.push(sameKey ? CHAIN_LINK_SAME_KEY : CHAIN_LINK_KEY_CHANGED);
  if (prevPub) out.checked.push(sameKey ? 'signature of previous declaration (same key)' : 'signature of previous declaration (with the key it names, which was among the keys given)');
  if (!sameKey) {
    out.notes.push(`key changed between the two declarations: the earlier one names ${prev.key.alg} ${prev.key.id}, this one names ${decl.key.alg} ${decl.key.id}. A link across a key change shows only what the newer signer chose to point at; it does not show that the same holder signed both (SPEC.md section 10)`);
    if (!prevPub) out.notChecked.push('signature of previous declaration (it names another key, which was not among the keys given; verify it on its own)');
  } else if (!prevPub) {
    out.notChecked.push('signature of previous declaration (key not available)');
  }
  if (locationChanged) {
    out.notes.push(`key location changed from ${prev.key.method} at ${prev.key.domain} to ${decl.key.method} at ${decl.key.domain}`);
  }
  if (prev.spec !== decl.spec) {
    out.notes.push(`format changed from ${prev.spec} to ${decl.spec}: the earlier declaration pins its tools with toolsHash, this one with the two digests of ${TOOL_SET_DIGEST_ID}; the two cannot be compared without the tool lists (SPEC.md section 4a)`);
  }
  return out;
}
