// The two digests of mcp-tool-set-digest/1 (editors' draft of 2026-11-13,
// https://github.com/alexar76/mcp-tool-set-digest, SPEC.md there): the
// contract digest and the extras digest of one complete tools/list result.
// Written from that text; section numbers below are that document's.
//
// This is not the toolsHash of this repository's SPEC.md section 4, and the
// two cannot be compared: see "Relation to mcp-tool-set-digest/1" in SPEC.md.
// The input rules differ from SPEC.md section 5 where that document says so
// (its section 3): see README.md.

import crypto from 'node:crypto';
import { parseStrict, canonicalize, decodeUtf8Strict, NoDouble, JsonError } from './jcs.js';
import { extractTools, ToolsError, PAGE_RESOURCE_DEPTH, SSE_START } from './tools.js';

export const TOOL_SET_DIGEST_ID = 'mcp-tool-set-digest/1';

// The document leaves the bound on nesting to the producer (section 12). This
// command uses the resource bound the tools hash uses for a whole page.
export const TSD_MAX_DEPTH = PAGE_RESOURCE_DEPTH;

const CONTRACT_MEMBERS = new Set(['name', 'description', 'inputSchema', 'outputSchema']);

const has = (o, k) => Object.hasOwn(o, k);
// A JSON object as parsed. A NoDouble is an object in JavaScript but a number in JSON.
const isJsonObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof NoDouble);

// A set has no digest of a kind: code is one of the codes of section 10.
export class DigestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DigestError';
    this.code = code;
  }
}

// Text that is not a usable page at all (not JSON, not UTF-8, not a tools
// list shape, or nested beyond the resource bound). No digest and no code.
export class InputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InputError';
  }
}

function setOwn(obj, key, value) {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

function digestOf(text) {
  const bytes = crypto.createHash('sha256').update(text, 'utf8').digest();
  return { digest: 'sha256-' + bytes.toString('base64'), hex: 'sha256:' + bytes.toString('hex'), canonical: text };
}

// RFC 8785 text of a value, with the failures of section 10 named by their code.
function write(value, depth, where) {
  try {
    return canonicalize(value, depth, TSD_MAX_DEPTH + 3);
  } catch (e) {
    if (e instanceof JsonError && e.reason === 'lone-surrogate') throw new DigestError('TSD-TEXT', `${where}: a string or member name holds a lone surrogate`);
    if (e instanceof JsonError && e.reason === 'range') throw new DigestError('TSD-NUMBER', `${where}: ${e.message}`);
    if (e instanceof JsonError && e.reason === 'depth') throw new InputError(`${where}: nested deeper than ${TSD_MAX_DEPTH} levels`);
    throw e;
  }
}

const nameOf = (t, n) => (typeof t.name === 'string' ? `tool "${t.name}"` : `tool ${n}`);

// Section 4: the contract entry of one tool.
function contractEntry(t) {
  const e = {};
  setOwn(e, 'name', t.name);
  setOwn(e, 'description', typeof t.description === 'string' ? t.description : '');
  setOwn(e, 'inputSchema', isJsonObject(t.inputSchema) ? t.inputSchema : {});
  if (has(t, 'outputSchema') && isJsonObject(t.outputSchema)) setOwn(e, 'outputSchema', t.outputSchema);
  return e;
}

// Sections 5 to 7.
function contractDigest(tools) {
  const entries = tools.map((t, n) => ({ name: t.name, text: write(contractEntry(t), 1, nameOf(t, n)) }));
  entries.sort((a, b) => {
    // UTF-16 code units (section 5.1); JavaScript compares strings that way.
    if (a.name !== b.name) return a.name < b.name ? -1 : 1;
    // Same name: canonical text as UTF-8, unsigned bytes (section 5.2).
    return Buffer.compare(Buffer.from(a.text, 'utf8'), Buffer.from(b.text, 'utf8'));
  });
  return digestOf('[' + entries.map((e) => e.text).join(',') + ']');
}

// Section 8.
function extrasDigest(tools) {
  const byName = {};
  for (const t of tools) {
    const extras = {};
    let any = false;
    for (const k of Object.keys(t)) {
      if (CONTRACT_MEMBERS.has(k)) continue;
      setOwn(extras, k, t[k]);
      any = true;
    }
    if (!any) continue;
    if (has(byName, t.name)) throw new DigestError('TSD-NAME', `two tools named "${t.name}" both have extras`);
    setOwn(byName, t.name, extras);
  }
  if (Object.keys(byName).length === 0) return { digest: null };
  const obj = {};
  setOwn(obj, 'tools', byName);
  return digestOf(write(obj, 0, 'extras'));
}

function attempt(fn) {
  try {
    return fn();
  } catch (e) {
    if (e instanceof DigestError) return { error: e.code, detail: e.message };
    throw e;
  }
}

// tools: the joined tools array; complete: false when the list still has a
// nextCursor. Returns { contract, extras }, each { digest, hex, canonical },
// { digest: null } (extras only) or { error, detail }.
export function toolSetDigests(tools, { complete = true } = {}) {
  if (!complete) {
    const page = { error: 'TSD-PAGE', detail: 'the last page carries nextCursor, so the list is not complete; give every page in order' };
    return { contract: page, extras: page };
  }
  // TSD-TOOL concerns the set and is reported before the others (section 10).
  for (const [n, t] of tools.entries()) {
    let detail = null;
    if (!isJsonObject(t)) detail = `tool ${n} is not a JSON object`;
    else if (typeof t.name !== 'string' || t.name.length === 0) detail = `tool ${n} has no non-empty string name`;
    if (detail) {
      const bad = { error: 'TSD-TOOL', detail };
      return { contract: bad, extras: { ...bad } };
    }
  }
  return { contract: attempt(() => contractDigest(tools)), extras: attempt(() => extrasDigest(tools)) };
}

// Names that more than one tool carries, in order of first appearance, each
// with its count. MCP requires unique names; mcp-tool-set-digest/1 keeps such
// tools (its section 8.5), and because extras are grouped by name, which of
// them carries title, annotations or other extras is not pinned by the digests
// when only one of them has extras (its section 11.1).
export function repeatedToolNames(tools) {
  const count = new Map();
  for (const t of tools) if (isJsonObject(t) && typeof t.name === 'string' && t.name.length) count.set(t.name, (count.get(t.name) || 0) + 1);
  return [...count].filter(([, c]) => c > 1).map(([name, c]) => ({ name, count: c }));
}

function parsePage(input, n, notes, counts) {
  let text;
  try {
    text = decodeUtf8Strict(input);
  } catch (e) {
    throw new InputError(`page ${n + 1}: ${e.message}`);
  }
  let repeated = 0;
  let inWrapper = 0;
  try {
    const value = parseStrict(text, { maxDepth: TSD_MAX_DEPTH, relaxed: true, onDuplicate: (key, where) => { repeated++; if (!where.inArray) inWrapper++; } });
    // mcp-tool-set-digest/1 starts at the tools array and does not say how a page
    // wrapper is read. A member repeated in the wrapper (for example two "tools"
    // members) would let a parser that keeps the first value see a wholly
    // different list, so such a page has no digest here.
    if (inWrapper) throw new InputError(`page ${n + 1}: ${inWrapper} repeated member name${inWrapper === 1 ? '' : 's'} outside the tools array (in the tools/list page wrapper); which list the page holds depends on the parser, so it has no digest`);
    if (repeated) notes.push(`page ${n + 1}: ${repeated} repeated member name${repeated === 1 ? '' : 's'}; the last value of each was used (${TOOL_SET_DIGEST_ID} section 3). A client whose JSON parser keeps the first value, or refuses the list, reads other tool definitions than the ones these digests pin`);
    counts.repeatedMembers += repeated;
    return value;
  } catch (e) {
    if (!(e instanceof JsonError)) throw e;
    const sse = SSE_START.test(text) ? '; this looks like a response saved as server sent events: keep only the JSON-RPC message the data lines carry' : '';
    throw new InputError(`page ${n + 1}: ${e.reason === 'depth' ? `nested deeper than ${TSD_MAX_DEPTH} levels` : e.message}${sse}`);
  }
}

// The members next to a page's tools array that say whether more pages follow.
function hasNextCursor(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  if (has(value, 'nextCursor')) return true;
  const r = value.result;
  return isJsonObject(r) && has(r, 'nextCursor');
}

// texts: the bytes or text of each tools/list page, in the order read.
// Returns { contract, extras, notes, repeatedMembers, repeatedNames }:
// repeatedMembers is the number of repeated member names read (the last value
// of each was used), repeatedNames lists { name, count } for each tool name
// that more than one tool carries. Both are also described in notes.
export function toolSetDigestsFromPages(texts) {
  if (!Array.isArray(texts) || texts.length === 0) throw new InputError('no tools/list page given');
  const notes = [];
  const counts = { repeatedMembers: 0 };
  const pages = texts.map((t, n) => parsePage(t, n, notes, counts));
  const tools = [];
  for (const [n, page] of pages.entries()) {
    try {
      tools.push(...extractTools(page));
    } catch (e) {
      if (e instanceof ToolsError) throw new InputError(`page ${n + 1}: ${e.message}`);
      throw e;
    }
  }
  const complete = !hasNextCursor(pages[pages.length - 1]);
  const repeatedNames = repeatedToolNames(tools);
  for (const { name, count } of repeatedNames) {
    notes.push(`tool name "${name}" appears ${count} times; MCP requires unique tool names, and ${TOOL_SET_DIGEST_ID} groups extras by name (its section 8.5), so which of these tools carries members such as title or annotations is not pinned by the digests`);
  }
  return { ...toolSetDigests(tools, { complete }), notes, repeatedMembers: counts.repeatedMembers, repeatedNames };
}
