// Tools hash: SHA-256 over the RFC 8785 canonical form of the tool list
// returned by MCP tools/list, with all pages joined in order and the tools
// sorted by name. See SPEC.md section 4.

import crypto from 'node:crypto';
import { canonicalize, parseStrict, containerDepth, decodeUtf8Strict, MAX_DEPTH, JsonError } from './jcs.js';

// reason: a short code for the rule that failed, the same codes the conformance
// vectors use: "shape", "ambiguous", "not-object", "no-name", "duplicate-name", "depth".
export class ToolsError extends Error {
  constructor(message, reason = 'shape') {
    super(message);
    this.name = 'ToolsError';
    this.reason = reason;
  }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.hasOwn(o, k);

// Accepts exactly one of three shapes, and reads the tools from one place only:
//   1. a bare array of tools
//   2. a tools/list result: an object with "tools" and none of "jsonrpc", "id", "result"
//   3. a JSON-RPC response: an object with "result" (holding a tools/list result)
//      and no top level "tools"
// An object that carries both "tools" and "result", or "tools" next to "jsonrpc"
// or "id", is refused: a JSON-RPC client reads only result.tools, so a second
// list at the top level could be hashed while the client runs the other one.
export function extractTools(value) {
  if (Array.isArray(value)) return value;
  if (!isObj(value)) throw new ToolsError('expected an array of tools, a tools/list result, or a JSON-RPC response holding one');
  const rpc = has(value, 'jsonrpc') || has(value, 'id') || has(value, 'result');
  if (has(value, 'tools') && rpc) throw new ToolsError('ambiguous input: "tools" next to "jsonrpc", "id" or "result"; give either the JSON-RPC response or its result, not a mix', 'ambiguous');
  if (has(value, 'tools')) {
    if (!Array.isArray(value.tools)) throw new ToolsError('"tools" is not an array');
    return value.tools;
  }
  if (has(value, 'result')) {
    const r = value.result;
    if (!isObj(r) || !Array.isArray(r.tools)) throw new ToolsError('JSON-RPC "result" does not hold a "tools" array');
    return r.tools;
  }
  throw new ToolsError('expected an array of tools, a tools/list result, or a JSON-RPC response holding one');
}

// pages: one parsed value per tools/list page, in the order the server sent them.
function canonicalPages(pages) {
  const tools = [];
  for (const page of pages) {
    const t = extractTools(page);
    // Depth is counted from each page's tools array, whatever wrapper it came in.
    if (containerDepth(t) > MAX_DEPTH) throw new ToolsError(`tool list nesting is deeper than ${MAX_DEPTH} levels`, 'depth');
    tools.push(...t);
  }
  const seen = new Set();
  for (const [n, t] of tools.entries()) {
    if (!isObj(t)) throw new ToolsError(`tool ${n} is not an object`, 'not-object');
    if (typeof t.name !== 'string' || t.name.length === 0) throw new ToolsError(`tool ${n} has no name`, 'no-name');
    if (seen.has(t.name)) throw new ToolsError(`duplicate tool name "${t.name}"`, 'duplicate-name');
    seen.add(t.name);
  }
  // Same UTF-16 code unit order RFC 8785 uses for member names.
  const sorted = [...tools].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return canonicalize(sorted);
}

export function canonicalTools(value) {
  return canonicalPages([value]);
}

export function toolsHash(value) {
  return hashCanonical(canonicalTools(value));
}

function hashCanonical(c) {
  return 'sha256:' + crypto.createHash('sha256').update(c, 'utf8').digest('hex');
}

// Where a page's tools array can sit: the page itself (a bare array), "tools"
// of a tools/list result, or "result.tools" of a JSON-RPC response. The nesting
// limit is counted from there (SPEC.md section 4); members next to it, such as
// nextCursor or _meta, are not hashed and are limited only by PAGE_RESOURCE_DEPTH.
const isToolsPath = (p, isArray) => (p.length === 0 && isArray) || (p.length === 1 && p[0] === 'tools') || (p.length === 2 && p[0] === 'result' && p[1] === 'tools');
export const PAGE_RESOURCE_DEPTH = 512;

// A page saved with its server sent events framing ("event: message",
// "data: {...}") is not JSON; say what to do instead of naming an offset.
export const SSE_START = /^﻿?\s*(?:(?:event|data|id|retry):|:)/;

function parsePage(input) {
  const text = decodeUtf8Strict(input);
  try {
    return parseStrict(text, { maxDepth: MAX_DEPTH, limitFrom: isToolsPath, outerMaxDepth: PAGE_RESOURCE_DEPTH });
  } catch (e) {
    if (e instanceof JsonError && SSE_START.test(text)) {
      throw new JsonError(`${e.message}; this looks like a response saved as server sent events: remove the framing (the "event:" and "data:" lines) and keep only the JSON-RPC message the data lines carry, one page per file (SPEC.md section 4)`, e.reason);
    }
    throw e;
  }
}

// text: a string or the raw bytes of a file (bytes must be UTF-8).
export function toolsHashFromText(text) {
  return toolsHashFromPages([text]);
}

// texts: the text or bytes of each tools/list page, in order. Each page is
// parsed under the same strict rules; names must be unique across all pages.
export function toolsHashFromPages(texts) {
  if (!Array.isArray(texts) || texts.length === 0) throw new ToolsError('no tools/list page given');
  return hashCanonical(canonicalPages(texts.map(parsePage)));
}
