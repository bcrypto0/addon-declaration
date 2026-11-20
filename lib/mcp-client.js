// The smallest MCP client that reads a server's tools/list over the Streamable
// HTTP transport, for check-listing --fetch-tools (SPEC.md section 8a).
//
// It follows the dual era rules of the MCP specification, revision 2026-07-28
// (basic/transports/streamable-http, "Backward Compatibility", and
// basic/versioning), read 19 November 2026:
//   1. A modern request first: POST tools/list with the per request metadata
//      in params._meta (io.modelcontextprotocol/protocolVersion, clientInfo,
//      clientCapabilities) and the mirrored headers MCP-Protocol-Version and
//      Mcp-Method. No session.
//   2. If the server answers with a 4xx status (other than 401, or 403 with a
//      Bearer challenge, which ask for authorization) without a recognized
//      modern JSON-RPC error (-32020 HeaderMismatch, -32021 MissingRequired
//      ClientCapability, -32022 UnsupportedProtocolVersion, or -32601 with a
//      404), it speaks a legacy revision, as the versioning compatibility
//      matrix says. The deprecated HTTP+SSE GET probe is not made: POST initialize (protocol version
//      2025-11-25), keep the Mcp-Session-Id header if one is returned, POST
//      notifications/initialized, then POST tools/list with the
//      MCP-Protocol-Version header the server negotiated, and DELETE the
//      session at the end, as revision 2025-11-25 says.
//   3. An UnsupportedProtocolVersionError that lists a legacy version this
//      client speaks leads to the legacy flow with that version.
// Pages are followed through nextCursor, at most MAX_TOOLS_PAGES of them. A
// response may be application/json or text/event-stream; from an event stream
// the JSON-RPC response to the request is taken (notifications before it are
// skipped), and its text is the page, as SPEC.md section 4 says.
//
// Every request goes through the hardened fetch of resolve.js (public
// addresses only, no redirects, a small request body, a size and time limit).
// The caller decides which URL may be contacted (only a remote of a verified
// declaration). Nothing here calls a tool.

import { httpsRequest } from './resolve.js';

export const MODERN_PROTOCOL_VERSION = '2026-07-28';
// The legacy revisions that use Streamable HTTP, newest first.
export const LEGACY_PROTOCOL_VERSIONS = Object.freeze(['2025-11-25', '2025-06-18', '2025-03-26']);
export const MAX_TOOLS_PAGES = 16;
export const MAX_MCP_RESPONSE = 1048576;
export const MCP_REQUEST_TIMEOUT_MS = 15000;
export const MCP_OVERALL_TIMEOUT_MS = 60000;
export const CLIENT_INFO = Object.freeze({ name: 'addon-declare', version: '0.2.0' });
const RECOGNIZED_MODERN_ERRORS = new Set([-32020, -32021, -32022]);

// kind: 'authorization' (the server asked for authorization; the tool check is
// not run, which is not a failure), 'unsupported' (no protocol version in
// common) or 'failed' (anything else).
export class McpFetchError extends Error {
  constructor(message, kind = 'failed') {
    super(message);
    this.name = 'McpFetchError';
    this.kind = kind;
  }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const decoder = new TextDecoder('utf-8', { fatal: true });

function decode(bytes, what) {
  try {
    return decoder.decode(bytes);
  } catch {
    throw new McpFetchError(`${what} is not UTF-8`);
  }
}

// The events of a text/event-stream body: the data lines of each event joined
// by line feeds (the SSE rule), comments and other fields skipped.
export function sseEvents(text) {
  const out = [];
  let data = null;
  for (const line of text.replace(/^﻿/, '').split(/\r\n|\r|\n/)) {
    if (line === '') {
      if (data !== null) out.push(data.join('\n'));
      data = null;
      continue;
    }
    if (line.startsWith(':')) continue;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'data') (data ||= []).push(value);
  }
  if (data !== null) out.push(data.join('\n'));
  return out;
}

// The JSON-RPC response to request `id` in an HTTP response. Returns
// { text, message, wire }: text is the JSON-RPC message as the server sent it
// (the body for application/json, the data of the event for an event stream),
// wire is what is handed to the tool check (the body bytes, or the event text),
// message is a parse of it used only to read result, error and nextCursor.
export function responseMessage(res, id) {
  const type = String(res.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const text = decode(res.body, 'the response');
  if (type === 'application/json') {
    const message = parseMessage(text);
    if (!isResponseTo(message, id)) throw new McpFetchError(`the response is not the JSON-RPC response to request ${id}`);
    return { text, message, wire: res.body };
  }
  if (type === 'text/event-stream') {
    for (const data of sseEvents(text)) {
      let message;
      try {
        message = JSON.parse(data);
      } catch {
        continue;
      }
      if (isResponseTo(message, id)) return { text: data, message, wire: data };
    }
    throw new McpFetchError(`the event stream holds no JSON-RPC response to request ${id}`);
  }
  throw new McpFetchError(`the response has content type ${type ? JSON.stringify(type) : 'none'}, not application/json or text/event-stream`);
}

function parseMessage(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new McpFetchError('the response body is not JSON');
  }
}

function isResponseTo(m, id) {
  return isObj(m) && m.id === id && (Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error'));
}

// A JSON-RPC error object in a 4xx body, when the body holds one.
function errorIn(res) {
  try {
    const m = JSON.parse(decoder.decode(res.body));
    if (isObj(m) && isObj(m.error) && Number.isInteger(m.error.code)) return m.error;
  } catch {
    // not JSON, or not UTF-8: no recognized error
  }
  return null;
}

// A value from the server, for a message: a string is quoted and cut short;
// anything else is named by its type. String() is never called on it, since an
// object with a toString or valueOf member of the server's choosing could throw.
export function describe(x) {
  if (typeof x === 'string') return JSON.stringify(x.length > 40 ? x.slice(0, 40) + '...' : x);
  if (x === null) return 'null';
  return Array.isArray(x) ? 'an array' : `a value of type ${typeof x}`;
}

// redact: applied to the whole message before it is cut, so a credential the
// server repeats is hidden also when the cut would leave only part of it.
const errTextOf = (e, redact = (t) => t) => `JSON-RPC error ${e.code}${typeof e.message === 'string' ? ` (${redact(e.message).slice(0, 200)})` : ''}`;

// remoteUrl: a remote of a verified declaration (the caller checks this).
// options: request (the hardened fetch, replaceable in tests), maxPages,
// headers: extra request headers sent with every request to remoteUrl (prepare
// --tools-header-env: the publisher's own credentials for their own server; the
// caller screens the names and decides that remoteUrl may receive them). They
// are sent to remoteUrl only: a redirect is not followed. The protocol headers
// of this client are set after them, so they cannot be replaced.
// redact: a function applied to the text of a JSON-RPC error from the server
// before it is cut short (prepare hides the header values with it).
// Returns { pages, protocolVersion, era, session, requests, notes } where
// pages are the tools/list responses in order, as the tool check reads them.
// Throws McpFetchError; error.requests holds the requests made so far.
export async function fetchToolsList(remoteUrl, { request = httpsRequest, maxPages = MAX_TOOLS_PAGES, overallTimeoutMs = MCP_OVERALL_TIMEOUT_MS, headers: extraHeaders = {}, redact } = {}) {
  const errText = (e) => errTextOf(e, redact);
  const requests = [];
  const notes = [];
  const deadline = Date.now() + overallTimeoutMs;
  let nextId = 0;

  async function send(method, payload, headers, { httpMethod = 'POST' } = {}) {
    const left = deadline - Date.now();
    if (left <= 0) throw new McpFetchError(`the tools fetch took longer than ${overallTimeoutMs / 1000} seconds`);
    const entry = { method, httpMethod, url: remoteUrl, status: null };
    requests.push(entry);
    let res;
    try {
      res = await request(remoteUrl, {
        method: httpMethod,
        headers: httpMethod === 'POST' ? { ...extraHeaders, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers } : { ...extraHeaders, ...headers },
        body: payload === undefined ? undefined : JSON.stringify(payload),
        maxBytes: MAX_MCP_RESPONSE,
        attempts: 1,
        attemptTimeoutMs: Math.min(MCP_REQUEST_TIMEOUT_MS, left),
        overallTimeoutMs: Math.min(MCP_REQUEST_TIMEOUT_MS, left),
      });
    } catch (e) {
      entry.error = e.message;
      throw new McpFetchError(`${httpMethod} ${method} to the remote failed: ${e.message}`);
    }
    entry.status = res.status;
    entry.contentType = res.headers['content-type'] === undefined ? null : String(res.headers['content-type']);
    if (res.status === 401 || (res.status === 403 && /bearer/i.test(String(res.headers['www-authenticate'] || '')))) {
      throw new McpFetchError(`the server asked for authorization: HTTP ${res.status} to ${method}`, 'authorization');
    }
    if (res.status >= 300 && res.status < 400) throw new McpFetchError(`${method} was answered with HTTP ${res.status}, a redirect, which is not followed`);
    return res;
  }

  const rpc = (method, params) => ({ jsonrpc: '2.0', id: ++nextId, method, ...(params === undefined ? {} : { params }) });

  // One page of tools/list. Returns { wire, cursor, message }.
  function page(res, id, method) {
    if (res.status !== 200) throw new McpFetchError(`${method} was answered with HTTP ${res.status}${errorIn(res) ? `, ${errText(errorIn(res))}` : ''}`);
    const { message, wire } = responseMessage(res, id);
    if (Object.hasOwn(message, 'error')) throw new McpFetchError(`${method} returned ${isObj(message.error) ? errText(message.error) : 'an error'}`);
    if (!isObj(message.result)) throw new McpFetchError(`${method} returned a result that is not an object`);
    const rt = message.result.resultType;
    if (rt !== undefined && rt !== 'complete') throw new McpFetchError(`${method} returned resultType ${describe(rt)}, not "complete"`);
    return { wire, cursor: message.result.nextCursor, message };
  }

  // Follows nextCursor; first is the response to the first request.
  async function allPages(first, firstId, more) {
    const pages = [];
    const seen = new Set();
    let current = page(first, firstId, 'tools/list');
    for (;;) {
      pages.push(current.wire);
      if (typeof current.cursor !== 'string') return pages;
      if (seen.has(current.cursor)) throw new McpFetchError('tools/list returned the same nextCursor twice; the paging does not end');
      seen.add(current.cursor);
      if (pages.length >= maxPages) throw new McpFetchError(`tools/list has more than ${maxPages} pages; the list was not read to the end, so it cannot be compared`);
      const { res, id } = await more(current.cursor);
      current = page(res, id, 'tools/list');
    }
  }

  // 1. Modern.
  const modernMeta = { 'io.modelcontextprotocol/protocolVersion': MODERN_PROTOCOL_VERSION, 'io.modelcontextprotocol/clientInfo': { ...CLIENT_INFO }, 'io.modelcontextprotocol/clientCapabilities': {} };
  const modernHeaders = { 'MCP-Protocol-Version': MODERN_PROTOCOL_VERSION, 'Mcp-Method': 'tools/list' };
  const modernList = async (cursor) => {
    const msg = rpc('tools/list', { ...(cursor === undefined ? {} : { cursor }), _meta: modernMeta });
    return { res: await send('tools/list', msg, modernHeaders), id: msg.id };
  };
  let legacyVersion = LEGACY_PROTOCOL_VERSIONS[0];
  try {
    const first = await modernList();
    const err = first.res.status >= 400 ? errorIn(first.res) : null;
    const recognized = err && (RECOGNIZED_MODERN_ERRORS.has(err.code) || (first.res.status === 404 && err.code === -32601));
    if (first.res.status === 200 || recognized) {
      if (recognized && err.code === -32022) {
        const supported = isObj(err.data) && Array.isArray(err.data.supported) ? err.data.supported.filter((v) => typeof v === 'string') : [];
        const legacy = LEGACY_PROTOCOL_VERSIONS.find((v) => supported.includes(v));
        if (!legacy) throw new McpFetchError(`the server does not support protocol version ${MODERN_PROTOCOL_VERSION} and lists no version this client speaks (it lists ${supported.slice(0, 8).map((v) => JSON.stringify(v.slice(0, 40))).join(', ') || 'none'})`, 'unsupported');
        legacyVersion = legacy;
        notes.push(`the server answered ${MODERN_PROTOCOL_VERSION} with UnsupportedProtocolVersionError; it lists ${legacy}, so the legacy flow was used`);
      } else if (recognized) {
        throw new McpFetchError(`tools/list was refused: HTTP ${first.res.status}, ${errText(err)}`);
      } else {
        const pages = await allPages(first.res, first.id, modernList);
        if (!pages.every((w) => /"resultType"\s*:/.test(typeof w === 'string' ? w : w.toString('utf8')))) {
          notes.push('a tools/list result has no resultType, which a server of revision 2026-07-28 includes; the server may have answered under an earlier revision');
        }
        return { pages, protocolVersion: MODERN_PROTOCOL_VERSION, era: 'modern', session: false, requests, notes };
      }
    } else if (first.res.status < 400 || first.res.status > 499 || first.res.status === 408 || first.res.status === 429) {
      // 401, and 403 with a Bearer challenge, were handled in send(); any other
      // 4xx without a recognized modern error is the dual era fallback trigger,
      // except 408 and 429, which say "later", not "another revision".
      throw new McpFetchError(`tools/list was answered with HTTP ${first.res.status}`);
    } else {
      notes.push(`the server answered the ${MODERN_PROTOCOL_VERSION} request with HTTP ${first.res.status} and no recognized modern error, so it was read as a legacy server (initialize, protocol version ${legacyVersion})`);
    }
  } catch (e0) {
    // Whatever went wrong is a failed fetch, never an unexpected error.
    const e = e0 instanceof McpFetchError ? e0 : new McpFetchError(`the tools fetch failed: ${e0 && typeof e0.message === 'string' ? e0.message : 'unknown error'}`);
    e.requests = requests;
    e.notes = notes;
    throw e;
  }

  // 2. Legacy: initialize, then tools/list in the session.
  try {
    const init = rpc('initialize', { protocolVersion: legacyVersion, capabilities: {}, clientInfo: { ...CLIENT_INFO } });
    const ires = await send('initialize', init, {});
    if (ires.status !== 200) throw new McpFetchError(`initialize was answered with HTTP ${ires.status}${errorIn(ires) ? `, ${errText(errorIn(ires))}` : ''}`);
    const { message } = responseMessage(ires, init.id);
    if (Object.hasOwn(message, 'error')) throw new McpFetchError(`initialize returned ${isObj(message.error) ? errText(message.error) : 'an error'}`);
    const negotiated = isObj(message.result) ? message.result.protocolVersion : undefined;
    if (!LEGACY_PROTOCOL_VERSIONS.includes(negotiated)) {
      throw new McpFetchError(`initialize negotiated protocol version ${describe(negotiated)}, which this client does not speak (it speaks ${LEGACY_PROTOCOL_VERSIONS.join(', ')} and ${MODERN_PROTOCOL_VERSION})`, 'unsupported');
    }
    const sidHeader = ires.headers['mcp-session-id'];
    let sid;
    if (sidHeader !== undefined) {
      // Visible ASCII only (revision 2025-11-25); anything else is not sent back.
      if (typeof sidHeader !== 'string' || !/^[\x21-\x7e]{1,1024}$/.test(sidHeader)) throw new McpFetchError('the server returned an Mcp-Session-Id header that is not 1 to 1024 visible ASCII characters');
      sid = sidHeader;
    }
    const headers = { 'MCP-Protocol-Version': negotiated, ...(sid ? { 'Mcp-Session-Id': sid } : {}) };
    const nres = await send('notifications/initialized', { jsonrpc: '2.0', method: 'notifications/initialized' }, headers);
    if (nres.status < 200 || nres.status > 299) throw new McpFetchError(`notifications/initialized was answered with HTTP ${nres.status}`);
    const legacyList = async (cursor) => {
      const msg = rpc('tools/list', cursor === undefined ? undefined : { cursor });
      const res = await send('tools/list', msg, headers);
      if (res.status === 404 && sid) throw new McpFetchError('tools/list was answered with HTTP 404 in the session; the server ended the session');
      return { res, id: msg.id };
    };
    const first = await legacyList();
    let pages;
    try {
      pages = await allPages(first.res, first.id, legacyList);
    } finally {
      if (sid) {
        // Revision 2025-11-25: a client that no longer needs the session SHOULD
        // end it with DELETE. Its answer (405 is allowed) changes nothing here.
        try {
          await send('session end', undefined, headers, { httpMethod: 'DELETE' });
        } catch {
          // ignored
        }
      }
    }
    return { pages, protocolVersion: negotiated, era: 'legacy', session: Boolean(sid), requests, notes };
  } catch (e) {
    if (!(e instanceof McpFetchError)) e = new McpFetchError(`the tools fetch failed: ${e && typeof e.message === 'string' ? e.message : 'unknown error'}`);
    e.requests = requests;
    e.notes = notes;
    throw e;
  }
}
