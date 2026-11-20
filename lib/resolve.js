// Live key lookup, following what the official MCP Registry does (SPEC.md
// section 9):
//   dns:  TXT records at the apex of the domain (no selector label), 5 seconds
//   http: GET https://<domain>/.well-known/mcp-registry-auth, Accept text/plain,
//         no redirects, 200 only, body at most 4096 bytes, at most 2 attempts of
//         10 seconds each within 15 seconds overall, and only to public
//         addresses (non public addresses are dropped, the public ones are
//         dialed in order, 3 seconds each, and only a checked address is dialed)
// Both return { keys, notes } on an answer, or { keys: [], notes, error } when
// the lookup itself failed (timeout, SERVFAIL, refused address, 408, 429, 5xx,
// an access refusal). Only this file touches the network: the registry,
// declaration and MCP reads of check-listing (lib/listing.js, lib/mcp-client.js)
// go through httpsRequest below.

import dns from 'node:dns';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { parseProofRecords } from './keys.js';

export const MAX_KEY_RESPONSE = 4096;
export const DNS_TIMEOUT_MS = 5000;
export const HTTP_ATTEMPT_TIMEOUT_MS = 10000;
export const HTTP_OVERALL_TIMEOUT_MS = 15000;
export const HTTP_ATTEMPTS = 2;
export const HTTP_PER_ADDRESS_DIAL_MS = 3000;
const HTTP_RETRY_BACKOFF_MS = 500;
export const HTTP_USER_AGENT = 'addon-declare/0.2';

// The registry's transient set (isTransientHTTPStatus in http.go): retried.
export function isTransientStatus(status) {
  return status === 408 || status === 429 || status >= 500;
}

// Statuses that are an answer: the domain does not publish a key there that the
// registry would read (the registry source read for SPEC.md section 2 does not follow redirects either).
export function isNotPublishedStatus(status) {
  return (status >= 300 && status < 400) || status === 404 || status === 410;
}

// Answers that mean "the domain does not publish a key there" rather than "the
// lookup could not be completed".
const DNS_NO_RECORD_CODES = new Set(['ENODATA', 'ENOTFOUND']);

// NXDOMAIN and an empty answer come from a real DNS answer here (the resolver
// talks to a name server), so they mean "not published". The http method's host
// lookup goes through the system resolver, which cannot tell a missing name from
// an unreachable name server, so there a failed host lookup is a lookup failure.
// resolver: anything with resolveTxt(name) -> Promise<string[][]>, so tests can
// pass a fake. Each TXT record arrives as one or more character strings; they
// are joined per record (as Go's net.LookupTXT, used by the registry, does).
// retries: how many more times a query that timed out or got SERVFAIL is sent
// (0 by default, so verify and check-listing ask once, as SPEC.md section 9
// says; prepare asks once more). Such a failure is marked transient: true, so a
// caller can say that a later run may get an answer.
export const DNS_RETRY_CODES = new Set(['ETIMEOUT', 'ESERVFAIL']);
export async function keysFromDns(domain, { resolver, retries = 0 } = {}) {
  const r = resolver || dnsResolverFor();
  let records;
  const notes = [];
  for (let n = 0; ; n++) {
    try {
      records = await r.resolveTxt(domain);
      break;
    } catch (e) {
      const code = e && e.code ? e.code : null;
      if (code && DNS_NO_RECORD_CODES.has(code)) return { keys: [], notes: [...notes, `no TXT records at ${domain}`] };
      const transient = DNS_RETRY_CODES.has(code);
      if (transient && n < retries) {
        notes.push(`the DNS query for ${domain} failed (${code}) and was sent again`);
        continue;
      }
      return { keys: [], notes, error: `DNS lookup for ${domain} failed (${code || 'unknown error'})${n ? `, also when asked ${n + 1} times` : ''}`, ...(transient ? { transient: true } : {}) };
    }
  }
  const keys = [];
  for (const rec of records) {
    const parsed = parseProofRecords(rec.join(''));
    keys.push(...parsed.keys);
    notes.push(...parsed.notes);
  }
  if (keys.length === 0) notes.push(`no usable proof record in ${records.length} TXT record(s) at ${domain}`);
  return { keys, notes };
}

// get: optional replacement for the HTTPS request, (url) -> Promise<{ status, body }>, for tests.
// Status rules (SPEC.md section 9): 200 is read; a 3xx, 404 or 410 means the key
// is not published there; every other status (408, 429, 5xx, and 401, 403, 451
// or another refusal, which may come from a CDN or bot challenge) and every
// network failure is a lookup failure that says nothing about the key.
export async function keysFromHttp(domain, { get } = {}) {
  const url = `https://${domain}/.well-known/mcp-registry-auth`;
  let res;
  try {
    res = await (get || httpsGetText)(url);
  } catch (e) {
    return { keys: [], notes: [], error: `could not fetch ${url} (${e.message})` };
  }
  // status: the HTTP status, for callers that list what they fetched.
  if (isNotPublishedStatus(res.status)) return { keys: [], notes: [`${url} answered HTTP ${res.status}; only 200 is read and redirects are not followed`], status: res.status };
  if (res.status !== 200) {
    const why = isTransientStatus(res.status)
      ? 'a temporary failure, try again later'
      : res.status === 401 || res.status === 403 || res.status === 451
        ? 'access was refused, possibly by a CDN, firewall or bot challenge; this does not show that the key is absent'
        : 'not an answer about the key';
    return { keys: [], notes: [], error: `${url} answered HTTP ${res.status} (${why})`, status: res.status };
  }
  // The registry reads only MCPv1 records from this file.
  const { keys, notes } = parseProofRecords(res.body.trim(), { kinds: ['mcp'] });
  if (keys.length === 0) notes.push(`no usable MCPv1 record at ${url}`);
  return { keys, notes, status: res.status };
}

// ---- address checks (same ranges the registry refuses) ----

function ipv4Bytes(s) {
  const p = s.split('.');
  if (p.length !== 4) return null;
  const b = p.map((x) => (/^\d{1,3}$/.test(x) ? Number(x) : NaN));
  return b.every((x) => x >= 0 && x <= 255) ? b : null;
}

function ipv6Bytes(s) {
  let t = s.split('%')[0];
  const lastColon = t.lastIndexOf(':');
  if (t.slice(lastColon + 1).includes('.')) {
    // Embedded dotted quad, as in ::ffff:127.0.0.1: rewrite it as two hex words.
    const v4 = ipv4Bytes(t.slice(lastColon + 1));
    if (!v4) return null;
    t = t.slice(0, lastColon + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = t.split('::');
  if (halves.length > 2) return null;
  const parse = (h) => (h === '' ? [] : h.split(':').map((x) => (/^[0-9a-fA-F]{1,4}$/.test(x) ? parseInt(x, 16) : NaN)));
  const head = parse(halves[0]);
  const back = halves.length === 2 ? parse(halves[1]) : [];
  if ([...head, ...back].some(Number.isNaN)) return null;
  let full;
  if (halves.length === 2) {
    const fill = 8 - head.length - back.length;
    if (fill < 1) return null;
    full = [...head, ...Array(fill).fill(0), ...back];
  } else full = head;
  if (full.length !== 8) return null;
  return full.flatMap((w) => [w >> 8, w & 0xff]);
}

function v4Blocked([a, b, c]) {
  return (
    a === 0 || // "this network", unspecified
    a === 10 || // private
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64.0.0/10
    (a === 169 && b === 254) || // link local
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 192 && b === 168) || // private
    // Special use ranges that are not reachable public hosts; additions to the
    // registry's list (SPEC.md section 9): IETF protocol assignments
    // 192.0.0.0/24, benchmarking 198.18.0.0/15, documentation 192.0.2.0/24,
    // 198.51.100.0/24 and 203.0.113.0/24.
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224 // multicast 224/4, reserved 240/4, broadcast
  );
}

// true when the address may be fetched from (a public unicast address).
export function isPublicAddress(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) return !v4Blocked(ipv4Bytes(ip));
  if (fam !== 6) return false;
  const b = ipv6Bytes(ip);
  if (!b) return false;
  const zero = (from, to) => b.slice(from, to).every((x) => x === 0);
  if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return !v4Blocked(b.slice(12)); // IPv4 mapped
  if (zero(0, 12)) return false; // ::, ::1 and IPv4 compatible
  // Additions to the registry's list (SPEC.md section 9): the IPv4 translated
  // range ::ffff:0:0:0/96, the discard only range 100::/64 and the
  // documentation range 2001:db8::/32.
  if (zero(0, 8) && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) return false;
  if (b[0] === 0x01 && b[1] === 0x00 && zero(2, 8)) return false;
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false;
  if ((b[0] & 0xfe) === 0xfc) return false; // unique local fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return false; // link local fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return false; // site local fec0::/10
  if (b[0] === 0xff) return false; // multicast
  if (b[0] === 0x20 && b[1] === 0x02) return false; // 6to4 2002::/16
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(4, 12)) return false; // NAT64 64:ff9b::/96
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b[4] === 0x00 && b[5] === 0x01) return false; // 64:ff9b:1::/48
  return true;
}

// true for a loopback address (127.0.0.0/8, ::1 and their IPv4 mapped forms).
// Used only for a registry base the person running the check gave as
// http://127.0.0.1:<port> or http://localhost:<port>.
export function isLoopbackAddress(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) return ipv4Bytes(ip)[0] === 127;
  if (fam !== 6) return false;
  const b = ipv6Bytes(ip);
  if (!b) return false;
  const zero = (from, to) => b.slice(from, to).every((x) => x === 0);
  if (zero(0, 15) && b[15] === 1) return true; // ::1
  return zero(0, 10) && b[10] === 0xff && b[11] === 0xff && b[12] === 127; // ::ffff:127.x.y.z
}

// The size limit of a request body sent by httpsRequest (an MCP initialize or
// tools/list request is a few hundred bytes; a long cursor could make it grow).
export const MAX_REQUEST_BODY = 16384;

// The key fetch of SPEC.md section 9: GET, Accept text/plain, at most 4096 bytes.
// It returns { status, body } with the body as text.
export async function httpsGetText(url, opts = {}) {
  const res = await httpsRequest(url, { ...opts, method: 'GET', headers: { Accept: 'text/plain' }, maxBytes: MAX_KEY_RESPONSE });
  return { status: res.status, body: res.body.toString('utf8') };
}

// The hardened fetch every network read of this tool goes through.
// For each attempt: resolve the host, drop every address that is not public,
// and dial the remaining checked addresses in order (3 seconds each) until one
// connects, as the registry's dialer does. Only a checked address is dialed, so
// a second DNS answer cannot point the request at an internal host. When no
// public address is left the fetch is refused. TLS name checks and the Host
// header still use the host name. Redirects are never followed (the status and
// headers of a 3xx are returned as they are). The body is read up to maxBytes;
// a longer body fails the request (error.tooLarge). Statuses 408, 429 and 5xx
// are retried within the attempts and time limits.
// opts:
//   method: 'GET' (default), 'POST' or 'DELETE'; body: a string or Buffer of at
//     most MAX_REQUEST_BODY bytes (POST only)
//   headers: extra request headers (User-Agent is always this tool's)
//   maxBytes: the body limit (default 4096)
//   attempts, attemptTimeoutMs, overallTimeoutMs, dialTimeoutMs: limits
//   allowLoopbackHttp: true accepts an http URL and dials loopback addresses
//     only (for a registry base given as http://127.0.0.1:<port>)
//   tests only: lookupAll, transport, allowAddress
// Returns { status, headers (lowercase names), body (Buffer) }.
export async function httpsRequest(url, opts = {}) {
  const {
    lookupAll = (host) => dns.promises.lookup(host, { all: true, verbatim: true }),
    attemptTimeoutMs = HTTP_ATTEMPT_TIMEOUT_MS,
    overallTimeoutMs = HTTP_OVERALL_TIMEOUT_MS,
    attempts = HTTP_ATTEMPTS,
    dialTimeoutMs = HTTP_PER_ADDRESS_DIAL_MS,
    method = 'GET',
    headers = {},
    body,
    maxBytes = MAX_KEY_RESPONSE,
    allowLoopbackHttp = false,
  } = opts;
  let { transport, allowAddress } = opts;
  let protocol;
  try {
    protocol = new URL(url).protocol;
  } catch {
    throw Object.assign(new Error('not a URL'), { refused: true });
  }
  if (!transport) {
    // Only https, except a loopback http base the person running the check gave.
    if (protocol === 'https:') transport = https;
    else if (protocol === 'http:' && allowLoopbackHttp) {
      transport = http;
      allowAddress ||= isLoopbackAddress;
    } else throw Object.assign(new Error('refusing to fetch: only https URLs are fetched'), { refused: true });
  }
  allowAddress ||= isPublicAddress;
  if (!['GET', 'POST', 'DELETE'].includes(method)) throw new TypeError(`method ${method} is not supported`);
  const bodyBytes = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  if (bodyBytes && bodyBytes.length > MAX_REQUEST_BODY) throw Object.assign(new Error(`request body larger than ${MAX_REQUEST_BODY} bytes; not sent`), { refused: true });
  const deadline = Date.now() + overallTimeoutMs;
  const pause = () => new Promise((r) => setTimeout(r, Math.min(HTTP_RETRY_BACKOFF_MS, Math.max(0, deadline - Date.now()))));
  const request = { method, headers, body: bodyBytes, maxBytes };
  let lastError;
  for (let n = 0; n < attempts; n++) {
    const left = deadline - Date.now();
    if (left <= 0) break;
    try {
      const res = await requestOnce(url, request, { lookupAll, transport, allowAddress, dialTimeoutMs, timeoutMs: Math.min(attemptTimeoutMs, left) });
      if (isTransientStatus(res.status) && n + 1 < attempts) {
        lastError = new Error(`HTTP ${res.status}`);
        await pause();
        continue;
      }
      return res;
    } catch (e) {
      lastError = e;
      if (e.refused || e.tooLarge) throw e; // a refused address or an oversized body is not retried
      if (n + 1 < attempts) await pause();
    }
  }
  throw lastError || new Error('timed out');
}

async function requestOnce(url, request, { lookupAll, transport, allowAddress, dialTimeoutMs, timeoutMs }) {
  const attemptDeadline = Date.now() + timeoutMs;
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  let addrs;
  try {
    addrs = await lookupAll(host);
  } catch (e) {
    // hostLookupCode: the code of the system resolver (ENOTFOUND, EAI_AGAIN, ...),
    // for a caller that has to tell a host with no address from a passing fault.
    throw Object.assign(new Error(`could not resolve host (${e && e.code ? e.code : 'error'})`), { hostLookupCode: e && typeof e.code === 'string' ? e.code : null });
  }
  if (!addrs.length) throw new Error('host has no address');
  const checked = addrs.filter((a) => allowAddress(a.address));
  if (!checked.length) {
    const e = new Error('refusing to connect: every address of the host is private, loopback, link local or otherwise not public');
    e.refused = true;
    throw e;
  }
  let lastDialError;
  for (const addr of checked) {
    const left = attemptDeadline - Date.now();
    if (left <= 0) break;
    try {
      return await requestVia(url, addr, request, { transport, timeoutMs: left, dialTimeoutMs: Math.min(dialTimeoutMs, left) });
    } catch (e) {
      if (!e.dialFailed) throw e; // connected, then failed: not a reason to try another address
      lastDialError = e;
    }
  }
  throw new Error(`every address tried failed${lastDialError ? ` (last: ${lastDialError.message})` : ' (timed out)'}`);
}

// One request, dialed to one checked address. agent: false, so no pooled
// socket (connected to some other address) is reused.
function requestVia(url, addr, request, { transport, timeoutMs, dialTimeoutMs }) {
  const { method, headers, body, maxBytes } = request;
  return new Promise((resolve, reject) => {
    let done = false;
    let connected = false;
    const finish = (fn, v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(dialTimer);
      fn(v);
    };
    const family = addr.family === 6 || addr.family === 'IPv6' ? 6 : 4;
    const options = {
      agent: false,
      method,
      headers: { ...headers, 'User-Agent': HTTP_USER_AGENT, ...(body ? { 'Content-Length': String(body.length) } : {}) },
      lookup: (_h, o, cb) => (o && o.all ? cb(null, [{ address: addr.address, family }]) : cb(null, addr.address, family)),
    };
    const onResponse = (res) => {
      connected = true;
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) {
          req.destroy();
          finish(reject, Object.assign(new Error(`body larger than ${maxBytes} bytes`), { tooLarge: true, status: res.statusCode, ...(typeof res.headers.location === 'string' ? { location: res.headers.location } : {}) }));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => finish(resolve, { status: res.statusCode, headers: { ...res.headers }, body: Buffer.concat(chunks) }));
      res.on('error', (e) => finish(reject, e));
    };
    // GET goes through transport.get, which ends the request itself.
    const req = method === 'GET' ? transport.get(url, options, onResponse) : transport.request(url, options, onResponse);
    if (method !== 'GET') req.end(body || undefined);
    req.on('socket', (sock) => {
      if (!sock.connecting) connected = true;
      else sock.once('connect', () => (connected = true));
    });
    const dialTimer = setTimeout(() => {
      if (connected) return;
      const e = new Error(`connect to ${addr.address} timed out`);
      e.dialFailed = true;
      req.destroy();
      finish(reject, e);
    }, dialTimeoutMs);
    // Whole request limit, not only socket idle time.
    const timer = setTimeout(() => {
      req.destroy();
      finish(reject, new Error('timed out'));
    }, timeoutMs);
    req.on('error', (e) => {
      if (!connected) e.dialFailed = true;
      finish(reject, e);
    });
  });
}

// Whether a host has no address in DNS, asked of the name servers (the system's,
// or the one --dns-server names) and not of the system lookup: the system lookup
// gives ENOTFOUND both for a name with no address and, on some systems, when no
// name server answered. Returns { noAddress, detail }: noAddress is true only
// when the name servers answered both the A and the AAAA query with "no such
// name" (ENOTFOUND) or "no address of this type" (ENODATA); a timeout, SERVFAIL,
// a refused query or any other error gives false. resolver: anything with
// resolve4 and resolve6, so tests can pass a fake.
export async function hostWithoutAddress(host, { resolver } = {}) {
  const r = resolver || dnsResolverFor();
  const ask = async (type) => {
    try {
      const a = await (type === 'A' ? r.resolve4(host) : r.resolve6(host));
      return { type, none: !Array.isArray(a) || a.length === 0, code: Array.isArray(a) && a.length ? `${a.length} address${a.length === 1 ? '' : 'es'}` : 'no address' };
    } catch (e) {
      const code = e && typeof e.code === 'string' ? e.code : 'error';
      return { type, none: DNS_NO_RECORD_CODES.has(code), code };
    }
  };
  const [a, aaaa] = [await ask('A'), await ask('AAAA')];
  return { noAddress: a.none && aaaa.none, detail: `the name servers answered the A query with ${a.code} and the AAAA query with ${aaaa.code}` };
}

// Resolver: replaceable in tests, to check the options it is built with.
export function dnsResolverFor(server, { Resolver = dns.promises.Resolver } = {}) {
  const r = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  if (server) {
    if (!net.isIP(server)) throw new TypeError('--dns-server must be an IP address');
    r.setServers([server]);
  }
  return r;
}
