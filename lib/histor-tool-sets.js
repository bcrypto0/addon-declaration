// The tool sets member that HISTOR, a third party watcher of MCP servers
// (https://histor.modelmarket.dev), reads from the publisher metadata of a
// registry listing. It is not part of this spec and not signed: it is the
// publisher's own statement of the tool sets a server serves, which HISTOR
// shows as stated by the publisher. The signed declaration is what shows who
// made the statement about the tool list.
//
// The only definition is HISTOR's own: docs/api.md, section "Declaring tool
// sets (publishers)", and the reader histor/declared.py, both at commit
// a7567b9a08f7b24aa8b34d27620eca40946b464f of github.com/alexar76/histor
// (HISTOR_DOC below). The rules used here are those of that reader
// (declared_tool_sets, parse_sets and url_refusal), as near as the URL parser
// of Node allows:
//   _meta["io.modelcontextprotocol.registry/publisher-provided"]
//        ["dev.modelmarket.histor/tool-sets"] = { "mtl": "1", "sets": [...], "url": ... }
//   mtl: the string "1" exactly (the digests are MTL/1 tool-set digests, the
//        contract digest of mcp-tool-set-digest/1), else nothing is read;
//   sets: a non-empty list of objects, each { "digest", "count"?, "when"? };
//        HISTOR takes at most 8 and skips an entry that is not an object, has
//        a digest in another form, repeats a digest or has a bad count;
//   digest: "sha256-" and standard padded base64 of 32 bytes (the sha256: hex
//        form is not read);
//   count: optional, an integer from 0 to 5000, the number of tools, for display;
//   when: optional free text, the condition in the publisher's words (not a time);
//   url: optional, a declaration file on the domain of the server's namespace.
// A set the member stops naming is marked withdrawn by HISTOR, so prepare
// merges its set into a member already there instead of replacing it.
// prepare writes "mtl" and one set with "digest" and "count": "when" has no
// value prepare could state for the publisher, and prepare writes no
// declaration file for "url".

export const HISTOR_MEMBER = 'dev.modelmarket.histor/tool-sets';
export const HISTOR_URL = 'https://histor.modelmarket.dev';
export const HISTOR_DOC = 'https://github.com/alexar76/histor/blob/a7567b9a08f7b24aa8b34d27620eca40946b464f/docs/api.md#declaring-tool-sets-publishers';
export const HISTOR_MTL = '1';
export const HISTOR_MAX_SETS = 8;
export const HISTOR_MAX_COUNT = 5000;
export const HISTOR_DIGEST_RE = /^sha256-[A-Za-z0-9+/]{43}=$/;
const GITHUB_USER_RE = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;
// The members of the member HISTOR reads; prepare writes no other.
const MEMBER_KEYS = ['mtl', 'sets', 'url'];

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const validCount = (c) => c === undefined || c === null || (Number.isInteger(c) && c >= 0 && c <= HISTOR_MAX_COUNT);

// Why HISTOR does not read a declaration file at url for serverName, or null
// (url_refusal of histor/declared.py).
export function historUrlRefusal(url, serverName) {
  if (typeof url !== 'string' || url === '' || url.length > 2000) return '"url" must be an https URL';
  let u;
  try {
    u = new URL(url);
  } catch {
    return '"url" does not parse';
  }
  if (u.protocol !== 'https:') return '"url" must be https';
  if (u.username || u.password) return '"url" must not carry credentials';
  if (u.port !== '' && u.port !== '443') return '"url" must use the default https port';
  const host = u.hostname.replace(/\.+$/, '');
  const namespace = String(serverName ?? '').split('/')[0].trim().toLowerCase();
  if (namespace.startsWith('io.github.')) {
    const user = namespace.slice('io.github.'.length);
    if (!GITHUB_USER_RE.test(user)) return 'the server name has no GitHub user HISTOR can bind the file to';
    const p = u.pathname.toLowerCase();
    if (host === `${user}.github.io` || ((host === 'raw.githubusercontent.com' || host === 'gist.githubusercontent.com') && p.startsWith(`/${user}/`))) return null;
    return `"url" must be on ${user}.github.io or under /${user}/ on raw.githubusercontent.com, the account the registry verified`;
  }
  const labels = namespace.split('.').filter(Boolean);
  if (labels.length < 2) return 'the server name has no domain HISTOR can bind the file to';
  const domain = labels.reverse().join('.');
  if (host === domain || host.endsWith(`.${domain}`)) return null;
  return `"url" must be on ${domain} or a subdomain, the domain the registry verified for ${namespace}`;
}

// The sets HISTOR takes from a "sets" list, each with the index of its entry,
// and why any entry was skipped (parse_sets of histor/declared.py).
export function parseHistorSets(entries, limit = HISTOR_MAX_SETS, where = 'sets') {
  if (!Array.isArray(entries) || entries.length === 0) return { sets: [], skipped: [`"${where}" must be a non-empty list`] };
  const sets = [];
  const skipped = [];
  const seen = new Set();
  for (let i = 0; i < entries.length; i++) {
    if (sets.length === limit) {
      skipped.push(`${where}[${i}:]: more than ${limit} sets`);
      break;
    }
    const e = entries[i];
    if (!isObj(e)) { skipped.push(`${where}[${i}]: not an object`); continue; }
    if (typeof e.digest !== 'string' || !HISTOR_DIGEST_RE.test(e.digest)) { skipped.push(`${where}[${i}]: digest is not an MTL/1 tool-set digest (sha256-<base64>)`); continue; }
    if (seen.has(e.digest)) { skipped.push(`${where}[${i}]: the same digest twice`); continue; }
    if (!validCount(e.count)) { skipped.push(`${where}[${i}]: count must be an integer from 0 to ${HISTOR_MAX_COUNT}`); continue; }
    seen.add(e.digest);
    sets.push({ index: i, digest: e.digest, ...(e.count !== undefined && e.count !== null ? { count: e.count } : {}) });
  }
  return { sets, skipped };
}

// The member for one tool list: its contract digest (as the declaration signs
// it) and its number of tools. Returns { value, notes } or { problem }.
export function historToolSetsMember(contract, toolCount) {
  if (typeof contract !== 'string' || !HISTOR_DIGEST_RE.test(contract)) {
    return { problem: `the contract digest ${typeof contract === 'string' ? contract : '(none)'} is not in the form HISTOR reads ("sha256-" and base64 of 32 bytes)` };
  }
  const notes = [];
  const set = { digest: contract };
  if (Number.isInteger(toolCount) && toolCount >= 0 && toolCount <= HISTOR_MAX_COUNT) set.count = toolCount;
  else notes.push(`the tool list has ${toolCount} tools, more than the ${HISTOR_MAX_COUNT} HISTOR accepts as "count", so the member names the digest without a count`);
  return { value: { mtl: HISTOR_MTL, sets: [set] }, notes };
}

// The member built here, merged into a member of that name already in the
// listing or the server.json given (existing; undefined when there is none),
// so nothing HISTOR reads from it is withdrawn. The sets built here come
// first; every set HISTOR takes from the existing member follows, unless it
// names a digest built here (its "when" then moves to the set built here
// when that set has none); its "url" is kept as it is. What HISTOR does not
// read (entries it skips, other members) is left out and named.
// Returns { value, action, carried: { digests, url }, keptSets, keptWhen,
// url, urlRefused, leftOut, overflow }; action is "added" (no member was
// there), "replaced" (HISTOR reads nothing from the existing one) or
// "merged". overflow lists the existing sets that would not fit in the 8
// HISTOR reads; the caller refuses the run when it is not empty.
export function mergeHistorMember(built, existing, serverName) {
  const none = { carried: { digests: [], url: undefined }, keptSets: [], keptWhen: false, url: undefined, urlRefused: null, leftOut: [], overflow: [] };
  if (existing === undefined) return { value: built, action: 'added', ...none };
  if (!isObj(existing)) return { value: built, action: 'replaced', ...none, leftOut: ['it is not a JSON object, so HISTOR reads nothing from it'] };
  if (existing.mtl !== HISTOR_MTL) return { value: built, action: 'replaced', ...none, leftOut: [`its "mtl" is not "${HISTOR_MTL}", so HISTOR reads nothing from it`] };
  const leftOut = [];
  const other = Object.keys(existing).filter((k) => !MEMBER_KEYS.includes(k));
  if (other.length) leftOut.push(`the member${other.length === 1 ? '' : 's'} ${other.map((k) => JSON.stringify(k.length > 80 ? `${k.slice(0, 80)}...` : k)).join(', ')}, which HISTOR does not read`);
  const builtSets = built.sets.map((s) => ({ ...s }));
  const builtDigests = new Set(builtSets.map((s) => s.digest));
  const kept = [];
  let keptWhen = false;
  if (Object.hasOwn(existing, 'sets')) {
    const { sets, skipped } = parseHistorSets(existing.sets);
    for (const x of skipped) leftOut.push(`${x} (HISTOR skips it too)`);
    for (const s of sets) {
      const raw = existing.sets[s.index];
      if (builtDigests.has(s.digest)) {
        const mine = builtSets.find((b) => b.digest === s.digest);
        if (mine.when === undefined && typeof raw.when === 'string' && raw.when.trim() !== '') {
          mine.when = raw.when;
          keptWhen = true;
        }
      } else kept.push(raw);
    }
  }
  const room = Math.max(0, HISTOR_MAX_SETS - builtSets.length);
  const fits = kept.slice(0, room);
  const overflow = kept.slice(room).map((s) => s.digest);
  const hasUrl = Object.hasOwn(existing, 'url');
  const value = { mtl: HISTOR_MTL, sets: [...builtSets, ...fits], ...(hasUrl ? { url: existing.url } : {}) };
  return {
    value,
    action: 'merged',
    carried: { digests: fits.map((s) => s.digest), url: hasUrl ? existing.url : undefined },
    keptSets: fits.map((s) => s.digest),
    keptWhen,
    url: hasUrl ? existing.url : undefined,
    urlRefused: hasUrl ? historUrlRefusal(existing.url, serverName) : null,
    leftOut,
    overflow,
  };
}

// The self check of a member prepare wrote: it must read under HISTOR's rules
// with nothing skipped and no member HISTOR does not read, its first set must
// name the contract digest of the signed declaration (its toolSetDigest) with
// the tool count of the list signed, and every other set and the "url" must
// be those carried from the member already there (carried: { digests, url }).
// Returns a list of problems (empty when it passes).
export function historMemberProblems(member, toolSetDigest, toolCount, carried = { digests: [], url: undefined }) {
  const p = [];
  if (!isObj(member)) return ['the member is not a JSON object'];
  for (const k of Object.keys(member)) if (!MEMBER_KEYS.includes(k)) p.push(`it has the member ${JSON.stringify(k)}, which HISTOR does not read`);
  if (member.mtl !== HISTOR_MTL) p.push(`"mtl" is ${JSON.stringify(member.mtl)}, not "${HISTOR_MTL}"`);
  if (!Array.isArray(member.sets) || member.sets.length === 0) return [...p, '"sets" is not a non-empty list'];
  if (member.sets.length > HISTOR_MAX_SETS) p.push(`"sets" has ${member.sets.length} entries, more than the ${HISTOR_MAX_SETS} HISTOR reads`);
  const contract = isObj(toolSetDigest) ? toolSetDigest.contract : undefined;
  const allowed = new Set(carried.digests);
  const seen = new Set();
  member.sets.forEach((s, n) => {
    if (!isObj(s)) return p.push(`sets[${n}] is not a JSON object`);
    const shown = typeof s.digest === 'string' ? s.digest : '(none)';
    if (typeof s.digest !== 'string' || !HISTOR_DIGEST_RE.test(s.digest)) p.push(`sets[${n}].digest is not in the form HISTOR reads`);
    if (seen.has(s.digest)) p.push(`sets[${n}].digest ${shown} names the same digest as an earlier set`);
    seen.add(s.digest);
    if (!validCount(s.count)) p.push(`sets[${n}].count is ${JSON.stringify(s.count)}, not an integer from 0 to ${HISTOR_MAX_COUNT}`);
    if (n === 0) {
      if (s.digest !== contract) p.push(`sets[0].digest is ${shown}, and the declaration signs the contract digest ${contract ?? '(none)'}`);
      if (s.count !== undefined && s.count !== toolCount) p.push(`sets[0].count is ${JSON.stringify(s.count)}, and the tool list signed has ${toolCount} tools`);
    } else if (!allowed.has(s.digest) || s.digest === contract) {
      p.push(`sets[${n}].digest is ${shown}, which is neither the contract digest the declaration signs in sets[0] nor a set carried from the member already there`);
    }
  });
  if (Object.hasOwn(member, 'url') && member.url !== carried.url) p.push('"url" is not the one carried from the member already there');
  return p;
}

// A digest as 64 hex digits, from the "sha256-" base64 form or the "sha256:"
// hex form of mcp-tool-set-digest/1, or null.
function digestHex(s) {
  if (typeof s !== 'string') return null;
  if (HISTOR_DIGEST_RE.test(s)) return Buffer.from(s.slice('sha256-'.length), 'base64').toString('hex');
  if (/^sha256:[0-9a-f]{64}$/.test(s)) return s.slice('sha256:'.length);
  return null;
}

// What HISTOR takes from a listing's member (declared_tool_sets of
// histor/declared.py), for an informational line of check-listing. It
// changes no state. serverName binds the url, as for HISTOR.
// Returns { readable, problem, mtl, sets, digests, url, urlRefused, skipped }:
// sets and digests are those HISTOR takes, url is the url as given (or
// null), urlRefused why HISTOR does not read it (or null), skipped why
// entries were skipped. readable is true when HISTOR takes a set or the url.
export function readHistorMember(value, serverName) {
  const base = { mtl: null, sets: 0, digests: [], url: null, urlRefused: null, skipped: [] };
  if (!isObj(value)) return { readable: false, problem: 'not a JSON object', ...base };
  const mtl = typeof value.mtl === 'string' ? value.mtl : null;
  if (value.mtl !== HISTOR_MTL) return { readable: false, problem: `"mtl" is not "${HISTOR_MTL}"`, ...base, mtl };
  const hasUrl = Object.hasOwn(value, 'url');
  const url = hasUrl ? (typeof value.url === 'string' ? value.url : JSON.stringify(value.url)) : null;
  const urlRefused = hasUrl ? historUrlRefusal(value.url, serverName) : null;
  const urlTaken = hasUrl && urlRefused === null;
  let sets = [];
  let skipped = [];
  if (Object.hasOwn(value, 'sets')) ({ sets, skipped } = parseHistorSets(value.sets));
  const digests = sets.map((s) => s.digest);
  const readable = sets.length > 0 || urlTaken;
  let problem = null;
  if (!readable) {
    const why = [...(urlRefused ? [urlRefused] : []), ...skipped];
    problem = why.length ? `HISTOR takes no set and no url from it: ${why.slice(0, 3).join('; ')}` : 'it names no set and no url';
  }
  return { readable, problem, mtl, sets: sets.length, digests, url, urlRefused, skipped };
}

// How the digests a member names compare with the contract digest of a
// declaration: "all" (every one equals it), "some", "none", or null when
// there is nothing to compare.
export function compareHistorDigests(digests, toolSetDigest) {
  const want = digestHex(isObj(toolSetDigest) ? toolSetDigest.contract : null);
  if (want === null || digests.length === 0) return null;
  const same = digests.filter((d) => digestHex(d) === want).length;
  return same === digests.length ? 'all' : same > 0 ? 'some' : 'none';
}
