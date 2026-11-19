// Strict JSON parsing and RFC 8785 (JSON Canonicalization Scheme) serialization.
//
// parseStrict accepts exactly RFC 8259 JSON and additionally rejects what I-JSON
// (RFC 7493) forbids or advises against and RFC 8785 relies on: duplicate object
// member names, lone surrogates in strings, numbers that do not fit an IEEE 754
// double, integer literals outside the I-JSON exact range, and nonzero literals
// that underflow to zero. See SPEC.md section 5.

// reason: a short code for the rule that failed, the same codes the conformance
// vectors use (vectors/manifest.json): "encoding", "syntax", "duplicate-member",
// "lone-surrogate", "range", "underflow", "depth".
export class JsonError extends Error {
  constructor(message, reason = 'syntax') {
    super(message);
    this.name = 'JsonError';
    this.reason = reason;
  }
}

// Nesting limit: the number of arrays and objects on the deepest path, counting
// the outermost one. Scalars do not count. SPEC.md section 5.
export const MAX_DEPTH = 64;

// Decodes file bytes as UTF-8 and refuses anything else. UTF-16 files (a common
// result of PowerShell 5.1 ">" and Out-File) get a message that names the cause.
export function decodeUtf8Strict(buf) {
  if (typeof buf === 'string') return buf;
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff) || b.includes(0)) {
    throw new JsonError('file is UTF-16 (or holds NUL bytes); save it as UTF-8 (in PowerShell: Out-File -Encoding utf8)', 'encoding');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b);
  } catch {
    throw new JsonError('input is not valid UTF-8', 'encoding');
  }
}

// Integer literals beyond 2^53 - 1. Most often an int64 or uint64 bound in a
// tool schema, which only the server can change (SPEC.md section 5).
export const INTEGER_RANGE_MESSAGE =
  'integer outside the range -(2^53 - 1) to 2^53 - 1 (SPEC.md section 5). If a tool schema holds an int64 or uint64 bound, change the server so its tools/list no longer sends this literal, then capture the tool list again; editing tools.json alone gives a hash that clients, which hash what the server sends, cannot match';

// A number literal with no IEEE 754 double (it overflows, such as 1e400). Only
// the relaxed parse below produces one; canonicalize refuses it with the
// reason "range", so a value that holds one has no canonical form.
export class NoDouble {
  constructor(literal) {
    this.literal = literal;
    Object.freeze(this);
  }
}

// options:
//   maxDepth: the nesting limit (SPEC.md section 5)
//   relaxed: the input rules of mcp-tool-set-digest/1 section 3, for the
//     tool-set-digest command only (README.md). A repeated member name keeps
//     the last value and calls onDuplicate(name); every number is the nearest
//     double, so integers beyond 2^53 - 1 are rounded and a nonzero literal
//     that underflows becomes 0; a literal with no double becomes a NoDouble;
//     lone surrogates are kept. canonicalize still refuses the last two, so
//     the caller sees them only when it writes the value. Off by default: the
//     declaration rules of SPEC.md section 5 do not change.
//   limitFrom: optional (path, isArray) => boolean. When given, maxDepth is
//     counted from the first container on a path for which it returns true
//     (path: the member names from the root, null for array elements), and
//     containers outside such a subtree are limited only by outerMaxDepth, a
//     resource limit. Tool pages use this: the limit is counted from the
//     page's tools array, whatever wrapper it came in (SPEC.md section 4).
export function parseStrict(text, { maxDepth = MAX_DEPTH, limitFrom, outerMaxDepth = maxDepth, relaxed = false, onDuplicate } = {}) {
  if (typeof text !== 'string') throw new JsonError('input is not text');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let i = 0;
  // The number of arrays that enclose the value being parsed. A member repeated
  // outside every array sits in the wrapper of a tools/list page, not in a tool.
  let arrays = 0;

  const fail = (msg, reason = 'syntax') => {
    throw new JsonError(`${msg} at offset ${i}`, reason);
  };
  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseString = () => {
    i++; // opening quote
    let out = '';
    for (;;) {
      if (i >= text.length) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        break;
      }
      if (c < 0x20) fail('control character in string');
      if (c === 0x5c) {
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('bad unicode escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail('bad escape');
        }
      } else {
        out += text[i];
        i++;
      }
    }
    if (!relaxed && hasLoneSurrogate(out)) fail('lone surrogate in string', 'lone-surrogate');
    return out;
  };

  const NUMBER = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
  const parseNumber = () => {
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m || m[0] === '-' || m[0] === '') fail('bad number');
    const n = Number(m[0]);
    if (relaxed) {
      i += m[0].length;
      return Number.isFinite(n) ? n : new NoDouble(m[0]);
    }
    if (!Number.isFinite(n)) fail('number out of range', 'range');
    // I-JSON (RFC 7493 section 2.2): integers beyond 2^53 - 1 lose precision in
    // a double, so two different literals could hash the same.
    if (m[2] === undefined && m[3] === undefined && !Number.isSafeInteger(n)) fail(INTEGER_RANGE_MESSAGE, 'range');
    // A nonzero literal that rounds to zero (for example 1e-400).
    if (n === 0 && /[1-9]/.test(m[1] + (m[2] || ''))) fail('number underflows to zero', 'underflow');
    i += m[0].length;
    return n;
  };

  // depth: the number of arrays and objects that enclose the value being parsed,
  // counted from the root, or from the start of the limited subtree.
  // path: member names from the root while outside a limited subtree, else null.
  const parseValue = (depth, path) => {
    ws();
    if (i >= text.length) fail('unexpected end of input');
    const c = text[i];
    if (c === '{' || c === '[') {
      if (path && limitFrom(path, c === '[')) {
        depth = 0;
        path = null;
      }
      if (depth + 1 > (path ? outerMaxDepth : maxDepth)) fail('nesting too deep', 'depth');
    }
    if (c === '{') {
      i++;
      const obj = Object.create(null);
      ws();
      if (text[i] === '}') {
        i++;
        return toPlain(obj);
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected member name');
        const key = parseString();
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          if (!relaxed) fail(`duplicate member name "${key}"`, 'duplicate-member');
          if (onDuplicate) onDuplicate(key, { inArray: arrays > 0 });
        }
        ws();
        if (text[i] !== ':') fail('expected ":"');
        i++;
        obj[key] = parseValue(depth + 1, path && [...path, key]);
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return toPlain(obj);
        }
        fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      ws();
      if (text[i] === ']') {
        i++;
        return arr;
      }
      arrays++;
      for (;;) {
        arr.push(parseValue(depth + 1, path && [...path, null]));
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          arrays--;
          return arr;
        }
        fail('expected "," or "]"');
      }
    }
    if (c === '"') return parseString();
    if (text.startsWith('true', i)) {
      i += 4;
      return true;
    }
    if (text.startsWith('false', i)) {
      i += 5;
      return false;
    }
    if (text.startsWith('null', i)) {
      i += 4;
      return null;
    }
    return parseNumber();
  };

  const value = parseValue(0, limitFrom ? [] : null);
  ws();
  if (i !== text.length) fail('trailing data');
  return value;
}

// Number of arrays and objects on the deepest path of a parsed value.
export function containerDepth(v) {
  if (v === null || typeof v !== 'object') return 0;
  let max = 0;
  for (const x of Array.isArray(v) ? v : Object.values(v)) {
    const d = containerDepth(x);
    if (d > max) max = d;
  }
  return max + 1;
}

// Objects are built without a prototype so a member named "__proto__" is stored
// as data; they are then copied into ordinary objects with defineProperty.
function toPlain(nullProtoObj) {
  const out = {};
  for (const k of Object.keys(nullProtoObj)) {
    Object.defineProperty(out, k, { value: nullProtoObj[k], enumerable: true, writable: true, configurable: true });
  }
  return out;
}

export function hasLoneSurrogate(s) {
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(k + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return true;
      k++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

// RFC 8785 serialization. For finite numbers and well formed strings the
// ECMAScript JSON.stringify output is exactly what RFC 8785 sections 3.2.2.2 and
// 3.2.2.3 require (the RFC defines both by reference to ECMAScript), including
// "-0" serializing as "0" and lowercase hex in \u escapes.
// maxDepth: MAX_DEPTH unless a caller sets its own resource bound.
export function canonicalize(value, depth = 0, maxDepth = MAX_DEPTH) {
  if (depth > maxDepth) throw new JsonError('nesting too deep', 'depth');
  if (value === null) return 'null';
  if (value instanceof NoDouble) throw new JsonError(`number ${value.literal} has no IEEE 754 double`, 'range');
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new JsonError('non finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    if (hasLoneSurrogate(value)) throw new JsonError('lone surrogate in string', 'lone-surrogate');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v, depth + 1, maxDepth)).join(',') + ']';
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new JsonError('not a plain object');
    // Default sort compares UTF-16 code units, which is the order RFC 8785 3.2.3 specifies.
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      if (value[k] === undefined) throw new JsonError(`undefined value for "${k}"`);
      parts.push(canonicalize(k, depth + 1, maxDepth) + ':' + canonicalize(value[k], depth + 1, maxDepth));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new JsonError(`cannot canonicalize a value of type ${typeof value}`);
}
