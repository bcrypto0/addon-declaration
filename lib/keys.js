// Key handling for the two algorithms the official MCP Registry accepts for
// domain namespaces: "ed25519" and "ecdsap384".
//
// Public key wire forms are the registry's own (the p= value of an MCPv1 proof
// record, standard padded base64):
//   ed25519   : the 32 byte raw public key
//   ecdsap384 : the 49 byte SEC1 compressed point (first byte 0x02 or 0x03)
// Signature forms are also the registry's:
//   ed25519   : 64 byte Ed25519 signature over the message (no prehash)
//   ecdsap384 : 96 byte r||s (IEEE P1363) over SHA-384 of the message

import crypto from 'node:crypto';

export const ALGS = Object.freeze(['ed25519', 'ecdsap384']);
export const SIG_LEN = Object.freeze({ ed25519: 64, ecdsap384: 96 });
const RAW_PUB_LEN = { ed25519: 32, ecdsap384: 49 };

export class KeyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'KeyError';
  }
}

// Two record kinds, same shape (SPEC.md section 9):
//   mcp   : the registry login record. Same pattern as MCPProofRecordPattern in
//           the registry (internal/api/handlers/v0/auth/common.go).
//   addon : a declaration only key, "v=ADKv1; k=...; p=...". The registry
//           pattern does not match it, so such a key cannot log in to the registry.
// The registry's pattern is Go RE2, where \s is only [\t\n\f\r ]. JavaScript \s
// also matches vertical tab, U+00A0, U+2000 to U+200A, U+FEFF and more, so the
// class is written out here: a record the registry does not match is not read.
export const RECORD_PATTERNS = Object.freeze({
  mcp: /v=MCPv1;[\t\n\f\r ]*k=([^;]+);[\t\n\f\r ]*p=([A-Za-z0-9+/=]+)/g,
  addon: /v=ADKv1;[\t\n\f\r ]*k=([^;]+);[\t\n\f\r ]*p=([A-Za-z0-9+/=]+)/g,
});
export const RECORD_PREFIX = Object.freeze({ mcp: 'v=MCPv1', addon: 'v=ADKv1' });

// Used for the declaration's own signature: the text must decode and encode
// back to itself (SPEC.md section 6).
export function decodeBase64Strict(s) {
  const buf = decodeBase64Go(s);
  if (!buf || buf.toString('base64') !== s) return null;
  return buf;
}

// Used for the p= value of proof records, as the registry decodes it: Go
// base64.StdEncoding.DecodeString without Strict(), which requires padding and
// refuses anything after it, but ignores nonzero bits in the last character.
export function decodeBase64Go(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  return Buffer.from(s, 'base64');
}

// Returns every usable key found in the given text, plus notes on records that
// were present but unusable (unknown algorithm, bad length, bad point).
// kinds: which record kinds to read (default both).
// The k= value is compared exactly, without trimming, as the registry does: a
// record such as "k=ed25519 ;" is refused there, so it is refused here.
export function parseProofRecords(text, { kinds = ['mcp', 'addon'] } = {}) {
  const keys = [];
  const notes = [];
  for (const kind of kinds) {
    for (const m of String(text).matchAll(RECORD_PATTERNS[kind])) {
      const alg = m[1];
      if (!ALGS.includes(alg)) {
        notes.push(`ignored ${RECORD_PREFIX[kind]} record with unsupported k=${JSON.stringify(alg)}`);
        continue;
      }
      const raw = decodeBase64Go(m[2]);
      if (!raw) {
        notes.push(`ignored ${alg} record with invalid base64`);
        continue;
      }
      try {
        keys.push({ ...publicKeyFromRaw(alg, raw), record: kind });
      } catch (e) {
        notes.push(`ignored ${alg} record: ${e.message}`);
      }
    }
  }
  return { keys, notes };
}

// { alg, raw, keyObject, id }
export function publicKeyFromRaw(alg, raw) {
  if (!ALGS.includes(alg)) throw new KeyError(`unsupported algorithm ${alg}`);
  if (raw.length !== RAW_PUB_LEN[alg]) throw new KeyError(`${alg} public key must be ${RAW_PUB_LEN[alg]} bytes`);
  let keyObject;
  if (alg === 'ed25519') {
    keyObject = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
  } else {
    if (raw[0] !== 0x02 && raw[0] !== 0x03) throw new KeyError('ecdsap384 public key must be a compressed point');
    let full;
    try {
      full = crypto.ECDH.convertKey(raw, 'secp384r1', undefined, undefined, 'uncompressed');
    } catch {
      throw new KeyError('ecdsap384 public key is not a point on P-384');
    }
    keyObject = crypto.createPublicKey({
      key: { kty: 'EC', crv: 'P-384', x: full.subarray(1, 49).toString('base64url'), y: full.subarray(49, 97).toString('base64url') },
      format: 'jwk',
    });
  }
  return { alg, raw: Buffer.from(raw), keyObject, id: keyId(raw) };
}

export function keyId(raw) {
  return 'sha256:' + crypto.createHash('sha256').update(raw).digest('hex');
}

// Raw wire form of a public KeyObject.
export function rawFromPublicKey(keyObject) {
  const type = keyObject.asymmetricKeyType;
  const jwk = keyObject.export({ format: 'jwk' });
  if (type === 'ed25519') return { alg: 'ed25519', raw: Buffer.from(jwk.x, 'base64url') };
  if (type === 'ec' && jwk.crv === 'P-384') {
    const x = Buffer.from(jwk.x, 'base64url');
    const y = Buffer.from(jwk.y, 'base64url');
    return { alg: 'ecdsap384', raw: Buffer.concat([Buffer.from([y[y.length - 1] & 1 ? 0x03 : 0x02]), x]) };
  }
  throw new KeyError('key is neither Ed25519 nor ECDSA P-384 (for example a P-256 or RSA key)');
}

export function proofRecord(pub, kind = 'mcp') {
  return `${RECORD_PREFIX[kind]}; k=${pub.alg}; p=${pub.raw.toString('base64')}`;
}

// Accepts a PEM public key (SPKI) or text holding one or more proof records.
export function parsePublicKeyText(text) {
  const t = String(text);
  if (t.includes('-----BEGIN PUBLIC KEY-----')) {
    let ko;
    try {
      ko = crypto.createPublicKey(t);
    } catch {
      throw new KeyError('PEM public key could not be read');
    }
    const { alg, raw } = rawFromPublicKey(ko);
    return [publicKeyFromRaw(alg, raw)];
  }
  const { keys } = parseProofRecords(t);
  if (keys.length === 0) throw new KeyError('no usable MCPv1 or ADKv1 proof record or PEM public key found');
  return keys;
}

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

// Private key input forms:
//   PEM: "PRIVATE KEY" (PKCS#8) or "EC PRIVATE KEY" (SEC1), as written by
//        openssl genpkey in the registry's instructions
//   hex: the value passed to `mcp-publisher login dns --private-key`, that is
//        the 32 byte Ed25519 seed (64 hex digits) or the 48 byte P-384 scalar
//        (96 hex digits). A P-384 scalar printed as a number may lose leading
//        zero digits (about 1 key in 16 loses at least one) or gain a leading
//        00 byte; 93 to 98 digits are left padded or stripped to 96.
// Error messages here describe the problem only and do not echo key material.
export function loadPrivateKey(text) {
  const t = String(text).trim();
  let keyObject;
  if (t.includes('-----BEGIN')) {
    if (t.includes('ENCRYPTED')) throw new KeyError('encrypted private keys are not supported; decrypt it locally first');
    if (t.includes('-----BEGIN PUBLIC KEY-----')) throw new KeyError('this is a public key; sign needs the private key');
    try {
      keyObject = crypto.createPrivateKey(t);
    } catch {
      throw new KeyError('PEM private key could not be read');
    }
  } else {
    let hex = t.replace(/[\s:]/g, '');
    if (!/^[0-9a-fA-F]+$/.test(hex)) throw new KeyError('private key is neither PEM nor hex');
    if (hex.length >= 93 && hex.length <= 98) {
      if (hex.length > 96) {
        if (!/^0+$/.test(hex.slice(0, hex.length - 96))) throw new KeyError(`hex private key has ${hex.length} digits; expected 64 (ed25519) or 96 (ecdsap384)`);
        hex = hex.slice(hex.length - 96);
      } else hex = hex.padStart(96, '0');
    }
    if (hex.length !== 64 && hex.length !== 96) throw new KeyError(`hex private key has ${hex.length} digits; expected 64 (ed25519) or 96 (ecdsap384)`);
    const bytes = Buffer.from(hex, 'hex');
    if (bytes.length === 32) {
      try {
        keyObject = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, bytes]), format: 'der', type: 'pkcs8' });
      } catch {
        throw new KeyError('Ed25519 seed could not be read');
      }
    } else {
      let pub;
      try {
        const ecdh = crypto.createECDH('secp384r1');
        ecdh.setPrivateKey(bytes);
        pub = ecdh.getPublicKey(null, 'uncompressed');
      } catch {
        throw new KeyError('P-384 private scalar is out of range');
      }
      keyObject = crypto.createPrivateKey({
        key: {
          kty: 'EC',
          crv: 'P-384',
          d: bytes.toString('base64url'),
          x: pub.subarray(1, 49).toString('base64url'),
          y: pub.subarray(49, 97).toString('base64url'),
        },
        format: 'jwk',
      });
    }
  }
  const pubObject = crypto.createPublicKey(keyObject);
  const { alg, raw } = rawFromPublicKey(pubObject);
  return { alg, privateKey: keyObject, public: publicKeyFromRaw(alg, raw) };
}

export function signBytes(alg, privateKey, message) {
  if (alg === 'ed25519') return crypto.sign(null, message, privateKey);
  if (alg === 'ecdsap384') return crypto.sign('sha384', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  throw new KeyError(`unsupported algorithm ${alg}`);
}

export function verifyBytes(pub, message, signature) {
  if (signature.length !== SIG_LEN[pub.alg]) return false;
  try {
    if (pub.alg === 'ed25519') return crypto.verify(null, message, pub.keyObject, signature);
    return crypto.verify('sha384', message, { key: pub.keyObject, dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}
