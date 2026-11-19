// Shared test fixtures. Keys are generated fresh in each test run and are
// not written anywhere outside the system temp folder. This file sits outside
// test/ so that `node --test` does not count it as a test file.

import crypto from 'node:crypto';
import { loadPrivateKey, proofRecord, signBytes } from '../lib/keys.js';
import { SPEC_ID, ordered, signingInput } from '../lib/declaration.js';

// Signs without any of signDeclaration's checks, to build declarations a
// publisher could not produce with the CLI (wrong namespace, too large, ...).
export function signRaw(unsignedDecl, loaded) {
  const d = ordered({ ...unsignedDecl, key: { ...unsignedDecl.key, alg: loaded.alg, id: loaded.public.id } });
  delete d.signature;
  return ordered({ ...d, signature: signBytes(loaded.alg, loaded.privateKey, signingInput(d)).toString('base64') });
}

export const NOW = Date.parse('2026-11-18T12:00:00Z');

export function makeKey(alg) {
  const pair =
    alg === 'ed25519'
      ? crypto.generateKeyPairSync('ed25519')
      : crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const pem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const d = Buffer.from(pair.privateKey.export({ format: 'jwk' }).d, 'base64url');
  const hex = d.toString('hex');
  const loaded = loadPrivateKey(pem);
  return { alg, pem, hex, loaded, record: proofRecord(loaded.public), secretStrings: secretStrings(pem, d) };
}

// Every textual form of the private key that must not show up in any output.
function secretStrings(pem, d) {
  const body = pem
    .split('\n')
    .filter((l) => l && !l.startsWith('-----'))
    .join('');
  return [body, d.toString('hex'), d.toString('hex').toUpperCase(), d.toString('base64'), d.toString('base64url')];
}

export const TOOLS = {
  tools: [
    {
      name: 'get_forecast',
      title: 'Get forecast',
      description: 'Weather forecast for a place.',
      inputSchema: { type: 'object', properties: { place: { type: 'string' }, days: { type: 'integer', minimum: 1, maximum: 7 } }, required: ['place'] },
    },
    {
      name: 'get_alerts',
      description: 'Active weather alerts. Ünïcödé text, 中文, 😀.',
      inputSchema: { type: 'object', properties: { region: { type: 'string' } } },
      annotations: { readOnlyHint: true },
    },
  ],
};

export function baseUnsigned(overrides = {}) {
  return {
    spec: SPEC_ID,
    name: 'com.example/weather',
    version: '1.4.0',
    toolsHash: 'sha256:' + '0'.repeat(64),
    remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }],
    payment: [{ network: 'eip155:8453', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: '0x1111111111111111111111111111111111111111', amount: '10000' }],
    contact: 'mailto:security@example.com',
    issuedAt: '2026-11-18T10:00:00Z',
    expiresAt: '2027-05-18T10:00:00Z',
    previous: 'sha256:' + 'a'.repeat(64),
    key: { method: 'dns', domain: 'example.com' },
    ...overrides,
  };
}
