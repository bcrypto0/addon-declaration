import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, parseStrict, JsonError, containerDepth, decodeUtf8Strict } from '../lib/jcs.js';

const jcs = (text) => canonicalize(parseStrict(text));

// The RFC inputs use JSON escapes. They are built from BS (one backslash) so
// the test text cannot be altered by editor or tool escape handling.
const BS = String.fromCharCode(92);
const u = (hex) => BS + 'u' + hex;
const EURO = String.fromCharCode(0x20ac);

test('RFC 8785 section 3.2.2 example: numbers, string escapes, literals', () => {
  const input =
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], ' +
    `"string": "${u('20ac')}$${u('000F')}${u('000a')}A'${u('0042')}${u('0022')}${u('005c')}${BS}${BS}${BS}"${BS}/", ` +
    '"literals": [null, true, false]}';
  const expected =
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
    `"string":"${EURO}$${u('000f')}${BS}nA'B${BS}"${BS}${BS}${BS}${BS}${BS}"/"}`;
  assert.equal(jcs(input), expected);
});

test('RFC 8785 section 3.2.3 example: member names sorted by UTF-16 code units', () => {
  const input =
    `{"${u('20ac')}": "Euro Sign", "${BS}r": "Carriage Return", "${u('fb33')}": "Hebrew Letter Dalet With Dagesh", "1": "One", ` +
    `"${u('d83d')}${u('de00')}": "Emoji: Grinning Face", "${u('0080')}": "Control", "${u('00f6')}": "Latin Small Letter O With Diaeresis"}`;
  const values = [...jcs(input).matchAll(/:"([^"]*)"/g)].map((m) => m[1]);
  // The emoji (U+1F600, surrogates D83D DE00) sorts before U+FB33 in UTF-16 order,
  // which a code point sort would get wrong.
  assert.deepEqual(values, [
    'Carriage Return',
    'One',
    'Control',
    'Latin Small Letter O With Diaeresis',
    'Euro Sign',
    'Emoji: Grinning Face',
    'Hebrew Letter Dalet With Dagesh',
  ]);
});

test('RFC 8785 appendix B number vectors', () => {
  const vectors = [
    ['0000000000000000', '0'],
    ['8000000000000000', '0'],
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555554', '333333333.33333325'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555556', '333333333.3333334'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
  ];
  for (const [hex, want] of vectors) {
    const n = Buffer.from(hex, 'hex').readDoubleBE(0);
    assert.equal(canonicalize(n), want, hex);
  }
});

test('nested structures and key order are canonical regardless of input layout', () => {
  const a = jcs('{"b":[{"z":1,"a":{"y":2,"x":[3,{"q":null,"p":true}]}}],"a":"x"}');
  const b = jcs('{ "a" : "x",\n "b" : [ { "a" : { "x" : [ 3 , { "p" : true , "q" : null } ] , "y" : 2 } , "z" : 1 } ] }');
  assert.equal(a, b);
  assert.equal(a, '{"a":"x","b":[{"a":{"x":[3,{"p":true,"q":null}],"y":2},"z":1}]}');
});

test('number spellings that parse to the same double canonicalize the same', () => {
  assert.equal(jcs('[1.0, 1e0, 10e-1, 0.1e1, -0, 0.0, 100, 1E2]'), '[1,1,1,1,0,0,100,100]');
});

test('unicode: non ASCII is kept as UTF-8, escapes are normalized, controls are escaped', () => {
  assert.equal(jcs('"\\u00e9\\u4e2d\\ud83d\\ude00"'), '"é中😀"');
  assert.equal(jcs('"é中😀"'), '"é中😀"');
  assert.equal(jcs('"\\u0001\\u001f\\b\\t\\n\\f\\r\\u007f\\/"'), '"\\u0001\\u001f\\b\\t\\n\\f\\r\u007f/"');
  // Different Unicode normal forms are different strings; no normalization is applied.
  assert.notEqual(jcs('"\\u00e9"'), jcs('"e\\u0301"'));
});

test('strict parser rejects what I-JSON forbids', () => {
  const bad = [
    '{"a":1,"a":2}',
    '"\\ud800"',
    '"\\udc00x"',
    '1e400',
    '-1e400',
    '[1,]',
    '{"a":1,}',
    '01',
    '+1',
    '.5',
    'NaN',
    "'x'",
    '{"a" 1}',
    '"tab\there"',
    '[1] [2]',
    '',
    '[' .repeat(100) + ']'.repeat(100),
  ];
  for (const t of bad) assert.throws(() => parseStrict(t), JsonError, JSON.stringify(t));
});

test('a member named __proto__ is data, not a prototype change', () => {
  const v = parseStrict('{"__proto__":{"x":1},"a":2}');
  assert.equal(Object.getPrototypeOf(v), Object.prototype);
  assert.deepEqual(Object.keys(v).sort(), ['__proto__', 'a']);
  assert.equal(canonicalize(v), '{"__proto__":{"x":1},"a":2}');
});

test('canonicalize refuses values JSON cannot hold', () => {
  for (const v of [NaN, Infinity, undefined, () => 1, new Date(0), { a: undefined }, '\ud800', 10n]) {
    assert.throws(() => canonicalize(v), JsonError);
  }
});

test('leading byte order mark is ignored by the parser', () => {
  // Written with fromCharCode so an editor cannot silently drop the character.
  const bom = String.fromCharCode(0xfeff);
  assert.deepEqual(parseStrict(bom + '{"a":1}'), { a: 1 });
  assert.deepEqual(parseStrict(decodeUtf8Strict(Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{"a":1}')]))), { a: 1 });
});

test('numbers: no silent precision loss or underflow (I-JSON)', () => {
  // Integer literals beyond 2^53 - 1 would round to a neighbour and hash the same.
  for (const t of ['9007199254740993', '9007199254740992', '-9007199254740992', '[1e-400]', '-1e-400', '1.5e-400']) {
    assert.throws(() => parseStrict(t), JsonError, t);
  }
  for (const [t, v] of [['9007199254740991', 9007199254740991], ['-9007199254740991', -9007199254740991], ['0e5', 0], ['0.000', 0], ['-0', -0], ['1e30', 1e30], ['0.0000e-999999', 0]]) {
    assert.equal(parseStrict(t), v, t);
  }
});

test('nesting depth counts arrays and objects only, from the root', () => {
  const nest = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  assert.doesNotThrow(() => parseStrict(nest(64)));
  assert.throws(() => parseStrict(nest(65)), /nesting too deep/);
  assert.equal(containerDepth(parseStrict(nest(64))), 64);
  assert.equal(containerDepth(1), 0);
  assert.equal(containerDepth({ a: [{}] }), 3);
});

test('file bytes: UTF-16 and invalid UTF-8 are refused with a clear reason', () => {
  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"a":1}', 'utf16le')]);
  assert.throws(() => decodeUtf8Strict(utf16), /UTF-16/);
  assert.throws(() => decodeUtf8Strict(Buffer.from('{"a":1}', 'utf16le')), /UTF-16/);
  assert.throws(() => decodeUtf8Strict(Buffer.from([0x22, 0xff, 0xfe, 0x22])), /not valid UTF-8/);
  assert.equal(decodeUtf8Strict(Buffer.from('{"a":"\r\n"}')), '{"a":"\r\n"}');
});
