import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decode, encode } from './cbor.mjs';

const keyVectors = JSON.parse(readFileSync(new URL('../vectors/cbor-encode-map-keys.json', import.meta.url)));
const key = entry => ({ number: () => entry.key, bigint: () => BigInt(entry.key),
  text: () => entry.key, bytes: () => Buffer.from(entry.key, 'hex') })[entry.keyType]();
for (const vector of keyVectors.cases) test('selected CBOR encoder map key: ' + vector.id, () => {
  const input = new Map(vector.entries.map(entry => [key(entry), entry.value]));
  if (vector.expected.overall === 'INVALID') {
    assert.throws(() => decode(Buffer.from(vector.oldWire, 'hex')), { code: vector.expected.reason });
    assert.throws(() => encode(input), { code: vector.expected.reason });
  } else {
    const wire = Buffer.from(vector.wire, 'hex');
    assert.deepEqual(encode(input), wire);
    assert.deepEqual(encode(decode(wire)), wire);
  }
});

for (const [name, input, normalized, wire] of [
  ['maximum positive integer', 0xffffffffffffffffn, 0xffffffffffffffffn, '1bffffffffffffffff'],
  ['minimum negative integer', -0x10000000000000000n, -0x10000000000000000n, '3bffffffffffffffff'],
  ['maximum safe positive integer', 9007199254740991n, 9007199254740991, '1b001fffffffffffff'],
  ['first positive bigint', 9007199254740992n, 9007199254740992n, '1b0020000000000000'],
  ['minimum safe negative integer', -9007199254740991n, -9007199254740991, '3b001ffffffffffffe'],
  ['first negative bigint', -9007199254740992n, -9007199254740992n, '3b001fffffffffffff'],
]) test('integer map label: ' + name, () => {
  const raw = Buffer.from('a1' + wire + 'f5', 'hex');
  assert.deepEqual(decode(raw), new Map([[normalized, true]]));
  assert.deepEqual(encode(new Map([[input, true]])), raw);
  assert.deepEqual(encode(decode(raw)), raw);
});

for (const key of ['1bffffffffffffffff', '3bffffffffffffffff'])
  test('duplicate bigint map label is rejected: ' + key, () => {
    assert.throws(() => decode(Buffer.from('a2' + key + 'f5' + key + 'f4', 'hex')), { code: 'CBOR_DUPLICATE' });
  });

test('nonminimal alternative encoding of the same integer label is rejected', () => {
  assert.deepEqual(decode(Buffer.from('a117f5', 'hex')), new Map([[23, true]]));
  assert.throws(() => decode(Buffer.from('a217f51817f4', 'hex')), { code: 'CBOR_NONMINIMAL' });
  assert.throws(() => decode(Buffer.from('a11b00000000fffffffff5', 'hex')), { code: 'CBOR_NONMINIMAL' });
});

for (const [name, raw] of [['Boolean', 'a1f5f5'], ['map', 'a1a0f5']])
  test('nonselected map key is rejected: ' + name, () => {
    assert.throws(() => decode(Buffer.from(raw, 'hex')), { code: 'CBOR_MAP_KEY' });
  });

for (const [name, key] of [['positive', 0x10000000000000000n], ['negative', -0x10000000000000001n]])
  test('integer label outside the CBOR 64-bit argument is rejected: ' + name, () => {
    assert.throws(() => encode(new Map([[key, true]])), { code: 'CBOR_RANGE' });
  });
