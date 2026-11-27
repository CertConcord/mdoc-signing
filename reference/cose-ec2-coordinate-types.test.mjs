import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { coseJWK, decode, encode } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/cose-ec2-coordinate-types.json', import.meta.url)));
const point = Object.fromEntries(Object.entries(vectors.point).map(([name, hex]) => [name, Buffer.from(hex, 'hex')]));
assert.equal(point.x.length, 32);
assert.equal(point.y.length, 32);
const selected = { kty: 'EC', crv: 'P-256', x: point.x.toString('base64url'),
  y: point.y.toString('base64url') };
assert.equal(createPublicKey({ key: selected, format: 'jwk' }).asymmetricKeyType, 'ec');

for (const vector of vectors.cases) test('EC2 coordinate CBOR type: ' + vector.id, () => {
  const wire = Buffer.from(vector.wire, 'hex');
  const key = decode(wire);
  assert.deepEqual(encode(key), wire);
  assert.deepEqual(Buffer.from(key.get(-2)), point.x);
  assert.deepEqual(Buffer.from(key.get(-3)), point.y);
  if (vector.expected.overall === 'VALID') {
    assert(Buffer.isBuffer(key.get(-2)) && Buffer.isBuffer(key.get(-3)));
    assert.deepEqual(coseJWK(key), selected);
  } else {
    assert.throws(() => coseJWK(key), { code: vector.expected.reason });
  }
});
