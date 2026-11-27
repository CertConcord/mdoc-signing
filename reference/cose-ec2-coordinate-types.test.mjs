import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createECDH, createPublicKey } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { types } from 'node:util';
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

const positiveWire = Buffer.from(vectors.cases.find(vector => vector.id === 'ec2-bstr-coordinates').wire, 'hex');
for (const [name, useX, useY] of [
  ['x', true, false], ['y', false, true], ['x and y', true, true],
]) test('native Uint8Array EC2 coordinate: ' + name, () => {
  const x = useX ? new Uint8Array(point.x) : point.x;
  const y = useY ? new Uint8Array(point.y) : point.y;
  const key = new Map([[1, 2], [-1, 1], [-2, x], [-3, y]]);
  assert.deepEqual(encode(key), positiveWire);
  assert.deepEqual(coseJWK(key), selected);
});

const foreignBytes = bytes => runInNewContext('new Uint8Array(bytes)', { bytes: [...bytes] });
for (const [name, useX, useY] of [
  ['x', true, false], ['y', false, true], ['x and y', true, true],
]) {
  const x = useX ? foreignBytes(point.x) : point.x;
  const y = useY ? foreignBytes(point.y) : point.y;
  const key = new Map([[1, 2], [-1, 1], [-2, x], [-3, y]]);
  if (useX) { assert.equal(x instanceof Uint8Array, false); assert(types.isUint8Array(x)); }
  if (useY) { assert.equal(y instanceof Uint8Array, false); assert(types.isUint8Array(y)); }
  test('cross-realm Uint8Array EC2 coordinate direct call: ' + name, () => {
    assert.deepEqual(coseJWK(key), selected);
  });
  test('cross-realm Uint8Array EC2 coordinate encoding: ' + name, () => {
    assert.deepEqual(encode(key), positiveWire);
  });
}

test('other byte views do not become EC2 coordinates', () => {
  const wrong = runInNewContext('new Uint8ClampedArray(bytes)', { bytes: [...point.x] });
  assert.equal(types.isUint8Array(wrong), false);
  const key = new Map([[1, 2], [-1, 1], [-2, wrong], [-3, point.y]]);
  assert.throws(() => coseJWK(key), { code: 'COSE_KEY' });
  assert.throws(() => encode(key), { code: 'CBOR_TYPE' });
});

test('EC2 direct conversion uses actual coordinate bytes despite shadowed valueOf', () => {
  const other = createECDH('prime256v1');
  other.setPrivateKey(Buffer.from([1]));
  const otherPoint = other.getPublicKey(undefined, 'uncompressed');
  const x = new Uint8Array(point.x), y = new Uint8Array(point.y);
  x.valueOf = () => otherPoint.subarray(1, 33);
  y.valueOf = () => otherPoint.subarray(33);
  const key = new Map([[1, 2], [-1, 1], [-2, x], [-3, y]]);
  assert.deepEqual(encode(key), positiveWire);
  assert.deepEqual(coseJWK(key), selected);
});

test('EC2 native byte views use their actual length and offset', () => {
  const storage = Uint8Array.from([9, ...point.x, 8]);
  const x = new Uint8Array(storage.buffer, 1, 32);
  Object.defineProperty(x, 'length', { value: 1 });
  const key = new Map([[1, 2], [-1, 1], [-2, x], [-3, new Uint8Array(point.y)]]);
  assert.deepEqual(encode(key), positiveWire);
  assert.deepEqual(coseJWK(key), selected);
});
