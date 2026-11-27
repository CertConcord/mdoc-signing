import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { types } from 'node:util';
import { coseJWK, decode, encode, get, unembed } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-base.json', import.meta.url)));
const credential = decode(Buffer.from(vectors.base.credential, 'hex'));
const mso = unembed(decode(get(credential, 'issuerAuth')[2]));
const selected = get(get(mso, 'deviceKeyInfo'), 'deviceKey');
const pub = get(selected, -1);
const selectedJWK = coseJWK(selected);
const selectedWire = encode(selected);
const withPub = value => new Map([...selected].map(([label, data]) =>
  [label, label === -1 ? value : data]));

test('selected serialized ML-DSA-65 AKP public key remains valid', () => {
  assert(Buffer.isBuffer(pub));
  assert.equal(pub.length, 1952);
  assert.equal(selectedJWK.alg, 'ML-DSA-65');
  assert.deepEqual(decode(selectedWire), selected);
});

for (const [name, bytes] of [
  ['native', new Uint8Array(pub)],
  ['cross-realm', runInNewContext('new Uint8Array(bytes)', { bytes: [...pub] })],
]) test('AKP pub accepts ' + name + ' Uint8Array with identical CBOR bytes', () => {
  assert(types.isUint8Array(bytes));
  assert.equal(Buffer.isBuffer(bytes), false);
  assert.deepEqual(encode(withPub(bytes)), selectedWire);
  assert.deepEqual(coseJWK(withPub(bytes)), selectedJWK);
});

test('AKP pub rejects arrays, other views and short bytes', () => {
  assert.throws(() => coseJWK(withPub([...pub])), { code: 'COSE_KEY' });
  assert.throws(() => coseJWK(withPub(new Uint8ClampedArray(pub))), { code: 'COSE_KEY' });
  assert.throws(() => coseJWK(withPub(pub.subarray(1))), { code: 'COSE_KEY' });
});

test('AKP pub is read once from a stable direct-call map', () => {
  const key = withPub(new Uint8Array(pub));
  let reads = 0;
  key.get = label => {
    if (label === -1) reads++;
    return Map.prototype.get.call(key, label);
  };
  assert.deepEqual(coseJWK(key), selectedJWK);
  assert.equal(reads, 1);
});

test('AKP pub uses the native bytes of an offset subview', () => {
  const storage = new Uint8Array(pub.length + 6);
  storage.fill(0x5a);
  storage.set(pub, 3);
  const bytes = storage.subarray(3, 3 + pub.length);
  assert.equal(bytes.byteOffset, 3);
  assert.deepEqual(encode(withPub(bytes)), selectedWire);
  assert.deepEqual(coseJWK(withPub(bytes)), selectedJWK);

  let conversions = 0;
  Object.defineProperties(bytes, {
    valueOf: { value() { conversions++; return Buffer.alloc(0); } },
    buffer: { get() { throw Error('shadowed buffer'); } },
    byteOffset: { get() { throw Error('shadowed offset'); } },
    byteLength: { get() { throw Error('shadowed length'); } },
  });
  assert.deepEqual(coseJWK(withPub(bytes)), selectedJWK);
  assert.equal(conversions, 0);
});
