import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { decode, encode, get } from './cbor.mjs';
import { verifyIssuerSigned } from './base.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/cbor-text.json', import.meta.url)));
const raw = hex => Buffer.from(hex, 'hex');
for (const row of vectors.text) test('CBOR text preserves code points: ' + row.id, () => {
  assert.equal(decode(raw(row.hex)), row.value);
  assert.deepEqual(encode(row.value), raw(row.hex));
});
test('CBOR text preserves every nested string', () => {
  assert.deepEqual(decode(raw(vectors.nested.hex)), vectors.nested.value);
  assert.deepEqual(encode(vectors.nested.value), raw(vectors.nested.hex));
  assert.deepEqual(decode(raw(vectors.opaque.hex)), raw(vectors.opaque.valueHex));
  assert.deepEqual(encode(raw(vectors.opaque.valueHex)), raw(vectors.opaque.hex));
});
for (const row of vectors.maps) test('CBOR text map preserves exact keys: ' + row.id, () => {
  const expected = new Map(row.entries), actual = decode(raw(row.hex));
  assert.deepEqual(actual, expected);
  assert.equal(actual.size, row.entries.length);
  assert.deepEqual(encode(expected), raw(row.hex));
});
test('CBOR text lookup does not alias a BOM-prefixed key', () => {
  const map = decode(raw('a167efbbbf726f6c656178'));
  assert.equal(get(map, '\ufeffrole'), 'x');
  assert.equal(map.has('role'), false);
  assert.throws(() => get(map, 'role'), { code: 'CBOR_FIELD_role' });
});
for (const row of vectors.duplicateMaps) test('CBOR text rejects duplicate keys: ' + row.id, () => {
  assert.throws(() => decode(raw(row.hex)), { code: 'CBOR_DUPLICATE' });
});
for (const row of vectors.invalidUTF8) test('CBOR text rejects malformed UTF-8: ' + row.id, () => {
  assert.throws(() => decode(raw(row.hex)), { code: 'ERR_ENCODING_INVALID_ENCODED_DATA' });
});
for (const row of vectors.invalidUTF16) test('CBOR text rejects lone UTF-16 surrogate: ' + row.id, () => {
  assert.throws(() => encode(row.value), { code: 'CBOR_TEXT' });
});
test('CBOR text rejects truncated payload', () => {
  assert.throws(() => decode(raw(vectors.truncated.hex)), { code: 'CBOR_TRUNCATED' });
});
test('CBOR text retains byte and item budgets', () => {
  const input = raw('64efbbbf41');
  assert.equal(decode(input, { maxBytes: 5, maxItems: 1 }), '\ufeffA');
  assert.throws(() => decode(input, { maxBytes: 4 }), { code: 'CBOR_SIZE' });
  assert.throws(() => decode(input, { maxItems: 0 }), { code: 'CBOR_LIMIT' });
  assert.deepEqual(decode(raw(vectors.nested.hex), { maxItems: 5 }), vectors.nested.value);
  assert.throws(() => decode(raw(vectors.nested.hex), { maxItems: 4 }), { code: 'CBOR_ITEM_BUDGET' });
});

test('CBOR text does not normalize decomposed Unicode', () => {
  assert.equal(decode(raw(vectors.nonNFC.hex)), vectors.nonNFC.value);
  assert.deepEqual(encode(vectors.nonNFC.value), raw(vectors.nonNFC.hex));
});
test('CBOR trailing-byte policy remains explicit for BOM-prefixed text', () => {
  const input = raw('64efbbbf4100');
  assert.deepEqual(decode(input, { allowTrailing: true }), { value: '\ufeffA', bytesRead: 5 });
  assert.throws(() => decode(input), { code: 'CBOR_TRAILING' });
});

const signed = JSON.parse(readFileSync(new URL('../vectors/base.json', import.meta.url))).cases[0];
for (const row of vectors.outerFields) test('IssuerSigned rejects BOM-prefixed outer field: ' + row.name, () => {
  const credential = raw(signed.credential), certificate = raw(signed.certificate);
  const options = { issuerKey: new X509Certificate(certificate).publicKey, certificate, at: signed.stateTime };
  const verified = verifyIssuerSigned(credential, options);
  assert.equal(verified.certificateBound, true);
  const key = raw(row.keyHex), replacement = raw(row.bomKeyHex), offset = credential.indexOf(key);
  assert(offset >= 0);
  assert.equal(credential.indexOf(key, offset + key.length), -1);
  // Change only the outer key bytes. Existing issuerAuth signature and payload stay intact.
  const changed = Buffer.concat([credential.subarray(0, offset), replacement, credential.subarray(offset + key.length)]);
  assert.throws(() => verifyIssuerSigned(changed, options), { code: 'MDOC_FIELDS' });
  const before = decode(credential), after = decode(changed);
  assert.equal(after.has(row.name), false);
  assert.deepEqual(after.get('\ufeff' + row.name), before.get(row.name));
  const other = row.name === 'issuerAuth' ? 'nameSpaces' : 'issuerAuth';
  assert.deepEqual(after.get(other), before.get(other));
});
