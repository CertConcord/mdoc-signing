import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';
import { CREDENTIAL_HEADER, prepareDocumentSignature, verifyDocumentSignature } from './base.mjs';
import { decode, encode } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-document-map-order.json', import.meta.url)));
const bytes = value => Buffer.from(value, 'hex');
const document = bytes(vectors.document), credential = bytes(vectors.credential);
const publicKey = createPublicKey({ key: bytes(vectors.publicKeyDER), format: 'der', type: 'spki' });
const requiredProtectedHeaders = decode(bytes(vectors.requiredProtectedHeaders));
const options = { credential, publicKey, requiredProtectedHeaders };
const selectedProtected = decode(bytes(vectors.cases[0].signature))[0];
const selectedHeaders = decode(selectedProtected);
const lengthFirstProtected = decode(bytes(vectors.cases[1].signature))[0];
assert.deepEqual([...selectedHeaders.keys()], [1, 2, 3, 100, -1, CREDENTIAL_HEADER]);
assert.deepEqual([...decode(lengthFirstProtected).keys()], [1, 2, 3, -1, 100, CREDENTIAL_HEADER]);

for (const vector of vectors.cases) test('serialized PQ document map order: ' + vector.id, () => {
  const signature = bytes(vector.signature), cose = decode(signature);
  const tbs = encode(['Signature1', cose[0], Buffer.alloc(0), document]);
  assert.equal(verify(null, tbs, publicKey, cose[3]), vector.nativeMath);
  assert.deepEqual(decode(cose[0]), selectedHeaders);
  if (vector.id !== vectors.cases[0].id)
    assert.notDeepEqual(cose[0], selectedProtected);
  if (vector.expected.overall === 'VALID') {
    const reversedInput = new Map([...requiredProtectedHeaders].reverse());
    assert.deepEqual(prepareDocumentSignature(document,
      { ...options, requiredProtectedHeaders: reversedInput }).finish(cose[3]), signature);
    assert.deepEqual(verifyDocumentSignature(signature, document, options).signature, cose[3]);
  } else {
    assert.throws(() => verifyDocumentSignature(signature, document, options),
      { overall: vector.expected.overall, code: vector.expected.reason });
  }
});
