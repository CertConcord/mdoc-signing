import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';
import { CREDENTIAL_HEADER, prepareDocumentSignature, verifyDocumentSignature } from './base.mjs';
import { decode, encode } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-document-headers.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const document = bytes(vectors.document), credential = bytes(vectors.credential);
const publicKey = createPublicKey({ key: bytes(vectors.publicKeyDER), format: 'der', type: 'spki' });
const requiredProtectedHeaders = decode(bytes(vectors.requiredProtectedHeaders));
const options = { credential, publicKey, requiredProtectedHeaders };

for (const vector of vectors.cases) test('serialized PQ document headers: ' + vector.id, () => {
  const signature = bytes(vector.signature), cose = decode(signature);
  const tbs = encode(['Signature1', cose[0], Buffer.alloc(0), document]);
  assert.equal(verify(null, tbs, publicKey, cose[3]), vector.nativeMath);
  if (vector.expected.overall === 'VALID') {
    const reversedInput = new Map([...requiredProtectedHeaders].reverse());
    const selected = { ...options, requiredProtectedHeaders: reversedInput };
    assert.deepEqual(decode(cose[0]).get(2),
      [CREDENTIAL_HEADER, 'urn:example:a', 'urn:example:z']);
    assert.deepEqual(prepareDocumentSignature(document, selected).finish(cose[3]), signature);
    assert.deepEqual(verifyDocumentSignature(signature, document, selected).signature, cose[3]);
  } else assert.throws(() => verifyDocumentSignature(signature, document, options), {
    overall: vector.expected.overall, code: vector.expected.reason,
  });
});

test('validly signed reversed critical order takes precedence over bad mathematics', () => {
  const reversed = vectors.cases.find(value => value.id === 'pqc-document-critical-reversed');
  const broken = vectors.cases.find(value => value.id === 'pqc-document-critical-reversed-bad-math');
  const first = decode(bytes(reversed.signature)), second = decode(bytes(broken.signature));
  assert.deepEqual(first.slice(0, 3), second.slice(0, 3));
  assert.notDeepEqual(first[3], second[3]);
  assert.deepEqual(reversed.expected, { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' });
  assert.deepEqual(broken.expected, { overall: 'INVALID', reason: 'MDOC_DOCUMENT_SIGNATURE' });
});
