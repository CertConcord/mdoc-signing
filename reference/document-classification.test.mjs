import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';
import { decode, encode } from './cbor.mjs';
import { prepareDocumentSignature, verifyDocumentSignature, CREDENTIAL_HEADER } from './base.mjs';
import { MdocValidationError } from './errors.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/document-classification.json', import.meta.url)));
const keys = new Map(vectors.keys.map((entry) => [entry.id, { algorithm: entry.algorithm,
  publicKey: createPublicKey({ key: Buffer.from(entry.publicKeyDER, 'hex'), format: 'der', type: 'spki' }) }]));
for (const vector of vectors.cases) test('serialized detached result: ' + vector.id, () => {
  const selected = keys.get(vector.keyID), signature = Buffer.from(vector.signature, 'hex');
  const document = Buffer.from(vector.document ?? vectors.document, 'hex');
  const options = { publicKey: selected.publicKey,
    credential: Buffer.from(vector.credential ?? vectors.credential, 'hex'),
    requiredProtectedHeaders: decode(Buffer.from(vectors.requiredProtectedHeaders, 'hex')) };
  const value = decode(signature), tbs = encode(['Signature1', value[0], Buffer.alloc(0), document]);
  // This fact uses the configured key's suite, not a guess about another declared alg.
  const mathematics = verify(selected.algorithm === -7 ? 'sha256' : null, tbs,
    selected.algorithm === -7 ? { key: selected.publicKey, dsaEncoding: 'ieee-p1363' } : selected.publicKey, value[3]);
  assert.equal(mathematics, vector.nativeMath);
  if (vector.expected.overall === 'VALID') {
    const result = verifyDocumentSignature(signature, document, options);
    assert.deepEqual(result.tbs, tbs);
    assert.deepEqual(result.signature, value[3]);
    const prepared = prepareDocumentSignature(document, options);
    assert.equal(prepared.algorithm, selected.algorithm);
    assert.deepEqual(prepared.tbs, tbs);
    assert.deepEqual(prepared.finish(value[3]), signature);
    assert.deepEqual(decode(value[0]).get(2), [CREDENTIAL_HEADER, ...options.requiredProtectedHeaders.keys()]);
  } else assert.throws(() => verifyDocumentSignature(signature, document, options), (error) => {
    assert(error instanceof MdocValidationError);
    assert.equal(error.overall, vector.expected.overall);
    assert.equal(error.code, vector.expected.reason);
    return true;
  });
});

test('detached strict-header pairs preserve received TBS with independently different mathematics', () => {
  for (const id of ['credential-last', 'unexpected-critical', 'changed-required-value', 'noncanonical-protected-order']) {
    const good = vectors.cases.find((entry) => entry.id === id);
    const bad = vectors.cases.find((entry) => entry.id === id + '-bad-math');
    const first = decode(Buffer.from(good.signature, 'hex')), second = decode(Buffer.from(bad.signature, 'hex'));
    assert.deepEqual(first.slice(0, 3), second.slice(0, 3));
    assert.notDeepEqual(first[3], second[3]);
    assert.equal(good.nativeMath, true);
    assert.equal(bad.nativeMath, false);
    assert.deepEqual(good.expected, { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' });
    assert.deepEqual(bad.expected, { overall: 'INVALID', reason: 'MDOC_DOCUMENT_SIGNATURE' });
  }
});
