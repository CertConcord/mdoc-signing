import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';
import { CREDENTIAL_HEADER, prepareDocumentSignature, verifyDocumentSignature } from './base.mjs';
import { decode, encode } from './cbor.mjs';

const fixture = JSON.parse(readFileSync(new URL('../vectors/pqc-document-headers.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const document = bytes(fixture.document);
const credential = bytes(fixture.credential);
const publicKey = createPublicKey({ key: bytes(fixture.publicKeyDER), type: 'spki', format: 'der' });
const largeLabel = 9007199254740993n;
const options = requiredProtectedHeaders => ({ credential, publicKey, requiredProtectedHeaders });

test('document preparation accepts an application-selected large integer critical label', () => {
  const prepared = prepareDocumentSignature(document, options(new Map([[largeLabel, 'application-intent']])));
  const input = decode(prepared.tbs);
  const headers = decode(input[1]);
  assert.equal(headers.get(largeLabel), 'application-intent');
  assert.deepEqual(headers.get(2), [CREDENTIAL_HEADER, largeLabel]);
  assert.deepEqual(input[3], document);
});

for (const label of [-18446744073709551616n, 18446744073709551615n])
  test(`document preparation accepts CBOR integer boundary ${label}`, () => {
    const prepared = prepareDocumentSignature(document, options(new Map([[label, 'boundary-intent']])));
    const headers = decode(decode(prepared.tbs)[1]);
    assert.equal(headers.get(label), 'boundary-intent');
    assert.deepEqual(headers.get(2), [CREDENTIAL_HEADER, label]);
  });

for (const label of [1n, 2n, 3n]) test(`BigInt alias ${label} cannot override a reserved document header`, () => {
  assert.throws(() => prepareDocumentSignature(document, options(new Map([[label, 'x']]))),
    { overall: 'INVALID', code: 'MDOC_REQUIRED_HEADERS' });
});

for (const label of [-18446744073709551617n, 18446744073709551616n])
  test(`out-of-range BigInt label ${label} is refused before encoding`, () => {
    assert.throws(() => prepareDocumentSignature(document, options(new Map([[label, 'x']]))),
      { overall: 'INVALID', code: 'MDOC_REQUIRED_HEADERS' });
  });

test('selected required headers cannot change labels between admission and encoding', () => {
  class ChangingHeaders extends Map {
    entries() { return new Map([[1, -50]]).entries(); }
    [Symbol.iterator]() { return this.entries(); }
  }
  const headers = new ChangingHeaders([['urn:example:safe', 'application-intent']]);
  assert.throws(() => prepareDocumentSignature(document, options(headers)),
    { overall: 'INVALID', code: 'MDOC_REQUIRED_HEADERS' });
});

test('selected required headers reject repeated iterator labels', () => {
  class RepeatedHeaders extends Map {
    entries() { return [['urn:example:a', 'first'], ['urn:example:a', 'second']][Symbol.iterator](); }
    [Symbol.iterator]() { return this.entries(); }
  }
  const headers = new RepeatedHeaders([['urn:example:a', 'first']]);
  assert.throws(() => prepareDocumentSignature(document, options(headers)),
    { overall: 'INVALID', code: 'MDOC_REQUIRED_HEADERS' });
});

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-document-large-critical.json', import.meta.url)));
const vectorDocument = bytes(vectors.document), vectorCredential = bytes(vectors.credential);
const vectorKey = createPublicKey({ key: bytes(vectors.publicKeyDER), type: 'spki', format: 'der' });
const vectorHeaders = decode(bytes(vectors.requiredProtectedHeaders));
const vectorOptions = { credential: vectorCredential, publicKey: vectorKey,
  requiredProtectedHeaders: vectorHeaders };

test('fixed large critical label is carried as an integer in the selected headers', () => {
  assert.equal(vectors.label, largeLabel.toString());
  assert.equal(vectorHeaders.get(largeLabel), 'application-intent');
  const valid = vectors.cases.find(value => value.id === 'pqc-document-large-critical-valid');
  const protectedHeaders = decode(decode(bytes(valid.signature))[0]);
  assert.equal(protectedHeaders.get(largeLabel), 'application-intent');
  assert.deepEqual(protectedHeaders.get(2), [CREDENTIAL_HEADER, largeLabel]);
});

for (const vector of vectors.cases) test('serialized large critical label: ' + vector.id, () => {
  const signature = bytes(vector.signature), cose = decode(signature);
  const tbs = encode(['Signature1', cose[0], Buffer.alloc(0), vectorDocument]);
  assert.equal(verify(null, tbs, vectorKey, cose[3]), vector.nativeMath);
  if (vector.expected.overall === 'VALID') {
    assert.deepEqual(prepareDocumentSignature(vectorDocument, vectorOptions).finish(cose[3]), signature);
    assert.deepEqual(verifyDocumentSignature(signature, vectorDocument, vectorOptions).signature, cose[3]);
  } else assert.throws(() => verifyDocumentSignature(signature, vectorDocument, vectorOptions),
    { overall: vector.expected.overall, code: vector.expected.reason });
});

test('reversed critical order and broken signature retain distinct failure precedence', () => {
  const reversed = vectors.cases.find(value => value.id === 'pqc-document-large-critical-reversed');
  const broken = vectors.cases.find(value => value.id === 'pqc-document-large-critical-reversed-bad-math');
  assert.deepEqual(decode(bytes(reversed.signature)).slice(0, 3),
    decode(bytes(broken.signature)).slice(0, 3));
  assert.notDeepEqual(decode(bytes(reversed.signature))[3], decode(bytes(broken.signature))[3]);
});
