import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate, verify } from 'node:crypto';
import * as base from './base.mjs';
import { decode, encode, get } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/issuer-facts.json', import.meta.url)));
const certificate = Buffer.from(vectors.certificate, 'hex'), cert = new X509Certificate(certificate);
const options = { certificate, issuerKey: cert.publicKey, docType: vectors.docType };
const original = Buffer.from(vectors.cases[0].credential, 'hex');

test('issuer facts API is available without weakening the full verification API', () => {
  assert.equal(typeof base.inspectIssuerSigned, 'function');
  assert.equal(typeof base.verifyIssuerSigned, 'function');
});

for (const vector of vectors.cases) test('serialized issuer facts: ' + vector.id, () => {
  const credential = Buffer.from(vector.credential, 'hex'), auth = get(decode(credential), 'issuerAuth');
  assert.equal(verify('sha256', encode(['Signature1', auth[0], Buffer.alloc(0), auth[2]]),
    { key: cert.publicKey, dsaEncoding: 'ieee-p1363' }, auth[3]), vector.es256Math);
  if (vector.expected.outcome === 'RETURNED') {
    const facts = base.inspectIssuerSigned(credential, options);
    const full = base.verifyIssuerSigned(credential, { ...options, at: vectors.stateTime });
    assert.deepEqual(facts.credential, credential);
    assert.deepEqual(facts.mso, full.mso);
    assert.deepEqual(facts.claims, full.claims);
    assert.deepEqual(facts.validity, full.validity);
    assert.equal(facts.claims.get(vectors.docType).get('family_name'), 'Fixture');
    assert.equal(Object.hasOwn(facts, 'overall'), false);
    assert.equal(Object.hasOwn(facts, 'authorization'), false);
    assert.equal(Object.hasOwn(facts, 'status'), false);
  } else for (const invoke of [
    () => base.inspectIssuerSigned(credential, options),
    () => base.verifyIssuerSigned(credential, { ...options, at: vectors.stateTime }),
  ]) assert.throws(invoke, { overall: vector.expected.overall, code: vector.expected.reason });
});

for (const [name, at, code] of [
  ['before certificate', cert.validFromDate.getTime() / 1000 - 1, 'MDOC_CERTIFICATE_VALIDITY'],
  ['at certificate end', cert.validToDate.getTime() / 1000, 'MDOC_CERTIFICATE_VALIDITY'],
  ['before credential', vectors.stateTime - 11, 'MDOC_EXPIRED'],
  ['at credential end', vectors.stateTime + 300, 'MDOC_EXPIRED'],
]) test('issuer facts do not admit external time: ' + name, () => {
  assert.throws(() => base.verifyIssuerSigned(original, { ...options, at }), { code });
  const facts = base.inspectIssuerSigned(original, { ...options, get at() { throw Error('No external time in facts'); } });
  assert.deepEqual(facts.credential, original);
  assert.equal(Object.hasOwn(facts, 'overall'), false);
});

test('full issuer verification still requires explicit integer state time', () => {
  for (const at of [undefined, null, false, '1800000000', -1])
    assert.throws(() => base.verifyIssuerSigned(original, { ...options, at }), { code: 'MDOC_STATE_TIME' });
  for (const at of [vectors.stateTime - 10, vectors.stateTime + 299])
    assert.deepEqual(base.verifyIssuerSigned(original, { ...options, at }).credential, original);
});

const typed = JSON.parse(readFileSync(new URL('../vectors/classification.json', import.meta.url)));
for (const id of ['algorithm-null', 'algorithm-unknown-text', 'unknown-critical', 'unknown-critical-bad-math',
  'version-number', 'version-1-1', 'digest-null', 'digest-sha384'])
  test('issuer facts retain typed primitive checks: ' + id, () => {
    const vector = typed.cases.find(entry => entry.id === id);
    const pinned = Buffer.from(vector.certificate ?? typed.certificate, 'hex');
    assert.throws(() => base.inspectIssuerSigned(Buffer.from(vector.credential, 'hex'), {
      certificate: pinned, issuerKey: new X509Certificate(pinned).publicKey, docType: typed.docType,
    }), { overall: vector.expected.overall, code: vector.expected.reason });
  });

const complete = JSON.parse(readFileSync(new URL('../vectors/base.json', import.meta.url)));
for (const id of ['changed-issuer-item', 'duplicate-issuer-item', 'incomplete-credential', 'invalid-calendar-date',
  'same-key-certificate-substitution']) test('issuer facts retain authenticated structure: ' + id, () => {
  const vector = complete.cases.find(entry => entry.id === id), pinned = Buffer.from(vector.certificate, 'hex');
  assert.throws(() => base.inspectIssuerSigned(Buffer.from(vector.credential, 'hex'), {
    certificate: pinned, issuerKey: new X509Certificate(pinned).publicKey,
  }), { overall: 'INVALID', code: vector.expected.reason });
});
