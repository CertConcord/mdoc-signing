import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verify, X509Certificate } from 'node:crypto';
import { evaluateSignedDocument, inspectIssuerSigned, verifyIssuerSigned } from './base.mjs';
import { coseJWK, decode, encode } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/ec2-invalid-point.json', import.meta.url)));
const certificate = Buffer.from(vectors.certificate, 'hex');
const issuerKey = new X509Certificate(certificate).publicKey;
const document = Buffer.from(vectors.document, 'hex');
const ordinary = vectors.cases[0];
const holderKey = inspectIssuerSigned(Buffer.from(ordinary.credential, 'hex'),
  { certificate, issuerKey }).holderPublicKey;
const opts = { certificate, issuerKey, stateTime: vectors.stateTime,
  knowledgeTime: vectors.stateTime, profileID: 'MDOC-SIGNING-PERSON-PQ-v2',
  documentKeyMode: 'DEVICE_KEY', allowLegacyClassical: true,
  authorizeIssuer: () => ({ overall: 'VALID' }),
  resolveStatus: () => ({ overall: 'VALID', status: 'GOOD', algorithm: 'ES256' }) };

for (const vector of vectors.cases) test('signed EC2 point: ' + vector.id, () => {
  const credential = Buffer.from(vector.credential, 'hex');
  const signature = Buffer.from(vector.signature, 'hex');
  const issuerAuth = decode(credential).get('issuerAuth');
  const tbs = encode(['Signature1', issuerAuth[0], Buffer.alloc(0), issuerAuth[2]]);
  assert.equal(verify('sha256', tbs,
    { key: issuerKey, dsaEncoding: 'ieee-p1363' }, issuerAuth[3]), vector.issuerSignatureMath);
  const detached = decode(signature);
  assert.equal(detached[2], null);
  assert.equal(verify('sha256', encode(['Signature1', detached[0], Buffer.alloc(0), document]),
    { key: holderKey, dsaEncoding: 'ieee-p1363' }, detached[3]), true);
  const result = evaluateSignedDocument(document, signature, credential, opts);
  assert.deepEqual({ overall: result.overall, ...(result.reason ? { reason: result.reason } : {}) },
    vector.expected);
  if (vector.expected.overall === 'VALID') {
    assert.equal(verifyIssuerSigned(credential, { certificate, issuerKey, at: vectors.stateTime })
      .holderPublicKey.asymmetricKeyType, 'ec');
  } else {
    assert.throws(() => inspectIssuerSigned(credential, { certificate, issuerKey }),
      { overall: vector.expected.overall, code: vector.expected.reason });
    assert.throws(() => verifyIssuerSigned(credential, { certificate, issuerKey, at: vectors.stateTime }),
      { overall: vector.expected.overall, code: vector.expected.reason });
  }
});

test('direct EC2 conversion classifies a native-length but invalid point', () => {
  const invalidPoint = new Map([[1, 2], [-1, 1], [-2, Buffer.alloc(32)], [-3, Buffer.alloc(32)]]);
  assert.throws(() => coseJWK(invalidPoint), { overall: 'INVALID', code: 'COSE_POINT' });
});
