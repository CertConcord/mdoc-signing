import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate, verify } from 'node:crypto';
import { verifyIssuerSigned } from './base.mjs';
import { decode, encode, get } from './cbor.mjs';
import { MdocValidationError } from './errors.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/classification.json', import.meta.url)));
for (const vector of vectors.cases) test('serialized issuer result: ' + vector.id, () => {
  const certificate = Buffer.from(vector.certificate ?? vectors.certificate, 'hex');
  const issuerKey = new X509Certificate(certificate).publicKey;
  const credential = Buffer.from(vector.credential, 'hex');
  const auth = get(decode(credential), 'issuerAuth');
  // This independent native check is an ES256 mathematical fact, not acceptance
  // of a different declared algorithm or of unknown critical semantics.
  assert.equal(verify('sha256', encode(['Signature1', auth[0], Buffer.alloc(0), auth[2]]),
    { key: issuerKey, dsaEncoding: 'ieee-p1363' }, auth[3]), vector.es256Math);
  const options = { certificate, issuerKey, docType: vectors.docType, at: vectors.stateTime,
    allowPartial: false };
  if (vector.expected.overall === 'VALID') {
    const result = verifyIssuerSigned(credential, options);
    assert.deepEqual(result.credential, credential);
    assert.equal(result.claims.get(vectors.docType).get('family_name'), 'Fixture');
    assert.equal(result.certificateBound, true);
  } else {
    assert.throws(() => verifyIssuerSigned(credential, options), (error) => {
      assert(error instanceof MdocValidationError);
      assert.equal(error.overall, vector.expected.overall);
      assert.equal(error.code, vector.expected.reason);
      return true;
    });
  }
});

test('critical and MSO capability pairs retain the identical signed message', () => {
  for (const name of ['unknown-critical', 'unknown-large-integer-critical', 'version-1-1', 'digest-sha384']) {
    const good = vectors.cases.find((entry) => entry.id === name);
    const bad = vectors.cases.find((entry) => entry.id === name + '-bad-math');
    const ga = get(decode(Buffer.from(good.credential, 'hex')), 'issuerAuth');
    const ba = get(decode(Buffer.from(bad.credential, 'hex')), 'issuerAuth');
    assert.deepEqual(ga.slice(0, 3), ba.slice(0, 3));
    assert.notDeepEqual(ga[3], ba[3]);
    assert.deepEqual(good.expected, { overall: 'UNSUPPORTED', reason: name.includes('critical')
      ? 'COSE_CRITICAL_UNSUPPORTED' : name === 'version-1-1' ? 'MDOC_VERSION_UNSUPPORTED' : 'MDOC_DIGEST_UNSUPPORTED' });
    assert.deepEqual(bad.expected, { overall: 'INVALID', reason: 'COSE_SIGNATURE' });
  }
});
