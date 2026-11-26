import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyIssuerSigned } from './base.mjs';
import { decode, encode, get } from './cbor.mjs';
import { MdocValidationError } from './errors.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-issuer-headers.json', import.meta.url)));
const bytes = value => Buffer.from(value, 'hex');
const root = new X509Certificate(bytes(vectors.rootCertificate));
const leaf = new X509Certificate(bytes(vectors.certificate));

test('serialized PQ issuer-header certificate mathematics is independently valid', () => {
  assert.equal(root.publicKey.asymmetricKeyType, 'ml-dsa-65');
  assert.equal(leaf.publicKey.asymmetricKeyType, 'ml-dsa-65');
  assert(root.verify(root.publicKey));
  assert(leaf.verify(root.publicKey));
  assert.equal(leaf.issuer, root.subject);
  assert.deepEqual([...decode(bytes(vectors.canonicalProtected)).keys()], [1, 34]);
  assert.deepEqual([...decode(bytes(vectors.reorderedProtected)).keys()], [34, 1]);
  assert.deepEqual(decode(bytes(vectors.canonicalProtected)), decode(bytes(vectors.reorderedProtected)));
  assert.notDeepEqual(bytes(vectors.canonicalProtected), bytes(vectors.reorderedProtected));
});

for (const entry of vectors.cases) test('serialized PQ issuer protected bytes: ' + entry.id, () => {
  const credential = bytes(entry.credential);
  const auth = get(decode(credential), 'issuerAuth');
  assert.equal(createHash('sha256').update(auth[2]).digest('hex'), vectors.payloadSha256);
  assert.equal(auth[3].length, 3309);
  const math = verify(null, encode(['Signature1', auth[0], Buffer.alloc(0), auth[2]]),
    leaf.publicKey, auth[3]);
  assert.equal(math, entry.pureMath);
  const options = { issuerKey: leaf.publicKey, certificate: bytes(vectors.certificate),
    docType: vectors.docType, at: vectors.stateTime };
  if (entry.expected.overall === 'VALID') {
    const facts = verifyIssuerSigned(credential, options);
    assert.deepEqual(facts.credential, credential);
    assert.equal(facts.claims.get(vectors.docType).get('family_name'), 'Fixture');
    assert.equal(Object.hasOwn(facts, 'overall'), false);
  } else {
    assert.throws(() => verifyIssuerSigned(credential, options), error => {
      assert(error instanceof MdocValidationError);
      assert.equal(error.overall, entry.expected.overall);
      assert.equal(error.code, entry.expected.reason);
      return true;
    });
  }
});
