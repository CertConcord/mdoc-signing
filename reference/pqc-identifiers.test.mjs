import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { BASE_PROFILE, evaluateSignedDocument, SIGNING_NAMESPACE, verifyIssuerSigned } from './base.mjs';
import { decode, encode, get } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-identifiers.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const root = new X509Certificate(bytes(vectors.trust.rootCertificate));
const leaf = new X509Certificate(bytes(vectors.base.certificate));
const documentKey = createPublicKey({ key: bytes(vectors.base.documentPublicKeyDER),
  type: 'spki', format: 'der' });
function statusDecision({ evidence, reference, certificate, knowledgeTime, statusAlgorithm }) {
  const parts = evidence.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(header.alg, 'ML-DSA-65');
  assert.equal(header.alg, statusAlgorithm);
  assert.equal(header.typ, 'statuslist+jwt');
  assert(verify(null, Buffer.from(parts[0] + '.' + parts[1]),
    new X509Certificate(certificate).publicKey, Buffer.from(parts[2], 'base64url')));
  assert.equal(reference.uri, vectors.trust.statusURI);
  assert.equal(claims.iss, reference.uri);
  assert.equal(claims.sub, reference.uri);
  assert(claims.iat <= knowledgeTime && knowledgeTime < claims.exp &&
    knowledgeTime < claims.iat + claims.ttl);
  assert.equal(claims.status_list.bits, 1);
  const list = inflateSync(Buffer.from(claims.status_list.lst, 'base64url'),
    { maxOutputLength: 1048576 });
  assert(reference.idx >= 0 && reference.idx < list.length * 8);
  assert.equal(list[reference.idx >> 3] & (1 << (reference.idx & 7)), 0);
  return { status: 'GOOD', overall: 'VALID', algorithm: header.alg };
}
function options() {
  return { certificate: bytes(vectors.base.certificate), issuerKey: leaf.publicKey,
    trustAnchorCertificate: bytes(vectors.trust.rootCertificate),
    profileID: BASE_PROFILE, documentKeyMode: 'INDEPENDENT_PQ',
    stateTime: vectors.base.stateTime, knowledgeTime: vectors.base.knowledgeTime,
    statusEvidence: vectors.base.statusEvidence,
    authorizeIssuer: context => {
      assert.deepEqual(context.trustAnchorCertificate, root.raw);
      assert(root.ca && root.verify(root.publicKey));
      assert(!leaf.ca && leaf.verify(root.publicKey) && leaf.issuer === root.subject);
      assert(leaf.keyUsage.includes('1.0.18013.5.1.2'));
      return { overall: 'VALID' };
    }, resolveStatus: statusDecision };
}
for (const entry of vectors.cases) test('serialized PQ identifier separation: ' + entry.id, () => {
  const credential = bytes(entry.credential), signature = bytes(entry.signature);
  assert(root.ca && root.verify(root.publicKey));
  assert(!leaf.ca && leaf.verify(root.publicKey) && leaf.issuer === root.subject);
  assert.equal(statusDecision({ evidence: vectors.base.statusEvidence,
    reference: { uri: vectors.trust.statusURI, idx: 1 },
    certificate: bytes(vectors.base.certificate), knowledgeTime: vectors.base.knowledgeTime,
    statusAlgorithm: 'ML-DSA-65' }).status, 'GOOD');
  const issuerAuth = get(decode(credential), 'issuerAuth');
  assert.equal(decode(issuerAuth[0]).get(1), -49);
  assert(verify(null, encode(['Signature1', issuerAuth[0], Buffer.alloc(0), issuerAuth[2]]),
    leaf.publicKey, issuerAuth[3]));
  const documentCose = decode(signature);
  assert.equal(decode(documentCose[0]).get(1), -49);
  assert(verify(null, encode(['Signature1', documentCose[0], Buffer.alloc(0),
    bytes(vectors.base.document)]), documentKey, documentCose[3]));
  const facts = verifyIssuerSigned(credential, { issuerKey: leaf.publicKey,
    certificate: bytes(vectors.base.certificate), at: vectors.base.stateTime });
  const claims = facts.claims.get(SIGNING_NAMESPACE);
  assert.equal(claims.get('subject_id').equals(claims.get('credential_id')),
    entry.id === 'pqc-reject-reused-subject-credential-id');
  const actual = evaluateSignedDocument(bytes(vectors.base.document), signature,
    credential, options());
  assert.deepEqual({ overall: actual.overall, ...(actual.reason ? { reason: actual.reason } : {}) },
    entry.expected);
});
