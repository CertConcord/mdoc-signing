import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { BASE_PROFILE, evaluateSignedDocument, verifyIssuerSigned } from './base.mjs';
import { verifyHolderAuthentication } from './holder-auth.mjs';
import { coseJWK, decode, encode, get, unembed } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-holder-ca-key-role.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const root = new X509Certificate(bytes(vectors.trust.rootCertificate));
const intermediate = new X509Certificate(bytes(vectors.trust.intermediateCertificate));
const leaf = new X509Certificate(bytes(vectors.base.certificate));
const documentKey = createPublicKey({ key: bytes(vectors.base.documentPublicKeyDER),
  type: 'spki', format: 'der' });
const spki = key => key.export({ format: 'der', type: 'spki' });
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
      assert.equal(context.certificateChain.length, 2);
      assert.deepEqual(context.certificateChain[1], intermediate.raw);
      assert(root.ca && intermediate.ca && !leaf.ca);
      assert(root.verify(root.publicKey) && intermediate.verify(root.publicKey) &&
        leaf.verify(intermediate.publicKey));
      return { overall: 'VALID' };
    }, resolveStatus: statusDecision };
}
for (const entry of vectors.cases) test('serialized PQ holder/CA key-role separation: ' + entry.id, () => {
  const credential = bytes(entry.credential), signature = bytes(entry.signature);
  const deviceSigned = bytes(entry.deviceSigned);
  const holderKey = createPublicKey({ key: bytes(entry.holderPublicKeyDER),
    type: 'spki', format: 'der' });
  assert(root.ca && intermediate.ca && !leaf.ca);
  assert(root.verify(root.publicKey) && intermediate.verify(root.publicKey) &&
    leaf.verify(intermediate.publicKey));
  assert.equal(spki(holderKey).equals(spki(root.publicKey)),
    entry.id === 'pqc-reject-root-ca-holder-key');
  assert.equal(spki(holderKey).equals(spki(intermediate.publicKey)),
    entry.id === 'pqc-reject-intermediate-ca-holder-key');
  for (const ca of [root, intermediate, leaf]) assert(!spki(documentKey).equals(spki(ca.publicKey)));
  assert(!spki(documentKey).equals(spki(holderKey)));
  const issuerAuth = get(decode(credential), 'issuerAuth');
  assert.equal(decode(issuerAuth[0]).get(1), -49);
  assert(verify(null, encode(['Signature1', issuerAuth[0], Buffer.alloc(0), issuerAuth[2]]),
    leaf.publicKey, issuerAuth[3]));
  assert.deepEqual(issuerAuth[1].get(33)[1], intermediate.raw);
  const mso = unembed(decode(issuerAuth[2]));
  const selectedHolderKey = createPublicKey({ key: coseJWK(get(get(mso, 'deviceKeyInfo'), 'deviceKey')),
    format: 'jwk' });
  assert.deepEqual(spki(selectedHolderKey), spki(holderKey));
  const documentCose = decode(signature);
  assert.equal(decode(documentCose[0]).get(1), -49);
  assert(verify(null, encode(['Signature1', documentCose[0], Buffer.alloc(0),
    bytes(vectors.base.document)]), documentKey, documentCose[3]));
  verifyIssuerSigned(credential, { issuerKey: leaf.publicKey,
    certificate: bytes(vectors.base.certificate), at: vectors.base.stateTime });
  const proof = verifyHolderAuthentication(deviceSigned, credential, {
    issuerKey: leaf.publicKey, certificate: bytes(vectors.base.certificate),
    at: vectors.base.stateTime, sessionTranscript: bytes(vectors.base.transcript) });
  assert(proof.holderProof);
  assert.equal(statusDecision({ evidence: vectors.base.statusEvidence,
    reference: { uri: vectors.trust.statusURI, idx: 1 },
    certificate: bytes(vectors.base.certificate), knowledgeTime: vectors.base.knowledgeTime,
    statusAlgorithm: 'ML-DSA-65' }).status, 'GOOD');
  const actual = evaluateSignedDocument(bytes(vectors.base.document), signature,
    credential, options());
  assert.deepEqual({ overall: actual.overall, ...(actual.reason ? { reason: actual.reason } : {}) },
    entry.expected);
});
