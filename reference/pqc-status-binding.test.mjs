import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { BASE_PROFILE, evaluateSignedDocument, verifySignedDocument } from './base.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-status-binding.json', import.meta.url)));
const root = new X509Certificate(Buffer.from(vectors.trust.rootCertificate, 'hex'));
const bytes = hex => Buffer.from(hex, 'hex');
const parse = part => {
  const value = Buffer.from(part, 'base64url');
  assert.equal(value.toString('base64url'), part);
  return value;
};
const result = (status, algorithm) => ({ status,
  overall: { GOOD: 'VALID', REVOKED: 'INVALID', INVALID: 'INVALID',
    STALE: 'INDETERMINATE', MISSING: 'INDETERMINATE' }[status],
  ...(algorithm ? { algorithm } : {}) });
function statusDecision({ evidence, reference, certificate, knowledgeTime, statusAlgorithm }) {
  if (!evidence) return result('MISSING');
  try {
    const parts = evidence.split('.'); assert.equal(parts.length, 3);
    const header = JSON.parse(parse(parts[0]));
    assert.equal(header.alg, statusAlgorithm); assert.equal(header.typ, 'statuslist+jwt');
    assert.equal(header.crit, undefined);
    assert(verify(null, Buffer.from(parts[0] + '.' + parts[1]),
      new X509Certificate(certificate).publicKey, parse(parts[2])));
    const claims = JSON.parse(parse(parts[1]));
    assert.equal(reference.uri, vectors.trust.statusURI);
    assert.equal(claims.iss, reference.uri); assert.equal(claims.sub, reference.uri);
    assert(Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) &&
      claims.exp > claims.iat && claims.exp - claims.iat <= 300 && claims.iat <= knowledgeTime);
    assert(Number.isSafeInteger(claims.ttl) && claims.ttl > 0 && claims.ttl <= 300);
    if (claims.exp <= knowledgeTime || claims.iat + claims.ttl <= knowledgeTime) return result('STALE');
    assert.equal(claims.status_list.bits, 1);
    const bits = inflateSync(parse(claims.status_list.lst), { maxOutputLength: 1048576 });
    assert(reference.idx >= 0 && reference.idx < bits.length * 8);
    return result(bits[reference.idx >> 3] & (1 << (reference.idx & 7)) ? 'REVOKED' : 'GOOD', header.alg);
  } catch { return result('INVALID'); }
}
function parameters(vector) {
  const certificate = bytes(vector.certificate);
  return { certificate, issuerKey: new X509Certificate(certificate).publicKey,
    trustAnchorCertificate: bytes(vectors.trust.rootCertificate),
    profileID: vector.profileID, documentKeyMode: vector.documentKeyMode,
    stateTime: vector.stateTime, knowledgeTime: vector.knowledgeTime,
    statusEvidence: vector.statusEvidence,
    authorizeIssuer: context => {
      const leaf = new X509Certificate(context.certificate);
      const admitted = root.ca && root.verify(root.publicKey) && !leaf.ca &&
        leaf.verify(root.publicKey) && leaf.issuer === root.subject &&
        leaf.keyUsage.includes('1.0.18013.5.1.2') &&
        context.issuer === vectors.trust.issuer && context.purpose === 'DOCUMENT_SIGN' &&
        context.statusAlgorithm === 'ML-DSA-65' && context.profileID === BASE_PROFILE;
      return { overall: admitted ? 'VALID' : 'INVALID' };
    }, resolveStatus: statusDecision,
  };
}
for (const entry of vectors.cases) test('serialized complete PQ status binding: ' + entry.id, () => {
  const vector = { ...vectors.base, ...entry };
  const certificate = new X509Certificate(bytes(vector.certificate));
  const parts = entry.statusEvidence.split('.');
  const input = Buffer.from(parts[0] + '.' + parts[1]), signature = parse(parts[2]);
  assert.equal(verify(null, input, certificate.publicKey, signature), entry.nativeMathUnderPinnedKey);
  if (entry.alternateStatusPublicKeyDER) {
    const alternate = createPublicKey({ key: bytes(entry.alternateStatusPublicKeyDER),
      type: 'spki', format: 'der' });
    assert.equal(alternate.asymmetricKeyType, 'ml-dsa-65');
    assert.equal(verify(null, input, alternate, signature), entry.nativeMathUnderAlternateKey);
  }
  const actual = evaluateSignedDocument(bytes(vector.document), bytes(vector.signature),
    bytes(vector.credential), parameters(vector));
  assert.deepEqual({ overall: actual.overall, ...(actual.reason ? { reason: actual.reason } : {}) }, entry.expected);
});

test('valid status-bound PQ path still uses a distinct document key', () => {
  const vector = { ...vectors.base, ...vectors.cases[0] };
  const signed = verifySignedDocument(bytes(vector.document), bytes(vector.signature),
    bytes(vector.credential), parameters(vector));
  assert.equal(signed.overall, 'VALID');
  assert.equal(signed.publicKey.asymmetricKeyType, 'ml-dsa-65');
  assert.equal(signed.holderPublicKey.asymmetricKeyType, 'ml-dsa-65');
  assert.notDeepEqual(signed.publicKey.export({ type: 'spki', format: 'der' }),
    signed.holderPublicKey.export({ type: 'spki', format: 'der' }));
});
