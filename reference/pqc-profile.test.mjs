import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { BASE_PROFILE, evaluateSignedDocument, verifySignedDocument } from './base.mjs';
import { verifyHolderAuthentication } from './holder-auth.mjs';
import { coseJWK, decode, get, unembed } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-base.json', import.meta.url)));
const root = new X509Certificate(Buffer.from(vectors.trust.rootCertificate, 'hex'));
const outcomes = { GOOD: 'VALID', REVOKED: 'INVALID', INVALID: 'INVALID',
  STALE: 'INDETERMINATE', MISSING: 'INDETERMINATE' };
const result = (status, algorithm) => ({ status, overall: outcomes[status], ...(algorithm ? { algorithm } : {}) });
const bytes = hex => Buffer.from(hex, 'hex');
const parse = part => {
  const value = Buffer.from(part, 'base64url');
  assert.equal(value.toString('base64url'), part);
  return value;
};
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
    trustAnchorCertificate: vector.trustAnchorCertificate === null ? undefined :
      bytes(vector.trustAnchorCertificate ?? vectors.trust.rootCertificate),
    profileID: vector.profileID, documentKeyMode: vector.documentKeyMode,
    stateTime: vector.stateTime, knowledgeTime: vector.knowledgeTime, statusEvidence: vector.statusEvidence,
    authorizeIssuer: context => {
      const leaf = new X509Certificate(context.certificate);
      const admitted = vector.policy !== 'issuer-not-admitted' &&
        root.publicKey.asymmetricKeyType === 'ml-dsa-65' && root.ca && root.verify(root.publicKey) &&
        leaf.publicKey.asymmetricKeyType === 'ml-dsa-65' && !leaf.ca &&
        leaf.verify(root.publicKey) && leaf.issuer === root.subject &&
        leaf.keyUsage.includes('1.0.18013.5.1.2') &&
        context.issuer === vectors.trust.issuer && context.purpose === 'DOCUMENT_SIGN' &&
        context.statusAlgorithm === 'ML-DSA-65' && context.profileID === BASE_PROFILE;
      return { overall: admitted ? 'VALID' : 'INVALID' };
    },
    resolveStatus: vector.policy === 'classic-status-claim' ? () => result('GOOD', 'ES256') : statusDecision,
  };
}
for (const entry of vectors.cases) test('serialized complete PQ profile: ' + entry.id, () => {
  const vector = { ...vectors.base, ...entry };
  if (entry.classicalStatusPublicKey) {
    const parts = entry.statusEvidence.split('.');
    assert.equal(JSON.parse(parse(parts[0])).alg, 'ES256');
    assert(verify('sha256', Buffer.from(parts[0] + '.' + parts[1]),
      { key: createPublicKey({ key: bytes(entry.classicalStatusPublicKey), format: 'der', type: 'spki' }),
        dsaEncoding: 'ieee-p1363' }, parse(parts[2])));
  }
  const actual = evaluateSignedDocument(bytes(vector.document), bytes(vector.signature),
    bytes(vector.credential), parameters(vector));
  assert.deepEqual({ overall: actual.overall, ...(actual.reason ? { reason: actual.reason } : {}) }, entry.expected);
});

test('complete PQ path binds issuer, holder, status and detached document proof', () => {
  const vector = vectors.base, options = parameters(vector), credential = bytes(vector.credential);
  const signed = verifySignedDocument(bytes(vector.document), bytes(vector.signature), credential, options);
  const holder = verifyHolderAuthentication(bytes(vector.deviceSigned), credential,
    { issuerKey: options.issuerKey, certificate: options.certificate, at: vector.stateTime,
      sessionTranscript: bytes(vector.sessionTranscript) });
  assert.equal(signed.overall, 'VALID');
  assert.equal(signed.publicKey.asymmetricKeyType, 'ml-dsa-65');
  assert.equal(holder.issuerFacts.holderPublicKey.asymmetricKeyType, 'ml-dsa-65');
  assert.equal(holder.holderProof.signature.length, 3309);
  const issuerAuth = get(decode(credential), 'issuerAuth');
  assert.equal(decode(issuerAuth[0]).get(1), -49);
  const mso = unembed(decode(issuerAuth[2]));
  const deviceKey = get(get(mso, 'deviceKeyInfo'), 'deviceKey');
  assert.equal(deviceKey.get(1), 7); assert.equal(deviceKey.get(3), -49);
  assert.equal(deviceKey.get(-1).length, 1952);
});

test('historical v2 credential has no implicit classical fallback', () => {
  const legacy = JSON.parse(readFileSync(new URL('../vectors/base.json', import.meta.url))).cases[0];
  const certificate = bytes(legacy.certificate);
  const actual = evaluateSignedDocument(bytes(legacy.document), bytes(legacy.signature),
    bytes(legacy.credential), { certificate, issuerKey: new X509Certificate(certificate).publicKey,
      profileID: legacy.profileID, documentKeyMode: legacy.documentKeyMode,
      stateTime: legacy.stateTime, knowledgeTime: legacy.knowledgeTime });
  assert.deepEqual(actual, { overall: 'UNSUPPORTED', reason: 'MDOC_PROFILE_UNSUPPORTED' });
});

test('public AKP device key rejects private bytes, wrong algorithm and wrong length', () => {
  const credential = bytes(vectors.base.credential);
  const mso = unembed(decode(get(decode(credential), 'issuerAuth')[2]));
  const selected = get(get(mso, 'deviceKeyInfo'), 'deviceKey');
  assert.equal(coseJWK(selected).alg, 'ML-DSA-65');
  const changed = ([key, value]) => new Map([...selected].map(([label, data]) => [label, label === key ? value : data]));
  assert.throws(() => coseJWK(changed([3, -50])), { code: 'COSE_KEY' });
  assert.throws(() => coseJWK(changed([-1, Buffer.alloc(1951)])), { code: 'COSE_KEY' });
  assert.throws(() => coseJWK(new Map([...selected, [-2, Buffer.alloc(32)]])), { code: 'COSE_KEY' });
});

test('issuer policy callback cannot change the validated trust anchor returned to callers', () => {
  const vector = vectors.base;
  const options = parameters(vector);
  const originalAnchor = Buffer.from(options.trustAnchorCertificate);
  options.authorizeIssuer = context => {
    assert.deepEqual(context.trustAnchorCertificate, originalAnchor);
    context.trustAnchorCertificate.fill(0);
    return { overall: 'VALID' };
  };
  const signed = verifySignedDocument(bytes(vector.document), bytes(vector.signature),
    bytes(vector.credential), options);
  assert.deepEqual(options.trustAnchorCertificate, originalAnchor);
  assert.equal(signed.pqPath.trustAnchorCertificate.equals(originalAnchor), true);
});
