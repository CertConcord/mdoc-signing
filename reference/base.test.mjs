import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate, verify, generateKeyPairSync, sign } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { evaluateSignedDocument, verifySignedDocument, verifySigningCredential, verifyIssuerSigned, prepareDocumentSignature, verifyDocumentSignature } from './base.mjs';
import { decode } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/base.json', import.meta.url)));
const root = new X509Certificate(Buffer.from(vectors.trust.rootCertificate, 'hex'));
const outcomes = { GOOD: 'VALID', REVOKED: 'INVALID', INVALID: 'INVALID', STALE: 'INDETERMINATE', MISSING: 'INDETERMINATE', CONFLICTING: 'INDETERMINATE', UNSUPPORTED: 'UNSUPPORTED' };
const result = status => ({ status, overall: outcomes[status] });

// A bounded test adapter for the exact signed JWT fixtures. Applications provide
// their assessed JOSE/PKIX stack and historical policy through the same interface.
function statusDecision({ evidence, reference, certificate, knowledgeTime }) {
  if (!evidence) return result('MISSING');
  if (Array.isArray(evidence)) {
    const states = evidence.map(token => statusDecision({ evidence: token, reference, certificate, knowledgeTime }));
    return new Set(states.map(value => value.status)).size > 1 ? result('CONFLICTING') : states[0];
  }
  try {
    const parts = evidence.split('.'); assert.equal(parts.length, 3);
    const parse = part => { const bytes = Buffer.from(part, 'base64url'); assert.equal(bytes.toString('base64url'), part); return bytes; };
    const header = JSON.parse(parse(parts[0]));
    assert.equal(header.alg, 'ES256'); assert.equal(header.typ, 'statuslist+jwt'); assert.equal(header.crit, undefined);
    assert(verify('sha256', Buffer.from(parts[0] + '.' + parts[1]), { key: new X509Certificate(certificate).publicKey, dsaEncoding: 'ieee-p1363' }, parse(parts[2])));
    const claims = JSON.parse(parse(parts[1]));
    assert.equal(reference.uri, vectors.trust.statusURI); assert.equal(claims.iss, reference.uri); assert.equal(claims.sub, reference.uri);
    assert(Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) && claims.exp > claims.iat && claims.exp - claims.iat <= 300);
    assert(claims.iat <= knowledgeTime);
    if (claims.exp <= knowledgeTime || claims.iat + claims.ttl <= knowledgeTime) return result('STALE');
    if (claims.status_list.bits !== 1) return result('UNSUPPORTED');
    const bits = inflateSync(parse(claims.status_list.lst), { maxOutputLength: 1048576 });
    assert(reference.idx >= 0 && reference.idx < bits.length * 8);
    return result(bits[reference.idx >> 3] & (1 << (reference.idx & 7)) ? 'REVOKED' : 'GOOD');
  } catch { return result('INVALID'); }
}
function parameters(vector) {
  const certificate = Buffer.from(vector.certificate, 'hex');
  return {
    certificate, issuerKey: new X509Certificate(certificate).publicKey,
    profileID: vector.profileID, documentKeyMode: vector.documentKeyMode,
    stateTime: vector.stateTime, knowledgeTime: vector.knowledgeTime, statusEvidence: vector.statusEvidence,
    authorizeIssuer: vector.policy === 'issuer-authorization-missing' ? undefined : context => {
      const selected = new X509Certificate(context.certificate);
      const admitted = vector.policy !== 'issuer-not-admitted' && selected.verify(root.publicKey) && selected.issuer === root.subject && selected.keyUsage.includes('1.0.18013.5.1.2') && context.issuer === vectors.trust.issuer && context.purpose === 'DOCUMENT_SIGN';
      return { overall: admitted ? 'VALID' : 'INVALID' };
    },
    resolveStatus: vector.policy === 'status-resolver-missing' ? undefined : vector.policy === 'status-method-unimplemented' ? () => result('UNSUPPORTED') : statusDecision,
  };
}
for (const vector of vectors.cases) test('serialized base profile: ' + vector.id, () => {
  const actual = evaluateSignedDocument(Buffer.from(vector.document, 'hex'), Buffer.from(vector.signature, 'hex'), Buffer.from(vector.credential, 'hex'), parameters(vector));
  assert.equal(actual.overall, vector.expected.overall);
  if (vector.expected.reason) assert.equal(actual.reason, vector.expected.reason);
});
test('issuer authentication alone does not establish document authority or status', () => {
  const vector = vectors.cases[0], options = parameters(vector), credential = Buffer.from(vector.credential, 'hex');
  const authenticated = verifyIssuerSigned(credential, { ...options, at: vector.stateTime });
  assert.equal(authenticated.overall, undefined);
  assert.throws(() => verifySigningCredential(credential, { ...options, authorizeIssuer: undefined }), { overall: 'INDETERMINATE', code: 'MDOC_ISSUER_AUTHORIZATION_MISSING' });
  assert.throws(() => verifySigningCredential(credential, { ...options, resolveStatus: () => ({ status: 'REVOKED', overall: 'VALID' }) }), { overall: 'INVALID', code: 'MDOC_STATUS_RESULT' });
  assert.throws(() => verifySigningCredential(credential, { ...options, resolveStatus: () => { throw new Error('issuer unavailable'); } }), { overall: 'INDETERMINATE', code: 'MDOC_STATUS_UNAVAILABLE' });
});
test('validation snapshots all signed inputs before calling external policy', () => {
  const vector = vectors.cases[0], options = parameters(vector);
  const document = Buffer.from(vector.document, 'hex'), signature = Buffer.from(vector.signature, 'hex'), credential = Buffer.from(vector.credential, 'hex');
  const admit = options.authorizeIssuer;
  options.authorizeIssuer = context => {
    const decision = admit(context);
    document.fill(0); signature.fill(0); credential.fill(0); options.certificate.fill(0); context.certificate.fill(0);
    return decision;
  };
  assert.equal(verifySignedDocument(document, signature, credential, options).overall, 'VALID');
});
test('external application critical headers are exact, signed, and mandatory', () => {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const document = Buffer.from('document'), credential = Buffer.from(vectors.cases[0].credential, 'hex');
  const requiredProtectedHeaders = new Map([['urn:example:intent:2', Buffer.alloc(64, 1)]]);
  const options = { credential, publicKey: keys.publicKey, requiredProtectedHeaders };
  const prepared = prepareDocumentSignature(document, options);
  const signature = prepared.finish(sign('sha256', prepared.tbs, { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }));
  verifyDocumentSignature(signature, document, options);
  assert.throws(() => verifyDocumentSignature(signature, document, { ...options, requiredProtectedHeaders: new Map() }), { code: 'MDOC_DOCUMENT_PROTECTED_HEADERS' });
  requiredProtectedHeaders.get('urn:example:intent:2').fill(0);
  assert.throws(() => verifyDocumentSignature(signature, document, options), { code: 'MDOC_DOCUMENT_PROTECTED_HEADERS' });
});
test('bounded CBOR rejects duplicate keys, non-minimal integers and indefinite lengths', () => {
  assert.throws(() => decode(Buffer.from('a201000100', 'hex')), { code: 'CBOR_DUPLICATE' });
  assert.throws(() => decode(Buffer.from('1817', 'hex')), { code: 'CBOR_NONMINIMAL' });
  assert.throws(() => decode(Buffer.from('9f01ff', 'hex')), { code: 'CBOR_INDEFINITE' });
});
