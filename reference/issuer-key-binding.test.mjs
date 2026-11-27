import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { encode, decode, get } from './cbor.mjs';
import { evaluateSignedDocument, inspectIssuerSigned, verifyIssuerSigned, verifySigningCredential } from './base.mjs';
import { verifyHolderAuthentication } from './holder-auth.mjs';

const sourceBytes = readFileSync(new URL('../vectors/pqc-base.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const historical = JSON.parse(readFileSync(new URL('../vectors/base.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/issuer-key-binding.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('certificate key, not caller key-like options, verifies issuerAuth mathematics', () => {
  const entry = vectors.cases[0], base = source.base;
  assert.equal(vectors.source.case, 'pqc-complete-ml-dsa-65');
  assert.equal(source.cases.find(value => value.id === vectors.source.case)?.expected.overall, 'VALID');
  assert.equal(entry.expected.overall, 'INVALID');
  assert.equal(sha256(sourceBytes), vectors.source.sha256);
  assert.equal(sha256(bytes(base.credential)), entry.originalCredentialSha256);
  const certificate = bytes(base.certificate);
  const selectedKey = new X509Certificate(certificate).publicKey;
  const selectedSpki = selectedKey.export({ type: 'spki', format: 'der' });
  assert.equal(sha256(selectedSpki), entry.selectedCertificateSpkiSha256);
  const attackerKey = createPublicKey({
    key: bytes(entry.attackerPublicKeySpki), type: 'spki', format: 'der',
  });
  assert.notEqual(sha256(attackerKey.export({ type: 'spki', format: 'der' })),
    entry.selectedCertificateSpkiSha256);

  const changed = decode(bytes(base.credential));
  const issuerAuth = get(changed, 'issuerAuth');
  const signed = encode(['Signature1', issuerAuth[0], Buffer.alloc(0), issuerAuth[2]]);
  issuerAuth[3] = bytes(entry.attackerIssuerAuthSignature);
  const tampered = encode(changed);
  assert.equal(sha256(tampered), entry.tamperedCredentialSha256);
  assert.equal(verify(null, signed, selectedKey, issuerAuth[3]), false);
  assert.equal(verify(null, signed, attackerKey, issuerAuth[3]), true);
  const forgedKey = {
    asymmetricKeyType: 'ml-dsa-65',
    export: () => Buffer.from(selectedSpki),
    key: attackerKey,
  };
  const nativeForgedKey = createPublicKey({
    key: bytes(entry.attackerPublicKeySpki), type: 'spki', format: 'der',
  });
  nativeForgedKey.export = () => Buffer.from(selectedSpki);
  const common = {
    certificate, stateTime: base.stateTime, knowledgeTime: base.knowledgeTime,
    trustAnchorCertificate: bytes(source.trust.rootCertificate),
    profileID: base.profileID, documentKeyMode: base.documentKeyMode,
    statusEvidence: base.statusEvidence,
    authorizeIssuer: () => ({ overall: 'VALID' }),
    resolveStatus: () => ({ overall: 'VALID', status: 'GOOD', algorithm: 'ML-DSA-65' }),
  };
  assert.equal(verifySigningCredential(bytes(base.credential),
    { ...common, issuerKey: selectedKey }).overall, 'VALID');
  assert.throws(() => verifyIssuerSigned(tampered,
    { issuerKey: selectedKey, certificate, at: base.stateTime }),
  { code: entry.expected.reason });
  assert.throws(() => verifyIssuerSigned(tampered,
    { issuerKey: forgedKey, certificate, at: base.stateTime }),
  { code: entry.expected.reason });
  assert.throws(() => verifyIssuerSigned(tampered,
    { issuerKey: nativeForgedKey, certificate, at: base.stateTime }),
  { code: entry.expected.reason });
  assert.throws(() => verifySigningCredential(tampered,
    { ...common, issuerKey: forgedKey }),
  { code: entry.expected.reason });
  assert.throws(() => verifyHolderAuthentication(bytes(base.deviceSigned), tampered, {
    issuerKey: forgedKey, certificate, at: base.stateTime,
    sessionTranscript: bytes(base.sessionTranscript),
  }), { code: entry.expected.reason });
  const highLevel = evaluateSignedDocument(bytes(base.document), bytes(base.signature),
    tampered, { ...common, issuerKey: forgedKey });
  assert.deepEqual({ overall: highLevel.overall, reason: highLevel.reason },
    { overall: 'INVALID', reason: 'MDOC_MALFORMED' });
});

test('direct issuer role comparison retains the selected leaf key', () => {
  const base = source.base, certificate = bytes(base.certificate);
  const selectedKey = new X509Certificate(certificate).publicKey;
  const selectedSpki = selectedKey.export({ type: 'spki', format: 'der' });
  const credential = bytes(base.credential);
  const holderSpki = inspectIssuerSigned(credential, { certificate, issuerKey: selectedKey })
    .holderPublicKey.export({ type: 'spki', format: 'der' });
  const changingExport = () => {
    let exports = 0;
    return { asymmetricKeyType: 'ml-dsa-65', export: () => Buffer.from(exports++ ? holderSpki : selectedSpki) };
  };
  assert.equal(verifyIssuerSigned(credential, { certificate, issuerKey: changingExport(), at: base.stateTime })
    .issuerAlgorithm, -49);
});

test('direct credential and holder suites retain the selected leaf algorithm', () => {
  const base = source.base, certificate = bytes(base.certificate), credential = bytes(base.credential);
  const selectedSpki = new X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' });
  const common = {
    certificate, stateTime: base.stateTime, knowledgeTime: base.knowledgeTime,
    trustAnchorCertificate: bytes(source.trust.rootCertificate),
    profileID: base.profileID, documentKeyMode: base.documentKeyMode,
    statusEvidence: base.statusEvidence,
    authorizeIssuer: () => ({ overall: 'VALID' }),
    resolveStatus: () => ({ overall: 'VALID', status: 'GOOD', algorithm: 'ML-DSA-65' }),
  };
  const changingType = () => {
    let reads = 0;
    return { get asymmetricKeyType() { return reads++ < 2 ? 'ml-dsa-65' : 'ec'; },
      export: () => Buffer.from(selectedSpki) };
  };
  assert.equal(verifySigningCredential(credential, { ...common, issuerKey: changingType() }).overall, 'VALID');
  assert(verifyHolderAuthentication(bytes(base.deviceSigned), credential, {
    issuerKey: changingType(), certificate, at: base.stateTime,
    sessionTranscript: bytes(base.sessionTranscript),
  }).holderProof);
});

test('direct issuer facts and both policy callbacks receive the verified leaf bytes', () => {
  const base = source.base, original = bytes(base.certificate), credential = bytes(base.credential);
  const selectedSpki = new X509Certificate(original).publicKey.export({ type: 'spki', format: 'der' });
  const mutableSelection = certificate => ({ asymmetricKeyType: 'ml-dsa-65', export: () => {
    certificate.fill(0);
    return Buffer.from(selectedSpki);
  } });
  for (const inspect of [inspectIssuerSigned,
    (value, options) => verifyIssuerSigned(value, { ...options, at: base.stateTime })]) {
    const certificate = Buffer.from(original);
    const facts = inspect(credential, { certificate, issuerKey: mutableSelection(certificate) });
    assert.deepEqual(facts.certificateBytes, original);
    assert.notStrictEqual(facts.certificateBytes, certificate);
  }
  const certificate = Buffer.from(original), observed = [];
  const validated = verifySigningCredential(credential, {
    issuerKey: mutableSelection(certificate), certificate,
    stateTime: base.stateTime, knowledgeTime: base.knowledgeTime,
    trustAnchorCertificate: bytes(source.trust.rootCertificate),
    profileID: base.profileID, documentKeyMode: base.documentKeyMode,
    statusEvidence: base.statusEvidence,
    authorizeIssuer: context => { observed.push(Buffer.from(context.certificate));
      context.certificate.fill(0); return { overall: 'VALID' }; },
    resolveStatus: context => { observed.push(Buffer.from(context.certificate));
      return { overall: 'VALID', status: 'GOOD', algorithm: 'ML-DSA-65' }; },
  });
  assert.equal(validated.overall, 'VALID');
  assert.deepEqual(validated.certificateBytes, original);
  assert.equal(observed.length, 2);
  for (const value of observed) assert.deepEqual(value, original);
});

for (const { name, vector, trustAnchorCertificate, allowLegacyClassical } of [
  { name: 'historical v2 short leaf', vector: historical.cases[0],
    allowLegacyClassical: true },
  { name: 'experimental v3 long leaf', vector: source.base,
    trustAnchorCertificate: bytes(source.trust.rootCertificate) },
]) test(`${name} retains distinct certificate storage for facts and policy callbacks`, () => {
  const certificate = bytes(vector.certificate), observed = [];
  const validated = verifySigningCredential(bytes(vector.credential), {
    issuerKey: new X509Certificate(certificate).publicKey, certificate,
    profileID: vector.profileID, documentKeyMode: vector.documentKeyMode,
    stateTime: vector.stateTime, knowledgeTime: vector.knowledgeTime,
    statusEvidence: vector.statusEvidence, trustAnchorCertificate, allowLegacyClassical,
    authorizeIssuer: context => { observed.push(context.certificate, context.certificateChain[0]);
      return { overall: 'VALID' }; },
    resolveStatus: context => { observed.push(context.certificate);
      return { overall: 'VALID', status: 'GOOD', algorithm: 'ML-DSA-65' }; },
  });
  assert.equal(validated.overall, 'VALID');
  const retained = [validated.certificateBytes, validated.certificateChain[0], ...observed];
  assert.equal(retained.length, 5);
  for (const [index, value] of retained.entries()) {
    assert.deepEqual(value, certificate, `${name} DER copy ${index} changed`);
    assert.equal(value.buffer.byteLength, value.length, `${name} DER copy ${index} uses pooled storage`);
    for (const prior of retained.slice(0, index))
      assert.notStrictEqual(value.buffer, prior.buffer, `${name} DER copies share backing storage`);
    assert.notStrictEqual(value.buffer, certificate.buffer, `${name} DER copy aliases caller storage`);
  }
});
