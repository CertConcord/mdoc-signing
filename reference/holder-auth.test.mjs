import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, verify, X509Certificate } from 'node:crypto';
import { BASE_PROFILE, inspectIssuerSigned, SIGNING_DOCTYPE, verifyDocumentSignature } from './base.mjs';
import { prepareHolderAuthentication, verifyHolderAuthentication } from './holder-auth.mjs';
import { decode, embedded, encode } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/holder-auth.json', import.meta.url)));
const bytes = value => Buffer.from(value, 'hex');
const input = entry => ({ ...vectors.base, ...entry });

for (const entry of vectors.cases) test('serialized holder proof: ' + entry.id, () => {
  const value = input(entry), certificate = bytes(value.certificate);
  const options = { issuerKey: new X509Certificate(certificate).publicKey, certificate, at: value.at,
    sessionTranscript: bytes(value.sessionTranscript), docType: value.docType,
    profileID: value.profileID, allowLegacyClassical: value.allowLegacyClassical };
  let result;
  try {
    const actual = verifyHolderAuthentication(bytes(value.deviceSigned), bytes(value.credential), options);
    assert.equal(actual.issuerFacts.overall, undefined);
    assert.equal(actual.holderProof.signature.length, 3309);
    result = { overall: 'VALID' };
  } catch (error) { result = { overall: error.overall ?? 'INVALID', reason: error.code }; }
  assert.deepEqual(result, entry.expected);
});

test('classical v3 holder rejection vector has a valid ES256 DeviceSignature', () => {
  const value = input(vectors.cases.find(entry => entry.id === 'validly-signed-classic-holder-v3-with-legacy-enabled'));
  const certificate = bytes(value.certificate), issuerKey = new X509Certificate(certificate).publicKey;
  const facts = inspectIssuerSigned(bytes(value.credential), { issuerKey, certificate });
  const signed = decode(bytes(value.deviceSigned)), cose = signed.get('deviceAuth').get('deviceSignature');
  const payload = encode(embedded(['DeviceAuthentication', decode(bytes(value.sessionTranscript)), SIGNING_DOCTYPE, signed.get('nameSpaces')]));
  assert.equal(facts.claims.get(SIGNING_DOCTYPE).get('profile_id'), BASE_PROFILE);
  assert.equal(facts.holderPublicKey.asymmetricKeyType, 'ec');
  assert(verify('sha256', encode(['Signature1', cose[0], Buffer.alloc(0), payload]),
    { key: facts.holderPublicKey, dsaEncoding: 'ieee-p1363' }, cose[3]));
});

test('valid holder proof signs the exact tagged DeviceAuthenticationBytes', () => {
  const value = vectors.base, certificate = bytes(value.certificate), issuerKey = new X509Certificate(certificate).publicKey;
  const facts = inspectIssuerSigned(bytes(value.credential), { issuerKey, certificate });
  const deviceSigned = decode(bytes(value.deviceSigned));
  const cose = deviceSigned.get('deviceAuth').get('deviceSignature');
  const payload = encode(embedded(['DeviceAuthentication', decode(bytes(value.sessionTranscript)), SIGNING_DOCTYPE, deviceSigned.get('nameSpaces')]));
  const expectedTbs = encode(['Signature1', cose[0], Buffer.alloc(0), payload]);
  const proof = verifyHolderAuthentication(bytes(value.deviceSigned), bytes(value.credential), { issuerKey, certificate, at: value.at, sessionTranscript: bytes(value.sessionTranscript) });
  assert.deepEqual(proof.holderProof.tbs, expectedTbs);
  assert(verify(null, proof.holderProof.tbs, facts.holderPublicKey, cose[3]));
  assert.equal(cose[2], null);
  assert.equal(cose[1].size, 0);
  assert.throws(() => verifyDocumentSignature(bytes(value.deviceSigned), Buffer.from('document'), { credential: bytes(value.credential), publicKey: facts.holderPublicKey }), { code: 'MDOC_DOCUMENT_COSE' });
});

function keyThatChangesInput(certificate, change) {
  const issuerKey = new X509Certificate(certificate).publicKey;
  const nativeExport = issuerKey.export.bind(issuerKey);
  issuerKey.export = function (options) {
    change();
    return nativeExport(options);
  };
  return issuerKey;
}

test('holder verification snapshots the selected transcript before issuer key methods', () => {
  const value = vectors.base;
  const changed = vectors.cases.find(entry => entry.id === 'changed-session-transcript');
  const certificate = bytes(value.certificate), credential = bytes(value.credential);
  const deviceSigned = bytes(value.deviceSigned), selectedTranscript = bytes(changed.sessionTranscript);
  const signedTranscript = bytes(value.sessionTranscript);
  assert.equal(selectedTranscript.length, signedTranscript.length);
  assert.throws(() => verifyHolderAuthentication(deviceSigned, credential, {
    issuerKey: new X509Certificate(certificate).publicKey, certificate, at: value.at,
    sessionTranscript: selectedTranscript,
  }), { code: 'MDOC_HOLDER_SIGNATURE' });
  const issuerKey = keyThatChangesInput(certificate, () => signedTranscript.copy(selectedTranscript));
  assert.throws(() => verifyHolderAuthentication(deviceSigned, credential, {
    issuerKey, certificate, at: value.at, sessionTranscript: selectedTranscript,
  }), { code: 'MDOC_HOLDER_SIGNATURE' });
  assert.deepEqual(selectedTranscript, signedTranscript);
});

test('holder verification snapshots DeviceSigned before issuer key methods', () => {
  const value = vectors.base, certificate = bytes(value.certificate);
  const credential = bytes(value.credential), signedDevice = bytes(value.deviceSigned);
  const changedValue = decode(signedDevice);
  changedValue.get('deviceAuth').get('deviceSignature')[3][0] ^= 1;
  const changedDevice = encode(changedValue);
  assert.equal(changedDevice.length, signedDevice.length);
  const sessionTranscript = bytes(value.sessionTranscript);
  assert.throws(() => verifyHolderAuthentication(changedDevice, credential, {
    issuerKey: new X509Certificate(certificate).publicKey, certificate, at: value.at,
    sessionTranscript,
  }), { code: 'MDOC_HOLDER_SIGNATURE' });
  const issuerKey = keyThatChangesInput(certificate, () => signedDevice.copy(changedDevice));
  assert.throws(() => verifyHolderAuthentication(changedDevice, credential, {
    issuerKey, certificate, at: value.at, sessionTranscript,
  }), { code: 'MDOC_HOLDER_SIGNATURE' });
  assert.deepEqual(changedDevice, signedDevice);
});

test('holder preparation refuses a malformed transcript and wrong signature', () => {
  const certificate = bytes(vectors.base.certificate), issuerKey = new X509Certificate(certificate).publicKey;
  const facts = inspectIssuerSigned(bytes(vectors.base.credential), { issuerKey, certificate });
  assert.throws(() => prepareHolderAuthentication(Buffer.from('82f6f6', 'hex'), { holderPublicKey: facts.holderPublicKey }), { code: 'MDOC_SESSION_TRANSCRIPT' });
  const prepared = prepareHolderAuthentication(bytes(vectors.base.sessionTranscript), { holderPublicKey: facts.holderPublicKey });
  assert.throws(() => prepared.finish(Buffer.alloc(3309)), { code: 'MDOC_HOLDER_SIGNATURE' });
});

test('holder preparation requires exact profile selection for classical keys', () => {
  const holder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const transcript = bytes(vectors.base.sessionTranscript);
  assert.throws(() => prepareHolderAuthentication(transcript, { holderPublicKey: holder.publicKey,
    allowLegacyClassical: true }), { code: 'MDOC_HOLDER_PQC_REQUIRED' });
  assert.throws(() => prepareHolderAuthentication(transcript, { holderPublicKey: holder.publicKey,
    profileID: 'MDOC-SIGNING-PERSON-PQ-v2' }), { code: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' });
  assert.throws(() => prepareHolderAuthentication(transcript, { holderPublicKey: holder.publicKey,
    profileID: 'MDOC-SIGNING-PERSON-PQ-v4', allowLegacyClassical: true }), { code: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' });
  const prepared = prepareHolderAuthentication(transcript, { holderPublicKey: holder.publicKey,
    profileID: 'MDOC-SIGNING-PERSON-PQ-v2', allowLegacyClassical: true });
  assert.deepEqual(decode(prepared.tbs)[1], encode(new Map([[1, -7]])));
});
