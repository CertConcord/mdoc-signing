import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { evaluateSignedDocument, inspectIssuerSigned, prepareDocumentSignature,
  verifyDocumentSignature } from './base.mjs';
import { prepareHolderAuthentication, verifyHolderAuthentication } from './holder-auth.mjs';
import { decode } from './cbor.mjs';

const pq = JSON.parse(readFileSync(new URL('../vectors/pqc-base.json', import.meta.url)));
const holder = JSON.parse(readFileSync(new URL('../vectors/holder-auth.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const shadowedChange = original => {
  const changed = Buffer.from(original);
  changed[0] ^= 1;
  changed.valueOf = () => original;
  return changed;
};
const selectedInputs = () => {
  const v = pq.base, certificate = bytes(v.certificate);
  return {
    document: bytes(v.document), signature: bytes(v.signature), credential: bytes(v.credential),
    options: {
      certificate, issuerKey: new X509Certificate(certificate).publicKey,
      trustAnchorCertificate: bytes(pq.trust.rootCertificate),
      profileID: v.profileID, documentKeyMode: v.documentKeyMode,
      stateTime: v.stateTime, knowledgeTime: v.knowledgeTime, statusEvidence: v.statusEvidence,
      authorizeIssuer: () => ({ overall: 'VALID' }),
      resolveStatus: () => ({ overall: 'VALID', status: 'GOOD', algorithm: 'ML-DSA-65' }),
    },
  };
};

test('CBOR decoding uses native byte-view contents instead of valueOf', () => {
  const input = Uint8Array.of(1);
  input.valueOf = () => Uint8Array.of(2);
  assert.equal(decode(input), 1);
  assert.equal(decode(runInNewContext('Uint8Array.of(1)')), 1);
  assert.throws(() => decode([1]), { code: 'CBOR_TYPE' });
  assert.throws(() => decode({ valueOf: () => Uint8Array.of(1) }), { code: 'CBOR_TYPE' });
  const encoded = Buffer.from([0x43, 1, 2, 3]);
  const decoded = decode(encoded);
  assert.deepEqual(decoded, Buffer.from([1, 2, 3]));
  assert.equal(decoded.byteOffset, 0);
  assert.equal(decoded.buffer.byteLength, decoded.length);
  assert.notEqual(decoded.buffer, encoded.buffer);
});

test('complete PQ evaluator binds all byte inputs to their presented contents', () => {
  const input = selectedInputs();
  const accepted = evaluateSignedDocument(input.document, input.signature, input.credential, input.options);
  assert.equal(accepted.overall, 'VALID');
  assert.equal(accepted.credential.byteOffset, 0);
  assert.equal(accepted.credential.buffer.byteLength, accepted.credential.length);
  assert.notEqual(accepted.credential.buffer, input.credential.buffer);
  for (const name of ['document', 'signature', 'credential', 'certificate', 'trustAnchorCertificate']) {
    const changed = shadowedChange(name in input ? input[name] : input.options[name]);
    const actual = name in input
      ? evaluateSignedDocument(...['document', 'signature', 'credential'].map(key => key === name ? changed : input[key]), input.options)
      : evaluateSignedDocument(input.document, input.signature, input.credential, { ...input.options, [name]: changed });
    assert.notEqual(actual.overall, 'VALID', name);
  }
  for (const name of ['certificate', 'trustAnchorCertificate']) {
    const original = input.options[name], changed = new Uint8Array(original);
    changed[0] ^= 1;
    changed.valueOf = () => original;
    const actual = evaluateSignedDocument(input.document, input.signature, input.credential,
      { ...input.options, [name]: changed });
    assert.notEqual(actual.overall, 'VALID', name + ' native Uint8Array');
  }
});

test('complete evaluator captures certificate options once before validation', () => {
  const input = selectedInputs();
  for (const name of ['certificate', 'trustAnchorCertificate']) {
    const original = input.options[name], changed = Buffer.from(original);
    changed[0] ^= 1;
    let reads = 0;
    const options = { ...input.options };
    Object.defineProperty(options, name, { enumerable: true, get() {
      return ++reads === 1 ? changed : original;
    } });
    const actual = evaluateSignedDocument(input.document, input.signature, input.credential, options);
    assert.notEqual(actual.overall, 'VALID', name);
    assert.equal(reads, 1, name);
  }
});

test('direct issuer inspection binds credential and pinned certificate bytes', () => {
  const input = selectedInputs();
  assert.equal(inspectIssuerSigned(input.credential, input.options).issuerAlgorithm, -49);
  assert.throws(() => inspectIssuerSigned(shadowedChange(input.credential), input.options));
  assert.throws(() => inspectIssuerSigned(input.credential,
    { ...input.options, certificate: shadowedChange(input.options.certificate) }));
  const otherCertificate = new Uint8Array(input.options.certificate);
  otherCertificate[0] ^= 1;
  otherCertificate.valueOf = () => input.options.certificate;
  assert.throws(() => inspectIssuerSigned(input.credential,
    { ...input.options, certificate: otherCertificate }));
});

test('document signature preparation binds the presented document bytes', () => {
  const input = selectedInputs();
  const validated = evaluateSignedDocument(input.document, input.signature, input.credential, input.options);
  assert.equal(validated.overall, 'VALID');
  const changed = Buffer.from(input.document);
  changed[0] ^= 1;
  const shadowed = Buffer.from(changed);
  shadowed.valueOf = () => input.document;
  const options = { credential: input.credential, publicKey: validated.publicKey };
  const expected = prepareDocumentSignature(changed, options).tbs;
  assert.notDeepEqual(expected, prepareDocumentSignature(input.document, options).tbs);
  assert.deepEqual(prepareDocumentSignature(shadowed, options).tbs, expected);
});

test('document signature packaging retains the verified signature bytes', () => {
  const input = selectedInputs();
  const validated = evaluateSignedDocument(input.document, input.signature, input.credential, input.options);
  assert.equal(validated.overall, 'VALID');
  const signature = decode(input.signature)[3];
  signature.valueOf = () => Buffer.alloc(signature.length);
  const options = { credential: input.credential, publicKey: validated.publicKey };
  const output = prepareDocumentSignature(input.document, options).finish(signature);
  assert.deepEqual(decode(output)[3], decode(input.signature)[3]);
  assert(verifyDocumentSignature(output, input.document, options).signature);
});

test('direct detached-signature verification reads the presented COSE bytes', () => {
  const input = selectedInputs();
  const validated = evaluateSignedDocument(input.document, input.signature, input.credential, input.options);
  assert.equal(validated.overall, 'VALID');
  assert.throws(() => verifyDocumentSignature(shadowedChange(input.signature), input.document,
    { credential: input.credential, publicKey: validated.publicKey }));
});

test('holder proof and transcript bind their presented bytes', () => {
  const v = holder.base, certificate = bytes(v.certificate), credential = bytes(v.credential);
  const options = { certificate, issuerKey: new X509Certificate(certificate).publicKey,
    at: v.at, sessionTranscript: bytes(v.sessionTranscript) };
  assert(verifyHolderAuthentication(bytes(v.deviceSigned), credential, options).holderProof.signature);
  assert.throws(() => verifyHolderAuthentication(shadowedChange(bytes(v.deviceSigned)), credential, options));
  assert.throws(() => verifyHolderAuthentication(bytes(v.deviceSigned), shadowedChange(credential), options));
  const facts = inspectIssuerSigned(credential, options);
  assert.throws(() => prepareHolderAuthentication(shadowedChange(options.sessionTranscript),
    { holderPublicKey: facts.holderPublicKey }));
});

test('holder proof packaging retains the verified DeviceSignature bytes', () => {
  const v = holder.base, certificate = bytes(v.certificate), credential = bytes(v.credential);
  const options = { certificate, issuerKey: new X509Certificate(certificate).publicKey,
    at: v.at, sessionTranscript: bytes(v.sessionTranscript) };
  const facts = inspectIssuerSigned(credential, options);
  const signature = decode(bytes(v.deviceSigned)).get('deviceAuth').get('deviceSignature')[3];
  signature.valueOf = () => Buffer.alloc(signature.length);
  const output = prepareHolderAuthentication(options.sessionTranscript,
    { holderPublicKey: facts.holderPublicKey }).finish(signature);
  assert.deepEqual(decode(output).get('deviceAuth').get('deviceSignature')[3],
    decode(bytes(v.deviceSigned)).get('deviceAuth').get('deviceSignature')[3]);
  assert(verifyHolderAuthentication(output, credential, options).holderProof.signature);
});
