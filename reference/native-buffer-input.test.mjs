import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verify, X509Certificate } from 'node:crypto';
import { types } from 'node:util';
import { runInNewContext } from 'node:vm';
import { evaluateSignedDocument, inspectIssuerSigned, prepareDocumentSignature,
  verifyDocumentSignature, verifyIssuerSigned } from './base.mjs';
import { prepareHolderAuthentication, verifyHolderAuthentication } from './holder-auth.mjs';
import { decode } from './cbor.mjs';
import { nativeUint8Copy } from './native-bytes.mjs';

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
const mutateSharedSourceDuringCopy = (source, work) => {
  const originalSet = Uint8Array.prototype.set;
  let mutated = false;
  Uint8Array.prototype.set = function (bytes, offset) {
    if (!mutated && bytes.buffer === source.buffer && this.byteLength === source.byteLength) {
      source[0] ^= 1;
      mutated = true;
    }
    return originalSet.call(this, bytes, offset);
  };
  try { return { result: work(), mutated }; }
  finally { Uint8Array.prototype.set = originalSet; }
};
const oversizedCredential = Buffer.from(new ArrayBuffer(8 * 1024 * 1024 + 1));
const observeOversizedCopy = work => {
  const originalAlloc = Buffer.alloc;
  let attempted = 0;
  Buffer.alloc = function (size, ...rest) {
    if (size === oversizedCredential.length) {
      attempted++;
      throw new Error('ALLOC_BEFORE_LIMIT');
    }
    return originalAlloc(size, ...rest);
  };
  try { return { result: work(), attempted }; }
  catch (error) { return { error, attempted }; }
  finally { Buffer.alloc = originalAlloc; }
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

test('CBOR decoder applies its byte limit before allocating an owned copy', () => {
  assert.equal(decode(Buffer.from([0x18, 0x18]), { maxBytes: 2 }), 24);
  const input = Buffer.from([1, 2, 3]), originalAlloc = Buffer.alloc;
  let copiedOversizeInput = false;
  Buffer.alloc = function (size, ...rest) {
    if (size === input.length) copiedOversizeInput = true;
    return originalAlloc(size, ...rest);
  };
  try { assert.throws(() => decode(input, { maxBytes: 2 }), { code: 'CBOR_SIZE' }); }
  finally { Buffer.alloc = originalAlloc; }
  assert.equal(copiedOversizeInput, false);
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
  const extracted = decode(output)[3];
  assert.deepEqual(extracted, decode(input.signature)[3]);
  assert.equal(verify(null, prepareDocumentSignature(input.document, options).tbs,
    validated.publicKey, extracted), true);
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
  const extracted = decode(output).get('deviceAuth').get('deviceSignature')[3];
  assert.deepEqual(extracted, decode(bytes(v.deviceSigned)).get('deviceAuth').get('deviceSignature')[3]);
  assert.equal(verify(null, prepareHolderAuthentication(options.sessionTranscript,
    { holderPublicKey: facts.holderPublicKey }).tbs, facts.holderPublicKey, extracted), true);
  assert(verifyHolderAuthentication(output, credential, options).holderProof.signature);
});

test('native byte copies reject wider views even when they inherit Buffer identity', () => {
  assert.deepEqual(nativeUint8Copy(runInNewContext('Uint8Array.from([1, 2])')),
    Buffer.from([1, 2]));
  const wider = new Uint16Array([0x0201]);
  Object.setPrototypeOf(wider, Buffer.prototype);
  assert.equal(Buffer.isBuffer(wider), true);
  assert.equal(types.isUint8Array(wider), false);
  assert.throws(() => nativeUint8Copy(wider), TypeError);
  const input = selectedInputs();
  const validated = evaluateSignedDocument(input.document, input.signature, input.credential, input.options);
  assert.equal(validated.overall, 'VALID');
  assert.throws(() => prepareDocumentSignature(wider,
    { credential: input.credential, publicKey: validated.publicKey }), { code: 'MDOC_DOCUMENT_BYTES' });
  assert.throws(() => inspectIssuerSigned(wider, input.options), { code: 'CBOR_TYPE' });
  assert.deepEqual(evaluateSignedDocument(wider, input.signature, input.credential, input.options),
    { overall: 'INVALID', reason: 'MDOC_DOCUMENT_BYTES' });
  const v = holder.base, certificate = bytes(v.certificate), credential = bytes(v.credential);
  const options = { certificate, issuerKey: new X509Certificate(certificate).publicKey,
    at: v.at, sessionTranscript: bytes(v.sessionTranscript) };
  const facts = inspectIssuerSigned(credential, options);
  assert.throws(() => prepareHolderAuthentication(wider,
    { holderPublicKey: facts.holderPublicKey }), { code: 'MDOC_SESSION_TRANSCRIPT' });
  assert.throws(() => verifyHolderAuthentication(wider, credential, options),
    { code: 'MDOC_HOLDER_BYTES' });
});

test('document finish packages only a signature verified from its retained snapshot', () => {
  const input = selectedInputs();
  const validated = evaluateSignedDocument(input.document, input.signature, input.credential, input.options);
  assert.equal(validated.overall, 'VALID');
  const options = { credential: input.credential, publicKey: validated.publicKey };
  const original = decode(input.signature)[3];
  const shared = Buffer.from(new SharedArrayBuffer(original.length));
  original.copy(shared);
  const prepared = prepareDocumentSignature(input.document, options);
  let packageBytes, error;
  const attempt = mutateSharedSourceDuringCopy(shared, () => {
    try { packageBytes = prepared.finish(shared); }
    catch (failure) { error = failure; }
  });
  assert.equal(attempt.mutated, true);
  assert.equal(error?.code, 'MDOC_DOCUMENT_SIGNATURE');
  assert.equal(packageBytes, undefined);
});

test('holder finish packages only a DeviceSignature verified from its retained snapshot', () => {
  const v = holder.base, certificate = bytes(v.certificate), credential = bytes(v.credential);
  const options = { certificate, issuerKey: new X509Certificate(certificate).publicKey,
    at: v.at, sessionTranscript: bytes(v.sessionTranscript) };
  const facts = inspectIssuerSigned(credential, options);
  const original = decode(bytes(v.deviceSigned)).get('deviceAuth').get('deviceSignature')[3];
  const shared = Buffer.from(new SharedArrayBuffer(original.length));
  original.copy(shared);
  const prepared = prepareHolderAuthentication(options.sessionTranscript,
    { holderPublicKey: facts.holderPublicKey });
  let packageBytes, error;
  const attempt = mutateSharedSourceDuringCopy(shared, () => {
    try { packageBytes = prepared.finish(shared); }
    catch (failure) { error = failure; }
  });
  assert.equal(attempt.mutated, true);
  assert.equal(error?.code, 'MDOC_HOLDER_SIGNATURE');
  assert.equal(packageBytes, undefined);
});

test('complete evaluator bounds CBOR credential and COSE signature before copying', () => {
  const tiny = Buffer.from([1]);
  for (const [signature, credential] of [[tiny, oversizedCredential],
    [oversizedCredential, tiny]]) {
    const observation = observeOversizedCopy(() =>
      evaluateSignedDocument(tiny, signature, credential, {}));
    assert.equal(observation.attempted, 0);
    assert.deepEqual(observation.result, { overall: 'INVALID', reason: 'CBOR_SIZE' });
  }
});

test('direct issuer verification bounds encoded credentials before copying', () => {
  const observation = observeOversizedCopy(() => verifyIssuerSigned(oversizedCredential, { at: 1 }));
  assert.equal(observation.attempted, 0);
  assert.equal(observation.error?.code, 'CBOR_SIZE');
});

test('holder entry bounds DeviceSigned, credential and transcript before copying', () => {
  const v = holder.base, certificate = bytes(v.certificate), credential = bytes(v.credential);
  const options = { certificate, issuerKey: new X509Certificate(certificate).publicKey,
    at: v.at, sessionTranscript: bytes(v.sessionTranscript) };
  const facts = inspectIssuerSigned(credential, options);
  for (const work of [
    () => prepareHolderAuthentication(oversizedCredential,
      { holderPublicKey: facts.holderPublicKey }),
    () => verifyHolderAuthentication(bytes(v.deviceSigned), oversizedCredential, options),
    () => verifyHolderAuthentication(oversizedCredential, credential, options),
  ]) {
    const observation = observeOversizedCopy(work);
    assert.equal(observation.attempted, 0);
    assert.equal(observation.error?.code, 'CBOR_SIZE');
  }
});
