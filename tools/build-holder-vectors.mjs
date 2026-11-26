import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_DOCTYPE, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { prepareHolderAuthentication } from '../reference/holder-auth.mjs';
import { decode, embedded, encode } from '../reference/cbor.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

// Synthetic material only. Private keys stay in memory; serialized fixtures
// contain only public credentials, certificates and signatures.
const hex = value => Buffer.from(value).toString('hex');
const issuer = generateKeyPairSync('ml-dsa-65'), holder = generateKeyPairSync('ml-dsa-65');
const otherHolder = generateKeyPairSync('ml-dsa-65'), documentKey = generateKeyPairSync('ml-dsa-65');
const at = Math.floor(Date.now() / 1000);
const certificate = syntheticPqcCertificate({ subjectKey: issuer.publicKey, signerKey: issuer.privateKey,
  subject: 'Synthetic PQ holder issuer', issuer: 'Synthetic PQ holder issuer', serial: 1, at, ca: false });
const documentSPKI = documentKey.publicKey.export({ format: 'der', type: 'spki' });
  const claims = {
    subject_id: Buffer.alloc(32, 1), credential_id: Buffer.alloc(32, 2), issuer: 'https://holder-fixture.example/',
    signing_key: documentSPKI, signing_key_id: createHash('sha512').update(documentSPKI).digest(),
    document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'], profile_id: BASE_PROFILE,
    status: { status_list: { uri: 'https://holder-fixture.example/status', idx: 0 } },
  };
  const mint = key => issueIssuerSigned({ namespaces: { [SIGNING_NAMESPACE]: claims }, holderJWK: key.publicKey.export({ format: 'jwk' }), certificate, privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600 });
  const credential = mint(holder), otherCredential = mint(otherHolder);
  const sessionTranscript = encode([null, null, Buffer.alloc(32, 7)]);
  const prepared = prepareHolderAuthentication(sessionTranscript, { holderPublicKey: holder.publicKey });
  const deviceSigned = prepared.finish(sign(null, prepared.tbs, holder.privateKey));
  const base = { credential: hex(credential), certificate: hex(certificate), at, sessionTranscript: hex(sessionTranscript), deviceSigned: hex(deviceSigned) };
  const cases = [];
  const add = (id, patch, overall, reason) => cases.push({ id, ...patch, expected: { overall, ...(reason ? { reason } : {}) } });
  const change = mutate => { const value = decode(deviceSigned); mutate(value); return hex(encode(value)); };
  add('holder-device-signature', {}, 'VALID');
  add('changed-session-transcript', { sessionTranscript: hex(encode([null, null, Buffer.alloc(32, 8)])) }, 'INVALID', 'MDOC_HOLDER_SIGNATURE');
  add('wrong-holder-key', { credential: hex(otherCredential) }, 'INVALID', 'MDOC_HOLDER_SIGNATURE');
  add('changed-holder-signature', { deviceSigned: change(value => { value.get('deviceAuth').get('deviceSignature')[3][0] ^= 1; }) }, 'INVALID', 'MDOC_HOLDER_SIGNATURE');
  add('classic-holder-alg-downgrade', { deviceSigned: change(value => { value.get('deviceAuth').get('deviceSignature')[0] = encode(new Map([[1, -7]])); }) }, 'INVALID', 'MDOC_HOLDER_ALGORITHM');
  add('device-mac-is-not-signature', { deviceSigned: change(value => { const auth = value.get('deviceAuth'); auth.set('deviceMac', auth.get('deviceSignature')); auth.delete('deviceSignature'); }) }, 'UNSUPPORTED', 'MDOC_HOLDER_MAC_UNSUPPORTED');
  add('device-mac-and-signature', { deviceSigned: change(value => { const auth = value.get('deviceAuth'); auth.set('deviceMac', auth.get('deviceSignature')); }) }, 'INVALID', 'MDOC_HOLDER_AUTH');
  add('embedded-holder-payload', { deviceSigned: change(value => { value.get('deviceAuth').get('deviceSignature')[2] = Buffer.alloc(0); }) }, 'INVALID', 'MDOC_HOLDER_COSE');
  add('nonempty-device-namespaces', { deviceSigned: change(value => { value.set('nameSpaces', embedded(new Map([['org.example', new Map([['x', true]])]]))); }) }, 'UNSUPPORTED', 'MDOC_DEVICE_NAMESPACES_UNSUPPORTED');
  add('changed-issuer-auth', { credential: (() => { const value = decode(credential); value.get('issuerAuth')[3][0] ^= 1; return hex(encode(value)); })() }, 'INVALID', 'COSE_SIGNATURE');
  add('wrong-document-type', { docType: 'org.example.other' }, 'INVALID', 'MDOC_DOCTYPE');
  const wrongHeaders = decode(deviceSigned), cose = wrongHeaders.get('deviceAuth').get('deviceSignature');
  cose[0] = encode(new Map([[1, -49], [3, 'application/example']]));
  const payload = encode(embedded(['DeviceAuthentication', decode(sessionTranscript), SIGNING_DOCTYPE, wrongHeaders.get('nameSpaces')]));
  cose[3] = sign(null, encode(['Signature1', cose[0], Buffer.alloc(0), payload]), holder.privateKey);
  add('validly-signed-extra-protected-header', { deviceSigned: hex(encode(wrongHeaders)) }, 'INVALID', 'MDOC_HOLDER_HEADERS');
  const document = Buffer.from('Not a holder presentation.\n');
  const preparedDocument = prepareDocumentSignature(document, { credential, publicKey: documentKey.publicKey });
  const documentSignature = preparedDocument.finish(sign(null, preparedDocument.tbs, documentKey.privateKey));
  add('document-signature-is-not-holder-proof', { deviceSigned: hex(documentSignature) }, 'INVALID', 'MDOC_DEVICE_SIGNED');
writeFileSync(new URL('../vectors/holder-auth.json', import.meta.url), JSON.stringify({ schemaVersion: 1, profile: 'mdoc-signing-holder-auth-draft-03', base, cases }, null, 2) + '\n');
