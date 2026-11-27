import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { prepareHolderAuthentication } from '../reference/holder-auth.mjs';
import { decode, encode, get } from '../reference/cbor.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

const ml = size => generateKeyPairSync('ml-dsa-' + size);
const hex = bytes => Buffer.from(bytes).toString('hex');
const spki = key => key.export({ type: 'spki', format: 'der' });
const digest = bytes => createHash('sha512').update(bytes).digest();
const root = ml(65), issuer = ml(65), holder = ml(65), documentKey = ml(65);
const at = Math.floor(Date.now() / 1000);
const rootCertificate = syntheticPqcCertificate({ subjectKey: root.publicKey, signerKey: root.privateKey,
  subject: 'Synthetic PQ document CA', issuer: 'Synthetic PQ document CA', serial: 1, at, ca: true });
const otherRoot = ml(65);
const otherRootCertificate = syntheticPqcCertificate({ subjectKey: otherRoot.publicKey,
  signerKey: otherRoot.privateKey, subject: 'Unadmitted PQ document CA',
  issuer: 'Unadmitted PQ document CA', serial: 3, at, ca: true });
const certificate = syntheticPqcCertificate({ subjectKey: issuer.publicKey, signerKey: root.privateKey,
  subject: 'Synthetic PQ document signer', issuer: 'Synthetic PQ document CA', serial: 2, at, ca: false });
const statusURI = 'https://issuer.example/pq/status/1';
const claims = {
  subject_id: Buffer.alloc(32, 1), credential_id: Buffer.alloc(32, 2), issuer: 'https://issuer.example/pq/',
  signing_key: spki(documentKey.publicKey), signing_key_id: digest(spki(documentKey.publicKey)),
  document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'], profile_id: BASE_PROFILE,
  status: { status_list: { uri: statusURI, idx: 1 } },
};
const mint = (selectedClaims = claims, holderKey = holder.publicKey) => issueIssuerSigned({
  namespaces: { [SIGNING_NAMESPACE]: selectedClaims }, holderJWK: holderKey.export({ format: 'jwk' }),
  certificate, privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600,
});
const document = Buffer.from('Post-quantum mdoc document-signing fixture.\n');
const signedDocument = (credential, key = documentKey) => {
  const prepared = prepareDocumentSignature(document, { credential, publicKey: key.publicKey });
  return prepared.finish(sign(prepared.algorithm === -7 ? 'sha256' : null, prepared.tbs,
    prepared.algorithm === -7 ? { key: key.privateKey, dsaEncoding: 'ieee-p1363' } : key.privateKey));
};
const statusToken = (revoked = false, patch = {}) => {
  const bits = Buffer.alloc(16);
  if (revoked) bits[0] = 2;
  const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-65', typ: 'statuslist+jwt' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI, iat: at, exp: at + 300,
    ttl: 300, status_list: { bits: 1, lst: deflateSync(bits).toString('base64url') }, ...patch })).toString('base64url');
  return header + '.' + payload + '.' + sign(null, Buffer.from(header + '.' + payload), issuer.privateKey).toString('base64url');
};
const classicalStatusSigner = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const classicalStatusToken = () => {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'statuslist+jwt' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI, iat: at, exp: at + 300,
    ttl: 300, status_list: { bits: 1, lst: deflateSync(Buffer.alloc(16)).toString('base64url') } })).toString('base64url');
  return header + '.' + payload + '.' + sign('sha256', Buffer.from(header + '.' + payload),
    { key: classicalStatusSigner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
};
const credential = mint(), signature = signedDocument(credential), token = statusToken();
const sessionTranscript = encode([null, null, Buffer.alloc(32, 7)]);
const holderPreparation = prepareHolderAuthentication(sessionTranscript, { holderPublicKey: holder.publicKey });
const deviceSigned = holderPreparation.finish(sign(null, holderPreparation.tbs, holder.privateKey));
const base = { credential: hex(credential), certificate: hex(certificate), signature: hex(signature),
  document: hex(document), sessionTranscript: hex(sessionTranscript), deviceSigned: hex(deviceSigned),
  statusEvidence: token, profileID: BASE_PROFILE,
  documentKeyMode: 'INDEPENDENT_PQ', stateTime: at, knowledgeTime: at };
const cases = [];
const add = (id, patch, overall, reason) => cases.push({ id, ...patch, expected: { overall, ...(reason ? { reason } : {}) } });
const credentialPatch = (bytes, key = documentKey) => ({ credential: hex(bytes), signature: hex(signedDocument(bytes, key)) });
add('pqc-complete-ml-dsa-65', {}, 'VALID');
const document87 = ml(87);
const credential87 = mint({ ...claims, signing_key: spki(document87.publicKey), signing_key_id: digest(spki(document87.publicKey)) });
add('pqc-complete-ml-dsa-87-document', credentialPatch(credential87, document87), 'VALID');
const brokenIssuer = decode(credential); get(brokenIssuer, 'issuerAuth')[3][0] ^= 1;
add('pqc-invalid-issuer-signature', { credential: hex(encode(brokenIssuer)) }, 'INVALID', 'COSE_SIGNATURE');
const classicalIssuerAlg = decode(credential), issuerHeaders = decode(get(classicalIssuerAlg, 'issuerAuth')[0]);
issuerHeaders.set(1, -7); get(classicalIssuerAlg, 'issuerAuth')[0] = encode(issuerHeaders);
add('pqc-reject-classic-issuer-alg', { credential: hex(encode(classicalIssuerAlg)) }, 'INVALID', 'MDOC_ISSUER_ALGORITHM_MISMATCH');
const brokenDocument = decode(signature); brokenDocument[3][0] ^= 1;
add('pqc-invalid-document-signature', { signature: hex(encode(brokenDocument)) }, 'INVALID', 'MDOC_DOCUMENT_SIGNATURE');
add('pqc-changed-document', { document: hex(Buffer.from('Changed document.\n')) }, 'INVALID', 'MDOC_DOCUMENT_SIGNATURE');
const classicHolder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
add('pqc-reject-classic-holder', credentialPatch(mint(claims, classicHolder.publicKey)), 'INVALID', 'MDOC_PQC_AUTHENTICATION_REQUIRED');
const classicDocument = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const classicCredential = mint({ ...claims, signing_key: spki(classicDocument.publicKey),
  signing_key_id: digest(spki(classicDocument.publicKey)), document_key_mode: 'PASSKEY_KEY' });
add('pqc-reject-classic-document-key', { ...credentialPatch(classicCredential, classicDocument),
  documentKeyMode: 'PASSKEY_KEY' }, 'INVALID', 'MDOC_PQC_DOCUMENT_KEY_REQUIRED');
add('pqc-reject-classic-status-claim', { policy: 'classic-status-claim' }, 'INVALID', 'MDOC_PQC_STATUS_REQUIRED');
add('pqc-reject-array-status-good', { policy: 'array-status-good-no-algorithm' }, 'INVALID', 'MDOC_STATUS_RESULT');
add('pqc-reject-classic-status-token', { statusEvidence: classicalStatusToken(),
  classicalStatusPublicKey: hex(spki(classicalStatusSigner.publicKey)) }, 'INVALID', 'MDOC_STATUS_INVALID');
add('pqc-status-revoked', { statusEvidence: statusToken(true) }, 'INVALID', 'MDOC_STATUS_REVOKED');
add('pqc-status-stale', { statusEvidence: statusToken(false, { iat: at - 400, exp: at - 100 }) },
  'INDETERMINATE', 'MDOC_STATUS_STALE');
add('pqc-status-invalid-ttl', { statusEvidence: statusToken(false, { ttl: 0 }) }, 'INVALID', 'MDOC_STATUS_INVALID');
add('pqc-issuer-not-admitted', { policy: 'issuer-not-admitted' }, 'INVALID', 'MDOC_ISSUER_AUTHORIZATION');
add('pqc-trust-anchor-missing', { trustAnchorCertificate: null }, 'INDETERMINATE', 'MDOC_PQC_TRUST_ANCHOR_MISSING');
add('pqc-trust-anchor-substitution', { trustAnchorCertificate: hex(otherRootCertificate) }, 'INVALID', 'MDOC_PQC_TRUST_PATH');
add('pqc-status-missing', { statusEvidence: null }, 'INDETERMINATE', 'MDOC_STATUS_MISSING');
add('pqc-reject-unselected-profile', { profileID: 'MDOC-SIGNING-PERSON-PQ-v2' }, 'INVALID', 'MDOC_PROFILE');
add('pqc-credential-binding', { credential: hex(mint()) }, 'INVALID', 'MDOC_DOCUMENT_PROTECTED_HEADERS');
writeFileSync(new URL('../vectors/pqc-base.json', import.meta.url), JSON.stringify({ schemaVersion: 1,
  profile: 'mdoc-signing-draft-03-pqc', trust: { rootCertificate: hex(rootCertificate), issuer: claims.issuer,
    statusURI }, base, cases }, null, 2) + '\n');
