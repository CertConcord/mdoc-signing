import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

// One-time synthetic fixture builder. Private keys exist only in this process.
const pair = () => generateKeyPairSync('ml-dsa-65');
const root = pair(), issuer = pair(), otherStatusSigner = pair(), holder = pair(), documentKey = pair();
const at = 1795710000;
const rootCertificate = syntheticPqcCertificate({ subjectKey: root.publicKey,
  signerKey: root.privateKey, subject: 'PQ status fixture CA', issuer: 'PQ status fixture CA',
  serial: 11, at, ca: true });
const certificate = syntheticPqcCertificate({ subjectKey: issuer.publicKey,
  signerKey: root.privateKey, subject: 'PQ status fixture signer', issuer: 'PQ status fixture CA',
  serial: 12, at, ca: false });
const spki = key => key.export({ type: 'spki', format: 'der' });
const hex = bytes => Buffer.from(bytes).toString('hex');
const statusURI = 'https://issuer.example/pq/status/2';
const issuerID = 'https://issuer.example/pq/';
const claims = {
  subject_id: Buffer.alloc(32, 0x31), credential_id: Buffer.alloc(32, 0x32),
  issuer: issuerID, signing_key: spki(documentKey.publicKey),
  signing_key_id: createHash('sha512').update(spki(documentKey.publicKey)).digest(),
  document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'],
  profile_id: BASE_PROFILE, status: { status_list: { uri: statusURI, idx: 1 } },
};
const credential = issueIssuerSigned({ namespaces: { [SIGNING_NAMESPACE]: claims },
  holderJWK: holder.publicKey.export({ format: 'jwk' }), certificate,
  privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600 });
const document = Buffer.from('PQ status-bound document fixture.\n');
const prepared = prepareDocumentSignature(document, { credential, publicKey: documentKey.publicKey });
const documentSignature = prepared.finish(sign(null, prepared.tbs, documentKey.privateKey));
const list = deflateSync(Buffer.alloc(16)).toString('base64url');
function statusToken(patch = {}, signer = issuer.privateKey) {
  const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-65', typ: 'statuslist+jwt' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI,
    iat: at, exp: at + 300, ttl: 300, status_list: { bits: 1, lst: list },
    ...patch })).toString('base64url');
  const input = Buffer.from(header + '.' + payload);
  return header + '.' + payload + '.' + sign(null, input, signer).toString('base64url');
}
const validToken = statusToken(), alternateToken = statusToken({}, otherStatusSigner.privateKey);
const badParts = validToken.split('.'), badSignature = Buffer.from(badParts[2], 'base64url');
badSignature[0] ^= 1;
badParts[2] = badSignature.toString('base64url');
const cases = [];
const add = (id, statusEvidence, nativeMathUnderPinnedKey, overall, reason, extra = {}) =>
  cases.push({ id, statusEvidence, nativeMathUnderPinnedKey, ...extra,
    expected: { overall, ...(reason ? { reason } : {}) } });
add('pqc-status-binding-valid', validToken, true, 'VALID');
add('pqc-status-binding-wrong-sub', statusToken({ sub: 'https://other.example/pq/status/2' }),
  true, 'INVALID', 'MDOC_STATUS_INVALID');
add('pqc-status-binding-wrong-iss', statusToken({ iss: 'https://other.example/pq/status/2' }),
  true, 'INVALID', 'MDOC_STATUS_INVALID');
add('pqc-status-binding-other-pq-signer', alternateToken, false, 'INVALID',
  'MDOC_STATUS_INVALID', { alternateStatusPublicKeyDER: hex(spki(otherStatusSigner.publicKey)),
    nativeMathUnderAlternateKey: true });
add('pqc-status-binding-ttl-stale-before-exp', statusToken({ iat: at - 150,
  exp: at + 150, ttl: 100 }), true, 'INDETERMINATE', 'MDOC_STATUS_STALE');
add('pqc-status-binding-bad-signature', badParts.join('.'), false,
  'INVALID', 'MDOC_STATUS_INVALID');
writeFileSync(new URL('../vectors/pqc-status-binding.json', import.meta.url), JSON.stringify({
  schemaVersion: 1, profile: 'mdoc-signing-draft-03-pqc-status-binding',
  scope: 'Complete experimental PQ signing credential and detached document; status JWT parsed by a bounded test adapter, not a production JOSE/PKIX stack',
  trust: { rootCertificate: hex(rootCertificate), issuer: issuerID, statusURI },
  base: { credential: hex(credential), certificate: hex(certificate),
    document: hex(document), signature: hex(documentSignature),
    profileID: BASE_PROFILE, documentKeyMode: 'INDEPENDENT_PQ',
    stateTime: at, knowledgeTime: at }, cases,
}, null, 2) + '\n');
