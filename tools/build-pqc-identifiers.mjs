import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

// One-time synthetic fixtures. Private keys are not serialized.
const key = () => generateKeyPairSync('ml-dsa-65');
const root = key(), issuer = key(), holder = key(), documentKey = key();
const at = 1795710000;
const rootCertificate = syntheticPqcCertificate({ subjectKey: root.publicKey,
  signerKey: root.privateKey, subject: 'PQ identifier fixture CA',
  issuer: 'PQ identifier fixture CA', serial: 21, at, ca: true });
const certificate = syntheticPqcCertificate({ subjectKey: issuer.publicKey,
  signerKey: root.privateKey, subject: 'PQ identifier fixture signer',
  issuer: 'PQ identifier fixture CA', serial: 22, at, ca: false });
const hex = value => Buffer.from(value).toString('hex');
const spki = documentKey.publicKey.export({ format: 'der', type: 'spki' });
const subjectID = Buffer.alloc(32, 0x51);
const statusURI = 'https://issuer.example/pq/status/identifiers';
const claims = credentialID => ({ subject_id: subjectID, credential_id: credentialID,
  issuer: 'https://issuer.example/pq/', signing_key: spki,
  signing_key_id: createHash('sha512').update(spki).digest(),
  document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'],
  profile_id: BASE_PROFILE, status: { status_list: { uri: statusURI, idx: 1 } } });
const document = Buffer.from('PQ identifier separation fixture.\n');
function signedCase(id, credentialID, overall, reason) {
  const credential = issueIssuerSigned({ namespaces: { [SIGNING_NAMESPACE]: claims(credentialID) },
    holderJWK: holder.publicKey.export({ format: 'jwk' }), certificate,
    privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600 });
  const prepared = prepareDocumentSignature(document, { credential, publicKey: documentKey.publicKey });
  const signature = prepared.finish(sign(null, prepared.tbs, documentKey.privateKey));
  return { id, credential: hex(credential), signature: hex(signature),
    expected: { overall, ...(reason ? { reason } : {}) } };
}
const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-65', typ: 'statuslist+jwt' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI, iat: at,
  exp: at + 300, ttl: 300, status_list: { bits: 1,
    lst: deflateSync(Buffer.alloc(16)).toString('base64url') } })).toString('base64url');
const statusEvidence = header + '.' + payload + '.' +
  sign(null, Buffer.from(header + '.' + payload), issuer.privateKey).toString('base64url');
writeFileSync(new URL('../vectors/pqc-identifiers.json', import.meta.url), JSON.stringify({
  schemaVersion: 1, profile: 'mdoc-signing-draft-03-pqc-identifiers',
  scope: 'Synthetic complete PQ issuer/path/status/document mathematics; explicit test policy admits only the selected root',
  trust: { rootCertificate: hex(rootCertificate), statusURI },
  base: { certificate: hex(certificate), document: hex(document), statusEvidence,
    documentPublicKeyDER: hex(spki), stateTime: at, knowledgeTime: at,
    profileID: BASE_PROFILE, documentKeyMode: 'INDEPENDENT_PQ' },
  cases: [
    signedCase('pqc-distinct-subject-credential-ids', Buffer.alloc(32, 0x52), 'VALID'),
    signedCase('pqc-reject-reused-subject-credential-id', Buffer.from(subjectID),
      'INVALID', 'MDOC_IDENTIFIER_REUSED'),
  ],
}, null, 2) + '\n');
