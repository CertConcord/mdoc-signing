import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { prepareHolderAuthentication } from '../reference/holder-auth.mjs';
import { decode, encode, get } from '../reference/cbor.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

// One-time synthetic fixtures. Private keys are not stored in the vector corpus.
const key = () => generateKeyPairSync('ml-dsa-65');
const root = key(), intermediate = key(), leaf = key(), holder = key(), documentKey = key();
const at = 1795710000;
const rootCertificate = syntheticPqcCertificate({ subjectKey: root.publicKey,
  signerKey: root.privateKey, subject: 'PQ holder-role root CA',
  issuer: 'PQ holder-role root CA', serial: 41, at, ca: true });
const intermediateCertificate = syntheticPqcCertificate({ subjectKey: intermediate.publicKey,
  signerKey: root.privateKey, subject: 'PQ holder-role intermediate CA',
  issuer: 'PQ holder-role root CA', serial: 42, at, ca: true });
const certificate = syntheticPqcCertificate({ subjectKey: leaf.publicKey,
  signerKey: intermediate.privateKey, subject: 'PQ holder-role issuer',
  issuer: 'PQ holder-role intermediate CA', serial: 43, at, ca: false });
const hex = value => Buffer.from(value).toString('hex');
const spki = key => key.export({ format: 'der', type: 'spki' });
const statusURI = 'https://issuer.example/pq/status/holder-roles';
const transcript = encode([null, null, ['holder-role-challenge']]);
const document = Buffer.from('PQ holder certificate-path role fixture.\n');
const claims = { subject_id: Buffer.alloc(32, 0x71), credential_id: Buffer.alloc(32, 0x72),
  issuer: 'https://issuer.example/pq/', signing_key: spki(documentKey.publicKey),
  signing_key_id: createHash('sha512').update(spki(documentKey.publicKey)).digest(),
  document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'],
  profile_id: BASE_PROFILE, status: { status_list: { uri: statusURI, idx: 1 } } };
function signedCase(id, holderKey, overall, reason) {
  const issued = issueIssuerSigned({ namespaces: { [SIGNING_NAMESPACE]: claims },
    holderJWK: holderKey.publicKey.export({ format: 'jwk' }), certificate,
    privateKey: leaf.privateKey, signed: at, validFrom: at, validUntil: at + 3600 });
  const issuerSigned = decode(issued);
  get(issuerSigned, 'issuerAuth')[1].set(33, [certificate, intermediateCertificate]);
  const credential = encode(issuerSigned);
  const prepared = prepareDocumentSignature(document, { credential, publicKey: documentKey.publicKey });
  const signature = prepared.finish(sign(null, prepared.tbs, documentKey.privateKey));
  const holderProof = prepareHolderAuthentication(transcript, { holderPublicKey: holderKey.publicKey });
  const deviceSigned = holderProof.finish(sign(null, holderProof.tbs, holderKey.privateKey));
  return { id, credential: hex(credential), signature: hex(signature),
    deviceSigned: hex(deviceSigned), holderPublicKeyDER: hex(spki(holderKey.publicKey)),
    expected: { overall, ...(reason ? { reason } : {}) } };
}
const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-65', typ: 'statuslist+jwt' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI, iat: at,
  exp: at + 300, ttl: 300, status_list: { bits: 1,
    lst: deflateSync(Buffer.alloc(16)).toString('base64url') } })).toString('base64url');
const statusEvidence = header + '.' + payload + '.' +
  sign(null, Buffer.from(header + '.' + payload), leaf.privateKey).toString('base64url');
writeFileSync(new URL('../vectors/pqc-holder-ca-key-role.json', import.meta.url), JSON.stringify({
  schemaVersion: 1, profile: 'mdoc-signing-draft-03-pqc-holder-ca-key-role',
  scope: 'Synthetic PQ path, issuer, holder and detached document signatures; test policy admits only the selected root',
  trust: { rootCertificate: hex(rootCertificate), intermediateCertificate: hex(intermediateCertificate), statusURI },
  base: { certificate: hex(certificate), document: hex(document),
    documentPublicKeyDER: hex(spki(documentKey.publicKey)), transcript: hex(transcript),
    statusEvidence, stateTime: at, knowledgeTime: at, profileID: BASE_PROFILE,
    documentKeyMode: 'INDEPENDENT_PQ' },
  cases: [
    signedCase('pqc-distinct-holder-key-from-ca-path', holder, 'VALID'),
    signedCase('pqc-reject-root-ca-holder-key', root, 'INVALID', 'MDOC_KEY_ROLE_COLLISION'),
    signedCase('pqc-reject-intermediate-ca-holder-key', intermediate,
      'INVALID', 'MDOC_KEY_ROLE_COLLISION'),
  ],
}, null, 2) + '\n');
