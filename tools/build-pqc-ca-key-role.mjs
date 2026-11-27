import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { decode, encode, get } from '../reference/cbor.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

// One-time synthetic fixtures. CA and document private keys exist only while building.
const key = () => generateKeyPairSync('ml-dsa-65');
const root = key(), intermediate = key(), leaf = key(), holder = key(), documentKey = key();
const at = 1795710000;
const rootCertificate = syntheticPqcCertificate({ subjectKey: root.publicKey,
  signerKey: root.privateKey, subject: 'PQ role fixture root CA',
  issuer: 'PQ role fixture root CA', serial: 31, at, ca: true });
const intermediateCertificate = syntheticPqcCertificate({ subjectKey: intermediate.publicKey,
  signerKey: root.privateKey, subject: 'PQ role fixture intermediate CA',
  issuer: 'PQ role fixture root CA', serial: 32, at, ca: true });
const certificate = syntheticPqcCertificate({ subjectKey: leaf.publicKey,
  signerKey: intermediate.privateKey, subject: 'PQ role fixture document signer',
  issuer: 'PQ role fixture intermediate CA', serial: 33, at, ca: false });
const hex = value => Buffer.from(value).toString('hex');
const spki = key => key.export({ format: 'der', type: 'spki' });
const statusURI = 'https://issuer.example/pq/status/key-roles';
const claims = signingKey => ({ subject_id: Buffer.alloc(32, 0x61),
  credential_id: Buffer.alloc(32, 0x62), issuer: 'https://issuer.example/pq/',
  signing_key: spki(signingKey), signing_key_id: createHash('sha512').update(spki(signingKey)).digest(),
  document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'],
  profile_id: BASE_PROFILE, status: { status_list: { uri: statusURI, idx: 1 } } });
const document = Buffer.from('PQ certificate-path key-role fixture.\n');
function signedCase(id, signer, overall, reason) {
  const issued = issueIssuerSigned({ namespaces: { [SIGNING_NAMESPACE]: claims(signer.publicKey) },
    holderJWK: holder.publicKey.export({ format: 'jwk' }), certificate,
    privateKey: leaf.privateKey, signed: at, validFrom: at, validUntil: at + 3600 });
  const issuerSigned = decode(issued);
  get(issuerSigned, 'issuerAuth')[1].set(33, [certificate, intermediateCertificate]);
  const credential = encode(issuerSigned);
  const prepared = prepareDocumentSignature(document, { credential, publicKey: signer.publicKey });
  const signature = prepared.finish(sign(null, prepared.tbs, signer.privateKey));
  return { id, credential: hex(credential), signature: hex(signature),
    documentPublicKeyDER: hex(spki(signer.publicKey)),
    expected: { overall, ...(reason ? { reason } : {}) } };
}
const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-65', typ: 'statuslist+jwt' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI, iat: at,
  exp: at + 300, ttl: 300, status_list: { bits: 1,
    lst: deflateSync(Buffer.alloc(16)).toString('base64url') } })).toString('base64url');
const statusEvidence = header + '.' + payload + '.' +
  sign(null, Buffer.from(header + '.' + payload), leaf.privateKey).toString('base64url');
writeFileSync(new URL('../vectors/pqc-ca-key-role.json', import.meta.url), JSON.stringify({
  schemaVersion: 1, profile: 'mdoc-signing-draft-03-pqc-ca-key-role',
  scope: 'Synthetic root/intermediate/leaf PQ path; valid status and detached document mathematics; explicit test policy admits only the selected root',
  trust: { rootCertificate: hex(rootCertificate),
    intermediateCertificate: hex(intermediateCertificate), statusURI },
  base: { certificate: hex(certificate), document: hex(document), statusEvidence,
    stateTime: at, knowledgeTime: at, profileID: BASE_PROFILE,
    documentKeyMode: 'INDEPENDENT_PQ' },
  cases: [
    signedCase('pqc-distinct-document-key-from-ca-path', documentKey, 'VALID'),
    signedCase('pqc-reject-root-ca-document-key', root, 'INVALID', 'MDOC_KEY_ROLE_COLLISION'),
    signedCase('pqc-reject-intermediate-ca-document-key', intermediate,
      'INVALID', 'MDOC_KEY_ROLE_COLLISION'),
  ],
}, null, 2) + '\n');
