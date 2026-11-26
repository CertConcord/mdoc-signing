import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { issueIssuerSigned, SIGNING_DOCTYPE } from '../reference/base.mjs';
import { decode, encode, get } from '../reference/cbor.mjs';
import { syntheticPqcCertificate } from './pqc-certificate.mjs';

const hex = value => Buffer.from(value).toString('hex');
const at = 1795720000;
const root = generateKeyPairSync('ml-dsa-65');
const issuer = generateKeyPairSync('ml-dsa-65');
const holder = generateKeyPairSync('ml-dsa-65');
const rootCertificate = syntheticPqcCertificate({ subjectKey: root.publicKey, signerKey: root.privateKey,
  subject: 'Synthetic PQ issuer-header root', issuer: 'Synthetic PQ issuer-header root', serial: 11,
  at, ca: true });
const certificate = syntheticPqcCertificate({ subjectKey: issuer.publicKey, signerKey: root.privateKey,
  subject: 'Synthetic PQ issuer-header signer', issuer: 'Synthetic PQ issuer-header root', serial: 12,
  at, ca: false });
const original = issueIssuerSigned({ namespaces: { [SIGNING_DOCTYPE]: { family_name: 'Fixture' } },
  holderJWK: holder.publicKey.export({ format: 'jwk' }), certificate, privateKey: issuer.privateKey,
  signed: at, validFrom: at, validUntil: at + 3600 });
const auth = get(decode(original), 'issuerAuth');
const canonicalProtected = auth[0], headers = decode(canonicalProtected);
if (headers.size !== 2 || headers.get(1) !== -49 || !headers.has(34))
  throw new Error('Unexpected issuer protected-header fixture');
// Encode the same two protected parameters in the opposite map order. COSE signs
// the received bstr; this low-level issuer primitive does not require a canonical map.
const reorderedProtected = Buffer.concat([Buffer.from([0xa2]), encode(34), encode(headers.get(34)),
  encode(1), encode(-49)]);
if (reorderedProtected.equals(canonicalProtected) || decode(reorderedProtected).get(1) !== -49)
  throw new Error('Reordered protected map was not distinct');
const reorderedSignature = sign(null, encode(['Signature1', reorderedProtected, Buffer.alloc(0), auth[2]]),
  issuer.privateKey);
const credential = (protectedBytes, signature) => {
  const value = decode(original), current = get(value, 'issuerAuth');
  current[0] = Buffer.from(protectedBytes);
  current[3] = Buffer.from(signature);
  return hex(encode(value));
};
const cases = [
  { id: 'pqc-issuer-canonical-protected', credential: hex(original), pureMath: true,
    expected: { overall: 'VALID' } },
  { id: 'pqc-issuer-reordered-protected-signed', credential: credential(reorderedProtected, reorderedSignature),
    pureMath: true, expected: { overall: 'VALID' } },
  { id: 'pqc-issuer-reordered-protected-old-signature', credential: credential(reorderedProtected, auth[3]),
    pureMath: false, expected: { overall: 'INVALID', reason: 'COSE_SIGNATURE' } },
  { id: 'pqc-issuer-canonical-protected-reordered-signature',
    credential: credential(canonicalProtected, reorderedSignature), pureMath: false,
    expected: { overall: 'INVALID', reason: 'COSE_SIGNATURE' } },
];
writeFileSync(new URL('../vectors/pqc-issuer-headers.json', import.meta.url), JSON.stringify({
  schemaVersion: 1, profile: 'mdoc-signing-draft-03-pqc-issuer-primitive', docType: SIGNING_DOCTYPE,
  stateTime: at, rootCertificate: hex(rootCertificate), certificate: hex(certificate),
  canonicalProtected: hex(canonicalProtected), reorderedProtected: hex(reorderedProtected),
  payloadSha256: hex(createHash('sha256').update(auth[2]).digest()), cases,
}, null, 2) + '\n');
