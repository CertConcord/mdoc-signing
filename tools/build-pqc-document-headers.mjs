import { generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { CREDENTIAL_HEADER, prepareDocumentSignature } from '../reference/base.mjs';
import { decode, encode } from '../reference/cbor.mjs';

// One-time synthetic fixture builder. Only public bytes and signatures are saved.
const keys = generateKeyPairSync('ml-dsa-65');
const document = Buffer.from('PQ detached critical-header fixture.\n');
const credential = Buffer.from('Opaque synthetic credential for primitive testing.\n');
const required = new Map([
  ['urn:example:z', Buffer.from('document-purpose')],
  ['urn:example:a', Buffer.from('application-intent')],
]);
const options = { credential, publicKey: keys.publicKey, requiredProtectedHeaders: required };
const prepared = prepareDocumentSignature(document, options);
const valid = prepared.finish(sign(null, prepared.tbs, keys.privateKey));
const validHeaders = decode(decode(valid)[0]);
if (JSON.stringify(validHeaders.get(2)) !== JSON.stringify([
  CREDENTIAL_HEADER, 'urn:example:a', 'urn:example:z',
])) throw new Error('Critical labels are not in canonical encoded-key order');

function signedWith(change) {
  const headers = decode(decode(valid)[0]);
  change(headers);
  const protectedBytes = encode(headers);
  const tbs = encode(['Signature1', protectedBytes, Buffer.alloc(0), document]);
  return encode([protectedBytes, new Map(), null, sign(null, tbs, keys.privateKey)]);
}
const reversed = signedWith(headers => headers.set(2,
  [CREDENTIAL_HEADER, 'urn:example:z', 'urn:example:a']));
const broken = decode(reversed);
broken[3][0] ^= 1;
const changed = signedWith(headers => headers.set('urn:example:a', Buffer.from('different-intent')));
const hex = bytes => bytes.toString('hex');
const cases = [
  { id: 'pqc-document-critical-canonical', signature: hex(valid), nativeMath: true,
    expected: { overall: 'VALID' } },
  { id: 'pqc-document-critical-reversed', signature: hex(reversed), nativeMath: true,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' } },
  { id: 'pqc-document-critical-reversed-bad-math', signature: hex(encode(broken)), nativeMath: false,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_SIGNATURE' } },
  { id: 'pqc-document-critical-changed-value', signature: hex(changed), nativeMath: true,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' } },
];
writeFileSync(new URL('../vectors/pqc-document-headers.json', import.meta.url), JSON.stringify({
  schemaVersion: 1,
  profile: 'mdoc-signing-draft-03-document-primitive',
  scope: 'ML-DSA-65 detached COSE only; opaque credential bytes grant no issuer or document authority',
  publicKeyDER: hex(keys.publicKey.export({ format: 'der', type: 'spki' })),
  document: hex(document), credential: hex(credential),
  requiredProtectedHeaders: hex(encode(required)), cases,
}, null, 2) + '\n');
