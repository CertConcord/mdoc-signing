import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { CREDENTIAL_HEADER, prepareDocumentSignature } from '../reference/base.mjs';
import { decode, encode } from '../reference/cbor.mjs';

// One-time synthetic fixture builder. Only public bytes and signatures are saved.
const label = 9007199254740993n;
const keys = generateKeyPairSync('ml-dsa-65');
const document = Buffer.from('PQ detached large critical-header fixture.\n');
const credential = Buffer.from('Opaque credential bytes for a document primitive.\n');
const required = new Map([[label, 'application-intent']]);
const options = { credential, publicKey: keys.publicKey, requiredProtectedHeaders: required };
const prepared = prepareDocumentSignature(document, options);
const valid = prepared.finish(sign(null, prepared.tbs, keys.privateKey));
const validHeaders = decode(decode(valid)[0]);
const critical = validHeaders.get(2);
if (validHeaders.get(label) !== 'application-intent' ||
  !Array.isArray(critical) || critical.length !== 2 ||
  critical[0] !== CREDENTIAL_HEADER || critical[1] !== label)
  throw new Error('Large critical label was not selected');

function signedWith(change) {
  const headers = decode(decode(valid)[0]);
  change(headers);
  const protectedBytes = encode(headers);
  const tbs = encode(['Signature1', protectedBytes, Buffer.alloc(0), document]);
  return encode([protectedBytes, new Map(), null, sign(null, tbs, keys.privateKey)]);
}
const changedValue = signedWith(headers => headers.set(label, 'different-intent'));
const changedLabel = signedWith(headers => {
  headers.set(label + 1n, headers.get(label));
  headers.delete(label);
  headers.set(2, [CREDENTIAL_HEADER, label + 1n]);
});
const reversed = signedWith(headers => headers.set(2, [label, CREDENTIAL_HEADER]));
const broken = decode(reversed);
broken[3][0] ^= 1;
const badMath = encode(broken);
const hex = bytes => bytes.toString('hex');
const cases = [
  { id: 'pqc-document-large-critical-valid', signature: hex(valid), nativeMath: true,
    expected: { overall: 'VALID' } },
  { id: 'pqc-document-large-critical-changed-value', signature: hex(changedValue), nativeMath: true,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' } },
  { id: 'pqc-document-large-critical-changed-label', signature: hex(changedLabel), nativeMath: true,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' } },
  { id: 'pqc-document-large-critical-reversed', signature: hex(reversed), nativeMath: true,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' } },
  { id: 'pqc-document-large-critical-reversed-bad-math', signature: hex(badMath), nativeMath: false,
    expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_SIGNATURE' } },
];
for (const sample of cases) {
  const cose = decode(Buffer.from(sample.signature, 'hex'));
  const tbs = encode(['Signature1', cose[0], Buffer.alloc(0), document]);
  if (verify(null, tbs, keys.publicKey, cose[3]) !== sample.nativeMath)
    throw new Error('Native mathematics mismatch: ' + sample.id);
}
writeFileSync(new URL('../vectors/pqc-document-large-critical.json', import.meta.url), JSON.stringify({
  schemaVersion: 1,
  profile: 'mdoc-signing-draft-03-document-primitive',
  scope: 'Synthetic application critical label; no IANA registration, issuer admission or document authority claimed',
  label: label.toString(),
  publicKeyDER: hex(keys.publicKey.export({ format: 'der', type: 'spki' })),
  document: hex(document), credential: hex(credential),
  requiredProtectedHeaders: hex(encode(required)), cases,
}, null, 2) + '\n');
