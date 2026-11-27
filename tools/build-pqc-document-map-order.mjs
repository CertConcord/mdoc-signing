import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { CREDENTIAL_HEADER, prepareDocumentSignature } from '../reference/base.mjs';
import { decode, encode } from '../reference/cbor.mjs';

// One-time synthetic fixture builder; only public bytes and signatures are saved.
const { publicKey, privateKey } = generateKeyPairSync('ml-dsa-65');
const document = Buffer.from('PQ document map-order fixture.\n');
const credential = Buffer.from('Opaque document-primitive credential.\n');
const requiredProtectedHeaders = new Map([[100, 'hundred'], [-1, 'minus-one']]);
const options = { credential, publicKey, requiredProtectedHeaders };
const prepared = prepareDocumentSignature(document, options);
const selected = prepared.finish(sign(null, prepared.tbs, privateKey));
const selectedHeaders = decode(decode(selected)[0]);
if (JSON.stringify(selectedHeaders.get(2)) !== JSON.stringify([CREDENTIAL_HEADER, 100, -1]))
  throw new Error('Unexpected critical-label order');

function lengthFirstMap(map) {
  if (map.size >= 24) throw new Error('Fixture map head needs a wider encoding');
  const pairs = [...map].map(([key, value]) => [encode(key), encode(value)])
    .sort((a, b) => a[0].length - b[0].length || Buffer.compare(a[0], b[0]));
  return Buffer.concat([Buffer.from([0xa0 + map.size]), ...pairs.flat()]);
}
const lengthFirst = lengthFirstMap(selectedHeaders);
if (lengthFirst.equals(decode(selected)[0])) throw new Error('Fixture did not distinguish map order');
const signatureInput = protectedBytes =>
  encode(['Signature1', protectedBytes, Buffer.alloc(0), document]);
const lengthFirstSignature = sign(null, signatureInput(lengthFirst), privateKey);
if (!verify(null, signatureInput(lengthFirst), publicKey, lengthFirstSignature))
  throw new Error('Length-first mathematics failed');
const alternate = encode([lengthFirst, new Map(), null, lengthFirstSignature]);
const damagedSignature = Buffer.from(lengthFirstSignature);
damagedSignature[0] ^= 1;
const damaged = encode([lengthFirst, new Map(), null, damagedSignature]);
const hex = value => value.toString('hex');
writeFileSync(new URL('../vectors/pqc-document-map-order.json', import.meta.url), JSON.stringify({
  schemaVersion: 1,
  profile: 'mdoc-signing-draft-03-document-primitive',
  scope: 'RFC 8949 core versus length-first protected-map order under an experimental ML-DSA-65 detached COSE primitive; opaque credential bytes grant no issuer or document authority',
  source: { id: 'rfc8949', section: '4.2.1 and 4.2.3' },
  publicKeyDER: hex(publicKey.export({ format: 'der', type: 'spki' })),
  document: hex(document),
  credential: hex(credential),
  requiredProtectedHeaders: hex(encode(requiredProtectedHeaders)),
  cases: [
    { id: 'pqc-document-map-core-bytewise', signature: hex(selected), nativeMath: true,
      expected: { overall: 'VALID' } },
    { id: 'pqc-document-map-length-first', signature: hex(alternate), nativeMath: true,
      expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_PROTECTED_HEADERS' } },
    { id: 'pqc-document-map-length-first-bad-math', signature: hex(damaged), nativeMath: false,
      expected: { overall: 'INVALID', reason: 'MDOC_DOCUMENT_SIGNATURE' } },
  ],
}, null, 2) + '\n');
