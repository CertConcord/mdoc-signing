import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { BASE_PROFILE, issueIssuerSigned, prepareDocumentSignature, SIGNING_DOCTYPE, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { prepareHolderAuthentication } from '../reference/holder-auth.mjs';
import { decode, embedded, encode } from '../reference/cbor.mjs';

// Synthetic material only. Private keys stay in memory or the checked temporary
// directory; the serialized corpus contains public credentials and signatures.
const temporary = mkdtempSync(join(tmpdir(), 'mdoc-holder-vectors-'));
const openssl = process.env.OPENSSL_BIN ?? 'openssl';
const ec = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const hex = value => Buffer.from(value).toString('hex');
const issuer = ec(), holder = ec(), otherHolder = ec(), documentKey = generateKeyPairSync('ml-dsa-65');
try {
  writeFileSync(join(temporary, 'issuer.key'), issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  execFileSync(openssl, ['req', '-new', '-x509', '-key', 'issuer.key', '-subj', '/CN=Synthetic mdoc holder fixture', '-days', '2', '-sha256', '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature', '-outform', 'DER', '-out', 'issuer.der'], { cwd: temporary, stdio: ['ignore', 'pipe', 'pipe'] });
  const certificate = readFileSync(join(temporary, 'issuer.der'));
  const at = Math.floor(Date.now() / 1000), documentSPKI = documentKey.publicKey.export({ format: 'der', type: 'spki' });
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
  const deviceSigned = prepared.finish(sign('sha256', prepared.tbs, { key: holder.privateKey, dsaEncoding: 'ieee-p1363' }));
  const base = { credential: hex(credential), certificate: hex(certificate), at, sessionTranscript: hex(sessionTranscript), deviceSigned: hex(deviceSigned) };
  const cases = [];
  const add = (id, patch, overall, reason) => cases.push({ id, ...patch, expected: { overall, ...(reason ? { reason } : {}) } });
  const change = mutate => { const value = decode(deviceSigned); mutate(value); return hex(encode(value)); };
  add('holder-device-signature', {}, 'VALID');
  add('changed-session-transcript', { sessionTranscript: hex(encode([null, null, Buffer.alloc(32, 8)])) }, 'INVALID', 'MDOC_HOLDER_SIGNATURE');
  add('wrong-holder-key', { credential: hex(otherCredential) }, 'INVALID', 'MDOC_HOLDER_SIGNATURE');
  add('changed-holder-signature', { deviceSigned: change(value => { value.get('deviceAuth').get('deviceSignature')[3][0] ^= 1; }) }, 'INVALID', 'MDOC_HOLDER_SIGNATURE');
  add('device-mac-is-not-signature', { deviceSigned: change(value => { const auth = value.get('deviceAuth'); auth.set('deviceMac', auth.get('deviceSignature')); auth.delete('deviceSignature'); }) }, 'UNSUPPORTED', 'MDOC_HOLDER_MAC_UNSUPPORTED');
  add('device-mac-and-signature', { deviceSigned: change(value => { const auth = value.get('deviceAuth'); auth.set('deviceMac', auth.get('deviceSignature')); }) }, 'INVALID', 'MDOC_HOLDER_AUTH');
  add('embedded-holder-payload', { deviceSigned: change(value => { value.get('deviceAuth').get('deviceSignature')[2] = Buffer.alloc(0); }) }, 'INVALID', 'MDOC_HOLDER_COSE');
  add('nonempty-device-namespaces', { deviceSigned: change(value => { value.set('nameSpaces', embedded(new Map([['org.example', new Map([['x', true]])]]))); }) }, 'UNSUPPORTED', 'MDOC_DEVICE_NAMESPACES_UNSUPPORTED');
  add('changed-issuer-auth', { credential: (() => { const value = decode(credential); value.get('issuerAuth')[3][0] ^= 1; return hex(encode(value)); })() }, 'INVALID', 'COSE_SIGNATURE');
  add('wrong-document-type', { docType: 'org.example.other' }, 'INVALID', 'MDOC_DOCTYPE');
  const wrongHeaders = decode(deviceSigned), cose = wrongHeaders.get('deviceAuth').get('deviceSignature');
  cose[0] = encode(new Map([[1, -7], [3, 'application/example']]));
  const payload = encode(embedded(['DeviceAuthentication', decode(sessionTranscript), SIGNING_DOCTYPE, wrongHeaders.get('nameSpaces')]));
  cose[3] = sign('sha256', encode(['Signature1', cose[0], Buffer.alloc(0), payload]), { key: holder.privateKey, dsaEncoding: 'ieee-p1363' });
  add('validly-signed-extra-protected-header', { deviceSigned: hex(encode(wrongHeaders)) }, 'INVALID', 'MDOC_HOLDER_HEADERS');
  const document = Buffer.from('Not a holder presentation.\n');
  const preparedDocument = prepareDocumentSignature(document, { credential, publicKey: documentKey.publicKey });
  const documentSignature = preparedDocument.finish(sign(null, preparedDocument.tbs, documentKey.privateKey));
  add('document-signature-is-not-holder-proof', { deviceSigned: hex(documentSignature) }, 'INVALID', 'MDOC_DEVICE_SIGNED');
  writeFileSync(new URL('../vectors/holder-auth.json', import.meta.url), JSON.stringify({ schemaVersion: 1, profile: 'mdoc-signing-holder-auth-draft-02', base, cases }, null, 2) + '\n');
} finally {
  const resolved = realpathSync(temporary), parent = realpathSync(tmpdir()) + sep;
  if (!resolved.startsWith(parent) || !resolved.split(sep).at(-1).startsWith('mdoc-holder-vectors-')) throw new Error('Unexpected temporary path');
  rmSync(resolved, { recursive: true, force: true });
}
