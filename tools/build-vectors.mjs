import { createHash, generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, realpathSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { deflateSync } from 'node:zlib';
import { issueIssuerSigned, prepareDocumentSignature, BASE_PROFILE, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { encode, decode, get, embedded, unembed, Tag } from '../reference/cbor.mjs';

// Generates synthetic fixtures through Node crypto and OpenSSL. No private key
// is published, and tests consume only the committed serialized public vectors.
const temporary = mkdtempSync(join(tmpdir(), 'mdoc-signing-vectors-'));
const openssl = process.env.OPENSSL_BIN ?? 'openssl';
const run = args => execFileSync(openssl, args, { cwd: temporary, stdio: ['ignore', 'pipe', 'pipe'] });
const ec = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const sha512 = bytes => createHash('sha512').update(bytes).digest();
const publicBytes = key => key.export({ format: 'der', type: 'spki' });
try {
  const root = ec(), issuer = ec(), holder = ec(), documentKey = generateKeyPairSync('ml-dsa-65');
  for (const [name, pair] of [['root', root], ['issuer', issuer]]) writeFileSync(join(temporary, name + '.key'), pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  run(['req', '-new', '-x509', '-key', 'root.key', '-subj', '/CN=Synthetic mdoc IACA', '-days', '3', '-sha256', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', 'root.pem']);
  writeFileSync(join(temporary, 'issuer.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,1.0.18013.5.1.2\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n');
  for (const [name, serial] of [['issuer', '2'], ['alternative', '3']]) {
    run(['req', '-new', '-key', 'issuer.key', '-subj', '/CN=Synthetic mdoc ' + name, '-out', name + '.csr']);
    run(['x509', '-req', '-in', name + '.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-set_serial', serial, '-days', '2', '-sha256', '-extfile', 'issuer.ext', '-outform', 'DER', '-out', name + '.der']);
  }
  const certificate = readFileSync(join(temporary, 'issuer.der')), alternative = readFileSync(join(temporary, 'alternative.der'));
  const rootCertificate = new X509Certificate(readFileSync(join(temporary, 'root.pem'))).raw;
  const at = Math.floor(Date.now() / 1000), statusURI = 'https://issuer.example/status/1';
  const baseClaims = {
    subject_id: Buffer.alloc(32, 1), credential_id: Buffer.alloc(32, 2), issuer: 'https://issuer.example/',
    signing_key: publicBytes(documentKey.publicKey), signing_key_id: sha512(publicBytes(documentKey.publicKey)),
    document_key_mode: 'INDEPENDENT_PQ', allowed_purposes: ['DOCUMENT_SIGN'], profile_id: BASE_PROFILE,
    status: { status_list: { uri: statusURI, idx: 1 } },
  };
  const mint = (claims = baseClaims, holderJWK = holder.publicKey.export({ format: 'jwk' })) => issueIssuerSigned({ namespaces: { [SIGNING_NAMESPACE]: claims }, holderJWK, certificate, privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600 });
  const document = Buffer.from('Independent mdoc document-signing test.\n');
  function signedDocument(credential, key = documentKey) {
    const prepared = prepareDocumentSignature(document, { credential, publicKey: key.publicKey });
    const signature = sign(prepared.algorithm === -7 ? 'sha256' : null, prepared.tbs, prepared.algorithm === -7 ? { key: key.privateKey, dsaEncoding: 'ieee-p1363' } : key.privateKey);
    return prepared.finish(signature);
  }
  function statusToken(revoked = false, patch = {}) {
    const bytes = Buffer.alloc(16); if (revoked) bytes[0] = 2;
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'statuslist+jwt' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ iss: statusURI, sub: statusURI, iat: at, exp: at + 300, ttl: 300, status_list: { bits: 1, lst: deflateSync(bytes).toString('base64url') }, ...patch })).toString('base64url');
    return header + '.' + payload + '.' + sign('sha256', Buffer.from(header + '.' + payload), { key: issuer.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  }
  const credential = mint(), signature = signedDocument(credential), token = statusToken();
  const base = { credential: credential.toString('hex'), signature: signature.toString('hex'), document: document.toString('hex'), certificate: certificate.toString('hex'), statusEvidence: token, profileID: BASE_PROFILE, documentKeyMode: 'INDEPENDENT_PQ', stateTime: at, knowledgeTime: at };
  const cases = [];
  const add = (id, patch, overall, reason) => cases.push({ id, ...base, ...patch, expected: { overall, ...(reason ? { reason } : {}) } });
  const credPatch = bytes => ({ credential: bytes.toString('hex'), signature: signedDocument(bytes).toString('hex') });
  const resignAuth = (original, change) => {
    const value = decode(original), auth = get(value, 'issuerAuth'), mso = unembed(decode(auth[2]));
    change({ value, auth, mso });
    auth[2] = encode(embedded(mso));
    auth[3] = sign('sha256', encode(['Signature1', auth[0], Buffer.alloc(0), auth[2]]), { key: issuer.privateKey, dsaEncoding: 'ieee-p1363' });
    return encode(value);
  };
  add('independent-ml-dsa-65', {}, 'VALID');
  for (const [id, mode, pair, profileID] of [
    ['independent-ml-dsa-87', 'INDEPENDENT_PQ', generateKeyPairSync('ml-dsa-87'), BASE_PROFILE],
    ['explicit-device-document-key', 'DEVICE_KEY', holder, 'MDOC-SIGNING-PERSON-DEVICE-v2'],
    ['explicit-associated-document-key', 'PASSKEY_KEY', ec(), 'MDOC-SIGNING-PERSON-ASSOCIATED-v2'],
  ]) {
    const bytes = mint({ ...baseClaims, signing_key: publicBytes(pair.publicKey), signing_key_id: sha512(publicBytes(pair.publicKey)), document_key_mode: mode, profile_id: profileID });
    add(id, { credential: bytes.toString('hex'), signature: signedDocument(bytes, pair).toString('hex'), profileID, documentKeyMode: mode }, 'VALID');
  }
  const brokenAuth = decode(credential); get(brokenAuth, 'issuerAuth')[3][0] ^= 1;
  add('invalid-issuer-signature', { credential: encode(brokenAuth).toString('hex') }, 'INVALID', 'COSE_SIGNATURE');
  const changedItem = decode(credential), items = get(changedItem, 'nameSpaces').get(SIGNING_NAMESPACE), item = unembed(items[0]); item.set('elementValue', 'substituted'); items[0] = embedded(item);
  add('changed-issuer-item', { credential: encode(changedItem).toString('hex') }, 'INVALID', 'MDOC_DIGEST');
  const duplicate = decode(credential); get(duplicate, 'nameSpaces').get(SIGNING_NAMESPACE).push(get(duplicate, 'nameSpaces').get(SIGNING_NAMESPACE)[0]);
  add('duplicate-issuer-item', { credential: encode(duplicate).toString('hex') }, 'INVALID', 'MDOC_ITEM');
  const partial = decode(credential); get(partial, 'nameSpaces').get(SIGNING_NAMESPACE).pop();
  add('incomplete-credential', { credential: encode(partial).toString('hex') }, 'INVALID', 'MDOC_INCOMPLETE_ISSUANCE');
  add('changed-document', { document: Buffer.from('Substituted document\n').toString('hex') }, 'INVALID', 'MDOC_DOCUMENT_SIGNATURE');
  const changedSignature = decode(signature); changedSignature[3][0] ^= 1;
  add('invalid-document-signature', { signature: encode(changedSignature).toString('hex') }, 'INVALID', 'MDOC_DOCUMENT_SIGNATURE');
  const oldBinding = resignAuth(credential, ({ auth }) => { const headers = decode(auth[0]); headers.delete(34); auth[0] = encode(headers); });
  add('legacy-missing-certificate-binding', credPatch(oldBinding), 'INVALID', 'MDOC_CERTIFICATE_BINDING_REQUIRED');
  const swappedCertificate = decode(credential); get(swappedCertificate, 'issuerAuth')[1].set(33, alternative);
  add('same-key-certificate-substitution', { credential: encode(swappedCertificate).toString('hex'), certificate: alternative.toString('hex') }, 'INVALID', 'MDOC_CERTIFICATE_THUMBPRINT');
  const protectedChain = resignAuth(credential, ({ auth }) => { const headers = decode(auth[0]); headers.set(33, certificate); auth[0] = encode(headers); auth[1].delete(33); });
  add('protected-x5chain', credPatch(protectedChain), 'VALID');
  const unsupportedDigest = resignAuth(credential, ({ mso }) => mso.set('digestAlgorithm', 'SHA-384'));
  add('unsupported-mso-digest', credPatch(unsupportedDigest), 'UNSUPPORTED', 'MDOC_DIGEST_UNSUPPORTED');
  const invalidDate = resignAuth(credential, ({ mso }) => get(mso, 'validityInfo').set('validFrom', new Tag(0, '2026-02-30T00:00:00Z')));
  add('invalid-calendar-date', credPatch(invalidDate), 'INVALID', 'MDOC_TIME');
  const critical = resignAuth(credential, ({ auth }) => { const headers = decode(auth[0]); headers.set(2, ['urn:unknown:critical']); headers.set('urn:unknown:critical', true); auth[0] = encode(headers); });
  add('unknown-issuer-critical-header', credPatch(critical), 'UNSUPPORTED', 'COSE_CRITICAL_UNSUPPORTED');
  const msoStatus = resignAuth(credential, ({ mso }) => mso.set('status', { status_list: { uri: statusURI, idx: 1 } }));
  add('unselected-mso-status-location', credPatch(msoStatus), 'UNSUPPORTED', 'MDOC_MSO_STATUS_UNSUPPORTED');
  add('purpose-escalation', credPatch(mint({ ...baseClaims, allowed_purposes: ['ORGANIZATION_SEAL'] })), 'INVALID', 'MDOC_PURPOSE');
  add('profile-substitution', credPatch(mint({ ...baseClaims, profile_id: 'unselected' })), 'INVALID', 'MDOC_PROFILE');
  add('key-identifier-substitution', credPatch(mint({ ...baseClaims, signing_key_id: Buffer.alloc(64) })), 'INVALID', 'MDOC_DOCUMENT_KEY_ID');
  add('mode-downgrade', credPatch(mint({ ...baseClaims, document_key_mode: 'DEVICE_KEY' })), 'INVALID', 'MDOC_KEY_MODE');
  add('mso-expired-at-state-time', { stateTime: at + 3600, knowledgeTime: at + 3600 }, 'INVALID', 'MDOC_EXPIRED');
  add('status-stale', { statusEvidence: statusToken(false, { iat: at - 400, exp: at - 100 }) }, 'INDETERMINATE', 'MDOC_STATUS_STALE');
  add('status-revoked', { statusEvidence: statusToken(true) }, 'INVALID', 'MDOC_STATUS_REVOKED');
  add('status-missing', { statusEvidence: null }, 'INDETERMINATE', 'MDOC_STATUS_MISSING');
  add('status-conflicting', { statusEvidence: [token, statusToken(true)] }, 'INDETERMINATE', 'MDOC_STATUS_CONFLICTING');
  add('status-wrong-uri', { statusEvidence: statusToken(false, { sub: 'https://other.example/status/1' }) }, 'INVALID', 'MDOC_STATUS_INVALID');
  const parts = token.split('.'), brokenToken = Buffer.from(parts[2], 'base64url'); brokenToken[0] ^= 1; parts[2] = brokenToken.toString('base64url');
  add('status-bad-signature', { statusEvidence: parts.join('.') }, 'INVALID', 'MDOC_STATUS_INVALID');
  add('issuer-not-admitted', { policy: 'issuer-not-admitted' }, 'INVALID', 'MDOC_ISSUER_AUTHORIZATION');
  add('issuer-authorization-missing', { policy: 'issuer-authorization-missing' }, 'INDETERMINATE', 'MDOC_ISSUER_AUTHORIZATION_MISSING');
  add('status-resolver-missing', { policy: 'status-resolver-missing' }, 'INDETERMINATE', 'MDOC_STATUS_MISSING');
  add('status-method-unimplemented', { policy: 'status-method-unimplemented' }, 'UNSUPPORTED', 'MDOC_STATUS_UNSUPPORTED');
  add('trailing-cbor-bytes', { credential: credential.toString('hex') + '00' }, 'INVALID', 'CBOR_TRAILING');
  const substitutedCredential = mint();
  add('original-credential-bytes-required', { credential: substitutedCredential.toString('hex') }, 'INVALID', 'MDOC_DOCUMENT_PROTECTED_HEADERS');
  const unknownHeader = decode(signature), documentHeaders = decode(unknownHeader[0]); documentHeaders.set(2, ['urn:unknown:critical']); unknownHeader[0] = encode(documentHeaders);
  add('unknown-document-critical-header', { signature: encode(unknownHeader).toString('hex') }, 'INVALID', 'MDOC_DOCUMENT_PROTECTED_HEADERS');
  const presentationHeaders = encode(new Map([[1, -7]]));
  const presentationPayload = encode(embedded(['DeviceAuthentication', [null, null, Buffer.alloc(32)], SIGNING_NAMESPACE, embedded(new Map())]));
  const presentationSignature = sign('sha256', encode(['Signature1', presentationHeaders, Buffer.alloc(0), presentationPayload]), { key: holder.privateKey, dsaEncoding: 'ieee-p1363' });
  add('presentation-reinterpreted-as-signature', { signature: encode([presentationHeaders, new Map(), null, presentationSignature]).toString('hex') }, 'INVALID', 'MDOC_DOCUMENT_PROTECTED_HEADERS');
  const result = { schemaVersion: 1, profile: 'mdoc-signing-draft-02', trust: { rootCertificate: rootCertificate.toString('hex'), issuer: baseClaims.issuer, statusURI }, cases };
  const output = new URL('../vectors/', import.meta.url); mkdirSync(output, { recursive: true });
  writeFileSync(new URL('base.json', output), JSON.stringify(result, null, 2) + '\n');
} finally {
  const resolved = realpathSync(temporary), parent = realpathSync(tmpdir()) + sep;
  if (!resolved.startsWith(parent) || !resolved.split(sep).at(-1).startsWith('mdoc-signing-vectors-')) throw new Error('Unexpected temporary path');
  rmSync(resolved, { recursive: true, force: true });
}
