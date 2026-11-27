import { createHash, generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueIssuerSigned, SIGNING_DOCTYPE, SIGNING_NAMESPACE } from '../reference/base.mjs';
import { prepareHolderAuthentication } from '../reference/holder-auth.mjs';

// A one-time synthetic fixture builder. Only public credential and proof bytes
// are committed; generated issuer and holder private keys stay transient.
const temporary = mkdtempSync(join(tmpdir(), 'mdoc-legacy-selector-'));
try {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const holder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  writeFileSync(join(temporary, 'issuer.key'), issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  execFileSync(process.env.OPENSSL_BIN ?? 'openssl', [
    'req', '-new', '-x509', '-key', 'issuer.key', '-subj', '/CN=Synthetic historical mdoc issuer',
    '-days', '3', '-sha256', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature',
    '-addext', 'extendedKeyUsage=critical,1.0.18013.5.1.2',
    '-out', 'issuer.pem',
  ], { cwd: temporary, stdio: ['ignore', 'pipe', 'pipe'] });
  const certificate = new X509Certificate(readFileSync(join(temporary, 'issuer.pem'))).raw;
  const at = Math.floor(Date.now() / 1000);
  const profileID = 'MDOC-SIGNING-PERSON-DEVICE-v2';
  const holderSpki = holder.publicKey.export({ format: 'der', type: 'spki' });
  const claims = {
    subject_id: Buffer.alloc(32, 13), credential_id: Buffer.alloc(32, 14),
    issuer: 'https://legacy-selector.example/', signing_key: holderSpki,
    signing_key_id: createHash('sha512').update(holderSpki).digest(),
    document_key_mode: 'DEVICE_KEY', allowed_purposes: ['DOCUMENT_SIGN'], profile_id: profileID,
    status: { status_list: { uri: 'https://legacy-selector.example/status/1', idx: 1 } },
  };
  const credential = issueIssuerSigned({
    namespaces: { [SIGNING_NAMESPACE]: claims },
    holderJWK: holder.publicKey.export({ format: 'jwk' }), certificate,
    privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600,
  });
  const existing = JSON.parse(readFileSync(new URL('../vectors/holder-auth.json', import.meta.url)));
  const sessionTranscript = Buffer.from(existing.base.sessionTranscript, 'hex');
  const prepared = prepareHolderAuthentication(sessionTranscript, {
    holderPublicKey: holder.publicKey, profileID, allowLegacyClassical: true,
  });
  const deviceSigned = prepared.finish(sign('sha256', prepared.tbs,
    { key: holder.privateKey, dsaEncoding: 'ieee-p1363' }));
  const vector = {
    schemaVersion: 1,
    profile: 'historical-v2-explicit-classical-selection',
    documentSource: { vector: 'vectors/base.json', id: 'explicit-device-document-key' },
    holder: { credential: credential.toString('hex'), certificate: certificate.toString('hex'),
      deviceSigned: deviceSigned.toString('hex'), sessionTranscript: sessionTranscript.toString('hex'),
      at, profileID, docType: SIGNING_DOCTYPE },
    cases: [
      { id: 'legacy-document-default-denied', target: 'document', selection: false,
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-document-string-false-denied', target: 'document', selection: 'false',
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-document-string-true-denied', target: 'document', selection: 'true',
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-document-number-one-denied', target: 'document', selection: 1,
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-document-boolean-true-accepted', target: 'document', selection: true,
        expected: { overall: 'VALID' } },
      { id: 'legacy-holder-prepare-default-denied', target: 'prepare', selection: false,
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-prepare-string-false-denied', target: 'prepare', selection: 'false',
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-prepare-string-true-denied', target: 'prepare', selection: 'true',
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-prepare-number-one-denied', target: 'prepare', selection: 1,
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-prepare-boolean-true-accepted', target: 'prepare', selection: true,
        expected: { overall: 'VALID' } },
      { id: 'legacy-holder-verify-default-denied', target: 'verify', selection: false,
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-verify-string-false-denied', target: 'verify', selection: 'false',
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-verify-string-true-denied', target: 'verify', selection: 'true',
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-verify-number-one-denied', target: 'verify', selection: 1,
        expected: { overall: 'UNSUPPORTED', reason: 'MDOC_HOLDER_PROFILE_UNSUPPORTED' } },
      { id: 'legacy-holder-verify-boolean-true-accepted', target: 'verify', selection: true,
        expected: { overall: 'VALID' } },
    ],
  };
  writeFileSync(new URL('../vectors/legacy-classical-selection.json', import.meta.url),
    JSON.stringify(vector, null, 2) + '\n');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
