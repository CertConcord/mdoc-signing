import { createHash, generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueIssuerSigned, prepareDocumentSignature, SIGNING_NAMESPACE } from '../reference/base.mjs';

// One-time public fixture generation. Private keys remain in memory or a
// transient local certificate directory and are never published.
const temporary = mkdtempSync(join(tmpdir(), 'mdoc-evaluator-relation-'));
try {
  const ec = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuer = ec(), holder = ec(), other = ec();
  writeFileSync(join(temporary, 'issuer.key'), issuer.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  execFileSync(process.env.OPENSSL_BIN ?? 'openssl', [
    'req', '-new', '-x509', '-key', 'issuer.key', '-subj', '/CN=Synthetic evaluator relation issuer',
    '-days', '3', '-sha256', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature',
    '-addext', 'extendedKeyUsage=critical,1.0.18013.5.1.2',
    '-out', 'issuer.pem',
  ], { cwd: temporary, stdio: ['ignore', 'pipe', 'pipe'] });
  const certificate = new X509Certificate(readFileSync(join(temporary, 'issuer.pem'))).raw;
  const at = Math.floor(Date.now() / 1000);
  const document = Buffer.from('Public evaluator key relation diagnostic.\n');
  const statusURI = 'https://evaluator-relation.example/status/1';
  const spki = key => key.export({ format: 'der', type: 'spki' });
  const hex = value => value.toString('hex');
  const selected = [
    ['relation-device', 'DEVICE_KEY', 'MDOC-SIGNING-PERSON-DEVICE-v2', other],
    ['relation-passkey', 'PASSKEY_KEY', 'MDOC-SIGNING-PERSON-ASSOCIATED-v2', holder],
    ['relation-independent', 'INDEPENDENT_PQ', 'MDOC-SIGNING-PERSON-PQ-v2', other],
  ];
  const fixtures = {};
  for (const [id, mode, profileID, documentKey] of selected) {
    const keyBytes = spki(documentKey.publicKey);
    const claims = {
      subject_id: Buffer.alloc(32, 41), credential_id: Buffer.alloc(32, 42),
      issuer: 'https://evaluator-relation.example/',
      signing_key: keyBytes, signing_key_id: createHash('sha512').update(keyBytes).digest(),
      document_key_mode: mode, allowed_purposes: ['DOCUMENT_SIGN'], profile_id: profileID,
      status: { status_list: { uri: statusURI, idx: 1 } },
    };
    const credential = issueIssuerSigned({
      namespaces: { [SIGNING_NAMESPACE]: claims },
      holderJWK: holder.publicKey.export({ format: 'jwk' }), certificate,
      privateKey: issuer.privateKey, signed: at, validFrom: at, validUntil: at + 3600,
    });
    const prepared = prepareDocumentSignature(document, { credential, publicKey: documentKey.publicKey });
    const signature = prepared.finish(sign('sha256', prepared.tbs,
      { key: documentKey.privateKey, dsaEncoding: 'ieee-p1363' }));
    fixtures[id] = { credential: hex(credential), certificate: hex(certificate),
      signature: hex(signature), document: hex(document),
      profileID, documentKeyMode: mode, stateTime: at, knowledgeTime: at };
  }
  const path = new URL('../vectors/evaluator-errors.json', import.meta.url);
  const vectors = JSON.parse(readFileSync(path));
  if (vectors.relationFixtures) throw new Error('relation fixtures already generated');
  vectors.relationFixtures = fixtures;
  writeFileSync(path, JSON.stringify(vectors, null, 2) + '\n');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
