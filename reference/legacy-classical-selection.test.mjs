import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { evaluateSignedDocument, inspectIssuerSigned } from './base.mjs';
import { prepareHolderAuthentication, verifyHolderAuthentication } from './holder-auth.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/legacy-classical-selection.json', import.meta.url)));
const historical = JSON.parse(readFileSync(new URL('../vectors/base.json', import.meta.url)));
const document = historical.cases.find(entry => entry.id === vectors.documentSource.id);
const bytes = hex => Buffer.from(hex, 'hex');

function run(entry) {
  if (entry.target === 'document') {
    const certificate = bytes(document.certificate);
    const result = evaluateSignedDocument(bytes(document.document), bytes(document.signature),
      bytes(document.credential), {
        certificate, issuerKey: new X509Certificate(certificate).publicKey,
        profileID: document.profileID, documentKeyMode: document.documentKeyMode,
        allowLegacyClassical: entry.selection, stateTime: document.stateTime,
        knowledgeTime: document.knowledgeTime, statusEvidence: document.statusEvidence,
        authorizeIssuer: () => ({ overall: 'VALID' }),
        resolveStatus: () => ({ status: 'GOOD', overall: 'VALID' }),
      });
    return { overall: result.overall, ...(result.reason ? { reason: result.reason } : {}) };
  }
  const holder = vectors.holder;
  const certificate = bytes(holder.certificate);
  const credential = bytes(holder.credential);
  const issuerKey = new X509Certificate(certificate).publicKey;
  try {
    if (entry.target === 'prepare') {
      const facts = inspectIssuerSigned(credential, { certificate, issuerKey });
      const prepared = prepareHolderAuthentication(bytes(holder.sessionTranscript), {
        holderPublicKey: facts.holderPublicKey, docType: holder.docType,
        profileID: holder.profileID, allowLegacyClassical: entry.selection,
      });
      assert(Buffer.isBuffer(prepared.tbs));
    } else if (entry.target === 'verify') {
      const proof = verifyHolderAuthentication(bytes(holder.deviceSigned), credential, {
        certificate, issuerKey, at: holder.at,
        sessionTranscript: bytes(holder.sessionTranscript), docType: holder.docType,
        profileID: holder.profileID, allowLegacyClassical: entry.selection,
      });
      assert.equal(proof.holderProof.signature.length, 64);
    } else throw new Error('unknown vector target: ' + entry.target);
    return { overall: 'VALID' };
  } catch (error) {
    return { overall: error.overall ?? 'INVALID', reason: error.code };
  }
}

for (const entry of vectors.cases) test('explicit historical selection: ' + entry.id, () => {
  assert.deepEqual(run(entry), entry.expected);
});
