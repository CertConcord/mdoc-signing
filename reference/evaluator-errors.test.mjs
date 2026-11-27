import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { evaluateSignedDocument } from './base.mjs';
import { MdocValidationError, requireThat } from './errors.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/evaluator-errors.json', import.meta.url)));
const pq = JSON.parse(readFileSync(new URL('../vectors/pqc-base.json', import.meta.url)));
const source = pq.cases.find(entry => entry.id === vectors.baseSource.id);
assert(source && source.expected.overall === 'VALID');
const signed = { ...pq.base, ...source };
const bytes = hex => Buffer.from(hex, 'hex');

function options(fault) {
  if (fault === 'own-validation-time') return { certificate: bytes(signed.certificate) };
  if (fault === 'issuer-key-helper') return {
    certificate: bytes(signed.certificate), stateTime: signed.stateTime,
    knowledgeTime: signed.knowledgeTime,
    issuerKey: { get asymmetricKeyType() {
      requireThat(false, 'CALLER_FORGED_INDETERMINATE', 'INDETERMINATE');
    } },
  };
  if (fault === 'status-evidence-helper') return {
    certificate: bytes(signed.certificate), stateTime: signed.stateTime,
    knowledgeTime: signed.knowledgeTime,
    statusEvidence: { get injected() {
      requireThat(false, 'CALLER_FORGED_UNSUPPORTED', 'UNSUPPORTED');
    } },
  };
  const error = fault === 'foreign-valid' ? Object.assign(new Error('foreign failure'),
    { overall: 'VALID', code: 'FORGED_SUCCESS' }) :
    fault === 'validation-valid' ? new MdocValidationError('FORGED_SUCCESS', 'VALID') :
    fault === 'validation-indeterminate' ? new MdocValidationError('FORGED_INDETERMINATE', 'INDETERMINATE') :
    fault === 'validation-mutated' ? Object.assign(new MdocValidationError('ORIGINAL', 'INVALID'),
      { overall: 'UNSUPPORTED', code: 'FORGED_UNSUPPORTED' }) :
    fault === 'validation-helper' ? (() => { try { requireThat(false, 'FORGED_INDETERMINATE', 'INDETERMINATE'); } catch (error) { return error; } })() :
    fault === 'foreign-indeterminate' ? Object.assign(new Error('foreign failure'),
      { overall: 'INDETERMINATE', code: 'FORGED_INDETERMINATE' }) :
    fault === 'throwing-overall' ? { code: 'FORGED', get overall() { throw new Error('getter failure'); } } :
    fault === 'null-throw' ? null : undefined;
  assert.notEqual(error, undefined);
  return { get certificate() { throw error; } };
}

for (const entry of vectors.cases) test('evaluator error boundary: ' + entry.id, () => {
  let actual;
  if (entry.fault.startsWith('relation-')) {
    const fixture = vectors.relationFixtures[entry.fault];
    assert(fixture);
    const certificate = bytes(fixture.certificate);
    actual = evaluateSignedDocument(bytes(fixture.document), bytes(fixture.signature),
      bytes(fixture.credential), {
        certificate, issuerKey: new X509Certificate(certificate).publicKey,
        profileID: fixture.profileID, documentKeyMode: fixture.documentKeyMode,
        allowLegacyClassical: true, stateTime: fixture.stateTime,
        knowledgeTime: fixture.knowledgeTime,
        authorizeIssuer: () => ({ overall: 'VALID' }),
        resolveStatus: () => ({ status: 'GOOD', overall: 'VALID' }),
      });
  } else {
    actual = evaluateSignedDocument(bytes(signed.document), bytes(signed.signature),
      bytes(signed.credential), options(entry.fault));
  }
  assert.deepEqual({ overall: actual.overall, ...(actual.reason ? { reason: actual.reason } : {}) }, entry.expected);
});
