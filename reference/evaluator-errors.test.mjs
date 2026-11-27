import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluateSignedDocument } from './base.mjs';
import { MdocValidationError } from './errors.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/evaluator-errors.json', import.meta.url)));
const pq = JSON.parse(readFileSync(new URL('../vectors/pqc-base.json', import.meta.url)));
const source = pq.cases.find(entry => entry.id === vectors.baseSource.id);
assert(source && source.expected.overall === 'VALID');
const signed = { ...pq.base, ...source };
const bytes = hex => Buffer.from(hex, 'hex');

function options(fault) {
  if (fault === 'own-validation-time') return { certificate: bytes(signed.certificate) };
  const error = fault === 'foreign-valid' ? Object.assign(new Error('foreign failure'),
    { overall: 'VALID', code: 'FORGED_SUCCESS' }) :
    fault === 'validation-valid' ? new MdocValidationError('FORGED_SUCCESS', 'VALID') :
    fault === 'foreign-indeterminate' ? Object.assign(new Error('foreign failure'),
      { overall: 'INDETERMINATE', code: 'FORGED_INDETERMINATE' }) :
    fault === 'throwing-overall' ? { code: 'FORGED', get overall() { throw new Error('getter failure'); } } :
    fault === 'null-throw' ? null : undefined;
  assert.notEqual(error, undefined);
  return { get certificate() { throw error; } };
}

for (const entry of vectors.cases) test('evaluator error boundary: ' + entry.id, () => {
  const actual = evaluateSignedDocument(bytes(signed.document), bytes(signed.signature),
    bytes(signed.credential), options(entry.fault));
  assert.deepEqual(actual, entry.expected);
});
