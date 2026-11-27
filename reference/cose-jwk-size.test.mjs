import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { coseJWK, coseKey, decode, get, unembed } from './cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/pqc-base.json', import.meta.url)));
const ecVector = JSON.parse(readFileSync(new URL('../vectors/cose-ec2-coordinate-types.json', import.meta.url)));
const credential = decode(Buffer.from(vectors.base.credential, 'hex'));
const mso = unembed(decode(get(credential, 'issuerAuth')[2]));
const selectedAKP = get(get(mso, 'deviceKeyInfo'), 'deviceKey');
const akp = coseJWK(selectedAKP);
const ec = { kty: 'EC', crv: 'P-256',
  x: Buffer.from(ecVector.point.x, 'hex').toString('base64url'),
  y: Buffer.from(ecVector.point.y, 'hex').toString('base64url') };
const oversized = 'A'.repeat(64 * 1024);

function classifyWithoutOversizedDecode(jwk) {
  const original = Buffer.from;
  let attempted = 0, error;
  Buffer.from = function (value, ...args) {
    if (value === oversized) {
      attempted++;
      throw new Error('DECODE_BEFORE_FIXED_KEY_SIZE_CHECK');
    }
    return original.call(this, value, ...args);
  };
  try { coseKey(jwk); }
  catch (failure) { error = failure; }
  finally { Buffer.from = original; }
  return { attempted, error };
}

for (const algorithm of ['ML-DSA-65', 'ML-DSA-87'])
  test('oversized ' + algorithm + ' JWK pub is rejected before base64url allocation', () => {
    const result = classifyWithoutOversizedDecode({ kty: 'AKP', alg: algorithm, pub: oversized });
    assert.equal(result.attempted, 0);
    assert.equal(result.error?.code, 'COSE_KEY');
    assert.deepEqual(coseKey(akp), selectedAKP);
  });

for (const coordinate of ['x', 'y'])
  test('oversized EC2 JWK ' + coordinate + ' is rejected before base64url allocation', () => {
    const result = classifyWithoutOversizedDecode({ ...ec, [coordinate]: oversized });
    assert.equal(result.attempted, 0);
    assert.equal(result.error?.code, 'COSE_POINT');
    assert.equal(coseKey(ec).get(1), 2);
  });

test('fixed-width malformed base64url retains its encoding classification', () => {
  assert.throws(() => coseKey({ ...akp, pub: '!' + akp.pub.slice(1) }),
    { code: 'COSE_BASE64URL' });
  assert.throws(() => coseKey({ ...ec, x: '!' + ec.x.slice(1) }),
    { code: 'COSE_BASE64URL' });
});
