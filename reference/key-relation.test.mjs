import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {documentKeyRelation as validate} from './key-relation.mjs';
const key = type => generateKeyPairSync(type,type==='ec'?{namedCurve:'prime256v1'}:{}).publicKey.export({format:'der',type:'spki'});
test('personal certificate key modes enforce their distinct authority',()=>{
  const holder=key('ec'),other=key('ec'),pq=key('ml-dsa-65');
  assert.equal(validate('DEVICE_KEY',holder,holder),'DEVICE_KEY');
  assert.equal(validate('INDEPENDENT_PQ',pq,holder),'INDEPENDENT_PQ');
  assert.equal(validate('PASSKEY_KEY',other,holder),'PASSKEY_KEY');
  assert.throws(()=>validate('DEVICE_KEY',other,holder),{code:'DOCUMENT_DEVICE_KEY_BINDING'});
  assert.throws(()=>validate('PASSKEY_KEY',holder,holder),{code:'DOCUMENT_PASSKEY_KEY_BINDING'});
  assert.throws(()=>validate('INDEPENDENT_PQ',other,holder),{code:'DOCUMENT_INDEPENDENT_PQ_KEY'});
  assert.throws(()=>validate('UNDECLARED',holder,holder),{code:'DOCUMENT_KEY_MODE'});
});
