import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const json=p=>JSON.parse(readFileSync(join(root,p),'utf8'));
assert.equal(json('draft.json').stable,false);
assert.equal(json('package.json').private,true);
const cases=json('cases.json').cases;
assert.equal(new Set(cases.map(x=>x.id)).size,cases.length);
for(const s of json('sources.json').sources){assert(s.url.startsWith('https://'));assert(/^[a-f0-9]{64}$/.test(s.sha256));}
const manifest=json('vectors/manifest.json').sha256;
const actualVectors=readdirSync(join(root,'vectors'),{withFileTypes:true})
  .filter(entry=>entry.name!=='manifest.json')
  .map(entry=>{
    assert(entry.isFile()&&entry.name.endsWith('.json'),'unexpected vector entry: '+entry.name);
    return 'vectors/'+entry.name;
  }).sort();
assert.deepEqual(Object.keys(manifest).sort(),actualVectors,'vector manifest inventory');
for(const [path,hash] of Object.entries(manifest)) {
  assert.equal(createHash('sha256').update(readFileSync(join(root,path))).digest('hex'),hash,path);
}
const prefixes={
  'vectors/classification.json':'issuer-result-',
  'vectors/document-classification.json':'document-result-',
  'vectors/issuer-facts.json':'issuer-facts-',
};
const covered=new Set();
for(const entry of cases) {
  assert(Object.hasOwn(manifest,entry.vector),entry.id);
  const prefix=prefixes[entry.vector]??'';
  assert(entry.id.startsWith(prefix),entry.id);
  const id=entry.id.slice(prefix.length),key=entry.vector+'\0'+id;
  const vector=json(entry.vector).cases.find(value=>value.id===id);
  assert(vector && !covered.has(key),entry.id);
  assert.equal(entry.overall,vector.expected.overall??(vector.expected.outcome==='RETURNED'?'VALID':undefined),entry.id);
  assert.equal(entry.reason,vector.expected.reason,entry.id);
  covered.add(key);
}
const seenVectorIds=new Set();
for(const path of Object.keys(manifest)) {
  const vectors=json(path).cases;
  if(vectors) for(const vector of vectors) {
    const key=path+'\0'+vector.id;
    assert(!seenVectorIds.has(key),'duplicate vector ID: '+path+': '+vector.id);
    seenVectorIds.add(key);
    assert(covered.has(key),path+': '+vector.id);
  }
}
for(const entry of readdirSync(join(root,'reference')).filter(name=>name.endsWith('.mjs'))) {
  const source=readFileSync(join(root,'reference',entry),'utf8');
  for(const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) {
    assert(match[1].startsWith('node:') || (match[1].startsWith('./') && !match[1].includes('..')),entry);
  }
}
function walk(dir=''){for(const e of readdirSync(join(root,dir),{withFileTypes:true})){if(['.git','.runtime','node_modules'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())walk(p);else{const t=readFileSync(join(root,p),'utf8');assert(!/\p{Script=Han}/u.test(t),p);assert(!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(t),p);assert(!/github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}/.test(t),p);}}}
walk();console.log('Draft sources, cases and publication content verified');
