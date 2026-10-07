import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const json=p=>JSON.parse(readFileSync(join(root,p),'utf8'));
assert.equal(json('draft.json').stable,false);
assert.equal(json('package.json').private,true);
assert.equal(new Set(json('cases.json').cases.map(x=>x.id)).size,json('cases.json').cases.length);
for(const s of json('sources.json').sources){assert(s.url.startsWith('https://'));assert(/^[a-f0-9]{64}$/.test(s.sha256));}
for(const [path,hash] of Object.entries(json('vectors/manifest.json').sha256)) {
  assert.equal(createHash('sha256').update(readFileSync(join(root,path))).digest('hex'),hash,path);
}
const ids=new Set(json('cases.json').cases.map(value=>value.id));
for(const vector of json('vectors/base.json').cases) assert(ids.has(vector.id),vector.id);
for(const entry of readdirSync(join(root,'reference')).filter(name=>name.endsWith('.mjs'))) {
  const source=readFileSync(join(root,'reference',entry),'utf8');
  for(const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) {
    assert(match[1].startsWith('node:') || (match[1].startsWith('./') && !match[1].includes('..')),entry);
  }
}
function walk(dir=''){for(const e of readdirSync(join(root,dir),{withFileTypes:true})){if(['.git','.runtime','node_modules'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())walk(p);else{const t=readFileSync(join(root,p),'utf8');assert(!/\p{Script=Han}/u.test(t),p);assert(!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(t),p);assert(!/github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}/.test(t),p);}}}
walk();console.log('Draft sources, cases and publication content verified');
