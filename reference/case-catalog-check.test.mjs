import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {cpSync,copyFileSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');

for(const conflicting of [false,true]) {
  test(`publication check rejects ${conflicting?'conflicting':'identical'} duplicate vector IDs`,()=>{
    const fixture=mkdtempSync(join(tmpdir(),'mdoc-case-catalog-'));
    try {
      for(const name of ['draft.json','package.json','cases.json','sources.json'])
        copyFileSync(join(root,name),join(fixture,name));
      cpSync(join(root,'vectors'),join(fixture,'vectors'),{recursive:true});
      cpSync(join(root,'reference'),join(fixture,'reference'),{recursive:true});
      mkdirSync(join(fixture,'tools'));
      copyFileSync(join(root,'tools','check.mjs'),join(fixture,'tools','check.mjs'));

      const path='vectors/classification.json';
      const vectors=JSON.parse(readFileSync(join(fixture,path),'utf8'));
      const duplicate=structuredClone(vectors.cases[0]);
      if(conflicting) duplicate.expected.reason='conflicting-duplicate';
      vectors.cases.push(duplicate);
      const bytes=JSON.stringify(vectors);
      writeFileSync(join(fixture,path),bytes);
      const manifestPath=join(fixture,'vectors','manifest.json');
      const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
      manifest.sha256[path]=createHash('sha256').update(bytes).digest('hex');
      writeFileSync(manifestPath,JSON.stringify(manifest));

      const result=spawnSync(process.execPath,[join(fixture,'tools','check.mjs')],{cwd:fixture,encoding:'utf8'});
      assert.notEqual(result.status,0,'a pinned duplicate vector ID must fail publication');
      assert.match(result.stderr,/duplicate vector ID: vectors\/classification\.json:/);
    } finally {
      rmSync(fixture,{recursive:true,force:true});
    }
  });
}
