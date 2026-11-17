/** Installed Node artifact SDK against an existing authenticated actual KVM session. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const config=JSON.parse(readFileSync(process.argv[2],'utf8'));
const {Client,APIError}=await import(pathToFileURL(config.release+'/sdk/node/index.js'));
const client=new Client(config.url,{token:readFileSync(config.root+'/secrets/token','utf8'),
  caFile:config.root+'/tls/ca.crt',certFile:config.root+'/tls/client.crt',keyFile:config.root+'/tls/client.key'});
const session=await client.connectSession(config.session_id),cases=[];
const check=(name,value)=>{assert.ok(value,name);cases.push(name);};
const info=await session.createArtifact('/workspace/export');
try{
  const data=await session.downloadArtifact(info);
  check('multi-chunk-full-digest',data.length===info.size&&data.length>(512<<10)&&createHash('sha256').update(data).digest('hex')===info.sha256);
  check('known-session-binding',info.session_id===session.id);
  const chunk=await session.readArtifact(info.id,0,512<<10);
  check('maximum-chunk-binary-digest',Buffer.from(chunk.data_base64,'base64').equals(data.subarray(0,512<<10)));
  const eof=await session.readArtifact(info.id,info.size,1);
  check('empty-eof',eof.eof&&eof.data_base64==='');
  await assert.rejects(session.readArtifact(info.id,info.size+1,1),e=>e instanceof APIError&&e.status===416&&e.code==='artifact_range');
  cases.push('typed-range-error');
}finally{await session.deleteArtifact(info.id);}
await assert.rejects(session.readArtifact(info.id),e=>e instanceof APIError&&e.status===404&&e.code==='artifact_not_found');
cases.push('delete-releases-cache');
console.log(JSON.stringify({passed:true,session_id:session.id,cases}));
