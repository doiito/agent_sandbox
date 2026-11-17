import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Session, ProtocolError, ConfigurationError, TransportError} from './index.js';

const SID = 'a'.repeat(24), AID = 'c'.repeat(24);
const sha = data => createHash('sha256').update(data).digest('hex');
const data = Buffer.alloc(768 * 1024, 0);
for (let i=0; i<data.length; i++) data[i]=i%256;
const metadata = {id:AID,session_id:SID,path:'/workspace',source_kind:'directory',format:'tar',size:data.length,sha256:sha(data),entries:1,files:1,payload_bytes:data.length-2048};
function chunk(info=metadata,offset=0,length=512<<10) {
  const block=data.subarray(offset,offset+length);
  return {id:AID,session_id:SID,offset,total_size:data.length,data_base64:block.toString('base64'),data_sha256:sha(block),archive_sha256:info.sha256,eof:offset+block.length===data.length};
}
function setup(replies) {
  const calls=[];
  const client={_exchange:async(method,path,body,accepted,timeout,signal)=>{
    calls.push({method,path,body,accepted,timeout,signal});
    if(signal?.aborted) throw new TransportError('cancelled');
    const next=replies.shift();if(next instanceof Error) throw next;return structuredClone(next);
  }};
  return {session:new Session(client,{id:SID}),calls};
}

test('artifact create and multiblock download verify bytes and explicit delete', async()=>{
  const {session,calls}=setup([metadata,chunk(),chunk(metadata,512<<10),undefined]);
  const info=await session.createArtifact();
  assert.ok(Object.isFrozen(info));
  assert.deepEqual(await session.downloadArtifact(info),data);
  await session.deleteArtifact(info.id);
  assert.deepEqual(calls.map(row=>row.method),['POST','POST','POST','DELETE']);
  assert.equal(calls[1].path,`/v2/sessions/${SID}/artifacts/${AID}/read`);
  assert.equal(calls[0].timeout,35000);
});

test('artifact download rejects archive rebinding and complete digest mismatch', async()=>{
  let fixture=setup([{...chunk(),archive_sha256:'d'.repeat(64)}]);
  await assert.rejects(fixture.session.downloadArtifact(metadata),ProtocolError);
  const wrong={...metadata,sha256:'e'.repeat(64)};
  fixture=setup([chunk(wrong),chunk(wrong,512<<10)]);
  await assert.rejects(fixture.session.downloadArtifact(wrong),/complete artifact integrity/);
});

test('artifact read rejects malformed identity range eof and block integrity', async()=>{
  for(const patch of [{id:'d'.repeat(24)},{session_id:'e'.repeat(24)},{offset:1},{offset:true},{total_size:data.length+1},
    {total_size:33<<20},{eof:true},{data_sha256:'0'.repeat(64)},{data_base64:'AA/='},{data_base64:''}]) {
    const {session}=setup([{...chunk(metadata,0,512),...patch}]);
    await assert.rejects(session.readArtifact(AID,0,512),ProtocolError);
  }
});

test('artifact empty EOF and maximum read block are supported', async()=>{
  const {session}=setup([chunk(),chunk(metadata,data.length,1)]);
  assert.equal(Buffer.from((await session.readArtifact(AID)).data_base64,'base64').length,512<<10);
  assert.equal((await session.readArtifact(AID,data.length,1)).eof,true);
});

test('artifact metadata source kind path counts and size are bounded', async()=>{
  for(const patch of [{path:'/etc/passwd'},{session_id:'d'.repeat(24)},{size:33<<20},{files:2},{format:'zip'},{source_kind:'symlink'},{entries:true},{sha256:'BAD'}]) {
    const {session}=setup([{...metadata,...patch}]);
    await assert.rejects(session.createArtifact(),ProtocolError);
  }
  const {session}=setup([{...metadata,path:'/workspace/other'}]);
  await assert.rejects(session.createArtifact(),ProtocolError);
});

test('artifact argument validation is local and cancelled create is never replayed', async()=>{
  const {session,calls}=setup([new TransportError('lost response')]);
  for(const path of ['/etc/passwd','/workspace/../etc','/workspace/\ud800']) await assert.rejects(session.createArtifact(path),ConfigurationError);
  for(const [offset,length] of [[-1,1],[true,1],[0,0],[0,524289],[33554433,1]]) await assert.rejects(session.readArtifact(AID,offset,length),ConfigurationError);
  assert.equal(calls.length,0);
  await assert.rejects(session.createArtifact(),TransportError);
  assert.equal(calls.length,1);
});
