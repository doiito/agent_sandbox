#!/usr/bin/env node
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Client, Session, APIError, TransportError, TimeoutException} from '../sdk/node/index.js';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const client = new Client(config.url, {token:'token-a', certFile:config.cert, keyFile:config.key, caFile:config.ca, requestTimeoutMs:4000});
const session = new Session(client, {...config.session, artifactManifestSha256:config.session.artifact_manifest_sha256});
const id = number => number.toString(16).padStart(24,'0');
const data = Buffer.alloc(204800); for (let i=0;i<data.length;i++) data[i]=i%256;
for (const number of [1,2]) {
  const handle = await session.ports.open(8080, {connectionId:id(number), timeoutMs:4000});
  let eof = number===2;
  if (eof) assert.equal((await handle.readFrame()).kind, 'eof');
  let writerError;
  const writer = (async () => {
    for (let offset=0;offset<data.length;offset+=16384) await handle.write(data.subarray(offset,offset+16384));
    await handle.closeWrite();
  })().catch(error=>{writerError=error;});
  const chunks=[];
  for (;;) {
    const frame = await handle.readFrame();
    if (frame.kind==='data') chunks.push(frame.data);
    else if(frame.kind==='eof') eof=true;
    else {assert.equal(frame.info.status,'completed'); assert.equal(frame.info.sent_bytes,data.length); break;}
  }
  await writer; assert.equal(writerError,undefined); assert.equal(eof,true);
  assert.deepEqual(Buffer.concat(chunks),number===1?data:Buffer.alloc(0));
  assert.equal((await handle.info()).status,'completed');
  console.log(number===1?'PASS binary duplex':'PASS peer half-close first');
}
let handle = await session.ports.open(8080,{connectionId:id(3),timeoutMs:3000});
await handle.closeWrite(); await assert.rejects(handle.readFrame(),TransportError);
assert.ok(['cancelled','cancelling'].includes((await handle.info()).status));
console.log('PASS unconfirmed disconnect and known-ID query');
handle=await session.ports.open(8080,{connectionId:id(4),timeoutMs:3000});
let started=performance.now(); assert.ok(['cancelled','cancelling'].includes((await handle.cancel()).status));
assert.ok(performance.now()-started<1000); handle.close(); console.log('PASS independent cancel');
handle=await session.ports.open(8080,{connectionId:id(5),timeoutMs:80});
started=performance.now(); await assert.rejects(handle.readFrame(),TransportError);
assert.ok(performance.now()-started<1000); assert.equal((await handle.cancel()).id,id(5));
console.log('PASS absolute timeout and cleanup');
handle=session.ports.connection(8080,id(6)); assert.equal((await handle.cancel()).status,'cancelled');
await assert.rejects(session.ports.open(8080,{connectionId:id(6)}),error=>error instanceof APIError && error.status===409 && error.connection.id===id(6));
console.log('PASS cancel-before-open blocks late dial');
handle=await session.ports.open(8080,{connectionId:id(10),timeoutMs:3000});
await new Promise(resolve=>setTimeout(resolve,100)); started=performance.now();
assert.ok(['cancelled','cancelling'].includes((await handle.cancel()).status));
assert.ok(performance.now()-started<1000); handle.close();
console.log('PASS reverse backpressure leaves cancellation available');
await assert.rejects(session.ports.open(8080,{connectionId:id(11),timeoutMs:3000,requestTimeoutMs:80}),error=>error instanceof TimeoutException && error.connection.id===id(11));
assert.ok(['cancelled','cancelling'].includes((await session.ports.connection(8080,id(11)).cancel()).status));
console.log('PASS pending handshake timeout preserves ID');
