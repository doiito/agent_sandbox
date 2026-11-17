'use strict';
const {test, beforeEach, afterEach} = require('node:test');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const fixture = JSON.parse(fs.readFileSync(require('node:path').join(__dirname, 'fixtures/inference-sdk.json')));
const original = http.request, sdkPath = require.resolve('../guest-sdk/node/remote-infer.cjs');
const clone = value => JSON.parse(JSON.stringify(value));
let sdk, calls;

function mock(responder) {
  http.request = (options, callback) => {
    const request = new EventEmitter();
    request.destroy = () => {};
    options.signal.addEventListener('abort', () => request.emit('error', new Error('aborted')), {once:true});
    request.end = data => {
      calls.push({options, data});
      queueMicrotask(() => {
        const selected = responder(options, data);
        if (selected === null) return;
        const response = new EventEmitter();
        const bytes = selected.bytes ?? Buffer.from(JSON.stringify(selected.value));
        response.statusCode = selected.status ?? 200;
        response.headers = selected.headers ?? {'content-type':'application/json','content-length':String(bytes.length)};
        response.rawHeaders = selected.rawHeaders ?? Object.entries(response.headers).flat();
        response.destroy = () => {};
        callback(response);
        for(let offset=0;offset<bytes.length;offset+=3) response.emit('data',bytes.subarray(offset,offset+3));
        response.emit('end');
      });
    };
    return request;
  };
}
function standard(options) {
  if (options.path.endsWith('/bill')) return {value:clone(fixture.bill)};
  if (options.path.endsWith('/policy')) return {value:clone(fixture.capabilities.remote_inference_policy)};
  return {value:clone(fixture.result)};
}
beforeEach(()=>{calls=[];delete require.cache[sdkPath];sdk=require(sdkPath);});
afterEach(()=>{http.request=original;});

test('guest import performs no network request',()=>{
  http.request=()=>{throw new Error('network on import');};
  delete require.cache[sdkPath];
  assert.equal(typeof require(sdkPath).ml.invoke,'function');
});
test('fixed route, partial response and exact money ignore proxy environment',async()=>{
  mock(standard);
  const result=await sdk.invoke('model',{query:'hi'},{invocationId:fixture.result.invocation.id});
  assert.equal(result.invocation.settled_units,'9007199254741066');
  assert.equal(result.invocationId,fixture.result.invocation.id);
  assert.equal(calls.length,3);
  for(const {options} of calls) {
    assert.equal(options.hostname,'127.0.0.1');assert.equal(options.port,3128);
    assert.equal(options.agent,false);assert.equal(options.headers.Host,'inference.osv.invalid');
    assert.match(options.path,/^http:\/\/inference\.osv\.invalid\/v1\//);
  }
});
test('bad explicit ID and unsafe plain JSON perform no I/O',async()=>{
  mock(()=>{throw new Error('unexpected request');});
  await assert.rejects(sdk.invoke('model',{}, {invocationId:'bad'}),sdk.ConfigurationError);
  const cycle={};cycle.value=cycle;
  for(const value of [NaN,2**53,1n,cycle,{get value(){throw new Error('getter invoked');}}]) {
    await assert.rejects(sdk.invoke('model',value,{invocationId:fixture.result.invocation.id}),error=>
      error instanceof sdk.InferenceError && !error.deliveryUnknown && error.invocationId===fixture.result.invocation.id);
  }
  assert.equal(calls.length,0);
});
test('task identity is pinned independently of caller state',async()=>{
  mock(standard);await sdk.bill();
  const changed=clone(fixture.bill);changed.task_id='f'.repeat(24);
  mock(()=>({value:changed}));await assert.rejects(sdk.bill(),sdk.ProtocolError);
});
test('receipt corruption retains known ID and never repeats POST',async()=>{
  mock(options=>{
    const response=standard(options);
    if(options.method==='POST')response.value.invocation.settled_units='1';
    return response;
  });
  await assert.rejects(sdk.invoke('model',{}, {invocationId:fixture.result.invocation.id}),error=>
    error instanceof sdk.InferenceError && error.deliveryUnknown && error.invocationId===fixture.result.invocation.id);
  assert.equal(calls.filter(row=>row.options.method==='POST').length,1);
});
test('absolute deadline cancels stalled metadata before POST',async()=>{
  mock(()=>null);
  const keepAlive=setTimeout(()=>{},1000);
  try {
    await assert.rejects(sdk.invoke('model',{}, {invocationId:fixture.result.invocation.id,requestTimeoutMs:30}),error=>
      error instanceof sdk.InferenceError && !error.deliveryUnknown);
  } finally {clearTimeout(keepAlive);}
  assert.equal(calls.length,1);
});
for(const [name,response] of Object.entries({
  'duplicate length':{value:{},headers:{'content-type':'application/json','content-length':'2'},rawHeaders:['Content-Type','application/json','Content-Length','2','Content-Length','2']},
  'transfer encoding':{value:{},headers:{'content-type':'application/json','content-length':'2','transfer-encoding':'chunked'}},
  'oversized body declaration':{value:{},headers:{'content-type':'application/json','content-length':'99999999'}},
  'invalid UTF-8':{bytes:Buffer.from([34,255,34])},
  'non-JSON':{bytes:Buffer.from('not-json')},
  'truncated body':{value:{},headers:{'content-type':'application/json','content-length':'5'}},
  'redirect without error contract':{status:302,value:{}},
})) {
  test('reject '+name+' without retry',async()=>{
    mock(()=>response);
    await assert.rejects(sdk.bill(),sdk.ProtocolError);
    assert.equal(calls.length,1);
  });
}
