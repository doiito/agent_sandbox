'use strict';
// Actual fixed guest module through a host bridge; no VM is represented here.
const fs = require('node:fs');
const sdk = require('../guest-sdk/node/remote-infer.cjs');
const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const identity = n => n.toString(16).padStart(24, '0');
const check = (name, value) => { if (!value) throw new Error(name); console.log('PASS node '+name); };
const wait = async action => {
  const end = Date.now()+5000;
  for (;;) { const result=await action(); if(result)return result; if(Date.now()>end)throw new Error('bill observation timed out'); await new Promise(resolve=>setTimeout(resolve,20)); }
};
const entry = async n => (await sdk.bill()).invocations.find(row=>row.id===identity(n)) ?? {};
(async()=>{
  const policy=await sdk.policy();
  check('fixed-route-redacted-policy',policy.endpoints[0].name==='model' && !JSON.stringify(policy).includes('url') && !JSON.stringify(policy).includes('credential'));
  const initial=await sdk.bill();
  check('root-logical-task',initial.task_id===config.task_id && initial.invocations.length===0 && initial.vm_id!==initial.task_id);
  const result=await sdk.ml.invoke('model',{query:'hi'},{invocationId:identity(1)});
  check('known-id-exact-integer-money',result.taskId===config.task_id && result.invocationId===identity(1) && result.data.answer==='ok' && typeof result.invocation.settled_units==='string' && BigInt(result.invocation.settled_units)>2n**53n);
  try { await sdk.invoke('model',{}, {invocationId:identity(1)}); throw new Error('duplicate succeeded'); }
  catch(error) {check('duplicate-id-no-replay',error instanceof sdk.InferenceError && error.code==='inference_replay' && error.invocationId===identity(1) && error.deliveryUnknown);}
  try {await sdk.invoke('other',{}, {invocationId:identity(10)}); throw new Error('unknown alias succeeded');}
  catch(error) {check('alias-denied-before-post',error instanceof sdk.InferenceError && !error.deliveryUnknown);}
  for(const value of [NaN,2**53,1n,{get bad(){throw new Error('getter called');}}]) {
    try {await sdk.invoke('model',value,{invocationId:identity(10)}); throw new Error('invalid payload succeeded');}
    catch(error) {if(!(error instanceof sdk.InferenceError) || error.deliveryUnknown || error.invocationId!==identity(10))throw error;}
  }
  check('unsafe-json-denied-before-post',true);
  const generated=await sdk.invoke('model',{});
  check('generated-id-retained',/^[0-9a-f]{24}$/.test(generated.invocationId) && generated.invocation.id===generated.invocationId);
  const large=await sdk.invoke('model',{mode:'unicode'},{invocationId:identity(3)});
  check('maximum-UTF8-response-through-root-relay',large.data.text==='\u2028'.repeat(config.unicode_count) && large.invocation.output_bytes<=512<<10);
  let failure;
  const pending=sdk.invoke('model',{mode:'pending'},{invocationId:identity(2),requestTimeoutMs:800}).catch(error=>{failure=error;});
  await wait(()=>fs.existsSync(config.pending_marker));
  check('pending-bill-is-observable',(await entry(2)).state==='reserved');
  await pending;
  const terminal=await wait(async()=>{const row=await entry(2);return row.state==='uncertain'&&row;});
  check('absolute-timeout-known-id-held-budget',failure instanceof sdk.InferenceError && failure.invocationId===identity(2) && failure.deliveryUnknown && terminal.settled_units==='0' && BigInt(terminal.reserved_units)>0n);
  const controller=new AbortController();
  const cancelled=sdk.invoke('model',{mode:'pending'},{invocationId:identity(4),signal:controller.signal}).catch(error=>error);
  await wait(async()=> (await entry(4)).state==='reserved');
  controller.abort();
  const error=await cancelled;
  await wait(async()=> (await entry(4)).state==='uncertain');
  check('AbortSignal-keeps-known-id-and-hold',error instanceof sdk.InferenceError && error.invocationId===identity(4) && error.deliveryUnknown);
  const final=await sdk.bill();
  check('all-five-attempts-durably-accounted',final.invocations.length===5 && final.invocations.filter(row=>row.state==='succeeded').length===3 && BigInt(final.held_units)>0n);
})().catch(error=>{console.error(error);process.exitCode=1;});
