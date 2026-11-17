#!/usr/bin/env node
/** Installed SDK callbacks against actual cold/prepared Linux VMs. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync,mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const argument=name=>process.argv[process.argv.indexOf(name)+1];
const root=argument('--root'),packagePath=argument('--package'),mode=argument('--expected-mode');
assert.match(root,/^\/var\/lib\/osv-offline-validation-20261030-[a-z0-9]+$/);assert.ok(['cold','warm'].includes(mode));
if(!process.argv.includes('--in-netns')){
  const probe=spawnSync('systemctl',['show','-p','MainPID','--value',root.split('/').at(-1)+'-api.service'],{encoding:'utf8'});assert.equal(probe.status,0);assert.ok(Number(probe.stdout)>1);
  const child=spawnSync('nsenter',['-t',probe.stdout.trim(),'-n',process.execPath,process.argv[1],'--root',root,'--package',packagePath,'--expected-mode',mode,'--in-netns'],{stdio:'inherit'});process.exit(child.status??1);
}
const versions=readdirSync(join(root,'releases'));assert.equal(versions.length,1);
const sdkPath=join(root,'releases',versions[0],'sdk/node/index.js');
const {Client,Session,Sandbox,APIError,UnsupportedCapability}=await import(pathToFileURL(sdkPath).href);
const config=JSON.parse(readFileSync(join(root,'config.production.json'),'utf8')),url='https://localhost:'+config.listen.split(':').at(-1);
const options={caFile:join(root,'tls/ca.crt'),certFile:join(root,'tls/client.crt'),keyFile:join(root,'tls/client.key'),requestTimeoutMs:35000};
const a=new Client(url,{...options,token:readFileSync(join(root,'secrets/token'),'utf8')}),b=new Client(url,{...options,token:readFileSync(join(root,'secrets/token-b'),'utf8')});
const cases=[],boxes=[],watchers=[];const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const check=(name,value)=>{assert.ok(value,name);cases.push(name);};
async function wait(action){const until=Date.now()+5000;while(true){const value=await action();if(value)return value;assert.ok(Date.now()<until,'watch condition timed out');await pause(25);}}
async function create(){const until=Date.now()+20000;while(true){try{const box=await Sandbox.create('firecracker-linux',{client:a,timeoutMs:30000});boxes.push(box);return box;}catch(error){if(!(error instanceof APIError)||error.status!==429||Date.now()>until)throw error;await pause(50);}}}
const command=(box,code)=>box._session.run({entrypoint:'/bin/bash',args:['-c',code],timeoutMs:5000});
let sessionId;
try{
  const caps=await a.capabilities();check('signed-v4-watch-capability',caps.artifact_manifest_protocol==='osv-sandbox-artifacts/v4'&&caps.features.file_watch&&caps.features.recursive_file_watch&&caps.limits.file_watch_active===4);
  const box=await create();sessionId=box.sandboxId;check('actual-startup-mode',box._session.created.startupMode===mode);
  const events=[];let exits=0,exitError;
  const handle=await box.files.watchDir('/workspace',async event=>{events.push(event);},{includeEntry:true,timeoutMs:0,onExit:error=>{exits++;exitError=error;}});watchers.push(handle);
  check('transient-command-succeeds',(await command(box,'printf transient > /workspace/transient; chmod 600 /workspace/transient; mv /workspace/transient /workspace/moved; rm /workspace/moved; printf stable > /workspace/stable')).succeeded);
  await wait(()=>['create','write','chmod','rename','remove'].every(type=>events.some(event=>event.type===type)));
  check('real-five-types-and-short-lived-file',events.some(event=>event.name==='moved'&&event.type==='remove'));
  check('entry-metadata-mapped',events.some(event=>event.entry?.path==='/workspace/stable'&&event.entry.modifiedTime instanceof Date));
  let finished=false;
  const running=command(box,'sleep .2; printf live > /workspace/concurrent; sleep 1').finally(()=>{finished=true;});
  await wait(()=>events.some(event=>event.name==='concurrent'));
  check('callback-and-session-info-during-synchronous-run',!finished&&(await box._session.info()).id===sessionId);
  check('concurrent-command-completes',(await running).succeeded);
  const denied=new Session(b,box._session.created);
  await assert.rejects(denied.startFileWatch('/workspace'),error=>error instanceof APIError&&error.status===404);cases.push('foreign-start-hidden');
  await handle.stop();await wait(()=>exits===1);check('manual-stop-onExit-once-clean',exits===1&&exitError===undefined);
  const count=events.length;await command(box,'printf after > /workspace/after-stop');await pause(100);check('stopped-callback-has-no-more-events',events.length===count);
  await command(box,'mkdir -p /workspace/tree/sub');
  const recursive=[];const recursiveHandle=await box.files.watchDir('/workspace/tree',event=>{recursive.push(event);},{recursive:true,timeoutMs:0});watchers.push(recursiveHandle);
  await command(box,'printf recursive > /workspace/tree/sub/a');await wait(()=>recursive.some(event=>event.name==='sub/a'));cases.push('recursive-subdirectory-events');
  await recursiveHandle.stop();
  let failedExits=0,callbackFailure,release,entered;
  const gate=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});
  const failed=await box.files.watchDir('/workspace',async()=>{entered();await gate;throw Error('expected callback rejection');},{timeoutMs:0,onExit:async error=>{failedExits++;callbackFailure=error;throw Error('terminal failure is contained');}});watchers.push(failed);
  await command(box,'printf callback > /workspace/callback');await started;release();await wait(()=>failedExits===1);
  check('async-callback-rejection-onExit-once',callbackFailure?.message==='expected callback rejection'&&failedExits===1);
  await wait(async()=>!(await box._session.listFileWatches()).some(info=>info.id===failed._native.id&&info.state==='watching'));cases.push('callback-failure-releases-guest-watcher');
  let timeoutExits=0,timeoutFailure;
  const timed=await box.files.watchDir('/workspace',()=>{}, {timeoutMs:120,onExit:error=>{timeoutExits++;timeoutFailure=error;}});watchers.push(timed);
  await wait(()=>timeoutExits===1);check('watch-deadline-clean-exit',timeoutFailure===undefined&&await box.isRunning());
  for(const settings of [{user:'root'},{allowNetworkMounts:true}])await assert.rejects(box.files.watchDir('/workspace',()=>{},settings),UnsupportedCapability);cases.push('unsupported-options-explicit');
  const active=[];for(let i=0;i<4;i++)active.push(await box._session.startFileWatch('/workspace'));
  await assert.rejects(box._session.startFileWatch('/workspace'),error=>error instanceof APIError&&error.status===429);cases.push('per-session-active-watch-limit');
  for(const watcher of active)await watcher.stop();
  let overExits=0,overError,releaseOver;
  const overGate=new Promise(resolve=>{releaseOver=resolve;});
  const over=await box.files.watchDir('/workspace',async()=>{await overGate;},{timeoutMs:0,onExit:error=>{overExits++;overError=error;}});watchers.push(over);
  await command(box,'for ((i=0;i<400;i++)); do : > /workspace/overflow-$i; done');
  // Release callback backpressure after proving the root queue has terminated.
  await wait(async()=>(await box._session.listFileWatches()).some(info=>info.id===over._native.id&&info.error_code==='overflow'));
  releaseOver();await wait(()=>overExits===1);
  check('slow-callback-overflow-explicit',/overflow/.test(overError?.message)&&await box.isRunning());
  await over.stop();check('overflow-cleanup-onExit-once',overExits===1);
  await box.kill();
}finally{
  for(const watch of watchers){try{await watch.stop();}catch(error){if(!(error instanceof APIError)||error.status!==404)throw error;}}
  for(const box of boxes){try{await box.kill();}catch(error){if(!(error instanceof APIError)||error.status!==404)throw error;}}
}
check('active-capacity-returned',(await a.doctor()).vm_capacity.active===0);
const hash=data=>createHash('sha256').update(data).digest('hex'),candidate=hash(readFileSync(packagePath));const evidence=join(root,'results/e2b-2.51.0');mkdirSync(evidence,{recursive:true});
const report={suite:'e2b-compat-case/v1',operation:'files.watch_dir',language:'typescript',upstream_commit:'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b',candidate_sha256:candidate,environment:'real-kvm',adapter:'sdk/node.Sandbox',official_sdk_unmodified:false,sandbox_id:sessionId,cases:[{name:'success',passed:true,detail:'actual inotify five types, metadata, recursive events, callbacks during synchronous command'},{name:'failure',passed:true,detail:'awaited callback rejection and terminal failure, quota, tenant and explicit overflow cleanup'}],passed:true};
writeFileSync(join(evidence,'typescript-files.watch_dir.json'),JSON.stringify(report,null,2)+'\n');
writeFileSync(join(root,'results/node-watch.json'),JSON.stringify({suite:'node-directory-watch-kvm/v1',passed:true,candidate_sha256:candidate,installed_sdk_sha256:hash(readFileSync(sdkPath)),expected_mode:mode,cases,case_count:cases.length,performance_gate_evidence:false},null,2)+'\n');console.log(JSON.stringify({passed:true,cases:cases.length}));
