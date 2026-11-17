#!/usr/bin/env node
/** Installed Node SDK -> actual Linux code VM in a network-isolated fixture. */
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {readFileSync, readdirSync, mkdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const arg=name=>process.argv[process.argv.indexOf(name)+1];
const root=arg('--root'), packagePath=arg('--package'), mode=arg('--expected-mode');
assert.match(root,/^\/var\/lib\/osv-offline-validation-20261030-[a-z0-9]+$/);
assert.ok(['cold','warm'].includes(mode));
if(!process.argv.includes('--in-netns')){
  const pid=spawnSync('systemctl',['show','-p','MainPID','--value',root.split('/').at(-1)+'-api.service'],{encoding:'utf8'});
  assert.equal(pid.status,0); assert.ok(Number(pid.stdout)>1);
  const child=spawnSync('nsenter',['-t',pid.stdout.trim(),'-n',process.execPath,process.argv[1],'--root',root,'--package',packagePath,'--expected-mode',mode,'--in-netns'],{stdio:'inherit'});
  process.exit(child.status??1);
}
const release=join(root,'releases',readdirSync(join(root,'releases'))[0]);
const {Client,Session,Sandbox,APIError,UnsupportedCapability,ConfigurationError,TimeoutException}=await import(pathToFileURL(join(release,'sdk/node/index.js')).href);
const config=JSON.parse(readFileSync(join(root,'config.production.json'),'utf8'));
const options={caFile:join(root,'tls/ca.crt'),certFile:join(root,'tls/client.crt'),keyFile:join(root,'tls/client.key'),requestTimeoutMs:60000};
const url='https://localhost:'+config.listen.split(':').at(-1);
const a=new Client(url,{...options,token:readFileSync(join(root,'secrets/token'),'utf8')});
const b=new Client(url,{...options,token:readFileSync(join(root,'secrets/token-b'),'utf8')});
const cases=[], boxes=[];
const check=(name,value)=>{assert.ok(value,name);cases.push(name);console.log('PASS node-code-'+name);};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function wait(action,seconds=45){const end=Date.now()+seconds*1000;while(true){const value=await action();if(value)return value;assert.ok(Date.now()<end,'code observation timed out');await pause(25);}}
async function create(){
  if(mode==='warm')await wait(async()=>(await a.doctor()).warm_pool.profiles.some(row=>row.name==='code'&&row.ready>=1));
  const box=await Sandbox.create('firecracker-linux',{client:a,timeoutMs:180000});boxes.push(box);
  check('startup-'+boxes.length,box._session.created.startupMode===mode);return box;
}
const ready=(controller,context)=>wait(async()=>{const value=await controller.get(context.id);return value.state==='idle'?value:undefined;});
async function journal(handle){let cursor=0;const events=[],end=Date.now()+20000;while(true){const page=await handle.poll(cursor);events.push(...page.events.map(row=>row.event));cursor=page.next_sequence;if(page.status!=='running'&&cursor===page.last_sequence)return {page,events};assert.ok(Date.now()<end);await pause(20);}}
const report={suite:'node-code-real-kvm/v1',passed:false,mode,cases,actual_code_vsock:true,performance_gate_evidence:false,candidate_sha256:createHash('sha256').update(readFileSync(packagePath)).digest('hex')};
try{
  const signedProtocol=JSON.parse(readFileSync(join(config.artifact_root,'manifest.json'),'utf8')).protocol;
  const cap=await a.capabilities();check('signed-profile',cap.artifact_manifest_protocol===signedProtocol&&['osv-sandbox-artifacts/v5','osv-sandbox-artifacts/v6','osv-sandbox-artifacts/v7','osv-sandbox-artifacts/v8'].includes(signedProtocol)&&cap.features.code_contexts&&cap.code_languages.join(',')==='python,javascript,typescript');
  const box=await create(),sid=box.sandboxId,control=box._session.code;report.sandbox_id=sid;
  const initial=await ready(control,await control.default());check('real-prewarmed-python',initial.pid>1&&initial.generation===1);
  check('owner-capabilities',(await box._session.capabilities()).session_id===sid);
  const foreign=new Sandbox(new Session(b,box._session.created));
  await assert.rejects(foreign.listCodeContexts(),error=>error instanceof APIError&&error.status===404);cases.push('foreign-list-hidden');
  const stdout=[],stderr=[],order=[];
  const result=await box.runCode("import sys\nvalue=41\nprint('中文')\nprint('stderr',file=sys.stderr)\nvalue+1",{
    onStdout:async output=>{await pause(5);stdout.push(output);order.push('stdout');},onStderr:async output=>{stderr.push(output);order.push('stderr');},onResult:async()=>{order.push('result');}});
  check('awaited-streaming-results',result.text==='42'&&result.logs.stdout.join('').includes('中文')&&result.logs.stderr.join('').includes('stderr')&&stdout.length&&stderr.length&&order.at(-1)==='result'&&!result.error);
  check('persistent-default',(await box.runCode('value+2')).text==='43');
  const rich=await box.runCode("class Rich:\n def _repr_mimebundle_(self): return {'application/json':{'zero':0,'flag':False},'text/html':'<b>rich</b>'}\nRich()");
  check('mime-zero-false',rich.results.at(-1).json.zero===0&&rich.results.at(-1).json.flag===false&&rich.results.at(-1).html==='<b>rich</b>');
  const bad=await box.runCode("raise ValueError('expected-user-error')");check('user-error-as-data',bad.error.name==='ValueError'&&bad.error.value.includes('expected-user-error'));
  check('usable-after-user-error',(await box.runCode('value+3')).text==='44');
  const context=await box.createCodeContext({language:'python'});check('create-ready',(await control.get(context.id)).state==='idle');
  check('context-isolation',(await box.runCode("'value' in globals()",{context})).text==='False');
  await box.runCode('isolated=71',{context});await box.restartCodeContext(context);
  check('restart-next-generation',(await control.get(context.id)).generation===2&&(await box.runCode("'isolated' in globals()",{context})).text==='False');
  check('list-contexts',(await box.listCodeContexts()).some(item=>item.id===context.id));
  await box.removeCodeContext(context);
  for(const method of ['runCode','restartCodeContext','removeCodeContext']){
    await assert.rejects(method==='runCode'?box.runCode('1',{context}):box[method](context),error=>error instanceof APIError&&error.status===404&&error.code==='code_not_found');
    cases.push('removed-context-'+method);
  }
  await assert.rejects(box.createCodeContext({cwd:'/etc'}),ConfigurationError);cases.push('invalid-create-cwd');
  check('javascript-runtime',(await box.runCode('globalThis.jsValue=40; jsValue+3',{language:'javascript'})).text==='43');
  check('typescript-runtime',(await box.runCode('const answer: number = 44; answer',{language:'typescript'})).text==='44');
  await assert.rejects(box.runCode('1',{language:'ruby'}),UnsupportedCapability);cases.push('unsupported-language-explicit');
  const native=await ready(control,await control.create());
  let shellDone=false;const shell=box._session.run({entrypoint:'/bin/sh',args:['-c','sleep 2; echo shell-ok'],timeoutMs:5000}).finally(()=>{shellDone=true;});
  await pause(100);const concurrent=await journal(await control.execute(native,'6*7'));
  check('code-and-info-during-shell',concurrent.page.status==='completed'&&(await box._session.info()).id===sid&&!shellDone);
  check('shell-still-completes',(await shell).succeeded);
  const eid=randomBytes(12).toString('hex'),placeholder=control.connectExecution(native,eid);
  await placeholder.cancel();const preempted=await journal(placeholder);
  check('cancel-before-submit',preempted.page.failure==='cancelled_before_submit'&&preempted.events.length===1);
  await assert.rejects(control.execute(native,'1',{executionId:eid}),error=>error instanceof APIError&&error.status===409);cases.push('cancelled-id-never-replayed');
  const execution=await control.execute(native,'import time\nwhile True: time.sleep(.01)',{timeoutMs:0});
  check('explicit-cancel-running',(await execution.poll()).status==='running');await execution.cancel();
  const cancelled=await journal(execution);check('explicit-cancel-confirmed',cancelled.page.status==='cancelled'&&cancelled.events.at(-1).type==='finished');
  await control.remove(await control.get(native.id));
  await assert.rejects(box.runCode('while True: pass',{timeoutMs:300}),TimeoutException);cases.push('e2b-timeout-confirmed');
  check('owner-survives-timeout',await box.isRunning());await box.kill();
  const fresh=await create();check('fresh-vm-no-state',(await fresh.runCode("'value' in globals()")).text==='False'&&(await fresh.listCodeContexts()).length===1);await fresh.kill();
  check('active-capacity-returned',(await a.doctor()).vm_capacity.active===0);report.passed=true;
  const evidence=join(root,'results/e2b-2.51.0');mkdirSync(evidence,{recursive:true});
  for(const operation of ['code.run_code','code.create_context','code.list_contexts','code.restart_context','code.remove_context']){
    writeFileSync(join(evidence,'typescript-'+operation+'.json'),JSON.stringify({suite:'e2b-compat-case/v1',operation,language:'typescript',upstream_commit:'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b',candidate_sha256:report.candidate_sha256,environment:'real-kvm',adapter:'sdk/node.Sandbox',official_sdk_unmodified:false,sandbox_id:sid,cases:[{name:'success',passed:true,detail:'actual code vsock, interpreter results, callbacks and context lifecycle'},{name:'failure',passed:true,detail:'user error, removed/stale contexts, tenant ownership, cancelled known ID and confirmed timeout'}],passed:true},null,2)+'\n');
  }
}finally{
  for(const box of boxes){try{await box.kill();}catch(error){if(!(error instanceof APIError)||error.status!==404)throw error;}}
  writeFileSync(join(root,'results/node-code-'+mode+'.json'),JSON.stringify(report,null,2)+'\n');
}
