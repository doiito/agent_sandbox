#!/usr/bin/env node
/** Installed Node SDK lifecycle behavior in one isolated, real-KVM fixture. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync,mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const argument=name=>process.argv[process.argv.indexOf(name)+1];
const root=argument('--root'),packagePath=argument('--package');assert.match(root,/^\/var\/lib\/osv-offline-validation-20261030-[a-z0-9]+$/);
if(!process.argv.includes('--in-netns')){
  const result=spawnSync('systemctl',['show','-p','MainPID','--value',root.split('/').at(-1)+'-api.service'],{encoding:'utf8'});assert.equal(result.status,0);assert.ok(Number(result.stdout)>1);
  const child=spawnSync('nsenter',['-t',result.stdout.trim(),'-n',process.execPath,process.argv[1],'--root',root,'--package',packagePath,'--in-netns'],{stdio:'inherit'});process.exit(child.status??1);
}
const version=readdirSync(join(root,'releases'));assert.equal(version.length,1);
const sdkPath=join(root,'releases',version[0],'sdk/node/index.js');
const {Client,Session,Sandbox,APIError}=await import(pathToFileURL(sdkPath).href);
const config=JSON.parse(readFileSync(join(root,'config.production.json'),'utf8')),url='https://localhost:'+config.listen.split(':').at(-1);
const options={caFile:join(root,'tls/ca.crt'),certFile:join(root,'tls/client.crt'),keyFile:join(root,'tls/client.key'),requestTimeoutMs:65000};
const a=new Client(url,{...options,token:readFileSync(join(root,'secrets/token'),'utf8')}),b=new Client(url,{...options,token:readFileSync(join(root,'secrets/token-b'),'utf8')});
const cases=[],sandboxes=[];let renewalId;
const check=(name,value)=>{assert.ok(value,name);cases.push(name);};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function rejected(name,action,status,code){await assert.rejects(action(),error=>error instanceof APIError&&error.status===status&&(code===undefined||error.code===code));cases.push(name);}
async function create(client=a,timeoutMs=30000,retry=false){
  const deadline=Date.now()+20000;
  while(true){try{const box=await Sandbox.create('firecracker-linux',{client,timeoutMs});sandboxes.push(box);return box;}
    catch(error){if(!retry||!(error instanceof APIError)||error.status!==429||Date.now()>deadline)throw error;await pause(50);}}
}
async function empty(client){const page=Sandbox.list({client});return (await page.nextItems()).length===0&&!page.hasNext;}
try{
  const caps=await a.capabilities();check('capabilities',caps.features.session_listing&&caps.features.session_timeout_update&&caps.limits.session_max_lifetime_ms===60000);
  const first=await create(),second=await create(),foreign=await create(b);
  await first.files.write('/workspace/metadata-marker','kept');const info=await first.getInfo();
  check('bound-real-metadata',info.sandboxId===first.sandboxId&&info.templateId==='firecracker-linux'&&info.cpuCount===config.defaults.vcpus&&info.memoryMB===config.defaults.memory_mib&&info.envdVersion==='fc-agent/v2'&&info.state==='running'&&Object.keys(info.metadata).length===0);
  check('metadata-dates-and-hard-limit',info.startedAt<=info.endAt&&info.endAt<=info.maxEndAt&&info.maxEndAt-info.startedAt>=59000&&info.maxEndAt-info.startedAt<=60000);
  check('get-info-preserves-workspace',await first.files.read('/workspace/metadata-marker')==='kept');
  const page=Sandbox.list({client:a,limit:1,order:'asc'});let items=await page.nextItems();const cursor=page.nextToken;
  check('first-page',items.length===1&&items[0].sandboxId===first.sandboxId&&page.hasNext&&cursor);
  const late=await create();items=await page.nextItems();
  check('stable-page-excludes-new-create',items.length===1&&items[0].sandboxId===second.sandboxId&&!page.hasNext);
  await assert.rejects(page.nextItems());cases.push('exhausted-page-error');
  await rejected('foreign-cursor-404',()=>Sandbox.list({client:b,limit:1,order:'asc',nextToken:cursor}).nextItems(),404);
  const bp=await Sandbox.list({client:b}).nextItems();check('tenant-list-isolation',bp.length===1&&bp[0].sandboxId===foreign.sandboxId);
  const reverse=await Sandbox.list({client:a,limit:3,order:'desc'}).nextItems();
  check('global-descending-order',JSON.stringify(reverse.map(row=>row.sandboxId))===JSON.stringify([late.sandboxId,second.sandboxId,first.sandboxId]));
  const changing=Sandbox.list({client:a,limit:1,order:'asc'});await changing.nextItems();await second.kill();const remaining=await changing.nextItems();
  check('deleted-item-skipped',remaining.length===1&&remaining[0].sandboxId===late.sandboxId&&!changing.hasNext);
  const denied=new Sandbox(new Session(b,first._session.created));
  await rejected('foreign-info-404',()=>denied.getInfo(),404);
  await rejected('foreign-timeout-404',()=>denied.setTimeout(5000),404);
  await rejected('hard-lifetime-rejected',()=>first.setTimeout(300000),400,'timeout_exceeds_lifetime');
  check('rejected-timeout-keeps-deadline',(await first.getInfo()).endAt.getTime()===info.endAt.getTime());
  for(const box of [first,second,late,foreign])await box.kill();check('empty-authorized-list',await empty(a)&&await empty(b));
  const box=await create(a,2000);renewalId=box.sandboxId;await box.files.write('/workspace/renew-marker','survived');const original=await box.getInfo();
  const task=await box.commands.run('printf once >> /workspace/run-count; sleep 3; cat /workspace/renew-marker',{background:true,timeoutMs:0});
  await box.setTimeout(6000);const updated=await box.getInfo();
  check('renewed-remaining-ttl',updated.endAt>original.endAt&&updated.maxEndAt.getTime()===original.maxEndAt.getTime());
  check('real-command-crosses-original-expiry',(await task.wait()).stdout==='survived'&&await box.files.read('/workspace/run-count')==='once');
  check('renewal-retains-identity',(await box.getInfo()).sandboxId===renewalId&&await box.isRunning());
  await box.commands.run('cat',{background:true,stdin:true,timeoutMs:0});await box.setTimeout(1000);
  let deadline=Date.now()+4000;
  while(await box.isRunning()){assert.ok(Date.now()<deadline,'shortened TTL did not expire');await pause(50);}
  cases.push('shortened-ttl-expires-active-command');
  await rejected('expired-info-404',()=>box.getInfo(),404);
  await rejected('expired-timeout-does-not-resurrect',()=>box.setTimeout(5000),404);
  deadline=Date.now()+4000;while((await a.doctor()).vm_capacity.active!==0){assert.ok(Date.now()<deadline);await pause(50);}
  check('expiry-releases-vm-resources',await empty(a));
  const replacements=[];for(let index=0;index<3;index++)replacements.push(await create(a,30000,true));
  check('all-tenant-slots-reusable',(await Promise.all(replacements.map(box=>box.isRunning()))).every(Boolean));
}finally{for(const box of sandboxes){try{await box.kill();}catch(error){if(!(error instanceof APIError)||error.status!==404)throw error;}}}
const jobs=path=>readdirSync(path).filter(name=>name.startsWith('job-'));
check('no-workdir-residual',jobs(join(root,'run')).length===0);check('no-cgroup-residual',jobs(join('/sys/fs/cgroup',root.split('/').at(-1))).length===0);
const hash=data=>createHash('sha256').update(data).digest('hex'),candidate=hash(readFileSync(packagePath));const evidence=join(root,'results/e2b-2.51.0');mkdirSync(evidence,{recursive:true});
const operations={
  'sandbox.list':['tenant-bound ascending/descending stable pages; new/deleted sessions handled','foreign cursor 404 and exhausted page error'],
  'sandbox.get_info':['same sandbox/template, actual CPU/memory/protocol and lifecycle dates','foreign and expired sandbox 404'],
  'sandbox.set_timeout':['actual command survived original TTL; shortened TTL killed active VM and quota recovered','hard-lifetime limit and foreign/expired updates rejected without resurrection']};
for(const [operation,[success,failure]] of Object.entries(operations)){
  const report={suite:'e2b-compat-case/v1',operation,language:'typescript',upstream_commit:'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b',candidate_sha256:candidate,environment:'real-kvm',adapter:'sdk/node.Sandbox',official_sdk_unmodified:false,sandbox_id:renewalId,cases:[{name:'success',passed:true,detail:success},{name:'failure',passed:true,detail:failure}],passed:true};
  writeFileSync(join(evidence,'typescript-'+operation+'.json'),JSON.stringify(report,null,2)+'\n');
}
writeFileSync(join(root,'results/node-lifecycle.json'),JSON.stringify({suite:'node-lifecycle-kvm/v1',passed:true,candidate_sha256:candidate,installed_sdk_sha256:hash(readFileSync(sdkPath)),cases,case_count:cases.length,renewal_session_id:renewalId,remaining_jobs:[],remaining_cgroups:[],performance_gate_evidence:false},null,2)+'\n');
console.log(JSON.stringify({passed:true,cases:cases.length}));
