#!/usr/bin/env node
/** Installed Node SDK fixed-input jobs in isolated cold/warm real KVM. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const argument=name=>process.argv[process.argv.indexOf(name)+1];
const root=argument('--root'),packagePath=argument('--package'),mode=argument('--expected-mode');assert.ok(['cold','warm'].includes(mode));assert.match(root,/^\/var\/lib\/osv-offline-validation-20261030-[a-z0-9]+$/);
if(!process.argv.includes('--in-netns')){
 const shown=spawnSync('systemctl',['show','-p','MainPID','--value',root.split('/').at(-1)+'-api.service'],{encoding:'utf8'});assert.equal(shown.status,0);assert.ok(Number(shown.stdout)>1);
 const child=spawnSync('nsenter',['-t',shown.stdout.trim(),'-n',process.execPath,process.argv[1],'--root',root,'--package',packagePath,'--expected-mode',mode,'--in-netns'],{stdio:'inherit'});process.exit(child.status??1);
}
const release=readdirSync(join(root,'releases'));assert.equal(release.length,1);const sdkPath=join(root,'releases',release[0],'sdk/node/index.js');
const {Client,APIError,ConfigurationError}=await import(pathToFileURL(sdkPath).href);
const config=JSON.parse(readFileSync(join(root,'config.production.json'),'utf8'));
const client=new Client('https://localhost:'+config.listen.split(':').at(-1),{token:readFileSync(join(root,'secrets/token'),'utf8'),caFile:join(root,'tls/ca.crt'),certFile:join(root,'tls/client.crt'),keyFile:join(root,'tls/client.key'),requestTimeoutMs:65000});
const report={suite:'node-job-inputs-kvm/v1',passed:false,mode,cases:[],job_ids:[],performance_gate_evidence:false};
const hash=data=>createHash('sha256').update(data).digest('hex');
const check=(name,value)=>{assert.ok(value,name);report.cases.push(name);};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function run(script,{legacy=false,...options}={}){
 if(mode==='warm'){
  const deadline=Date.now()+20000;
  for(;;){const doctor=await client.doctor();if(doctor.warm_pool.healthy&&doctor.warm_pool.profiles.some(row=>row.name==='small'&&row.ready>=1))break;assert.ok(Date.now()<deadline,'warm profile did not refill');await pause(50);}
 }
 const job={entrypoint:'/bin/sh',args:['-c',script],memoryMiB:128,timeoutMs:5000,...options};
 const value=await (legacy?client.runLegacy(job):client.run(job));report.job_ids.push(value.id);
 if(mode==='warm')assert.equal(value.startupMode,'warm','input test silently used cold fallback');return value;
}
try{
 const caps=await client.capabilities();check('capabilities',['environment','stdin','working_directory'].every(key=>caps.features[key])&&caps.limits.max_stdin_bytes===16384&&caps.limits.max_env_entries===32&&caps.limits.max_env_bytes===8192);
 check('fixture-mode',Boolean(config.warm_pool?.enabled)===(mode==='warm'));
 let data=Buffer.concat([Buffer.from([0,255]),Buffer.from('中文\n')]);const value="中文='quoted'";
 let result=await run('printf "%s|%s|%s|%s|" "$KEY" "$PWD" "$LD_LIBRARY_PATH" "$(/bin/busybox id -u)"; /bin/busybox cat marker; /bin/busybox sha256sum; printf job-stderr >&2',{environment:{KEY:value,LD_LIBRARY_PATH:'/workspace/lib'},cwd:'/input/nested',stdin:data,inputFiles:[{path:'nested/marker',data:Buffer.from('marker|')}]});
 check('combined-env-cwd-binary-stdin',result.succeeded&&result.guestResult.stdout===value+'|/input/nested|/workspace/lib|10000|marker|'+hash(data)+'  -\n'&&result.guestResult.stderr==='job-stderr');
 check('empty-stdin-eof',(await run('/bin/busybox wc -c',{stdin:new Uint8Array()})).guestResult.stdout.trim()==='0');
 check('omitted-stdin-eof',(await run('/bin/busybox wc -c')).guestResult.stdout.trim()==='0');
 data=Buffer.from(Array.from({length:16384},(_,i)=>i%256));
 result=await run('/bin/busybox sha256sum',{stdin:data});check('full-16k-binary-stdin',result.succeeded&&result.guestResult.stdout.split(/\s+/)[0]===hash(data));
 result=await run('/bin/busybox head -c 65536 /dev/zero; /bin/busybox sha256sum >&2',{stdin:data});
 check('duplex-output-and-input',result.succeeded&&result.guestResult.stdout.length===65536&&result.guestResult.stderr.split(/\s+/)[0]===hash(data));
 result=await run('exit 7',{stdin:data});check('program-may-close-stdin-early',result.state==='guest_error'&&result.exitCode===7&&result.protocolOk);
 result=await run('printf started; sleep 20',{stdin:data,timeoutMs:1500});check('unconsumed-input-deadline',result.timedOut&&result.state==='timed_out');
 result=await run('printf should-not-run',{cwd:'/missing-job-cwd'});check('missing-cwd-fails',result.state==='guest_error'&&result.guestResult.error&&!result.guestResult.stdout.includes('should-not-run'));
 result=await run('printf should-not-run',{cwd:'/lost+found'});check('cwd-checked-after-dropping-uid',result.state==='guest_error'&&result.guestResult.error.includes('Permission denied'));
 result=await run('printf "%s|%s" "${KEY-unset}" "$PWD"');check('next-job-env-and-workspace-fresh',result.succeeded&&result.guestResult.stdout==='unset|/workspace');
 result=await run('printf "%s|%s|" "$KEY" "$PWD"; /bin/busybox wc -c',{legacy:true,environment:{KEY:'legacy'},cwd:'/input',stdin:Buffer.from('input'),inputFiles:[{path:'marker',data:Buffer.from('kept')}]});
 check('v1-legacy-carries-inputs',result.succeeded&&result.guestResult.stdout.trim()==='legacy|/input|5');
 for(const [name,job] of [['sdk-relative-cwd',{entrypoint:'/bin/sh',cwd:'relative'}],['sdk-oversized-input',{entrypoint:'/bin/sh',stdin:Buffer.alloc(16385)}]]){await assert.rejects(client.run(job),ConfigurationError);report.cases.push(name);}
 const selector={backend:caps.backend,artifact_manifest_sha256:caps.artifact_manifest_sha256,entrypoint:'/bin/sh',args:['-c','true'],memory_mib:128};
 for(const [name,extra] of [['api-relative-cwd',{cwd:'relative'}],['api-oversized-input',{stdin:Buffer.alloc(16385).toString('base64')}],['api-invalid-environment',{environment:{'1BAD':'value'}}],['api-invalid-base64',{stdin:'??=='}]]){
  await assert.rejects(client._exchange('POST','/v2/jobs',{...selector,...extra}),error=>error instanceof APIError&&error.status===400);report.cases.push(name);
 }
 result=await run('printf recovered');check('quota-reusable-after-failures',result.succeeded&&result.guestResult.stdout==='recovered');
 check('distinct-job-identities',new Set(report.job_ids).size===report.job_ids.length);
 const inspection=spawnSync('python3',[join(dirname(process.argv[1]),'check-job-input-pool-state.py'),'--root',root,'--expected-mode',mode],{encoding:'utf8'});assert.equal(inspection.status,0,inspection.stderr);report.cleanup_inspection=JSON.parse(inspection.stdout);
 check('no-active-workdir-residual',report.cleanup_inspection.active_jobs===0&&report.cleanup_inspection.remaining_active_workdirs.length===0);check('remaining-cgroups-belong-only-to-idle-pool',report.cleanup_inspection.passed&&report.cleanup_inspection.remaining_active_cgroups.length===0);
 report.passed=true;
}finally{
 report.candidate_sha256=hash(readFileSync(packagePath));report.installed_sdk_sha256=hash(readFileSync(sdkPath));report.case_count=report.cases.length;
 writeFileSync(join(root,'results/node-job-inputs.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:report.passed,cases:report.case_count,mode}));
}
