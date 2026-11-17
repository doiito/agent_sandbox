import { APIError, Client, Sandbox, TemplateMismatch, type E2BWriteInfo, type JobRequest, type JobResult,
  type SessionRequest, type SessionInfo } from './index.js';

const job: JobRequest = {
	 network: 'proxy',
  entrypoint: '/bin/sh',
  cwd: '/input', environment: {KEY:'value'}, stdin: new Uint8Array([0,255]),
  args: ['-c', 'cat /input/prompt.txt'],
  inputFiles: [{ path: 'prompt.txt', data: new Uint8Array([65]), mode: 0o444 }],
};
const client = new Client('https://localhost:8443', {
  token: 'example', certFile: '/client.crt', keyFile: '/client.key', caFile: '/ca.crt',
});
async function compileOnly(): Promise<boolean> {
  const fetched = await client.fetchNetwork('https://allowed.example/data', {method:'POST',body:new Uint8Array([0,255]),timeoutMs:1000});
  const fetchedBody: Uint8Array = fetched.body;
  void fetchedBody;
  const options: SessionRequest = { ttlMs: 5000, inputFiles: [], network:'proxy' };
  const session = await client.createSession(options);
  const artifact = await session.createArtifact('/workspace', {requestTimeoutMs:35000});
  const artifactBytes: Uint8Array = await session.downloadArtifact(artifact);
  const artifactChunk = await session.readArtifact(artifact.id,0,512);
  const archiveDigest: string = artifactChunk.archive_sha256;
  await session.deleteArtifact(artifact.id);
  void artifactBytes; void archiveDigest;
  const grant = await session.ports.createPreview(8080, {previewId: 'a'.repeat(24), ttlMs: 60000});
  const previewURL: string | undefined = grant.bootstrapURL;
  const previewOrigin: string = (await grant.info()).origin;
  await session.ports.preview(8080, grant.id).revoke();
  void previewURL; void previewOrigin;
  // @ts-expect-error Preview IDs are immutable.
  grant.id = 'b'.repeat(24);
  // @ts-expect-error Query does not return a bootstrap secret.
  const noSecret: string = (await grant.info()).bootstrap_url;
  void noSecret;
  const port = await session.ports.open(8080, {connectionId:'c'.repeat(24), maxBytes:1048576, timeoutMs:5000});
  await port.write(new Uint8Array([0,255])); await port.closeWrite();
  const frame = await port.readFrame();
  if(frame.kind==='data') { const bytes:Uint8Array = frame.data; void bytes; }
  if(frame.kind==='finished') { const code:string|null = frame.info.error; void code; }
  await port.info(); await session.ports.connection(8080,port.id).cancel(); port.close();
  // @ts-expect-error Port IDs are immutable bindings.
  port.id='d'.repeat(24);
  // @ts-expect-error Native port DATA requires binary bytes.
  await port.write('text');
  const boundCapabilities = await session.capabilities({requestTimeoutMs: 1000});
  const boundSessionId: string = boundCapabilities.session_id;
  void boundSessionId;
  const codeContext = await session.code.create({language: 'python', contextId: 'c'.repeat(24)});
  const codeDefault = await session.code.default('typescript');
  const codeContexts = await session.code.list();
  const codeCurrent = await session.code.get(codeContext.id);
  const execution = await session.code.execute(codeCurrent, '40 + 2', {executionId: 'e'.repeat(24), timeoutMs: 0});
  const codePage = await execution.poll(0, {requestTimeoutMs: 1000});
  for (const item of codePage.events) {
    if (item.event.type === 'result') {
      const mime: Record<string, unknown> = item.event.data;
      void mime;
    }
  }
  await execution.cancel();
  await session.code.restart(codeCurrent);
  await session.code.remove(codeCurrent);
  const reconnected = session.code.connectExecution(codeCurrent, execution.id);
  void codeDefault; void codeContexts; void reconnected;
  // @ts-expect-error Code contexts are immutable generation snapshots.
  codeContext.generation = 9;
  // @ts-expect-error Native interpreter languages are closed.
  await session.code.create({language: 'ruby'});
  // @ts-expect-error Native execution requires source text.
  await session.code.execute(codeCurrent, 42);
  // @ts-expect-error E2B envs is not a native environment option.
  await session.code.execute(codeCurrent, '', {envs: {VALUE: 'x'}});
  const info: SessionInfo = await session.info();
  await session.run({ entrypoint: '/bin/sh', args: ['-c', 'true'] });
  const written: number = await session.writeFile('/workspace/a', new Uint8Array([65]));
  const read: Uint8Array = await session.readFile('/workspace/a');
  const entries: string[] = await session.listFiles();
  const watcher = await session.startFileWatch('/workspace', {recursive:true,includeEntry:true});
  const watchPage = await watcher.poll(0);
  const eventName: string|undefined = watchPage.events[0]?.name;
  await session.listFileWatches();
  await watcher.stop();void eventName;
  const metadata: { kind: 'file' | 'directory'; size: number } = await session.statFile('/workspace/a');
  await session.deleteFile('/workspace/a');
  const directoryCreated: boolean = await session.makeDir('/workspace/deep');
  const compatible = await Sandbox.create('firecracker-linux', { client, timeoutMs: 30000 });
  const interpreterContext = await compatible.createCodeContext({language:'typescript'});
  const interpreted = await compatible.runCode('40 + 2', {context: interpreterContext, timeoutMs: 60000,
    onStdout: async output => { const text: string = output.line; void text; },
    onResult: async result => { const formats: string[] = result.formats(); void formats; }});
  const interpretedText: string | undefined = interpreted.text;
  const interpretedError: string | undefined = interpreted.error?.traceback;
  await compatible.listCodeContexts();
  await compatible.restartCodeContext(interpreterContext);
  await compatible.removeCodeContext(interpreterContext.id);
  void interpretedText; void interpretedError;
  // @ts-expect-error E2B language and context are mutually exclusive.
  await compatible.runCode('', {language: 'python', context: interpreterContext});
  // @ts-expect-error Callbacks receive OutputMessage instead of plain strings.
  await compatible.runCode('', {onStdout: (text: string) => { void text; }});
  const compatibleWatch = await compatible.files.watchDir('/workspace', async event => {
    const name: string = event.name;
    const changedAt: Date|undefined = event.entry?.modifiedTime;
    void name;void changedAt;
  }, {recursive:true,includeEntry:true,timeoutMs:0,onExit:async error=>{void error;}});
  await compatibleWatch.stop();
  const compatibleText: string = await compatible.files.read('/workspace/a');
  const compatibleBytes: Uint8Array = await compatible.files.read('/workspace/a', { format: 'bytes' });
  const compatibleExists: boolean = await compatible.files.exists('/workspace/a');
  const compatibleDirectory: boolean = await compatible.files.makeDir('/workspace/deep');
  const compatibleWrite: E2BWriteInfo = await compatible.files.write('/workspace/deep/a', 'hello');
  const compatibleBatch: E2BWriteInfo[] = await compatible.files.writeFiles([
    { path: '/workspace/deep/b', data: new Uint8Array([66]) }]);
  const foreground = await compatible.commands.run('printf hello', { envs: { KEY: 'value' }, cwd: '/workspace' });
  const exitCode: number = foreground.exitCode;
  const background = await compatible.commands.run('sleep 1', { background: true, timeoutMs: 0 });
  const guestPid: number = background.pid;
  const interactive = await compatible.commands.run('cat', { background: true, stdin: true });
  await interactive.sendStdin('hello');
  await compatible.commands.sendStdin(interactive.pid, new Uint8Array([0,255]));
  await compatible.commands.closeStdin(interactive.pid);
  await interactive.wait();
  const attached = await compatible.commands.connect(guestPid, { onStdout: text => console.log(text) });
  await attached.disconnect();
  await background.kill();
  const processes = await compatible.commands.list();
  void exitCode; void processes;
  const lifecycleInfo = await compatible.getInfo();
  const memoryMB: number = lifecycleInfo.memoryMB;
  await compatible.setTimeout(30000);
  const paginator = Sandbox.list({client,limit:1,order:"asc"});
  const items = await paginator.nextItems();
  await session.setTimeout(30000);
  const nativePage = await client.listSessions({limit:1});
  void memoryMB;void items;void nativePage;
  await compatible.kill();
  await session.close();
  await client.connectSession(info.id);
  const caps = await client.capabilities();
  const result: JobResult = await client.run(job, {
    template: { backend: caps.backend, artifactManifestSha256: caps.artifact_manifest_sha256! },
  });
  try { await client.runLegacy(job); }
  catch (error) {
    if (error instanceof TemplateMismatch || error instanceof APIError) return error.status === 409;
  }
  return result.succeeded && result.protocolOk && written === read.byteLength &&
    entries.length >= 0 && metadata.kind === 'file' &&
    compatibleText.length >= 0 && compatibleBytes.length >= 0 && compatibleExists &&
    directoryCreated && compatibleDirectory && compatibleWrite.name.length > 0 && compatibleBatch.length === 1;
}
void compileOnly;
