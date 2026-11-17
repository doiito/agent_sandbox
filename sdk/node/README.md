# Node.js / TypeScript native client

## Controlled remote inference

This is an unreleased integration path; guest, signed-template and same-package deployment acceptance remain open. The actual session must advertise `features.remote_inference`. Existing templates do not gain permission. Submit a configured model alias; provider URLs and credentials stay in the service.

```js
import {InferenceError} from './index.js';

const invocationId = '0123456789abcdef01234567'; // Save before submitting; use a new ID for each new call.
const controller = new AbortController();
try {
  const result = await session.ml.invoke('model', {query: 'hello'}, {
    invocationId, timeoutMs: 1000, requestTimeoutMs: 5000, signal: controller.signal
  });
  console.log(result.data, result.invocationId);
} catch (error) {
  if (!(error instanceof InferenceError)) throw error;
  const bill = await client.getInferenceBill(error.taskId);
  console.log(error.invocationId, error.deliveryUnknown, bill);
}
const bill = await session.ml.bill(); // Also works after this session closes.
```

An omitted ID is generated locally before I/O. Results and `InferenceError` retain the task/invocation IDs; an invalid explicit ID fails locally as configuration. Errors expose `cause`, optional HTTP `status` and `code`. `deliveryUnknown` means a POST was attempted without a validated success response, including a rejection that requires inspecting an existing ID. It never means that a bill is absent. The SDK never automatically retries a model POST.

Amounts and prices are canonical uint64 decimal strings. Use `BigInt` explicitly for arithmetic; do not convert amounts to `Number`. Payloads are copied before capability I/O and accept ordinary JSON up to depth 64. NaN/Infinity, unsafe integer numbers, BigInt, undefined/omitted values, custom serialization, accessors, sparse arrays and cycles are rejected; encode large integers as strings. `requestTimeoutMs` is a total observation deadline (default 35000); `timeoutMs` is the model deadline, with 0 using tenant policy. AbortSignal closes the API request. Observe the known ID in the bill after timeout/cancellation; a pending reservation can later become uncertain and retain its budget.

## Native persistent code contexts

`session.code` supports signed Linux v5 and code-enabled v6 templates. rc74 still
contains v5. The default shell image
has no interpreters: select the installed `linux-code` template from the catalog,
or ask the administrator to configure it as default. See the
[same-bundle validation record](../../docs/validation/2026-11-06-code-template-rc74.md)
for functional evidence and release status.

`await session.capabilities({requestTimeoutMs:10000})` returns the active owner's
bound template capability with session_id. Code discovery uses it and verifies
session/backend/signed digest. Expiry may stop new VM admission while an existing
VM continues within its original lease and API policy. This does not extend TTL;
global client.capabilities({template}) still checks new admission. Upgrade the
server together with the SDK to use this endpoint.

```javascript
const entry = (await client.templates()).templates.find(row =>
  row.id === 'linux-code' && row.available);
if (!entry) throw new Error('linux-code template is unavailable');
const cap = entry.capabilities;
const session = await client.createSession({ttlMs:180000}, {template:{
  backend:cap.backend, artifactManifestSha256:cap.artifact_manifest_sha256
}});
const sandbox = new Sandbox(session);
const context = await sandbox.createCodeContext({language:'typescript'});
const result = await sandbox.runCode('const value: number = 40; value + 2', {
  context, timeoutMs:60000, onStdout:async message => console.log(message.line)
});
console.log(result.text, result.logs.stdout, result.error);
await sandbox.restartCodeContext(context);
console.log(await sandbox.listCodeContexts());
await sandbox.removeCodeContext(context.id);
```

E2B `language` and `context` are mutually exclusive; default is a persistent
Python context. Supported languages are python/javascript/typescript. Creation
waits for idle, restart for the next generation idle, removal for code_not_found.
Lifecycle readiness waits up to 40 seconds; requestTimeoutMs bounds individual
requests, defaulting to 10000. timeoutMs defaults to 60000, accepts 0 to remove
the execution deadline, and has a maximum of 300000; session TTL still applies.

Callbacks are awaited in order and receive OutputMessage or Result/ExecutionError.
Message timestamps are client receipt times. Result exposes text/html/json etc.,
normalized raw fields and original MIME data in mimeData. User code errors are
Execution.error; runtime failure, eviction and timeout throw. The unavailable
executionCount remains undefined. AbortSignal is an extension for cancelling
readiness or execution observation.

Callback rejection, timeout, abort or uncertain delivery cancels the same known
execution and confirms its journal terminal state, with an independent 8-second
cleanup budget. Failure requests owner close and raises CodeCleanupError carrying
originalError, cleanupError and execution; owner-close ACK alone does not prove
termination. Asynchronous callback waits can be interrupted. A synchronous
callback that blocks the local event loop cannot be forcibly interrupted; the
guest execution deadline remains independent, and the SDK checks on return.
Native handles keep their separate asynchronous observation semantics.

```javascript
// session is bound to a signed code template permitting Python.
let context = await session.code.default('python');
while (context.state === 'starting') {
  await new Promise(resolve => setTimeout(resolve, 20));
  context = await session.code.get(context.id);
}
if (context.state !== 'idle') throw new Error(`context is ${context.state}`);
const execution = await session.code.execute(context, 'value = 40\nvalue + 2', {timeoutMs: 60000});
let cursor = 0;
while (true) {
  const page = await execution.poll(cursor);
  if (page.events_evicted) throw new Error('execution output was evicted');
  console.log(page.events);
  cursor = page.next_sequence;
  if (page.status !== 'running' && cursor === page.last_sequence) break;
  await new Promise(resolve => setTimeout(resolve, 20));
}
```

`create({language, cwd, contextId})`, `get(id)`, `list()`, `restart(context)` and
`remove(context)` use frozen `CodeContext` snapshots. Default language is Python,
cwd is `/workspace`. Creation and restart expose real transition states; poll
get until idle. Mutations use the snapshot generation and refuse stale state.
Removal ACK schedules cleanup; observe get returning 404 to confirm removal.

`execute(context, source, {executionId, environment, timeoutMs})` submits once.
The default timeout is 60000ms, 0 removes the execution deadline while session
TTL still applies. `requestTimeoutMs` bounds each code request and the initial
capability query, defaults to 10000, and is capped by Client timeout.
`execution.cancel()` acknowledges cancellation admission; poll the journal to
confirm its terminal state. Observation loss never cancels or replays code.

Errors after submission carry `error.execution`, preserving the known handle;
query or cancel it instead of resubmitting. Creation reply errors carry
`error.contextId` and `error.sessionId`. IDs may also be supplied in advance;
they are 24 lowercase hex digits. `connectExecution(context, id)` restores a
bound observer without creating work.

Events retain binary stdout/stderr as base64 and rich results as MIME maps.
JSON uses normal JavaScript number semantics. Finished status can precede the
last output page; use both status and cursor, and handle `events_evicted`
explicitly. Limits are four contexts, 256 execution IDs per session, 64KiB
source/output, 64 events per page and a 300000ms execution timeout maximum.

See [native SDK validation](../../docs/validation/2026-11-05-code-native-sdks.md)
for local evidence and outstanding VM acceptance.

Signed Linux templates with `features.file_watch` support
`session.startFileWatch('/workspace', {recursive:true,includeEntry:true})`.
The handle exposes `poll(after)` and `stop()`; `listFileWatches()` lists bounded
session history. Polling a later cursor acknowledges older events, so each
watcher has one consumer. Pages hold up to 64 events; each watcher buffers at
most 256 events/64 KiB, and each session allows four active watchers.

The E2B facade provides `await sandbox.files.watchDir(path, async event => {...},
{recursive:true,includeEntry:true,timeoutMs:0,onExit:error=>{...}})`.
Callbacks are awaited in order. Callback rejection stops the watcher and reaches
`onExit` once; terminal callback rejection is contained. Call `await handle.stop()`
to release the watcher. The default timeout is 60 seconds; zero follows the
session lifetime. Events have relative names, five operation types, and optional
entry metadata. Overflow terminates explicitly. inotify may coalesce repeated
operations; metadata reflects event processing time, and changes before a new
recursive subdirectory is registered cannot be guaranteed. Custom users,
network mounts and per-call request timeout options are unsupported.

The offline release contains `sdk/node/index.js`, `index.d.ts`, and
`package.json`. Copy that directory into a Node.js 20+ application, then import
`./sdk/node/index.js` in JavaScript or the local package directory in
TypeScript. There are no npm runtime dependencies or network installation
steps. Node.js itself is required on the client host; it is not required to
install or run the sandbox server.

```js
import { Client } from './sdk/node/index.js';

const client = new Client('https://sandbox.example:8443', {
  token: process.env.OSV_TOKEN,
  caFile: '/etc/osv-sandbox/ca.crt',
  certFile: '/etc/osv-sandbox/client.crt',
  keyFile: '/etc/osv-sandbox/client.key',
});
const result = await client.run({
  entrypoint: '/bin/sh',
  args: ['-c', 'cat /input/prompt.txt'],
  inputFiles: [{ path: 'prompt.txt', data: new TextEncoder().encode('hello') }],
});
if (!result.succeeded) throw new Error(`guest state: ${result.state}`);
console.log(result.guestResult);
```

`run()` fetches authenticated capabilities and submits to the signed v2
template. Pass `{ template: { backend, artifactManifestSha256 } }` to bind a
known digest. A stale template raises `TemplateMismatch` with status 409. No
automatic retry or v1 fallback occurs. `runLegacy()` is the explicit v1 path.
The client connects directly to its HTTPS origin, requires mTLS and a bearer
token, validates the CA/hostname, and rejects redirects. Input file bytes are
base64 encoded in the API request; no local path is read implicitly.

The native Linux session API keeps `/workspace` for sequential commands in one
VM. `createSession()` binds the signed template after an authenticated
capabilities request; `connectSession(id)` checks current tenant visibility.
The session exposes `info()`, `run()` and `close()`:

```js
const session = await client.createSession({ ttlMs: 30000 });
try {
  const first = await session.run({ entrypoint: '/bin/sh',
    args: ['-c', 'echo hello > /workspace/hello'] });
  const connected = await client.connectSession(session.id);
  const second = await connected.run({ entrypoint: '/bin/sh',
    args: ['-c', 'cat /workspace/hello'] });
  await session.writeFile('/workspace/data.bin', new Uint8Array([0, 255]));
  const file = await session.readFile('/workspace/data.bin');
  if (file[0] !== 0 || file[1] !== 255) throw new Error('file roundtrip failed');
  if (!(await session.listFiles()).includes('data.bin')) throw new Error('file list failed');
  if ((await session.statFile('/workspace/data.bin')).size !== 2) throw new Error('file stat failed');
  await session.deleteFile('/workspace/data.bin');
  if (!first.succeeded || !second.succeeded) throw new Error('session command failed');
} finally {
  await session.close();
}
```

Each remaining session TTL is at most 300 seconds; an immutable VM lifetime cap also applies. Sessions end if their owning API
process exits. The release's Python and Node clients are optional for remote
callers; neither runtime is needed to install or run the sandbox server.
File content operations are restricted to regular files under `/workspace`, with a
512 KiB per-file limit. Writes atomically replace a target. Traversal,
symlink following, and cross-mount paths are denied. `listFiles()` returns at most 256
direct names and 64 KiB of names; `statFile()` returns file or directory kind
and size; `deleteFile()` removes one regular file. `makeDir()` creates at most
16 confined directory components and reports whether the final directory was
new. `renameFile(path, destination)` moves files, directories or links themselves,
retains inode metadata and returns destination entry information. The destination
parent must exist. `removePath(path)` recursively removes a tree without following
links; it visits at most 4096 entries and 32 directory levels. A limit returns
`file_operation_limit` (413) and may leave partial deletion. Both reject the
workspace root. Artifact export remains unsupported; bounded batch writes are
provided by the explicit E2B facade below.

This is the project's native API client. E2B compatibility is a separate
versioned contract and is not claimed by this package.

## Explicit E2B 2.51.0 facade

The exported `Sandbox` accepts an authenticated native `Client` and keeps all
calls bound to one signed Linux session. It does not replace the unmodified
upstream `e2b` package.

```js
import { Sandbox } from './index.js';
const sandbox = await Sandbox.create('firecracker-linux', { client, timeoutMs: 30000 });
try {
  const info = await sandbox.files.write('/workspace/deep/hello', 'hello');
  if (!await sandbox.isRunning()) throw new Error('session ended');
  const text = await sandbox.files.read(info.path);
  const bytes = await sandbox.files.read(info.path, { format: 'bytes' });
  const exists = await sandbox.files.exists(info.path);
  const details = await sandbox.files.getInfo(info.path);
  if (details.size !== 5 || details.type !== 'file') throw new Error('file info changed');
  const entries = await sandbox.files.list('/workspace/deep');
  if (!entries.some(entry => entry.path === info.path)) throw new Error('file list changed');
} finally {
  await sandbox.kill();
}
```

The facade supports live `create`/`connect`, `isRunning`, `kill`, UTF-8 text/byte
`files.read`, `files.exists`, `files.makeDir`, in-memory text/byte `files.write`,
sequential `files.writeFiles` with at most 16 entries and 512 KiB total,
`files.rename` with destination entry information, bounded recursive `files.remove`, and
default one-level `files.list` and `files.getInfo` with type, size, Linux mode,
permissions, owner, group, and modification time. Lists and direct info calls
report symlinks and their target text without following the link. Special
inodes have an undefined type. `write` and `writeFiles` accept up to 16
printable ASCII `metadata` entries totaling 16 KiB; the guest applies them as
`user.e2b.*` xattrs before atomic replacement, and info calls return them.
Writes create missing parent directories. A failed batch may leave earlier
successful writes; do not automatically retry it. Paths remain under
`/workspace`, and each file is limited to 512 KiB. A missing target returns
`false`; authentication, permission, and transport failures propagate.
Pause/resume, streaming writes, recursive lists, custom user
or file timeout options and port URLs throw `UnsupportedCapability`. Code contexts require the signed v5 template described above.
Fixed-matrix scoring
requires both-language real KVM evidence.


## Background commands and streaming output

```js
const command = await session.startCommand({ entrypoint: '/bin/sh',
  args: ['-c', 'printf first; sleep 1; printf last'] });
for await (const event of command.events()) {
  if (event.data) consume(event.stream, event.data); // Uint8Array
  if (event.result) console.log(event.result.exitCode);
}
// session.connectCommand(command.id) reconnects; events(N) resumes after N.
// await command.kill() requests cancellation; await command.wait() confirms completion.
```

`listCommands()` returns the latest 32 command records. Completed oldest records
are evicted; observing never executes a command again. Breaking an output iterator
only detaches that observer. Background work remains bound to the session lease;
use `kill()` to request cancellation, then `wait()` for guest cleanup confirmation.
Its boolean reports whether the first cancellation request was accepted.

One command executes at a time per session; other execution and file operations
return busy while it runs. Observation and cancellation remain available. Output
uses real SSE with ordered, binary stdout/stderr events, bounded by the server's
byte policy (at most 64 KiB) and 256 data events. Truncation is explicit. `wait()`
returns a native JobResult including nonzero exits, timeout and cancellation.
Session close, TTL and lost ownership destroy the VM and its work. Session commands support `environment` and `cwd` as described below.
Interactive stdin is described below.


## Bash and E2B commands

The offline Linux template includes real static GNU Bash 5.3; the tenant must
allow `/bin/bash`. `sandbox.commands.run(cmd, options)` uses Bash `-l -c` and
supports `envs`, `cwd`, `onStdout`, `onStderr` and `background: true`.
`commands.list()` returns running commands with actual guest PIDs, arguments,
environment and cwd. `commands.connect(pid)` attaches a new observer;
`commands.kill(pid)` returns false for a missing or completed process.

```js
const handle = await sandbox.commands.run('a=(hello world); printf "%s" "${a[1]}"',
  { background: true, envs: { APP_MODE: 'offline' }, cwd: '/workspace',
    timeoutMs: 0, onStdout: text => console.log(text) });
const result = await handle.wait();
if (await handle.wait() !== result) throw new Error('cached result changed');
```

Background handles automatically consume output and callbacks. `disconnect()`
ends observation and stops callbacks; the process continues and can reconnect.
`wait()` caches the result, or throws `CommandExitError` with stdout, stderr,
exitCode and optional error for a nonzero exit. `timeoutMs` defaults to 60000;
zero adds no observation deadline. `TimeoutException` ends observation without
killing the process; server execution limits and the session TTL still apply.
Custom users and PTY remain unsupported.

Native session commands accept `environment` and `cwd`. Environment has at most
32 ASCII-identifier keys, 8 KiB total and 1 KiB per value. Cwd is an absolute guest
path up to 1024 bytes, checked after dropping privileges; missing or inaccessible
directories fail to start. Defaults remain `/workspace`, and state does not leak
to later commands. The capability flags are `session_environment` and
`session_working_directory`; one-shot Linux job fields are described below.


## Interactive stdin

Start native commands with `interactiveStdin: true`, or E2B commands with
`stdin: true, background: true`. The default closes stdin; the capability is
`interactive_stdin`. One-shot jobs and synchronous session.run keep their
existing contract and cannot enable interactive input.

```js
const handle = await sandbox.commands.run('cat', { background: true, stdin: true, timeoutMs: 0 });
await sandbox.commands.sendStdin(handle.pid, 'hello\n');
await handle.sendStdin(new Uint8Array([0, 255]));
await handle.closeStdin();
const result = await handle.wait();
```

Native handles also offer `sendStdin(bytes, options)` and `closeStdin(options)`;
E2B command/PID and handle methods accept text or Uint8Array and return void.
Input has a 16 KiB chunk limit, 1 MiB/256 transactions per command, and one pending
transaction. Additional pending input returns 429 busy. Writes after EOF return
409 stdin_closed; disabled input returns 409 stdin_unavailable; missing or exited
processes return 404. A child closing its read end reports delivery failure.
An ack means bytes entered the pipe, not that the application consumed them.

Slow readers do not block output or cancellation. Observer disconnect leaves
input open. `requestTimeoutMs` limits the current input submission/confirmation
wait; it never retries or kills the process. A failed POST may already have taken
effect. Native `submitStdin(bytes, { close })` returns a sequence-bound receipt;
`pollStdin(sequence)` safely observes pending/delivered/closed/failed and actual
written_bytes. Continue polling a known ticket after an observation timeout.
A transport failure without a ticket has an uncertain outcome; use application
idempotency or cancel the command instead of blindly repeating input. Existing
execution limits and session TTL still apply.


## Session listing, metadata and timeout

```js
await sandbox.setTimeout(30000); // reset remaining milliseconds; returns void
const info = await sandbox.getInfo();
console.log(info.sandboxId, info.memoryMB, info.cpuCount, info.endAt, info.maxEndAt);
const pages = Sandbox.list({ client, limit: 10, order: 'desc' });
while (pages.hasNext) {
  for (const item of await pages.nextItems()) console.log(item.sandboxId, item.state);
}
```

Native `client.listSessions({ limit, cursor, order })` returns sessions and
nextCursor; `session.setTimeout(ttlMs)` returns fresh metadata. E2B paginators
resume with nextToken. Listing is tenant-bound, ordered globally by creation
time, with 1..100 entries per page. A bounded ID snapshot excludes later creates;
later pages skip deleted/expired IDs and refresh live metadata. Snapshots last
30 seconds, at most 8 per tenant/128 globally. Expired/evicted/foreign cursors
fail explicitly. Concurrent advances of one paginator are rejected.

Remaining TTL is 1..300 seconds per update. session_max_lifetime_ms can lower
the immutable VM lifetime cap (at most 600 seconds by default). Warm sessions
also retain the verified original host/guest remaining lifetime minus a guard.
maxEndAt is the actual immutable bound. Beyond it, updates return
400 timeout_exceeds_lifetime rather than silently clipping. An initial short
TTL can extend; shortening/expiry destroys active work and the VM. Per-command
execution limits remain independent, and expired/foreign sessions return 404.
Uncertain cleanup retains the existing temporary tenant quota quarantine.

Info includes actual identity, template, CPU/memory and lifecycle dates.
The compatibility field envdVersion reports this project's fc-agent protocol
(v2/v3); the project does not run envd. This is the explicit facade. Paused
resume, metadata filtering and custom request options remain unsupported.

## Linux one-shot job inputs

Cold and pristine warm jobs accept `environment`, `cwd` and fixed `stdin: Uint8Array`.
The corresponding capability flags are `environment`, `working_directory` and `stdin`.

```js
const result = await client.run({entrypoint:'/bin/sh',
  args:['-c','printf "%s|%s|" "$KEY" "$PWD"; wc -c'],
  environment:{KEY:'offline'},cwd:'/input',stdin:new Uint8Array([0,255]),
  inputFiles:[{path:'marker',data:new TextEncoder().encode('data')}]});
console.log(result.guestResult,result.startupMode);
```

The environment allows 32 entries/8 KiB total, 64-byte names and 1 KiB values.
The child starts with a clean environment plus default PATH/HOME/LANG and this job's
variables. `cwd` is an absolute guest path, at most 1024 bytes, applied after dropping
privileges; missing or inaccessible directories fail execution without fallback.
The default is `/workspace`. OSv still rejects cwd and reserved loader/OSV variables
and requires its signed agent features.

Fixed stdin is limited to 16 KiB. An explicit empty array produces pipe EOF;
omission uses `/dev/null`. Nonblocking input delivery shares output draining and
deadline supervision; completing delivery closes the pipe. Programs may ignore input,
and success does not assert consumption of every byte. This does not enable interactive
job input or retries. Each job uses a fresh VM. `startupMode` preserves only an actual
server-reported warm/cold value and remains undefined when an older cold path omits it;
it is functional information, not performance evidence.

## 受控网络 fetch

`await client.fetchNetwork(url, {method:"POST", body:new Uint8Array([123,125]), headers:{"Content-Type":"application/json"}, timeoutMs:10000})` 使用同一认证 API，返回 `NetworkFetchResult` 的上游 `status`、二进制 `body`、报头和有界计数。远端4xx/5xx仍返回真实HTTP结果；策略/配额/上游连接失败使用既有APIError。缺省不跟随重定向，不自动重试。先检查 capabilities 的 `network_fetch_policy`；没有授权时抛UnsupportedCapability。它不修改guest网络。见[egress配置](../../docs/EGRESS.zh-CN.md)。


## Multiple signed templates

`client.templates()` discovers installed, tenant-visible templates and their availability.
`client.capabilities({template})` queries the selected backend and signed digest.
Omitting a selector uses the configured default; an unavailable or hidden default
never selects a different template automatically.

```javascript
const catalog = await client.templates();
const entry = catalog.templates.find(row => row.available && row.capabilities.backend === 'firecracker-osv');
const cap = entry.capabilities;
const template = {backend: cap.backend, artifactManifestSha256: cap.artifact_manifest_sha256};
const value = await client.run({entrypoint: '/python3.12.so', args: ['-c', 'import numpy; print(numpy.arange(4).sum())'], memoryMiB: 512}, {template});
console.log(value.guestResult, value.templateId, value.artifactManifestSha256);
```

New signed job responses include the actual template binding, which the client checks.
Older responses may omit these fields. Proxy authorization uses the selected live
capability. Linux session and E2B command operations use the session's bound template.
The OSv science template currently supports x64 one-shot jobs; inspect its own capabilities.
See [ADR-0060](../../docs/adr/0060-multi-template-catalog-and-shared-capacity.md).

## Native TCP ports

`session.ports` requires a signed Linux v6 port capability and an explicit tenant
port policy. It connects only to IPv4 loopback inside the same VM, using the
client's existing mTLS, CA and bearer over HTTP/1.1. No external Node dependencies
are added. rc74 does not ship ports; see the [port contract](../../docs/contracts/port-tunnel-v1.md)
for protocol and candidate validation status.

```js
const tunnel = await session.ports.open(8080, {
  maxBytes: 1 << 20, timeoutMs: 10000, idleTimeoutMs: 5000,
});
try {
  await tunnel.write(new TextEncoder().encode('GET / HTTP/1.0\r\n\r\n'));
  await tunnel.closeWrite();
  for (;;) {
    const frame = await tunnel.readFrame();
    if (frame.kind === 'data') await consumeBytes(frame.data);
    if (frame.kind === 'finished') {
      if (frame.info.status !== 'completed') throw new Error(frame.info.error);
      break;
    }
    // Application EOF still requires FINISHED; reverse writes remain possible.
  }
} finally { tunnel.close(); }
```

One read and one write may run concurrently, with no background output queue.
Each write is 1..16384 bytes; `closeWrite()` sends protocol EOF rather than a TLS
half-close. `requestTimeoutMs` bounds negotiation/control requests; `timeoutMs`
includes negotiation and closes an otherwise idle local transport. It does not
extend the session lease. Bytes are never replayed after uncertainty.

An open error retains `error.connection` with its known ID and port. Supply an
explicit 24-character lowercase hex `connectionId`, or construct
`session.ports.connection(port, id)` to call `info()`/`cancel()` without reopening.
These independent controls bypass data locks and new admission discovery, and
support cancel-before-open. A cancellation ACK may still be `cancelling`; query
the terminal state. Missing FINISHED is unconfirmed. Local `close()` does not
prove guest cleanup. Handle inspection/JSON excludes credentials and transport.

## 浏览器预览授权

在报告 features.port_preview 的 v6 Linux 会话中，调用 `const grant = await session.ports.createPreview(8080, {ttlMs: 60000})`，向获授权的浏览器提供 `grant.bootstrapURL`。URL 是一次性凭据，不要记录到日志。`await grant.info()` 查询状态，`await grant.revoke()` 撤销授权；查询不重发 secret、不延长租期。授权归 API 会话所有，客户端进程退出不会撤销。

创建只发一次 POST，异常的非枚举 `error.preview` 保留已知 ID。`session.ports.preview(8080, previewId)` 可从另一个进程取得查询/撤销句柄。结果未知时不能重放创建；先查询或撤销原 ID，再选新 ID，旧 bootstrap secret 无法恢复。requestTimeoutMs 缺省 10000，且受客户端请求上限约束。TTL 为 1000..300000ms，并受创建时会话剩余租期限制。撤销只证明授权撤销，guest 连接清理使用原端口生命周期门禁。

离线入口的配置、DNS/TLS 和限制见项目与安装包内 `docs/PREVIEW.zh-CN.md`。rc74 尚不包含此功能，新候选须完成整包验收。原生预览未映射为 E2B get_host，兼容矩阵仍为 28/34。
# 会话产物归档

源码新增 `createArtifact/readArtifact/downloadArtifact/deleteArtifact`，仅新签名 Linux v8 的 `workspace-artifacts-v1` 模板支持。新离线包与实机验收仍待完成，rc90 不含本节功能。额度为每会话两个归档、每个含开销最多 32 MiB、1024 条目；块读取最多 512 KiB。

```js
const artifact = await session.createArtifact('/workspace/results');
try {
  const bytes = await session.downloadArtifact(artifact);
  // bytes 是校验每块及整体 SHA256 后的 tar Buffer，可按应用需求保存。
} finally {
  await session.deleteArtifact(artifact.id);
}
```

下载不自动解包，不重放创建；`readArtifact(id, offset, length)` 返回 base64、块与归档 SHA256、总大小和 EOF。缓存随会话关闭释放；创建时检测普通文件变化并明确失败，不承诺运行中文件树的原子快照。`options.signal` 可取消读取而保留 VM；创建中断沿用会话清理语义。
