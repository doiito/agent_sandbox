#!/usr/bin/env node
/** Installed offline Node SDK -> mTLS API -> launcher -> KVM acceptance. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}
const root = argument('--root');
const packagePath = argument('--package');
assert.match(root, /^\/var\/lib\/osv-offline-validation-20261030-[a-z0-9]+$/);
if (!process.argv.includes('--in-netns')) {
  const unit = root.split('/').at(-1) + '-api.service';
  const shown = spawnSync('systemctl', ['show', '-p', 'MainPID', '--value', unit], { encoding: 'utf8' });
  assert.equal(shown.status, 0);
  const pid = Number(shown.stdout.trim());
  assert.ok(Number.isSafeInteger(pid) && pid > 1);
  const run = spawnSync('nsenter', ['-t', String(pid), '-n', process.execPath, process.argv[1],
    '--root', root, '--package', packagePath, '--in-netns',
    ...(process.argv.includes('--expect-doctor-ready') ? ['--expect-doctor-ready'] : [])], { stdio: 'inherit' });
  process.exit(run.status ?? 1);
}

const jobDirs = path => readdirSync(path).filter(x => x.startsWith('job-')).sort();
assert.deepEqual(jobDirs(join(root, 'run')), []);
const releases = readdirSync(join(root, 'releases'));
assert.equal(releases.length, 1);
const sdkPath = join(root, 'releases', releases[0], 'sdk/node/index.js');
const { Client, ConfigurationError, TemplateMismatch, APIError, Sandbox,
  UnsupportedCapability, Session, CommandExitError, TimeoutException } = await import(pathToFileURL(sdkPath).href);
const config = JSON.parse(readFileSync(join(root, 'config.production.json'), 'utf8'));
assert.equal(config.run_root, join(root, 'run'));
const port = config.listen.split(':').at(-1);
const options = { token: readFileSync(join(root, 'secrets/token'), 'utf8'),
  caFile: join(root, 'tls/ca.crt'), certFile: join(root, 'tls/client.crt'),
  keyFile: join(root, 'tls/client.key'), requestTimeoutMs: 65000 };
const url = `https://localhost:${port}`;
const client = new Client(url, options);
const report = await client.capabilities();
assert.equal(report.backend, 'firecracker-linux');
assert.equal(report.artifact_authenticated, true);
assert.ok(report.methods.includes('POST /v2/jobs'));
const doctor = await client.doctor();
assert.equal(doctor.ready, process.argv.includes('--expect-doctor-ready'));

const result = await client.run({ entrypoint: '/bin/sh',
  args: ['-c', 'cat /input/prompt.txt'], timeoutMs: 30000,
  inputFiles: [{ path: 'prompt.txt', data: new TextEncoder().encode('node-sdk-e2e') }] });
assert.equal(result.succeeded, true);
assert.equal(result.guestResult.stdout, 'node-sdk-e2e');
assert.equal(result.guestResult.job_id, result.id);
assert.deepEqual(jobDirs(join(root, 'run')), []);

const wrong = report.artifact_manifest_sha256 === '0'.repeat(64) ? '1'.repeat(64) : '0'.repeat(64);
await assert.rejects(client.run({ entrypoint: '/bin/sh', args: ['-c', 'printf should-not-run'] },
  { template: { backend: report.backend, artifactManifestSha256: wrong } }),
error => error instanceof TemplateMismatch && error.status === 409 && error.code === 'template_mismatch');
assert.deepEqual(jobDirs(join(root, 'run')), []);
const denied = new Client(url, { ...options, token: 'invalid-test-token' });
await assert.rejects(denied.capabilities(), error => error instanceof APIError && error.status === 401);
assert.deepEqual(jobDirs(join(root, 'run')), []);
assert.equal(report.features.sessions, true);
assert.ok(report.methods.includes('POST /v2/sessions'));
const session = await client.createSession({ ttlMs: 30000 });
let second;
try {
  const first = await session.run({ entrypoint: '/bin/sh',
    args: ['-c', 'printf node-session > /workspace/sdk-marker'] });
  assert.equal(first.succeeded, true);
  const connected = await client.connectSession(session.id);
  assert.equal((await connected.info()).id, session.id);
  second = await connected.run({ entrypoint: '/bin/sh',
    args: ['-c', 'cat /workspace/sdk-marker'] });
  assert.equal(second.succeeded, true);
  assert.equal(second.guestResult.stdout, 'node-session');
  assert.equal(report.features.session_files, true);
  assert.ok(report.methods.includes('POST /v2/sessions/{id}/files'));
  const binary = Uint8Array.from({ length: 256 * 2048 }, (_, index) => index % 256);
  assert.equal(await session.writeFile('/workspace/sdk-bytes', binary), binary.byteLength);
  assert.deepEqual(Buffer.from(await connected.readFile('/workspace/sdk-bytes')), Buffer.from(binary));
  const counted = await session.run({ entrypoint: '/bin/sh',
    args: ['-c', '/bin/busybox wc -c /workspace/sdk-bytes'] });
  assert.equal(counted.succeeded, true);
  assert.ok(counted.guestResult.stdout.includes(String(binary.byteLength)));
  const listed = await session.listFiles();
  assert.ok(listed.includes('sdk-bytes') && listed.includes('sdk-marker'));
  assert.deepEqual(await session.statFile('/workspace/sdk-bytes'), { kind: 'file', size: binary.byteLength });
  assert.deepEqual(await session.statFile('/workspace'), { kind: 'directory', size: 0 });
  assert.equal(await session.writeFile('/workspace/delete-me', new TextEncoder().encode('gone')), 4);
  await session.deleteFile('/workspace/delete-me');
  await assert.rejects(session.readFile('/workspace/delete-me'),
    error => error instanceof APIError && error.status === 404 && error.code === 'file_not_found');
  await assert.rejects(session.writeFile('/workspace/too-large', new Uint8Array(binary.byteLength + 1)),
    ConfigurationError);
  await assert.rejects(client._exchange('POST', `/v2/sessions/${session.id}/files`, {
    action: 'write', path: '/workspace/too-large',
    data_base64: Buffer.alloc(binary.byteLength + 1).toString('base64') }),
  error => error instanceof APIError && error.status === 413 && error.code === 'file_too_large');
  await assert.rejects(session.readFile('/workspace/missing'),
    error => error instanceof APIError && error.status === 404 && error.code === 'file_not_found');
  const linked = await session.run({ entrypoint: '/bin/sh',
    args: ['-c', '/bin/busybox ln -s /etc/passwd /workspace/sdk-link'] });
  assert.equal(linked.succeeded, true);
  await assert.rejects(session.readFile('/workspace/sdk-link'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(session.writeFile('/workspace/sdk-link', new Uint8Array([65])),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(session.statFile('/workspace/sdk-link'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(session.deleteFile('/workspace/sdk-link'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(session.readFile('/workspace/../etc/passwd'), ConfigurationError);
  await assert.rejects(sdkFileRaw(client, session.id, '/workspace/../etc/passwd'),
    error => error instanceof APIError && error.status === 400 && error.code === 'invalid_path');
  const tenantB = new Client(url, { ...options,
    token: readFileSync(join(root, 'secrets/token-b'), 'utf8') });
  await assert.rejects(tenantB.connectSession(session.id),
    error => error instanceof APIError && error.status === 404);
  await assert.rejects(sdkFileRaw(tenantB, session.id, '/workspace/sdk-bytes'),
    error => error instanceof APIError && error.status === 404);
} finally {
  await session.close();
}
await assert.rejects(client.connectSession(session.id),
  error => error instanceof APIError && error.status === 404);
assert.deepEqual(jobDirs(join(root, 'run')), []);
const cgroup = join('/sys/fs/cgroup', root.split('/').at(-1));
assert.deepEqual(jobDirs(cgroup), []);

const background = await exerciseCommands(client, new Client(url, { ...options, token: readFileSync(join(root, 'secrets/token-b'), 'utf8') }));
assert.deepEqual(jobDirs(join(root, 'run')), []);
assert.deepEqual(jobDirs(cgroup), []);

const facade = await Sandbox.create('firecracker-linux', { client, timeoutMs: 90000 });
const facadeId = facade.sandboxId;
let ended = false;
let e2bCommands, interactiveStdin;
try {
  assert.equal(await facade.isRunning(), true);
  assert.equal((await Sandbox.connect(facadeId, { client })).sandboxId, facadeId);
  const native = await client.connectSession(facadeId);
  assert.equal(await native.writeFile('/workspace/e2b-text', new TextEncoder().encode('hello-e2b')), 9);
  assert.equal(await facade.files.read('/workspace/e2b-text'), 'hello-e2b');
  assert.deepEqual(Buffer.from(await facade.files.read('/workspace/e2b-text', { format: 'bytes' })),
    Buffer.from('hello-e2b'));
  assert.equal(await facade.files.exists('/workspace/e2b-text'), true);
  assert.equal(await facade.files.exists('/workspace/missing'), false);
  const linked = await native.run({ entrypoint: '/bin/sh',
    args: ['-c', '/bin/busybox ln -s /etc/passwd /workspace/e2b-link'] });
  assert.equal(linked.succeeded, true);
  const tagged = await facade.files.write('/workspace/e2b-meta', 'tagged',
    { metadata: { label: 'proof' } });
  assert.deepEqual(tagged.metadata, { label: 'proof' });
  assert.equal(Buffer.from(await native.readFile('/workspace/e2b-meta')).toString(), 'tagged');
  await assert.rejects(facade.files.write('/workspace/e2b-meta', 'bad',
    { metadata: { 'bad key': 'x' } }), ConfigurationError);
  assert.equal(Buffer.from(await native.readFile('/workspace/e2b-meta')).toString(), 'tagged');
  const listedInfo = await facade.files.list('/workspace');
  const textInfo = listedInfo.find(item => item.name === 'e2b-text');
  const linkInfo = listedInfo.find(item => item.name === 'e2b-link');
  const metaInfo = listedInfo.find(item => item.name === 'e2b-meta');
  assert.ok(textInfo && textInfo.path === '/workspace/e2b-text' &&
    textInfo.type === 'file' && textInfo.size === 9 &&
    textInfo.permissions.length === 9 && textInfo.owner && textInfo.group &&
    textInfo.modifiedTime instanceof Date && Number.isFinite(textInfo.modifiedTime.getTime()));
  assert.ok(linkInfo && linkInfo.type === 'symlink' && linkInfo.symlinkTarget === '/etc/passwd');
  assert.deepEqual(metaInfo?.metadata, { label: 'proof' });
  assert.deepEqual(await facade.files.getInfo('/workspace/e2b-text'), textInfo);
  assert.deepEqual(await facade.files.getInfo('/workspace/e2b-link'), linkInfo);
  assert.deepEqual(await facade.files.getInfo('/workspace/e2b-meta'), metaInfo);
  assert.equal((await facade.files.getInfo('/workspace')).type, 'dir');
  await assert.rejects(facade.files.list('/workspace/e2b-link'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(facade.files.getInfo('/workspace/missing'),
    error => error instanceof APIError && error.status === 404 && error.code === 'file_not_found');
  assert.equal(await facade.files.makeDir('/workspace/e2b-deep/a'), true);
  assert.equal(await facade.files.makeDir('/workspace/e2b-deep/a'), false);
  const single = await facade.files.write('/workspace/e2b-deep/new/single', 'hello');
  assert.deepEqual(single, { name: 'single', path: '/workspace/e2b-deep/new/single', type: 'file' });
  assert.equal(Buffer.from(await native.readFile(single.path)).toString(), 'hello');
  const batch = await facade.files.writeFiles([
    { path: '/workspace/e2b-deep/batch/one', data: '1' },
    { path: '/workspace/e2b-deep/batch/two', data: new Uint8Array([50]) }]);
  assert.deepEqual(batch.map(item => item.name), ['one', 'two']);
  assert.equal(Buffer.from(await native.readFile(batch[0].path)).toString(), '1');
  assert.equal(Buffer.from(await native.readFile(batch[1].path)).toString(), '2');
  await assert.rejects(facade.files.makeDir('/workspace/e2b-link/sub'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(facade.files.write('/workspace/e2b-link/escape', 'bad'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(facade.files.writeFiles([
    { path: '/workspace/e2b-deep/partial', data: 'safe' },
    { path: '/workspace/e2b-link/escape', data: 'bad' }]),
  error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  assert.equal(Buffer.from(await native.readFile('/workspace/e2b-deep/partial')).toString(), 'safe');
  await assert.rejects(facade.files.exists('/workspace/e2b-link'),
    error => error instanceof APIError && error.status === 403 && error.code === 'file_denied');
  await assert.rejects(facade.files.read('/workspace/missing'),
    error => error instanceof APIError && error.status === 404 && error.code === 'file_not_found');
  const renamed = await facade.files.rename('/workspace/e2b-meta', '/workspace/e2b-deep/tagged');
  assert.equal(renamed.name, 'tagged');
  assert.equal(renamed.path, '/workspace/e2b-deep/tagged');
  assert.equal(renamed.type, 'file');
  assert.deepEqual(renamed.metadata, { label: 'proof' });
  assert.equal(Buffer.from(await native.readFile(renamed.path)).toString(), 'tagged');
  assert.equal(await facade.files.exists('/workspace/e2b-meta'), false);
  await assert.rejects(facade.files.rename('/workspace/e2b-deep', '/workspace/e2b-deep/a/invalid'),
    error => error instanceof APIError && error.status === 409 && error.code === 'file_conflict');
  const moved = await facade.files.rename('/workspace/e2b-deep', '/workspace/e2b-moved');
  assert.equal(moved.type, 'dir');
  assert.equal(moved.path, '/workspace/e2b-moved');
  assert.equal(await facade.files.read('/workspace/e2b-moved/new/single'), 'hello');
  const link = await facade.files.rename('/workspace/e2b-link', '/workspace/e2b-moved/external');
  assert.equal(link.type, 'symlink');
  assert.equal(link.symlinkTarget, '/etc/passwd');
  assert.equal(await facade.files.remove('/workspace/e2b-moved'), undefined);
  assert.equal(await facade.files.exists('/workspace/e2b-moved'), false);
  assert.equal(await facade.files.read('/workspace/e2b-text'), 'hello-e2b');
  const sentinel = await native.run({ entrypoint: '/bin/sh',
    args: ['-c', '/bin/busybox test -s /etc/passwd'] });
  assert.equal(sentinel.succeeded, true);
  await assert.rejects(facade.files.rename('/workspace/missing', '/workspace/no-source'),
    error => error instanceof APIError && error.status === 404 && error.code === 'file_not_found');
  await assert.rejects(facade.files.remove('/workspace/e2b-moved'),
    error => error instanceof APIError && error.status === 404 && error.code === 'file_not_found');
  await assert.rejects(Sandbox.create('base', { client }), UnsupportedCapability);
  e2bCommands = await exerciseE2BCommands(facade, native, new Client(url, { ...options, token: readFileSync(join(root, 'secrets/token-b'), 'utf8') }));
  interactiveStdin = await exerciseInteractiveStdin(facade,native,new Client(url, { ...options, token: readFileSync(join(root, 'secrets/token-b'), 'utf8') }));
  assert.equal(await facade.kill(), true);
  ended = true;
  assert.equal(await facade.isRunning(), false);
  assert.equal(await facade.kill(), false);
} finally {
  if (!ended) await facade.kill();
}
assert.deepEqual(jobDirs(join(root, 'run')), []);
assert.deepEqual(jobDirs(cgroup), []);

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const packageSha = hash(readFileSync(packagePath));
const e2bCases = {
  'commands.send_stdin': ['PID/handle text and binary input matched persisted bytes; reconnect retained input', 'disabled/closed stdin, missing PID, cross tenant and size quota rejected'],
  'commands.close_stdin': ['empty and populated stdin EOF confirmed; buffered bytes retained', 'disabled/missing/foreign process rejected; writing after EOF failed'],
  'commands.run': ['real Bash arrays, env/cwd and callbacks matched result', 'exit 7 raised typed exception with stdout/stderr'],
  'commands.list': ['only actual running guest PID and process metadata returned', 'foreign tenant list returned 404'],
  'commands.connect': ['disconnected and timed-out observers reattached to running PID', 'unknown and foreign PID returned 404'],
  'commands.kill': ['SIGKILL confirmed by exit 137; session reused', 'repeat kill false and foreign tenant returned 404'],
  'command_handle.wait': ['cached result and UTF-8 callbacks; one execution', 'exit error and observation timeout typed distinctly'],
  'sandbox.create': ['signed firecracker-linux session retained one ID',
    'unsupported base template rejected'],
  'sandbox.is_running': ['live session reported true', 'terminated session reported false'],
  'sandbox.kill': ['live session terminated and resources cleared', 'repeat kill reported false'],
  'files.read': ['UTF-8 text and bytes matched native file bytes',
    'missing file returned 404 file_not_found'],
  'files.exists': ['existing file true and missing file false',
    'symlink returned 403 file_denied'],
  'files.make_dir': ['nested directory created then existing returned false',
    'symlink parent returned 403 file_denied'],
  'files.write': ['text write auto-created parent and returned bound WriteInfo',
    'symlink parent returned 403 file_denied'],
  'files.write_files': ['ordered two-file batch created parents and retained bytes',
    'second denied write left earlier success without escape'],
  'files.list': ['directory returned file, symlink and xattr metadata',
    'symlink directory returned 403 file_denied'],
  'files.get_info': ['file, symlink and xattr info matched list',
    'missing path returned 404 file_not_found'],
  'files.rename': ['file, directory and symlink moved; bytes and xattr metadata retained',
    'missing source returned 404; self-descendant directory returned 409'],
  'files.remove': ['nested directory tree removed without following external link',
    'repeat remove returned 404 file_not_found'],
};
const evidenceDir = join(root, 'results/e2b-2.51.0');
mkdirSync(evidenceDir, { recursive: true });
for (const [operation, [success, failure]] of Object.entries(e2bCases)) {
  const operationReport = { suite: 'e2b-compat-case/v1', operation,
    language: 'typescript', upstream_commit: 'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b',
    candidate_sha256: packageSha, environment: 'real-kvm', adapter: 'sdk/node.Sandbox',
    official_sdk_unmodified: false, sandbox_id: facadeId,
    cases: [{ name: 'success', passed: true, detail: success },
      { name: 'failure', passed: true, detail: failure }], passed: true };
  writeFileSync(join(evidenceDir, `typescript-${operation}.json`),
    JSON.stringify(operationReport, null, 2) + '\n');
}
const evidence = { suite: 'node-sdk-kvm/v8', generated_at: new Date().toISOString(),
  package_sha256: packageSha, installed_sdk_sha256: hash(readFileSync(sdkPath)),
  background_commands: background, e2b_commands: e2bCommands, interactive_stdin: interactiveStdin,
  backend: report.backend, manifest_sha256: report.artifact_manifest_sha256,
  doctor_ready: doctor.ready, doctor_expected_ready: process.argv.includes('--expect-doctor-ready'),
  job: { id: result.id, state: result.state,
    protocol_ok: result.protocolOk, stdout: result.guestResult.stdout },
  stale_template_status: 409, bad_token_status: 401,
  session: { id: session.id, workspace_stdout: second.guestResult.stdout,
    cross_tenant_status: 404, closed_status: 404 },
  file: { bytes: 256 * 2048, binary_roundtrip: true, command_observed: true,
    list_contains_files: true, stat_file_size: 256 * 2048, stat_root_kind: 'directory',
    delete_then_missing_status: 404, symlink_stat_status: 403, symlink_delete_status: 403,
    oversized_status: 413,
    missing_status: 404, symlink_read_status: 403, symlink_write_status: 403,
    traversal_status: 400, cross_tenant_status: 404 },
  remaining_workdirs: jobDirs(join(root, 'run')), remaining_cgroups: jobDirs(cgroup), passed: true };
writeFileSync(join(root, 'results/node-sdk.json'), JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify({ passed: true, job_state: result.state,
  stale_template_status: 409, bad_token_status: 401 }));

async function sdkFileRaw(sdk, id, path) {
  return sdk._exchange('POST', `/v2/sessions/${id}/files`, { action: 'read', path });
}


async function exerciseCommands(client, tenantB) {
  const session = await client.createSession({ ttlMs: 90000 });
  const cases = [];
  function check(name, value) { assert.ok(value, name); cases.push(name); }
  try {
    const caps = await client.capabilities();
    check('capability', caps.features.background_commands && caps.features.streaming_output);
    await session.writeFile('/workspace/persistent', Buffer.from('preserved'));
    const command = await session.startCommand({ entrypoint: '/bin/sh', args: ['-c',
      "sleep 30 & echo $! > /workspace/background-pid; printf once >> /workspace/exec-count; " +
      "printf '\\000\\377first'; printf error >&2; sleep 30"], timeoutMs: 20000 });
    const stream = command.events();
    const first = (await stream.next()).value;
    check('live-output-before-exit', !first.result && (await command.poll()).info.state === 'running');
    await stream.return();
    check('observer-disconnect-preserves-command', (await (await session.connectCommand(command.id)).poll()).info.state === 'running');
    check('list-and-connect', (await session.listCommands()).some(row => row.id === command.id));
    await assert.rejects(session.startCommand({ entrypoint: '/bin/sh', args: ['-c', 'printf forbidden-parallel'] }),
      error => error instanceof APIError && error.status === 429);
    cases.push('one-running-command-limit');
    check('cancel-accepted', await command.kill());
    check('repeat-cancel-false', !(await command.kill()));
    check('cancel-confirmed', (await command.wait()).state === 'cancelled');
    const replay = [];
    for await (const event of command.events()) replay.push(event);
    const stdout = Buffer.concat(replay.filter(e => e.stream === 'stdout').map(e => Buffer.from(e.data)));
    const stderr = Buffer.concat(replay.filter(e => e.stream === 'stderr').map(e => Buffer.from(e.data)));
    check('binary-output-and-stderr', stdout.equals(Buffer.concat([Buffer.from([0, 255]), Buffer.from('first')])) && stderr.toString() === 'error');
    const resumed = [];
    for await (const event of command.events(first.sequence)) resumed.push(event);
    check('cursor-resume', resumed.filter(e => !e.result).every(e => e.sequence > first.sequence) && resumed.at(-1).result.state === 'cancelled');
    const follow = await session.run({ entrypoint: '/bin/sh', args: ['-c',
      'if kill -0 $(cat /workspace/background-pid) 2>/dev/null; then exit 9; fi; printf continued'] });
    check('descendants-reaped-and-session-reused', follow.succeeded && follow.guestResult.stdout === 'continued');
    check('workspace-retained', Buffer.from(await session.readFile('/workspace/persistent')).toString() === 'preserved');
    const failed = await session.startCommand({ entrypoint: '/bin/sh', args: ['-c', 'printf out; printf err >&2; exit 7'] });
    const final = await failed.wait();
    check('nonzero-terminal', final.state === 'guest_error' && final.exitCode === 7 && final.guestResult.stdout === 'out' && final.guestResult.stderr === 'err');
    const timed = await (await session.startCommand({ entrypoint: '/bin/sh', args: ['-c', 'sleep 30'], timeoutMs: 200 })).wait();
    check('guest-timeout', timed.state === 'timed_out' && timed.timedOut);
    const flood = await session.startCommand({ entrypoint: '/bin/sh', args: ['-c', '/bin/busybox yes x | /bin/busybox head -c 200000'] });
    const flooded = [];
    for await (const event of flood.events()) flooded.push(event);
    check('bounded-flood', flooded.at(-1).result.succeeded && flooded.at(-1).result.outputTruncated && flooded.length <= 257 &&
      flooded.reduce((sum, event) => sum + (event.data?.length ?? 0), 0) <= caps.limits.command_output_bytes);
    const path = `/v2/sessions/${session.id}/commands`;
    for (const [method, suffix] of [['GET', ''], ['GET', '/' + command.id], ['GET', '/' + command.id + '/events'], ['DELETE', '/' + command.id]]) {
      await assert.rejects(tenantB._exchange(method, path + suffix), error => error instanceof APIError && error.status === 404);
      cases.push('cross-tenant-' + method + suffix);
    }
    for (let index = 0; index < 33; index++) {
      check('history-command-' + index, (await (await session.startCommand({ entrypoint: '/bin/sh', args: ['-c', ':'] })).wait()).succeeded);
    }
    check('bounded-command-history', (await session.listCommands()).length === 32);
    await assert.rejects(session.connectCommand(command.id), error => error instanceof APIError && error.status === 404 && error.code === 'command_not_found');
    cases.push('old-handle-evicted');
    check('observation-does-not-reexecute', Buffer.from(await session.readFile('/workspace/exec-count')).toString() === 'once');
    await session.startCommand({ entrypoint: '/bin/sh', args: ['-c', 'sleep 30'] });
  } finally {
    await session.close();
  }
  return { passed: true, cases, case_count: cases.length, active_command_closed_with_session: true };
}

async function exerciseE2BCommands(facade, native, tenantB) {
  const cases = [];
  function check(name, value) { assert.ok(value, name); cases.push(name); }
  async function failed(handle, code) {
    try { await handle.wait(); } catch (error) {
      assert.ok(error instanceof CommandExitError);
      check('exit-exception-' + code, error.exitCode === code);
      return error;
    }
    throw new Error('nonzero command did not raise');
  }
  check('command-directory', await facade.files.makeDir('/workspace/command-work'));
  const out = [], err = [];
  let value = await facade.commands.run(
    'a=(one two); read -r p < <(printf process); [[ $p == process ]] || exit 8; printf "%s|%s|%s" "${a[1]^^}" "$SDK_KEY" "$PWD"; ' +
    'printf once >> /workspace/command-count; printf warning >&2',
    { envs: { SDK_KEY: '环境' }, cwd: '/workspace/command-work', onStdout: text => out.push(text), onStderr: text => err.push(text) });
  check('bash-env-cwd-callbacks', value.exitCode === 0 && value.stdout === 'TWO|环境|/workspace/command-work' &&
    value.stderr === 'warning' && out.join('') === value.stdout && err.join('') === value.stderr);
  value = await facade.commands.run('printf "%s|%s" "${SDK_KEY-unset}" "$PWD"');
  check('env-cwd-do-not-leak', value.stdout === 'unset|/workspace');
  const error = await failed(await facade.commands.run('printf out; printf err >&2; exit 7', { background: true }), 7);
  check('nonzero-fields', error.stdout === 'out' && error.stderr === 'err');
  const callbacks = [];
  const cached = await facade.commands.run('printf cached', { background: true, onStdout: text => callbacks.push(text) });
  const first = await cached.wait();
  check('cached-wait', await cached.wait() === first && callbacks.join('') === 'cached' &&
    Buffer.from(await native.readFile('/workspace/command-count')).toString() === 'once');
  const liveCallbacks = [];
  const live = await facade.commands.run('printf "%s" "$$"; sleep 30',
    { background: true, envs: { SDK_KEY: 'live' }, cwd: '/workspace/command-work', timeoutMs: 0, onStdout: text => liveCallbacks.push(text) });
  for (let index = 0; !liveCallbacks.length && index < 200; index++) await new Promise(resolve => setTimeout(resolve, 10));
  check('background-callback-before-exit', liveCallbacks.join('') === String(live.pid));
  const rows = await facade.commands.list();
  check('list-real-running-pid', rows.length === 1 && rows[0].pid === live.pid && rows[0].cmd === '/bin/bash' &&
    rows[0].args[0] === '-l' && rows[0].args[1] === '-c' && rows[0].envs.SDK_KEY === 'live' && rows[0].cwd === '/workspace/command-work');
  await live.disconnect();
  const snapshot = liveCallbacks.join('');
  check('disconnect-preserves-process', (await facade.commands.list())[0]?.pid === live.pid);
  const attached = await facade.commands.connect(live.pid, { timeoutMs: 0 });
  check('kill-live-pid', await facade.commands.kill(live.pid));
  const killed = await failed(attached, 137);
  check('started-pid-matches-bash', killed.stdout === String(live.pid));
  check('disconnect-stops-callbacks', liveCallbacks.join('') === snapshot);
  check('repeat-kill-false', !(await facade.commands.kill(live.pid)));
  check('completed-not-listed', (await facade.commands.list()).length === 0);
  await assert.rejects(facade.commands.connect(1000000000), error => error instanceof APIError && error.status === 404);
  cases.push('unknown-connect-404');
  const timed = await facade.commands.run('printf before; sleep 30', { background: true, timeoutMs: 1000 });
  await assert.rejects(timed.wait(), TimeoutException);
  check('observation-timeout-preserves-process', (await facade.commands.list())[0]?.pid === timed.pid);
  const resumed = await facade.commands.connect(timed.pid, { timeoutMs: 0 });
  check('kill-after-observation-timeout', await resumed.kill());
  check('reconnect-replays-output', (await failed(resumed, 137)).stdout === 'before');
  const denied = new Sandbox(new Session(tenantB, native.created));
  for (const [name, action] of [['list', () => denied.commands.list()], ['connect', () => denied.commands.connect(timed.pid)], ['kill', () => denied.commands.kill(timed.pid)]]) {
    await assert.rejects(action(), error => error instanceof APIError && error.status === 404);
    cases.push('cross-tenant-' + name);
  }
  const inaccessible = await native.run({ entrypoint: '/bin/bash', args: ['-c', 'printf forbidden'], cwd: '/proc/1/fd' });
  check('cwd-after-permission-drop', !inaccessible.succeeded);
  check('session-reused', (await facade.commands.run('printf continued')).stdout === 'continued');
  return { passed: true, cases, case_count: cases.length };
}

async function exerciseInteractiveStdin(facade,native,tenantB){
  const cases=[];
  function check(name,value){assert.ok(value,name);cases.push(name);}
  async function rejected(action,status,code){await assert.rejects(action(),error=>error instanceof APIError&&error.status===status&&(code===undefined||error.code===code));cases.push('rejected-'+status+(code?'-'+code:''));}
  async function waitOutput(command,text){
    for(let index=0;index<300;index++){
      const page=await command.poll();const out=Buffer.concat(page.events.filter(row=>row.stream==='stdout').map(row=>Buffer.from(row.data_base64,'base64')));
      if(out.includes(text))return;
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    throw new Error('stdin process did not reach readiness marker');
  }
  const handle=await facade.commands.run('cat > /workspace/stdin-bytes; cat /workspace/stdin-bytes; printf eof >&2',{background:true,stdin:true,timeoutMs:0});
  await facade.commands.sendStdin(handle.pid,'首行\n');
  await handle.disconnect();
  const attached=await facade.commands.connect(handle.pid,{timeoutMs:0});
  await attached.sendStdin(new Uint8Array([0,255,116,97,105,108]));
  await facade.commands.closeStdin(handle.pid);
  const final=await attached.wait(),expected=Buffer.concat([Buffer.from('首行\n'),Buffer.from([0,255]),Buffer.from('tail')]);
  check('binary-and-text-through-pid-and-handle',Buffer.from(await native.readFile('/workspace/stdin-bytes')).equals(expected));
  check('eof-and-output-after-reconnect',final.exitCode===0&&final.stdout===expected.toString('utf8')&&final.stderr==='eof');
  await rejected(()=>facade.commands.sendStdin(1000000000,'missing'),404);
  await rejected(()=>facade.commands.closeStdin(1000000000),404);
  const held=await facade.commands.run('cat > /workspace/empty-stdin; printf eof; sleep 30',{background:true,stdin:true,timeoutMs:0});
  await held.closeStdin();await waitOutput(held._native,Buffer.from('eof'));
  check('empty-eof-delivered',(await held._native.poll()).info.stdin_closed===true);
  check('repeat-close-live-input',await held.closeStdin()===undefined);
  await rejected(()=>facade.commands.sendStdin(held.pid,'after-eof'),409,'stdin_closed');
  await held.kill();await assert.rejects(held.wait(),error=>error instanceof CommandExitError&&error.exitCode===137);
  check('empty-stdin-was-empty',Buffer.from(await native.readFile('/workspace/empty-stdin')).length===0);
  const disabled=await facade.commands.run('sleep 30',{background:true,timeoutMs:0});
  await rejected(()=>disabled.sendStdin('disabled'),409,'stdin_unavailable');
  await rejected(()=>disabled.closeStdin(),409,'stdin_unavailable');
  await disabled.kill();await assert.rejects(disabled.wait(),error=>error instanceof CommandExitError&&error.exitCode===137);
  const broken=await facade.commands.run('exec 0<&-; printf closed; sleep 30',{background:true,stdin:true,timeoutMs:0});
  await waitOutput(broken._native,Buffer.from('closed'));
  await rejected(()=>broken.sendStdin('unused'),409,'stdin_closed');
  await broken.kill();await assert.rejects(broken.wait(),error=>error instanceof CommandExitError&&error.exitCode===137);
  const blocked=await native.startCommand({entrypoint:'/bin/bash',args:['-c','printf ready; sleep 30'],timeoutMs:20000,interactiveStdin:true});
  await waitOutput(blocked,Buffer.from('ready'));
  let stalled;
  for(let sequence=1;sequence<=16;sequence++){
    try{await blocked.sendStdin(new Uint8Array(16384),{requestTimeoutMs:300});}
    catch(error){if(!(error instanceof TimeoutException))throw error;stalled=sequence;break;}
  }
  check('bounded-backpressure-observation-timeout',stalled!==undefined);
  check('pending-input-queryable',(await blocked.pollStdin(stalled)).state==='pending');
  await rejected(()=>blocked.submitStdin(Buffer.from('extra')),429,'busy');
  const denied=new Sandbox(new Session(tenantB,native.created));
  await rejected(()=>denied.commands.sendStdin(42,'foreign'),404);
  await rejected(()=>denied.commands.closeStdin(42),404);
  for(const [method,suffix,payload] of [['POST','',{data_base64:'eA==',close:false}],['GET','/'+stalled,undefined]]){
    await rejected(()=>tenantB._exchange(method,blocked._path+'/stdin'+suffix,payload),404);
  }
  const started=Date.now();check('backpressure-cancel-accepted',await blocked.kill());
  check('backpressure-cancel-confirmed',(await blocked.wait()).state==='cancelled'&&Date.now()-started<3000);
  const pending=await blocked.pollStdin(stalled);check('unfinished-input-not-delivered',pending.state==='failed'&&pending.error_code==='command_exited');
  const quota=await native.startCommand({entrypoint:'/bin/bash',args:['-c','/bin/busybox wc -c > /workspace/stdin-count'],timeoutMs:20000,interactiveStdin:true});
  for(let index=0;index<64;index++)await quota.sendStdin(Buffer.alloc(16384,113));
  await rejected(()=>quota.submitStdin(Buffer.from('extra')),413,'stdin_limit');
  await rejected(()=>native._client._exchange('POST',quota._path+'/stdin',{data_base64:Buffer.alloc(16385).toString('base64'),close:false},[202]),413,'stdin_limit');
  await quota.closeStdin();check('full-input-byte-budget-and-eof',(await quota.wait()).succeeded&&Buffer.from(await native.readFile('/workspace/stdin-count')).toString().trim()==='1048576');
  check('session-reused-after-input',(await facade.commands.run('printf reused')).stdout==='reused');
  return {passed:true,cases,case_count:cases.length};
}
