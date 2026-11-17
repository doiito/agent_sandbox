import test from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import { inspect } from 'node:util';
import { APIError, Client, ConfigurationError, ProtocolError, Sandbox, Session, TemplateMismatch, UnsupportedCapability,
  CodeCleanupError, CodeExecutionFailed, ExecutionError, OutputMessage, TimeoutException, TransportError, PortConnection, SessionPorts } from './index.js';

const previewSID = 'a'.repeat(24), previewID = 'b'.repeat(24), previewOrigin = `https://${'c'.repeat(24)}.preview.test:9444`;
function previewMetadata(creating = false, changes = {}) {
  return {protocol: 'osv-sandbox-preview/v1', id: previewID, session_id: previewSID, port: 8080, origin: previewOrigin,
    created_at: '2026-11-07T00:00:00.123456789Z', expires_at: '2026-11-07T00:01:00.123456789Z', status: 'active',
    ...(creating ? {bootstrap_url: previewOrigin + '/.osv/authorize?token=' + 'd'.repeat(64)} : {}), ...changes};
}
function previewPorts({response, failing = false} = {}) {
  const calls = [], session = {id: previewSID, _client: {_token: 'hidden-test-token', _exchange: async (method, path, ...args) => {
    calls.push({method, path, args});
    if (failing && method === 'POST') throw new TransportError('response lost');
    return response ?? previewMetadata(method === 'POST', {status: method === 'DELETE' ? 'revoked' : 'active'});
  }}, capabilities: async () => ({backend: 'firecracker-linux', artifact_manifest_protocol: 'osv-sandbox-artifacts/v6',
    features: {port_forward: true, port_preview: true}})};
  return {ports: new SessionPorts(session), calls, session};
}

test('preview creates once and cleans up without new admission or exposing handles', async () => {
  const {ports, calls, session} = previewPorts();
  const handle = await ports.createPreview(8080, {previewId: previewID, ttlMs: 60000, requestTimeoutMs: 2000});
  assert.equal(handle.bootstrapURL, previewMetadata(true).bootstrap_url);
  assert(Object.isFrozen(handle.created));
  assert(!inspect(handle).includes('token')); assert(!JSON.stringify(handle).includes('token'));
  session.capabilities = async () => { throw new Error('cleanup must not discover'); };
  assert(!Object.hasOwn(await handle.info(), 'bootstrap_url'));
  assert.equal((await ports.preview(8080, previewID).revoke()).status, 'revoked');
  assert.deepEqual(calls.map(v => v.method), ['POST', 'GET', 'DELETE']);
  assert.deepEqual(calls[0].args, [{ttl_ms: 60000}, [201], 2000]);
  assert.throws(() => { handle.id = 'e'.repeat(24); }, TypeError);
});

test('preview uncertain create retains nonenumerable handle and never replays or revokes', async () => {
  const {ports, calls} = previewPorts({failing: true});
  let failure;
  try { await ports.createPreview(8080, {previewId: previewID}); } catch (error) { failure = error; }
  assert(failure instanceof TransportError); assert.equal(failure.preview.id, previewID);
  assert.equal(failure.preview.bootstrapURL, undefined); assert(!Object.keys(failure).includes('preview'));
  assert(!inspect(failure).includes('hidden-test-token'));
  assert.deepEqual(calls.map(v => v.method), ['POST']);
  assert.equal((await failure.preview.info()).status, 'active');
  assert.equal((await failure.preview.revoke()).status, 'revoked');
});

test('preview local input validation never sends an invalid create', async () => {
  const {ports, calls} = previewPorts();
  for (const port of [true, 0, 65536, '8080']) await assert.rejects(ports.createPreview(port), ConfigurationError);
  for (const ttlMs of [true, 999, 300001, 1000.5]) await assert.rejects(ports.createPreview(8080, {ttlMs}), ConfigurationError);
  assert.throws(() => ports.preview(8080, '../bad'), ConfigurationError);
  await assert.rejects(ports.createPreview(8080, {requestTimeoutMs: 0}), ConfigurationError);
  assert.deepEqual(calls, []);
});

test('preview old disabled and wrong backend capabilities reject before POST', async () => {
  for (const cap of [{}, {backend: 'osv', artifact_manifest_protocol: 'osv-sandbox-artifacts/v6', features: {port_forward: true, port_preview: true}},
    {backend: 'firecracker-linux', artifact_manifest_protocol: 'osv-sandbox-artifacts/v5', features: {port_forward: true, port_preview: true}}]) {
    const {ports, calls, session} = previewPorts(); session.capabilities = async () => cap;
    await assert.rejects(ports.createPreview(8080), UnsupportedCapability); assert.equal(calls.length, 0);
  }
});

test('preview rejects malformed proofs and accepts nanosecond lifetime', async () => {
  for (const changes of [{id: 'e'.repeat(24)}, {session_id: 'f'.repeat(24)}, {port: true}, {port: 8081}, {extra: 'bad'},
    {protocol: 'other'}, {status: 'unknown'}, {origin: 'https://user@evil.test'}, {origin: previewOrigin + '/'},
    {origin: previewOrigin + '?x=1'}, {created_at: '2026-02-30T00:00:00Z'}, {expires_at: '2026-11-07T00:00:00.123456789Z'},
    {expires_at: '2026-11-07T00:10:00Z'}, {bootstrap_url: 'https://evil.test/.osv/authorize?token=' + 'd'.repeat(64)},
    {bootstrap_url: previewMetadata(true).bootstrap_url + '&extra=1'}]) {
    const {ports, calls} = previewPorts({response: previewMetadata(true, changes)});
    await assert.rejects(ports.createPreview(8080, {previewId: previewID}), error => error instanceof ProtocolError && error.preview.id === previewID);
    assert.equal(calls.length, 1);
  }
  const {ports} = previewPorts({response: previewMetadata(true, {expires_at: '2026-11-07T00:00:00.123456790Z'})});
  assert((await ports.createPreview(8080, {previewId: previewID})).bootstrapURL);
});

test('preview info cannot reissue secrets or change created binding and revoke must be terminal', async () => {
  for (const response of [previewMetadata(true), previewMetadata(false, {extra: 1}), previewMetadata(false, {port: 8081})]) {
    const {ports} = previewPorts({response}); await assert.rejects(ports.preview(8080, previewID).info(), ProtocolError);
  }
  const {ports} = previewPorts({response: previewMetadata()});
  await assert.rejects(ports.preview(8080, previewID).revoke(), ProtocolError);
  const setup = previewPorts(), handle = await setup.ports.createPreview(8080, {previewId: previewID});
  setup.session._client._exchange = async () => previewMetadata(false, {origin: previewOrigin.replace('c'.repeat(24), 'e'.repeat(24))});
  await assert.rejects(handle.info(), ProtocolError);
});

function portFrame(kind, data = Buffer.alloc(0)) {
  const frame = Buffer.alloc(5 + data.length); frame[0] = kind; frame.writeUInt32BE(data.length, 1); frame.set(data, 5); return frame;
}
function portResult(changes = {}) {
  return {id: 'c'.repeat(24), port: 8080, status: 'cancelled', sent_bytes: 0, received_bytes: 0, error: 'cancelled', ...changes};
}
function portHandle(payload = Buffer.alloc(0), {hang = false} = {}) {
  const calls = [], sdk = {_exchange: async (method, path) => {
    calls.push({method, path}); return {session_id: 'b'.repeat(24), connection: portResult()};
  }};
  const handle = new PortConnection({id: 'b'.repeat(24), _client: sdk}, 8080, 'c'.repeat(24));
  let fed = false;
  const socket = new Duplex({read() { if (!fed) { fed = true; this.push(payload.length ? payload : null); if (payload.length && !hang) this.push(null); } },
    write(chunk, _encoding, callback) { calls.push(Buffer.from(chunk)); callback(); }});
  socket.on('error', () => {});
  handle._socket = socket;
  return {handle, calls, socket};
}

test('native port binary duplex EOF and exact terminal proof', async () => {
  const final = portResult({status: 'completed', error: null, sent_bytes: 2, received_bytes: 2});
  const {handle, calls} = portHandle(Buffer.concat([portFrame(1, Buffer.from([0, 255])), portFrame(2), portFrame(4, Buffer.from(JSON.stringify(final)))]));
  await handle.write(new Uint8Array([255, 0])); await handle.closeWrite();
  assert.deepEqual(calls, [portFrame(1, Buffer.from([255, 0])), portFrame(2)]);
  assert.deepEqual((await handle.readFrame()).data, Buffer.from([0, 255]));
  assert.equal((await handle.readFrame()).kind, 'eof');
  assert.deepEqual((await handle.readFrame()).info, final);
  assert.equal((await handle.info()).status, 'cancelled');
});

test('native port peer EOF permits reverse writes and missing FINISHED remains unknown', async () => {
  const {handle, calls} = portHandle(portFrame(2), {hang: true});
  assert.equal((await handle.readFrame()).kind, 'eof');
  await handle.write(new Uint8Array([42])); await handle.closeWrite();
  assert.deepEqual(calls, [portFrame(1, Buffer.from([42])), portFrame(2)]);
  handle._socket.push(null);
  await assert.rejects(handle.readFrame(), TransportError);
  assert.equal((await handle.cancel()).id, handle.id);
});

test('native port rejects oversized invalid and truncated frames without replay', async () => {
  for (const [kind, size] of [[0, 0], [1, 0], [1, 16385], [2, 1], [3, 0], [4, 0], [4, 4097], [255, 0xffffffff]]) {
    const header = Buffer.alloc(5); header[0] = kind; header.writeUInt32BE(size, 1);
    const {handle} = portHandle(header); await assert.rejects(handle.readFrame(), ProtocolError);
    assert.equal(handle._closed, true);
  }
  for (const payload of [Buffer.alloc(0), Buffer.from([1]), portFrame(1, Buffer.from([1, 2])).subarray(0, 6)]) {
    const {handle} = portHandle(payload); await assert.rejects(handle.readFrame(), TransportError);
    assert.equal((await handle.info()).status, 'cancelled');
  }
});

test('native port rejects false terminal counts binding state and data after EOF', async () => {
  for (const changes of [{id:'d'.repeat(24)}, {port:8081}, {status:'open', error:null}, {status:'completed', error:null},
    {received_bytes:1}, {sent_bytes:1}, {status:'failed',error:'arbitrary'}, {sent_bytes:true}, {extra:1}]) {
    const {handle} = portHandle(portFrame(4, Buffer.from(JSON.stringify(portResult(changes)))));
    await assert.rejects(handle.readFrame(), ProtocolError);
  }
  for (const tail of [portFrame(2), portFrame(1, Buffer.from([1]))]) {
    const {handle} = portHandle(Buffer.concat([portFrame(2), tail])); await handle.readFrame();
    await assert.rejects(handle.readFrame(), ProtocolError);
  }
  for (const value of ['[]', 'null', '{', '\ufffd']) {
    const {handle} = portHandle(portFrame(4, Buffer.from(value))); await assert.rejects(handle.readFrame(), ProtocolError);
  }
});

test('native port input limits identity and concurrent operations are explicit', async () => {
  const {handle, calls} = portHandle();
  for (const data of [new Uint8Array(), new Uint8Array(16385), 'text']) await assert.rejects(handle.write(data), ConfigurationError);
  assert.deepEqual(calls, []); handle._maximum = 1;
  await handle.write(new Uint8Array([1])); await assert.rejects(handle.write(new Uint8Array([1])), ConfigurationError);
  await handle.closeWrite(); await assert.rejects(handle.closeWrite(), ConfigurationError);
  assert.throws(() => {handle.id = 'd'.repeat(24);}, TypeError); handle.close();
});

test('native port blocked reader leaves control and independent writer available', async () => {
  const {handle, socket, calls} = portHandle(Buffer.from([1]), {hang: true});
  const reading = handle.readFrame(); await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(handle.readFrame(), ConfigurationError);
  await handle.write(new Uint8Array([1])); assert.equal((await handle.cancel()).status, 'cancelled');
  assert.equal(calls.at(-1).method, 'DELETE');
  handle._expired = true; handle.close(); await assert.rejects(reading, TimeoutException);
  assert.equal(socket.destroyed, true);
});

test('native port uncertain open retains one known ID and rejects v5 port claim', async () => {
  const sdk = client(), session = new Session(sdk, {...sessionInfo, artifactManifestSha256: digest});
  session.capabilities = async () => ({backend:'firecracker-linux', artifact_manifest_protocol:'osv-sandbox-artifacts/v6', features:{port_forward:true}});
  const original = PortConnection.prototype._open; let calls = 0;
  PortConnection.prototype._open = async () => {calls++; throw new TransportError('ACK lost');};
  try {
    await assert.rejects(session.ports.open(8080), error => {
      assert.match(error.connection.id, /^[a-f0-9]{24}$/);
      assert.equal(Object.keys(error).includes('connection'), false);
      assert.doesNotMatch(inspect(error) + JSON.stringify(error.connection), /test-token|PRIVATE KEY|_tls|_session/);
      return error instanceof TransportError;
    });
    assert.equal(calls, 1);
    session.capabilities = async () => ({backend:'firecracker-linux', artifact_manifest_protocol:'osv-sandbox-artifacts/v5', features:{port_forward:true}});
    await assert.rejects(session.ports.open(8080), UnsupportedCapability); assert.equal(calls, 1);
  } finally {PortConnection.prototype._open = original;}
  for (const [port, id] of [[0,'a'.repeat(24)], [65536,'a'.repeat(24)], [8080,'A'.repeat(24)]]) assert.throws(() => session.ports.connection(port, id), ConfigurationError);
  for (const options of [{maxBytes:0}, {timeoutMs:300001}, {idleTimeoutMs:-1}]) await assert.rejects(session.ports.open(8080, options), ConfigurationError);
});

const certFile = '/dev/null';
const keyFile = '/dev/null';
const digest = 'a'.repeat(64);
const sessionId = 'b'.repeat(24);
const capabilities = {
  protocol: 'osv-sandbox-capabilities/v1', methods: ['POST /v2/jobs'],
  allowed_entrypoints: ['/bin/sh'], backend: 'firecracker-linux',
  artifact_authenticated: true, artifact_manifest_sha256: digest,
  features: { input_files: true }
};
function client() {
  return new Client('https://localhost:8443', { token: 'test-token', certFile, keyFile });
}
const sessionInfo = { id: sessionId, state: 'running', backend: 'firecracker-linux',
  artifact_manifest_sha256: digest, created_at: '2026-10-30T00:00:00Z',
  expires_at: '2026-10-30T00:05:00Z' };
const success = { id: 'job', state: 'succeeded', backend: 'firecracker-linux',
  exit_code: 0, timed_out: false, duration_ms: 1, output: '',
  output_truncated: false, protocol_ok: true, guest_result: {} };

const codeContextId = 'c'.repeat(24), codeExecutionId = 'e'.repeat(24);
function codeCapabilities() {
  return {...capabilities, session_id: sessionId, artifact_manifest_protocol: 'osv-sandbox-artifacts/v5',
    features: {code_contexts: true}, code_languages: ['python', 'javascript', 'typescript'],
    code_runtime: {kernel_protocol: 'osv-code-kernel/v2'}};
}
function codeContextInfo(changes = {}) {
  return {session_id: sessionId, id: codeContextId, generation: 1, language: 'python', cwd: '/workspace',
    state: 'idle', pid: 42, failure: null, discarded_late_events: 0, discarded_late_bytes: 0, ...changes};
}
function codePage(changes = {}) {
  return {session_id: sessionId, id: codeExecutionId, context_id: codeContextId, generation: 1, language: 'python',
    status: 'completed', events: [{sequence: 1, event: {type: 'started'}},
      {sequence: 2, event: {type: 'finished', status: 'completed', context_usable: true}}],
    next_sequence: 2, last_sequence: 2, events_evicted: false, failure: null, ...changes};
}
function codeClient(replies = []) {
  const sdk = client(), calls = [];
  sdk._exchange = async (method, path, payload, accepted, timeout) => {
    calls.push({method, path, payload, accepted, timeout});
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    assert.notEqual(reply, undefined, 'unexpected code request');
    return reply;
  };
  return {native: new Session(sdk, {...sessionInfo, artifactManifestSha256: digest}), sdk, calls};
}

test('native code composed v6 preserves code and rejects wrong runtime protocol', async () => {
  for (const protocol of ['osv-sandbox-artifacts/v6','osv-sandbox-artifacts/v7','osv-sandbox-artifacts/v8']) {
    const composed = {...codeCapabilities(), artifact_manifest_protocol:protocol};
    const {native} = codeClient([composed, codeContextInfo()]);
    assert.equal((await native.code.default()).id, codeContextId);
  }
  const cap = {...codeCapabilities(), artifact_manifest_protocol:'osv-sandbox-artifacts/v8'};
  const invalid = codeClient([{...cap, code_runtime:{kernel_protocol:'unknown'}}]);
  await assert.rejects(invalid.native.code.default(),UnsupportedCapability);
});

test('native code bound capabilities reject wrong owner template and authentication', async () => {
  for(const changes of [{session_id:'d'.repeat(24)},{backend:'firecracker-osv'},
    {artifact_manifest_sha256:'b'.repeat(64)},{artifact_authenticated:false}]){
    const {native,calls}=codeClient([{...codeCapabilities(),...changes}]);
    await assert.rejects(native.code.default(),ProtocolError);assert.equal(calls.length,1);
  }
});

test('native code owner discovery does not reenter expired new template admission', async () => {
  const {native,sdk,calls}=codeClient();
  sdk._exchange=async(method,path)=>{
    calls.push({method,path});assert.ok(!path.startsWith('/v1/capabilities'));
    return path.endsWith('/capabilities')?codeCapabilities():codeContextInfo();
  };
  assert.equal((await native.capabilities()).session_id,sessionId);
  assert.equal((await native.code.default()).id,codeContextId);
  assert.ok(calls.every(call=>call.path.startsWith(`/v2/sessions/${sessionId}`)));
});

test('native code context lifecycle retains generation and actual transition state', async () => {
  const {native, calls} = codeClient([codeCapabilities(), codeContextInfo({state: 'starting', pid: null}),
    codeContextInfo(), {session_id: sessionId, contexts: [codeContextInfo()]}, codeContextInfo({state: 'stopping'}),
    {session_id: sessionId, context_id: codeContextId, removed: true}]);
  const created = await native.code.create({contextId: codeContextId, requestTimeoutMs: 2000});
  assert.equal(created.state, 'starting');
  assert.throws(() => {created.generation = 9;}, TypeError);
  const current = await native.code.get(codeContextId);
  assert.deepEqual(await native.code.list(), [current]);
  assert.equal((await native.code.restart(current)).state, 'stopping');
  await native.code.remove(current);
  assert.equal(calls[1].timeout, 2000);
  assert.equal(calls[0].timeout, 2000);
  assert.deepEqual(calls.at(-2).payload, {generation: 1});
  assert.ok(calls.at(-1).path.endsWith('?generation=1'));
  assert.equal(calls[0].path, `/v2/sessions/${sessionId}/capabilities`);
});

test('native code default submission preserves known id empty source and zero timeout', async () => {
  const {native, calls} = codeClient([codeCapabilities(), codeContextInfo(),
    {session_id: sessionId, execution_id: codeExecutionId, accepted: true}]);
  const context = await native.code.default();
  const handle = await native.code.execute(context, '', {executionId: codeExecutionId, timeoutMs: 0, environment: {VALUE: '中文'}});
  assert.equal(handle.id, codeExecutionId);
  assert.equal(handle.context.id, context.id);
  assert.deepEqual(calls.at(-1).payload, {context_id: codeContextId, generation: 1,
    execution_id: codeExecutionId, code: '', environment: {VALUE: '中文'}, timeout_ms: 0});
});

test('native code uncertain submission exposes handle without replay or automatic cancellation', async () => {
  const loss = new Error('lost acknowledgment');
  const {native, calls} = codeClient([codeCapabilities(), loss, codePage(),
    {session_id: sessionId, execution_id: codeExecutionId, accepted: true}]);
  let handle;
  await assert.rejects(native.code.execute(codeContextInfo(), 'side_effect()', {executionId: codeExecutionId}), error => {
    assert.equal(error, loss); handle = error.execution; return true;
  });
  assert.equal(calls.length, 2);
  assert.equal((await handle.poll()).status, 'completed');
  await handle.cancel();
  assert.equal(calls.filter(call => call.method === 'POST').length, 1);
});

test('native code lost creation reply retains generated context identity', async () => {
  const loss = new Error('lost context creation reply');
  const {native, calls} = codeClient([codeCapabilities(), loss]);
  await assert.rejects(native.code.create(), error => {
    assert.equal(error, loss);
    assert.equal(error.sessionId, sessionId);
    assert.equal(error.contextId, calls[1].payload.context_id);
    assert.match(error.contextId, /^[a-f0-9]{24}$/);
    return true;
  });
  assert.equal(calls.length, 2);
});

test('native code completed journal still exposes later pages and false terminal flags', async () => {
  const first = codePage({last_sequence: 3, events: [{sequence: 1, event: {type: 'started'}},
    {sequence: 2, event: {type: 'result', data: {'application/json': {integer: 42}}, is_main_result: false}}]});
  const last = codePage({last_sequence: 3, next_sequence: 3, events: [{sequence: 3,
    event: {type: 'finished', status: 'completed', context_usable: false}}]});
  const {native} = codeClient([first, last]);
  const handle = native.code.connectExecution(codeContextInfo(), codeExecutionId);
  const initial = await handle.poll();
  assert.ok(initial.next_sequence < initial.last_sequence);
  assert.equal(initial.events[1].event.is_main_result, false);
  assert.equal((await handle.poll(2)).events[0].event.context_usable, false);
});

test('native code cancellation placeholder has no started and eviction stays explicit', async () => {
  const placeholder = codePage({status: 'cancelled', failure: 'cancelled_before_submit', last_sequence: 1, next_sequence: 1,
    events: [{sequence: 1, event: {type: 'finished', status: 'cancelled', context_usable: true}}]});
  const {native} = codeClient([placeholder, codePage({events: [], next_sequence: 0, events_evicted: true})]);
  const handle = native.code.connectExecution(codeContextInfo(), codeExecutionId);
  assert.equal((await handle.poll()).events[0].event.type, 'finished');
  assert.equal((await handle.poll()).events_evicted, true);
});

test('native code binary stdout and empty error fields stay data', async () => {
  const events = [{sequence: 1, event: {type: 'started'}},
    {sequence: 2, event: {type: 'stdout', data: 'AP8='}},
    {sequence: 3, event: {type: 'error', name: 'Error', value: '', traceback: ''}},
    {sequence: 4, event: {type: 'finished', status: 'completed', context_usable: true}}];
  const {native} = codeClient([codePage({events, last_sequence: 4, next_sequence: 4})]);
  const result = await native.code.connectExecution(codeContextInfo(), codeExecutionId).poll();
  assert.deepEqual(Buffer.from(result.events[1].event.data, 'base64'), Buffer.from([0, 255]));
  assert.equal(result.events[2].event.value, '');
});

test('native code journal rejects forged identity gaps omitted output and terminal changes', async () => {
  const changes = [p => {p.session_id = 'a'.repeat(24);}, p => {p.context_id = 'd'.repeat(24);},
    p => {p.generation = 2;}, p => {p.language = 'javascript';}, p => {p.id = 'f'.repeat(24);},
    p => {p.next_sequence = 1;}, p => {p.events[0].sequence = 2;}, p => {p.events.at(-1).event.status = 'failed';},
    p => {p.events.at(-1).event.context_usable = null;}, p => {p.events[0].event.type = [];},
    p => {p.events = []; p.next_sequence = 0;}, p => {p.events_evicted = true;}, p => {p.generation = true;}];
  for (const change of changes) {
    const reply = codePage(); change(reply);
    const {native} = codeClient([reply]);
    await assert.rejects(native.code.connectExecution(codeContextInfo(), codeExecutionId).poll(), ProtocolError);
  }
});

test('native code context owner missing fields and duplicate list are rejected', async () => {
  const {native} = codeClient([codeCapabilities(), {session_id: sessionId, contexts: [codeContextInfo(), codeContextInfo()]}]);
  for (const changes of [{session_id: 'a'.repeat(24)}, {generation: true}, {pid: 1}, {cwd: '/tmp'}, {pid: undefined}]) {
    assert.throws(() => native.code.connectExecution(codeContextInfo(changes), codeExecutionId), changes.session_id ? ConfigurationError : ProtocolError);
  }
  await assert.rejects(native.code.list(), ProtocolError);
});

test('native code unsupported signed profile or tenant language never admits code', async () => {
  for (const report of [{...capabilities, session_id: sessionId}, {...codeCapabilities(), artifact_manifest_protocol: 'osv-sandbox-artifacts/v4'},
    {...codeCapabilities(), code_languages: ['javascript']}]) {
    const {native, calls} = codeClient([report]);
    await assert.rejects(native.code.default(), UnsupportedCapability);
    assert.equal(calls.length, 1);
  }
});

test('native code invalid options source and environment never reach transport', async () => {
  const {native, calls} = codeClient();
  for (const [source, options] of [['x'.repeat(65537), {}], ['\ud800', {}], ['x\0', {}], ['', {timeoutMs: true}],
    ['', {timeoutMs: -1}], ['', {environment: {'BAD=KEY': 'x'}}], ['', {environment: {X: 'x'.repeat(8193)}}],
    ['', {requestTimeoutMs: 0}], ['', {envs: {X: 'not a native option'}}]]) {
    await assert.rejects(native.code.execute(codeContextInfo(), source, options), ConfigurationError);
  }
  assert.equal(calls.length, 0);
});

test('native code context and mutation acknowledgments cannot change known binding', async () => {
  const current = codeContextInfo();
  const cases = [[c => c.create({contextId: codeContextId}), codeContextInfo({id: 'd'.repeat(24)})],
    [c => c.default(), codeContextInfo({language: 'javascript'})],
    [c => c.get(codeContextId), codeContextInfo({id: 'd'.repeat(24)})],
    [c => c.restart(current), codeContextInfo({generation: 7})],
    [c => c.remove(current), {session_id: sessionId, context_id: 'd'.repeat(24), removed: true}],
    [c => c.execute(current, '', {executionId: codeExecutionId}), {session_id: sessionId, execution_id: 'd'.repeat(24), accepted: true}]];
  for (const [call, reply] of cases) {
    const {native} = codeClient([codeCapabilities(), reply]);
    await assert.rejects(call(native.code), ProtocolError);
  }
  const {native} = codeClient([{session_id: 'd'.repeat(24), execution_id: codeExecutionId, accepted: true}]);
  await assert.rejects(native.code.connectExecution(current, codeExecutionId).cancel(), ProtocolError);
});

class E2BCodeGateway {
  constructor() {
    const {native, sdk} = codeClient();
    this.native = native; this.sandbox = new Sandbox(native);
    this.calls = []; this.contexts = new Map([[codeContextId, codeContextInfo()]]); this.records = new Map();
    this.transitions = new Map(); this.removing = new Map(); this.events = []; this.pageSize = 64;
    this.running = false; this.terminalStatus = 'completed'; this.cancelled = false;
    sdk._exchange = (...args) => this.exchange(...args);
  }
  async exchange(method, path, payload, accepted, timeout) {
    this.calls.push({method, path, payload: structuredClone(payload), accepted, timeout});
    if (path.endsWith('/capabilities')) return codeCapabilities();
    if (path.endsWith('/contexts/default')) {
      let value = [...this.contexts.values()].find(row => row.language === payload.language);
      if (!value) { value = codeContextInfo({id: (payload.language === 'javascript' ? 'd' : 'f').repeat(24), language: payload.language}); this.contexts.set(value.id, value); }
      return structuredClone(value);
    }
    if (path.endsWith('/contexts')) {
      if (method === 'GET') return {session_id: sessionId, contexts: structuredClone([...this.contexts.values()])};
      const value = codeContextInfo({id: payload.context_id, language: payload.language, cwd: payload.cwd, state: 'starting', pid: null});
      this.contexts.set(value.id, value); this.transitions.set(value.id, [['starting', 1], ['idle', 1]]);
      if (this.createLoss) {this.createLoss = false;throw new TransportError('created context reply lost');}
      return structuredClone(value);
    }
    if (path.includes('/contexts/')) {
      const id = path.split('/contexts/')[1].split(/[/?]/)[0];
      if (method === 'GET') {
        if (this.removing.has(id)) {
          const left = this.removing.get(id) - 1; this.removing.set(id, left);
          if (!left) this.contexts.delete(id);
        }
        if (!this.contexts.has(id)) throw new APIError(404, this.ownerMissing ? 'not_found' : 'code_not_found', 'missing');
        const value = this.contexts.get(id), pending = this.transitions.get(id);
        if (pending?.length) { [value.state, value.generation] = pending.shift(); value.pid = value.state === 'idle' ? 42 : null; }
        return structuredClone(value);
      }
      const value = this.contexts.get(id);
      if (method === 'POST') {
        this.transitions.set(id, [['stopping', value.generation], ['starting', value.generation + 1], ['idle', value.generation + 1]]);
        value.state = 'stopping'; value.pid = null; return structuredClone(value);
      }
      value.state = 'stopping'; this.removing.set(id, 2);
      return {session_id: sessionId, context_id: id, removed: true};
    }
    if (path.endsWith('/code-executions')) {
      const id = payload.execution_id;
      if (this.records.has(id)) throw new APIError(409, 'conflict', 'execution already exists');
      if (this.submitLoss === 'reject') throw new APIError(409, 'stale_context', 'generation changed');
      if (this.submitLoss === 'before') throw new TransportError('lost response before delayed admission');
      const events = [{type:'started'}, ...structuredClone(this.events)], status = this.running ? 'running' : this.terminalStatus;
      if (!this.running) events.push({type:'finished', status, context_usable: status === 'completed'});
      this.records.set(id, {context_id:payload.context_id, generation:payload.generation, status, events, failure:this.failure ?? null});
      if (this.submitLoss === 'accepted') throw new TransportError('accepted reply lost');
      return {session_id:sessionId, execution_id:id, accepted:true};
    }
    if (path.includes('/code-executions/')) {
      const id = path.split('/code-executions/')[1].split('?')[0], query = new URLSearchParams(path.split('?')[1]);
      if (method === 'DELETE') {
        if (!this.records.has(id)) this.records.set(id, {context_id:query.get('context_id'), generation:Number(query.get('generation')), status:'cancelled',
          events:[{type:'finished',status:'cancelled',context_usable:true}],failure:'cancelled_before_submit'});
        const row = this.records.get(id);
        if (row.status === 'running') { row.status = 'cancelled'; row.events.push({type:'finished',status:'cancelled',context_usable:true}); }
        this.cancelled = true;
        if (this.cancelLoss) { this.cancelLoss = false; throw new TransportError('cancel acknowledgment lost'); }
        return {session_id:sessionId,execution_id:id,accepted:true};
      }
      const row = this.records.get(id), after = Number(query.get('after'));
      const events = this.evicted ? [] : row.events.map((event,index) => ({sequence:index+1,event})).slice(after,after+this.pageSize);
      return structuredClone({session_id:this.forgedAfterCancel && this.cancelled ? 'a'.repeat(24) : sessionId,id,
        context_id:row.context_id,generation:row.generation,language:this.contexts.get(row.context_id).language,status:row.status,
        events,last_sequence:row.events.length,next_sequence:after+events.length,events_evicted:!!this.evicted,failure:row.failure});
    }
    if (method === 'DELETE' && path.endsWith(sessionId)) return {};
    throw new Error(`unexpected ${method} ${path}`);
  }
  submitted() { return this.calls.filter(call => call.method === 'POST' && call.path.endsWith('/code-executions')); }
}

async function transportAtExecutionDeadline(expired, phase) {
    const gateway = new E2BCodeGateway(); gateway.running = true;
    const original = new TransportError('HTTPS exchange failed (timeout)');
    const descriptor = Object.getOwnPropertyDescriptor(performance, 'now');
    let clock = 0, injected = false;
    Object.defineProperty(performance, 'now', {configurable:true, value:()=>clock});
    const exchange = gateway.exchange.bind(gateway);
    gateway.exchange = async (method,path,...args) => {
      const submit = method === 'POST' && path.endsWith('/code-executions');
      const poll = method === 'GET' && path.includes('/code-executions/');
      if ((phase === 'submit' ? submit : poll) && !injected) {
        if (submit) await exchange(method,path,...args);
        injected = true; clock = expired ? 40 : 10; throw original;
      }
      if (method === 'DELETE') clock = 40;
      return exchange(method,path,...args);
    };
    try {
      await assert.rejects(gateway.sandbox.runCode('while True: pass',{timeoutMs:30}), error => {
        assert.ok(expired ? error instanceof TimeoutException : error === original);
        if (expired) assert.equal(error.cause,original);
        assert.equal(gateway.records.get(error.execution.id).status,'cancelled');
        return true;
      });
      assert.ok(injected && gateway.cancelled);
      assert.equal(gateway.submitted().length,1);
    } finally {
      if (descriptor) Object.defineProperty(performance,'now',descriptor);
      else delete performance.now;
    }
}

test('E2B code transport failure after execution deadline is timeout', async () => {
  for (const phase of ['submit','poll']) await transportAtExecutionDeadline(true,phase);
});
test('E2B code transport failure before execution deadline is preserved', async () => {
  for (const phase of ['submit','poll']) await transportAtExecutionDeadline(false,phase);
});

test('E2B code callback transport exception remains original after deadline', async () => {
  const gateway = new E2BCodeGateway(); gateway.running = true;
  gateway.events = [{type:'stdout',data:'eA=='}];
  const original = new TransportError('callback request failed');
  const descriptor = Object.getOwnPropertyDescriptor(performance,'now');
  let clock=0;
  Object.defineProperty(performance,'now',{configurable:true,value:()=>clock});
  try {
    await assert.rejects(gateway.sandbox.runCode('print(1)',{timeoutMs:30,onStdout:()=>{clock=40;throw original;}}), error=>error===original);
    assert.ok(gateway.cancelled);
    assert.equal(gateway.submitted().length,1);
  } finally {
    if (descriptor) Object.defineProperty(performance,'now',descriptor);
    else delete performance.now;
  }
});

test('E2B code decodes split UTF8 and retains rich output empty strings and all pages', async () => {
  const gateway = new E2BCodeGateway(); gateway.pageSize = 2;
  gateway.events = [{type:'stdout',data:Buffer.from([120,226]).toString('base64')},
    {type:'stdout',data:Buffer.from([130,172]).toString('base64')},{type:'stderr',data:'d2FybmluZw=='},
    {type:'result',data:{'text/plain':'','text/html':'','application/json':{integer:42}},is_main_result:true}];
  const seen = [];
  const result = await gateway.sandbox.runCode('value = 42\nvalue', {timeoutMs:0,envs:{VALUE:'中文'},
    onStdout:value=>{seen.push(value);},onStderr:value=>{seen.push(value);},onResult:value=>{seen.push(value);}});
  assert.equal(result.logs.stdout.join(''),'x€'); assert.deepEqual(result.logs.stderr,['warning']);
  assert.equal(result.text,''); assert.equal(result.results[0].json.integer,42); assert.equal(result.executionCount,undefined);
  assert.ok(seen[0] instanceof OutputMessage); assert.equal(seen[0].error,false); assert.equal(seen[2].error,true);
  assert.equal(result.results[0].html,''); assert.equal(gateway.submitted()[0].payload.timeout_ms,0); assert.equal(gateway.cancelled,false);
});

test('E2B code returns typed user errors and awaits callbacks in order', async () => {
  const gateway = new E2BCodeGateway();
  gateway.events = [{type:'stdout',data:'eA=='},{type:'stdout',data:'eQ=='},{type:'error',name:'ValueError',value:'',traceback:''}];
  let release, entered; const seen = [];
  const gate = new Promise(resolve=>{release=resolve;}), started = new Promise(resolve=>{entered=resolve;});
  const pending = gateway.sandbox.runCode('raise ValueError()', {onStdout:async output=>{
    seen.push(output.line); if(output.line==='x'){entered();await gate;}
  },onError:async error=>{assert.ok(error instanceof ExecutionError);seen.push(error.name);}});
  await started; assert.deepEqual(seen,['x']); release();
  const result = await pending;
  assert.deepEqual(seen,['x','y','ValueError']); assert.equal(result.error.value,''); assert.equal(gateway.cancelled,false);
});

test('E2B code callback failure confirms cancellation and keeps the original exception', async () => {
  const gateway = new E2BCodeGateway(); gateway.running = true; gateway.events = [{type:'stdout',data:'eA=='}];
  const original = new Error('callback failed');
  await assert.rejects(gateway.sandbox.runCode('while True: pass',{onStdout:async()=>{throw original;}}), error=>error===original);
  assert.equal(gateway.cancelled,true); assert.equal(gateway.submitted().length,1);
  assert.ok([...gateway.records.values()].every(row=>row.status==='cancelled'));
});

test('E2B code unknown submit delivery and lost cancel ACK retain the same identity without replay', async () => {
  for(const mode of ['accepted','before']){
    const gateway = new E2BCodeGateway(); gateway.running=true;gateway.submitLoss=mode;gateway.cancelLoss=true;
    await assert.rejects(gateway.sandbox.runCode('side_effect()'),TransportError);
    assert.equal(gateway.submitted().length,1);
    const request=gateway.submitted()[0], row=gateway.records.get(request.payload.execution_id);
    assert.equal(row.status,'cancelled');
    if(mode==='before'){
      assert.equal(row.failure,'cancelled_before_submit');
      await assert.rejects(gateway.exchange('POST',request.path,request.payload),APIError);
    }
  }
});

test('E2B code deadline interrupts an unresolved callback and confirms guest stop', async () => {
  const gateway=new E2BCodeGateway();gateway.running=true;gateway.events=[{type:'stdout',data:'eA=='}];
  await assert.rejects(gateway.sandbox.runCode('while True: pass',{timeoutMs:30,onStdout:()=>new Promise(()=>{})}),TimeoutException);
  assert.equal(gateway.cancelled,true);assert.equal(gateway.submitted()[0].payload.timeout_ms,30);
});

test('E2B code AbortSignal cancels only the known execution and prevents further callbacks', async () => {
  const gateway=new E2BCodeGateway();gateway.running=true;gateway.events=[{type:'stdout',data:'eA=='},{type:'stdout',data:'eQ=='}];
  const controller=new AbortController(), original=new Error('caller cancelled');let called=0;
  await assert.rejects(gateway.sandbox.runCode('while True: pass',{timeoutMs:0,signal:controller.signal,onStdout:()=>{
    called++;controller.abort(original);return new Promise(()=>{});
  }}),error=>error===original);
  assert.equal(called,1);assert.equal(gateway.cancelled,true);
  const before=gateway.calls.length;
  await assert.rejects(gateway.sandbox.runCode('',{signal:controller.signal}),error=>error===original);
  assert.equal(gateway.calls.length,before);
});

test('E2B code unconfirmed stop requests owner close and reports cleanup uncertainty', async () => {
  const gateway=new E2BCodeGateway();gateway.running=true;gateway.forgedAfterCancel=true;gateway.events=[{type:'stdout',data:'eA=='}];
  const original=new Error('callback failed');
  await assert.rejects(gateway.sandbox.runCode('while True: pass',{onStdout:()=>{throw original;}}),error=>{
    assert.ok(error instanceof CodeCleanupError);assert.equal(error.originalError,original);
    assert.ok(error.cleanupError instanceof ProtocolError);assert.equal(error.ownerCloseRequested,true);return true;
  });
  assert.equal(gateway.calls.at(-1).method,'DELETE');assert.ok(gateway.calls.at(-1).path.endsWith(sessionId));
});

test('E2B code context methods observe ready restart generation and actual removal', async () => {
  const gateway=new E2BCodeGateway();
  const context=await gateway.sandbox.createCodeContext({language:'javascript',requestTimeoutMs:2000});
  assert.equal(gateway.contexts.get(context.id).state,'idle');assert.equal((await gateway.sandbox.listCodeContexts()).length,2);
  await gateway.sandbox.restartCodeContext(context);assert.equal(gateway.contexts.get(context.id).generation,2);
  await gateway.sandbox.runCode('40+2',{context});assert.equal(gateway.submitted()[0].payload.generation,2);
  await gateway.sandbox.removeCodeContext(context.id);assert.equal(gateway.contexts.has(context.id),false);assert.equal(gateway.contexts.has(codeContextId),true);
});

test('E2B code session disappearance is not context removal confirmation', async () => {
  const gateway=new E2BCodeGateway();gateway.ownerMissing=true;
  await assert.rejects(gateway.sandbox.removeCodeContext(codeContextId),error=>error instanceof APIError&&error.code==='not_found');
});

test('E2B code invalid input options and foreign context never reach transport', async () => {
  const gateway=new E2BCodeGateway();
  for(const [source,options] of [['',{language:'python',context:{id:codeContextId,language:'python',cwd:'/workspace'}}],
    ['',{onStdout:42}],['',{timeoutMs:true}],['x'.repeat(65537),{}],['',{envs:{'BAD=KEY':'x'}}],
    ['',{context:codeContextInfo({session_id:'a'.repeat(24)})}],['',{unsupportedOption:true}]]){
    await assert.rejects(gateway.sandbox.runCode(source,options),ConfigurationError);
  }
  assert.equal(gateway.calls.length,0);
});

test('E2B code definitive submit rejection does not cancel another cell', async () => {
  const gateway=new E2BCodeGateway();gateway.submitLoss='reject';
  await assert.rejects(gateway.sandbox.runCode('40+2'),APIError);assert.equal(gateway.cancelled,false);
});

test('E2B code old templates still reject and runtime failure differs from user errors', async () => {
  const legacy=new E2BCodeGateway();const original=legacy.exchange.bind(legacy);
  legacy.native._client._exchange=(method,path,...args)=>path.endsWith('/capabilities')?Promise.resolve({...capabilities,session_id:sessionId}):original(method,path,...args);
  await assert.rejects(legacy.sandbox.runCode('40+2'),UnsupportedCapability);
  const gateway=new E2BCodeGateway();gateway.terminalStatus='failed';gateway.failure='kernel_exited';
  await assert.rejects(gateway.sandbox.runCode('40+2'),error=>error instanceof CodeExecutionFailed&&error.failure==='kernel_exited');
});

test('E2B code timeout and evicted journal cannot return empty success', async () => {
  for(const [status,evicted,ErrorClass] of [['timed_out',false,TimeoutException],['completed',true,ProtocolError]]){
    const gateway=new E2BCodeGateway();gateway.terminalStatus=status;gateway.evicted=evicted;
    await assert.rejects(gateway.sandbox.runCode('40+2'),ErrorClass);assert.equal(gateway.cancelled,true);
  }
});

test('E2B code cancel ACK and transient absent journal do not prove termination', async () => {
  const gateway=new E2BCodeGateway();gateway.running=true;gateway.events=[{type:'stdout',data:'eA=='}];
  const originalExchange=gateway.exchange.bind(gateway);let checked=0;
  gateway.native._client._exchange=async(method,path,...args)=>{
    if(method==='GET'&&path.includes('/code-executions/')&&gateway.cancelled&&++checked<3)throw new APIError(404,'code_not_found','not yet admitted');
    return originalExchange(method,path,...args);
  };
  const original=new Error('callback failed');
  await assert.rejects(gateway.sandbox.runCode('while True: pass',{onStdout:()=>{throw original;}}),error=>error===original);
  assert.equal(checked,3);
});

test('E2B code creation reply loss observes existing context without recreating it', async () => {
  const gateway=new E2BCodeGateway();gateway.createLoss=true;
  const context=await gateway.sandbox.createCodeContext({language:'typescript'});
  assert.equal(gateway.contexts.get(context.id).state,'idle');
  assert.equal(gateway.calls.filter(call=>call.method==='POST'&&call.path.endsWith('/contexts')).length,1);
});

test('E2B code busy or failed context never submits or cancels another cell', async () => {
  for(const [state,ErrorClass] of [['running',APIError],['failed',CodeExecutionFailed]]){
    const gateway=new E2BCodeGateway();gateway.contexts.get(codeContextId).state=state;
    await assert.rejects(gateway.sandbox.runCode('40+2'),ErrorClass);
    assert.equal(gateway.submitted().length,0);assert.equal(gateway.cancelled,false);
  }
});

test('E2B code callback can query contexts without blocking independent control', async () => {
  const gateway=new E2BCodeGateway();gateway.events=[{type:'stdout',data:'eA=='}];
  let seen;
  await gateway.sandbox.runCode('print(42)',{onStdout:async()=>{seen=await gateway.sandbox.listCodeContexts();}});
  assert.equal(seen[0].id,codeContextId);
});

test('E2B code abort during interpreter readiness sends no execution or cancellation', async () => {
  const gateway=new E2BCodeGateway(), controller=new AbortController(), original=new Error('cancel ready wait');
  gateway.contexts.get(codeContextId).state='starting';
  const exchange=gateway.exchange.bind(gateway);
  gateway.native._client._exchange=async(method,path,...args)=>{
    if(method==='GET'&&path.includes('/contexts/'))controller.abort(original);
    return exchange(method,path,...args);
  };
  await assert.rejects(gateway.sandbox.runCode('40+2',{signal:controller.signal}),error=>error===original);
  assert.equal(gateway.submitted().length,0);assert.equal(gateway.cancelled,false);
});

test('native file watch binds options, owner, events, cursor and stop', async () => {
  const sdk = client(), calls = [], id = 'c'.repeat(24);
  const info = { id, session_id: sessionId, path: '/workspace', recursive: false, include_entry: false, state: 'watching' };
  const page = { info, events: [{sequence:1,name:'live',type:'create'}], next_sequence:1,complete:false };
  sdk._exchange = async (method, path, payload) => { calls.push({method,path,payload}); return method === 'POST' ? info : method === 'DELETE' ? {stopped:true} : page; };
  const native = await new Session(sdk, sessionInfo).startFileWatch('/workspace');
  assert.equal((await native.poll()).events[0].name, 'live');
  assert.equal(await native.stop(), true);
  assert.ok(calls[1].path.endsWith(id+'?after=0'));
  for (const kind of ['session','id','path','sequence','traversal','nested','entry','complete']) {
    const bad = structuredClone(page);
    if (kind === 'session') bad.info.session_id = 'd'.repeat(24);
    else if (kind === 'id') bad.info.id = 'd'.repeat(24);
    else if (kind === 'path') bad.info.path = '/workspace/other';
    else if (kind === 'sequence') bad.events[0].sequence = 2;
    else if (kind === 'traversal') bad.events[0].name = '../other';
    else if (kind === 'nested') bad.events[0].name = 'dir/other';
    else if (kind === 'entry') bad.events[0].entry = {};
    else bad.complete = true;
    sdk._exchange = async () => bad;
    await assert.rejects(native.poll(), ProtocolError);
  }
});

test('E2B file watch awaits callback backpressure and reports rejected callback once', async () => {
  const sdk = client(), id = 'c'.repeat(24), observed = [];
  const info = {id,session_id:sessionId,path:'/workspace',recursive:false,include_entry:false,state:'watching'};
  let release, entered, stopped = 0, exits = 0, exitError;
  const barrier = new Promise(resolve => {release=resolve;});
  const started = new Promise(resolve => {entered=resolve;});
  sdk._exchange = async (method) => method === 'POST' ? info : method === 'DELETE' ? (stopped++, {stopped:true}) : {
    info, events:[{sequence:1,name:'first',type:'create'},{sequence:2,name:'second',type:'write'}],next_sequence:2,complete:false};
  const handle = await new Sandbox(new Session(sdk,sessionInfo)).files.watchDir('/workspace', async event => {
    observed.push(event.name);
    if(event.name==='first'){entered();await barrier;}else throw new Error('callback failed');
  }, {timeoutMs:0,onExit:async error=>{exits++;exitError=error;throw new Error('terminal callback failed');}});
  await started;
  assert.deepEqual(observed,['first']);
  release();await handle._task;
  assert.deepEqual(observed,['first','second']);
  assert.equal(exits,1);assert.match(exitError.message,/callback failed/);assert.equal(stopped,1);
  await handle.stop();assert.equal(stopped,1);
});

test('E2B file watch stop inside callback releases watcher and exits once', async () => {
  const sdk=client(),id='c'.repeat(24),info={id,session_id:sessionId,path:'/workspace',recursive:false,include_entry:false,state:'watching'};
  let release,handle,stopped=0,exits=0;
  const gate=new Promise(resolve=>{release=resolve;});
  sdk._exchange=async method=>method==='POST'?info:method==='DELETE'?(stopped++,{stopped:true}):{info,events:[{sequence:1,name:'live',type:'write'}],next_sequence:1,complete:false};
  handle=await new Sandbox(new Session(sdk,sessionInfo)).files.watchDir('/workspace',async()=>{await gate;await handle.stop();},{onExit:error=>{assert.equal(error,undefined);exits++;}});
  release();await handle._task;
  assert.equal(stopped,1);assert.equal(exits,1);
});

test('E2B file watch rejects unsupported options before creating a subscription', async () => {
  const sdk=client();let requests=0;sdk._exchange=async()=>{requests++;throw Error('unexpected request');};
  const files=new Sandbox(new Session(sdk,sessionInfo)).files;
  for(const options of [{allowNetworkMounts:true},{user:'root'},{requestTimeoutMs:1}]) await assert.rejects(files.watchDir('/workspace',()=>{},options),UnsupportedCapability);
  await assert.rejects(files.watchDir('/workspace',()=>{},{recursive:1}),ConfigurationError);
  assert.equal(requests,0);
});

test('guest proxy is explicit, live and bound to the advertised signed template', async () => {
  for(const session of [false,true]){
    const sdk=client();const calls=[];
    const report={...capabilities,methods:[...capabilities.methods,'POST /v2/sessions'],features:{...capabilities.features,network_egress:true,sessions:true}};
    sdk._exchange=async(method,path,payload)=>{calls.push({method,path,payload});return path.startsWith('/v1/capabilities')?report:session?sessionInfo:success;};
    if(session)await sdk.createSession({network:'proxy'});else await sdk.run({entrypoint:'/bin/sh',network:'proxy'});
    assert.equal(calls.length,2);assert.equal(calls[1].payload.network,'proxy');assert.equal(calls[1].payload.artifact_manifest_sha256,digest);
    for(const wrongTemplate of [false,true]){
      calls.length=0;report.features.network_egress=wrongTemplate;
      const options={template:{backend:'firecracker-linux',artifactManifestSha256:wrongTemplate?'c'.repeat(64):digest}};
      await assert.rejects(session?sdk.createSession({network:'proxy'},options):sdk.run({entrypoint:'/bin/sh',network:'proxy'},options),wrongTemplate?ProtocolError:UnsupportedCapability);
      assert.equal(calls.length,1);assert.equal(calls[0].method,'GET');
    }
  }
});

test('template catalog discovery and selected capability do not require a visible default', async () => {
  const sdk=client(), calls=[];
  const cap={...capabilities,artifact_manifest_sha256:'c'.repeat(64)};
  const catalog={protocol:'osv-sandbox-template-catalog/v1',default_template_id:'',templates:[{id:'secondary',available:true,capabilities:cap}]};
  sdk._exchange=async(method,path)=>{calls.push({method,path});return path==='/v2/templates'?catalog:cap;};
  assert.equal((await sdk.templates()).templates[0].id,'secondary');
  await sdk.capabilities({template:{backend:'firecracker-linux',artifactManifestSha256:'c'.repeat(64)}});
  const query=new URL(calls[1].path,'https://localhost').searchParams;
  assert.equal(query.get('backend'),'firecracker-linux');assert.equal(query.get('artifact_manifest_sha256'),'c'.repeat(64));
});

test('proxy job and session authorize the selected template and bind returned digest', async () => {
  for(const session of [false,true]){
    const sdk=client(),calls=[],selected='c'.repeat(64);
    const cap={...capabilities,artifact_manifest_sha256:selected,features:{...capabilities.features,network_egress:true}};
    const response={...(session?sessionInfo:success),artifact_manifest_sha256:selected,template_id:'secondary'};
    sdk._exchange=async(method,path,payload)=>{calls.push({method,path,payload});return method==='GET'?cap:response;};
    const options={template:{backend:'firecracker-linux',artifactManifestSha256:selected}};
    const value=session?await sdk.createSession({network:'proxy'},options):await sdk.run({entrypoint:'/bin/sh',network:'proxy'},options);
    assert.equal(calls.length,2);assert.ok(calls[0].path.includes('artifact_manifest_sha256='+selected));
    assert.equal(calls[1].payload.artifact_manifest_sha256,selected);
    if(!session){assert.equal(value.templateId,'secondary');assert.equal(value.artifactManifestSha256,selected);}
  }
});

test('template catalog duplicates and execution template mismatch are rejected', async () => {
  const base={protocol:'osv-sandbox-template-catalog/v1',default_template_id:'main',templates:[{id:'main',available:true,capabilities}]};
  for(const kind of ['duplicate-id','duplicate-selector','hidden-default','unsigned']){
    const value=structuredClone(base);
    if(kind.startsWith('duplicate')){value.templates.push(structuredClone(value.templates[0]));if(kind==='duplicate-selector')value.templates[1].id='other';}
    else if(kind==='hidden-default')value.default_template_id='hidden';
    else value.templates[0].capabilities.artifact_authenticated=false;
    const sdk=client();sdk._exchange=async()=>value;
    await assert.rejects(sdk.templates(),ProtocolError);
  }
  const sdk=client();sdk._exchange=async()=>({...success,artifact_manifest_sha256:'c'.repeat(64)});
  await assert.rejects(sdk.run({entrypoint:'/bin/sh'},{template:{backend:'firecracker-linux',artifactManifestSha256:digest}}),ProtocolError);
});

test('network fetch uses authenticated API and bounded binary results', async () => {
  const sdk = client();
  const calls = [];
  const caps = {...capabilities, methods:[...capabilities.methods,'POST /v2/net/fetch'], features:{network_fetch:true},
    network_fetch_policy:{max_request_bytes:262144,max_response_bytes:524288,timeout_ms:1000}};
  let value = {protocol:'osv-sandbox-network-fetch/v1',request_id:'a'.repeat(24),url:'https://allowed.test/data',status:404,
    headers:{'Content-Type':['application/octet-stream']},body_base64:'AP8=',body_bytes:2,redirects:0,duration_ms:1,request_bytes:2,response_bytes:2};
  sdk._exchange = async (method,path,payload) => {calls.push({method,path,payload});return path==='/v1/capabilities'?caps:value;};
  const result = await sdk.fetchNetwork('https://allowed.test/data',{method:'POST',body:new Uint8Array([0,255]),headers:{Authorization:'remote-key'},timeoutMs:1000});
  assert.equal(result.status,404);assert.deepEqual([...result.body],[0,255]);
  assert.equal(calls[1].path,'/v2/net/fetch');assert.equal(calls[1].payload.body_base64,'AP8=');assert.equal(calls[1].payload.headers.Authorization,'remote-key');
  for (const options of [{body:'text'},{method:'CONNECT'},{timeoutMs:true},{followRedirects:'yes'},{body:new Uint8Array(262145)},{timeoutMs:1001}]) {
    await assert.rejects(()=>sdk.fetchNetwork('https://allowed.test',options),ConfigurationError);
  }
  for (const change of [{body_base64:'???'},{body_bytes:3},{redirects:6},{request_id:'other'},{headers:{X:'not-list'}},{status:true},{response_bytes:1}]) {
    const original=value;value={...original,...change};await assert.rejects(()=>sdk.fetchNetwork('https://allowed.test'),ProtocolError);value=original;
  }
  caps.features.network_fetch=false;
  await assert.rejects(()=>sdk.fetchNetwork('https://allowed.test'),UnsupportedCapability);
});

test('signed OSv job binds environment and binary stdin', async () => {
  const sdk = client();
  const calls = [];
  let stdinEnabled = true;
  sdk._exchange = async (_, path, payload) => {
    calls.push({ path, payload });
    if (path === '/v1/capabilities') return { ...capabilities,
      backend: 'firecracker-osv', allowed_entrypoints: ['/task-probe.so'],
      features: { environment: true, stdin: stdinEnabled } };
    return success;
  };
  await sdk.run({ entrypoint: '/task-probe.so', environment: { SANDBOX_TEST_MARKER: 'ok' },
    stdin: new Uint8Array([65, 0, 66, 255, 10]) });
  assert.equal(calls[1].payload.stdin, 'QQBC/wo=');
  assert.deepEqual(calls[1].payload.environment, { SANDBOX_TEST_MARKER: 'ok' });
  await sdk.run({ entrypoint: '/task-probe.so', stdin: new Uint8Array() });
  assert.equal(calls.at(-1).payload.stdin, '');
  stdinEnabled = false;
  await assert.rejects(sdk.run({ entrypoint: '/task-probe.so', stdin: new Uint8Array() }), UnsupportedCapability);
  await assert.rejects(sdk.run({ entrypoint: '/task-probe.so', stdin: new Uint8Array(16385) }), ConfigurationError);
  await assert.rejects(sdk.run({ entrypoint: '/task-probe.so', environment: { LD_PRELOAD: 'bad' } }), ConfigurationError);
});

test('Linux one-shot inputs bind cwd, environment and binary data with capability checks', async () => {
  const sdk=client(),calls=[];let enabled=true;
  sdk._exchange=async (_,path,payload)=>{
    calls.push({path,payload});
    if(path==='/v1/capabilities')return {...capabilities,features:{environment:true,stdin:true,working_directory:enabled}};
    return {...success,startup_mode:"warm"};
  };
  const job={entrypoint:'/bin/sh',cwd:'/input/nested',environment:{LD_LIBRARY_PATH:'/workspace/lib',KEY:'中文'},stdin:new Uint8Array([0,255])};
  assert.equal((await sdk.run(job)).startupMode,'warm');assert.equal(calls[1].payload.cwd,'/input/nested');assert.equal(calls[1].payload.stdin,'AP8=');assert.equal(calls[1].payload.environment.KEY,'中文');
  for(const cwd of ['relative','/workspace/\u0000bad','/workspace/\n','/'+('中'.repeat(342))])await assert.rejects(sdk.run({...job,cwd}),ConfigurationError);
  enabled=false;const before=calls.length;await assert.rejects(sdk.run(job),UnsupportedCapability);assert.equal(calls.length,before+1);
  await assert.rejects(sdk.run(job,{template:{backend:'firecracker-osv',artifactManifestSha256:digest}}),ConfigurationError);
  await assert.rejects(sdk.run({...job,environment:{KEY:'ok'}},{template:{backend:'firecracker-osv',artifactManifestSha256:digest}}),UnsupportedCapability);
});

test('session create, connect, run and close bind IDs and template', async () => {
  const sdk = client();
  const calls = [];
  sdk._exchange = async (method, path, payload, accepted) => {
    calls.push({ method, path, payload, accepted });
    if (path === '/v1/capabilities') return { ...capabilities,
      methods: [...capabilities.methods, 'POST /v2/sessions'],
      features: { ...capabilities.features, sessions: true } };
    if (path === '/v2/sessions' || method === 'GET') return sessionInfo;
    if (method === 'POST') return { session_id: sessionId, result: success };
    return {};
  };
  const session = await sdk.createSession({ ttlMs: 5000, inputFiles: [
    { path: 'x', data: new Uint8Array([65]) }] });
  assert.equal(session.id, sessionId);
  assert.equal(calls[1].payload.artifact_manifest_sha256, digest);
  assert.equal(calls[1].payload.input_files[0].data, 'QQ==');
  assert.deepEqual(calls[1].accepted, [201]);
  assert.equal((await sdk.connectSession(sessionId)).id, sessionId);
  assert.equal((await session.info()).id, sessionId);
  assert.equal((await session.run({ entrypoint: '/bin/sh' })).succeeded, true);
  await session.close();
  assert.deepEqual(calls.at(-1).accepted, [204]);
});

test('session rejects unsupported capability and mismatched binding', async () => {
  const sdk = client();
  sdk._exchange = async () => capabilities;
  await assert.rejects(sdk.createSession(), UnsupportedCapability);
  await assert.rejects(sdk.connectSession('../wrong'), ConfigurationError);
  sdk._exchange = async () => ({ ...sessionInfo, id: 'c'.repeat(24) });
  await assert.rejects(sdk.connectSession(sessionId), ProtocolError);
  sdk._exchange = async (_, path) => path === '/v2/sessions' ? sessionInfo :
    { session_id: 'c'.repeat(24), result: success };
  const session = await sdk.createSession({}, {
    template: { backend: 'firecracker-linux', artifactManifestSha256: digest } });
  await assert.rejects(session.run({ entrypoint: '/bin/sh' }), ProtocolError);
});

test('session file bytes, path and response binding', async () => {
  const sdk = client();
  const calls = [];
  sdk._exchange = async (_, path, payload) => {
    calls.push({ path, payload });
    if (path === '/v2/sessions') return sessionInfo;
    if (payload.action === 'write') return { session_id: sessionId, action: 'write',
      path: '/workspace/x', size: 3 };
    return { session_id: sessionId, action: 'read', path: '/workspace/x',
      size: 3, data_base64: 'AP8K' };
  };
  const session = await sdk.createSession({}, {
    template: { backend: 'firecracker-linux', artifactManifestSha256: digest } });
  assert.equal(await session.writeFile('/workspace/x', new Uint8Array([0, 255, 10])), 3);
  assert.equal(calls[1].payload.data_base64, 'AP8K');
  assert.deepEqual([...await session.readFile('/workspace/x')], [0, 255, 10]);
  await assert.rejects(session.readFile('/workspace/../secret'), ConfigurationError);
  sdk._exchange = async () => ({ session_id: sessionId, action: 'read',
    path: '/workspace/x', size: 2, data_base64: 'AA==' });
  await assert.rejects(session.readFile('/workspace/x'), ProtocolError);
});

test('session file list, stat and delete bind metadata', async () => {
  const sdk = client();
  sdk._exchange = async (_, path, payload) => {
    if (path === '/v2/sessions') return sessionInfo;
    if (payload.action === 'list') return { session_id: sessionId, action: 'list',
      path: '/workspace', size: 2, entries: ['a', 'sub'] };
    if (payload.action === 'stat') return { session_id: sessionId, action: 'stat',
      path: '/workspace/a', size: 3, kind: 'file' };
    return { session_id: sessionId, action: 'delete', path: '/workspace/a', size: 0 };
  };
  const session = await sdk.createSession({}, {
    template: { backend: 'firecracker-linux', artifactManifestSha256: digest } });
  assert.deepEqual(await session.listFiles(), ['a', 'sub']);
  assert.deepEqual(await session.statFile('/workspace/a'), { kind: 'file', size: 3 });
  assert.equal(await session.deleteFile('/workspace/a'), undefined);
  await assert.rejects(session.deleteFile('/workspace'), ConfigurationError);
  sdk._exchange = async () => ({ session_id: sessionId, action: 'list',
    path: '/workspace', size: 2, entries: ['z', 'a'] });
  await assert.rejects(session.listFiles(), ProtocolError);
});

test('E2B facade binds one session and preserves false versus denied', async () => {
  const sdk = client();
  let running = true;
  const calls = [];
  sdk._exchange = async (method, path, payload) => {
    calls.push({ method, path, payload });
    if (path === '/v1/capabilities') return { ...capabilities,
      methods: [...capabilities.methods, 'POST /v2/sessions'],
      features: { ...capabilities.features, sessions: true } };
    if (path === '/v2/sessions') return sessionInfo;
    if (path.endsWith('/files') && payload.action === 'read') return {
      session_id: sessionId, action: 'read', path: payload.path, size: 2, data_base64: 'aGk=' };
    if (path.endsWith('/files') && payload.path === '/workspace/missing') {
      throw new APIError(404, 'file_not_found', 'missing');
    }
    if (path.endsWith('/files') && payload.path === '/workspace/linked') {
      throw new APIError(403, 'file_denied', 'denied');
    }
    if (path.endsWith('/files')) return {
      session_id: sessionId, action: 'stat', path: payload.path, size: 2, kind: 'file' };
    if (!running) throw new APIError(404, 'not_found', 'closed');
    if (method === 'DELETE') { running = false; return {}; }
    return sessionInfo;
  };
  const sandbox = await Sandbox.create('firecracker-linux', { client: sdk, timeoutMs: 30000 });
  assert.equal(sandbox.sandboxId, sessionId);
  assert.equal(await sandbox.isRunning(), true);
  assert.equal(await sandbox.files.read('/workspace/text'), 'hi');
  assert.deepEqual([...await sandbox.files.read('/workspace/text', { format: 'bytes' })], [104, 105]);
  assert.equal(await sandbox.files.exists('/workspace/text'), true);
  assert.equal(await sandbox.files.exists('/workspace/missing'), false);
  await assert.rejects(sandbox.files.exists('/workspace/linked'),
    error => error instanceof APIError && error.status === 403);
  assert.equal(await sandbox.kill(), true);
  assert.equal(await sandbox.isRunning(), false);
  assert.equal(await sandbox.kill(), false);
  assert.equal(calls[1].payload.ttl_ms, 30000);
  await assert.rejects(Sandbox.create('base', { client: sdk }), UnsupportedCapability);
  await assert.rejects(sandbox.files.write('/workspace/new', new Blob(['x'])), UnsupportedCapability);
  await assert.rejects(sandbox.commands.run('forbidden',{user:'root'}), UnsupportedCapability);
});

test('E2B write creates parents and validates a batch before side effects', async () => {
  const sdk = client();
  const calls = [];
  sdk._exchange = async (_method, _path, payload) => {
    calls.push(payload);
    if (payload.action === 'mkdir') return { session_id: sessionId, action: 'mkdir',
      path: payload.path, size: 0, created: calls.length === 1 };
    if (payload.action === 'write') return { session_id: sessionId, action: 'write',
      path: payload.path, size: Buffer.from(payload.data_base64, 'base64').length };
    throw new Error('unexpected operation');
  };
  const sandbox = new Sandbox(new Session(sdk, {
    id: sessionId, backend: 'firecracker-linux', state: 'running',
    artifactManifestSha256: digest, createdAt: sessionInfo.created_at,
    expiresAt: sessionInfo.expires_at }));
  await assert.rejects(sandbox.files.writeFiles([
    { path: '/workspace/deep/a', data: 'ok' },
    { path: '/workspace/../escape', data: 'x' }]), ConfigurationError);
  await assert.rejects(sandbox.files.write('/workspace/huge', new Uint8Array(512 * 1024 + 1)),
    ConfigurationError);
  await assert.rejects(sandbox.files.write('/workspace/labelled', 'ok',
    { metadata: { 'bad key': 'x' } }), ConfigurationError);
  assert.equal(calls.length, 0);
  const result = await sandbox.files.writeFiles([
    { path: '/workspace/deep/a', data: 'ok' },
    { path: '/workspace/deep/b', data: new Uint8Array([33]) }]);
  assert.deepEqual(result, [
    { name: 'a', path: '/workspace/deep/a', type: 'file' },
    { name: 'b', path: '/workspace/deep/b', type: 'file' }]);
  assert.deepEqual(calls.map(call => call.action), ['mkdir', 'write', 'mkdir', 'write']);
  const labelled = await sandbox.files.write('/workspace/labelled', 'ok',
    { metadata: { label: 'proof' } });
  assert.deepEqual(labelled.metadata, { label: 'proof' });
  assert.deepEqual(calls.at(-1).metadata, { label: 'proof' });
});

test('E2B file info maps guest metadata and refuses missing or forged fields', async () => {
  const sdk = client();
  const fileInfo = { name: 'a', path: '/workspace/a', type: 'file', size: 3,
    mode: 0o100600, permissions: 'rw-------', owner: 'agent', group: 'agent',
    modified_time_ms: 1800000000000, metadata: { label: 'proof' } };
  const link = { name: 'link', path: '/workspace/link', type: 'symlink', size: 11,
    mode: 0o120777, permissions: 'rwxrwxrwx', owner: 'agent', group: 'agent',
    modified_time_ms: 1800000000000, symlink_target: '/etc/passwd' };
  const directory = { name: 'sub', path: '/workspace/sub', type: 'directory', size: 4096,
    mode: 0o40700, permissions: 'rwx------', owner: 'agent', group: 'agent',
    modified_time_ms: 1800000000000 };
  let next = 0;
  sdk._exchange = async (_, path, payload) => {
    if (path === '/v1/capabilities') return { ...capabilities,
      methods: [...capabilities.methods, 'POST /v2/sessions'],
      features: { ...capabilities.features, sessions: true } };
    if (path === '/v2/sessions') return sessionInfo;
    if (payload.action === 'list') return { session_id: sessionId, action: 'list',
      path: '/workspace', size: 3, entries: ['a', 'link', 'sub'],
      entry_infos: [fileInfo, link, directory] };
    const info = [fileInfo, link, undefined, { ...fileInfo, path: '/etc/passwd' }][next++];
    return { session_id: sessionId, action: 'info', path: payload.path,
      size: info?.type === 'symlink' ? 0 : 3, kind: info?.type === 'symlink' ? 'symlink' : 'file',
      ...(info === undefined ? {} : { info }) };
  };
  const sandbox = await Sandbox.create('firecracker-linux', { client: sdk });
  const entries = await sandbox.files.list('/workspace');
  assert.deepEqual(entries.map(value => [value.name, value.type]),
    [['a', 'file'], ['link', 'symlink'], ['sub', 'dir']]);
  assert.deepEqual(entries[0].metadata, { label: 'proof' });
  assert.equal(entries[1].symlinkTarget, '/etc/passwd');
  assert.equal(entries[2].owner, 'agent');
  assert.equal(entries[2].modifiedTime.getTime(), 1800000000000);
  assert.equal((await sandbox.files.getInfo('/workspace/a')).size, 3);
  assert.equal((await sandbox.files.getInfo('/workspace/link')).symlinkTarget, '/etc/passwd');
  await assert.rejects(sandbox.files.getInfo('/workspace/a'), UnsupportedCapability);
  await assert.rejects(sandbox.files.getInfo('/workspace/a'), ProtocolError);
  await assert.rejects(sandbox.files.list('/workspace', { depth: 2 }), UnsupportedCapability);
});

test('rename and recursive remove bind both paths and preserve metadata', async () => {
  const sdk = client();
  const session = new Session(sdk, sessionInfo);
  const sandbox = new Sandbox(session);
  const calls = [];
  let wrong = false;
  sdk._exchange = async (_, path, payload) => {
    calls.push({ path, payload });
    if (payload.action === 'remove') return { session_id: sessionId, action: 'remove', path: payload.path, size: 0 };
    return { session_id: sessionId, action: 'rename', path: payload.path,
      destination: wrong ? '/workspace/wrong' : payload.destination, kind: 'file', size: 3,
      info: { name: 'new', path: '/workspace/new', type: 'file', size: 3,
        mode: 0o100600, permissions: 'rw-------', owner: 'agent', group: 'agent',
        modified_time_ms: 1800000000000, metadata: { label: 'kept' } } };
  };
  const moved = await sandbox.files.rename('/workspace/old', '/workspace/new');
  assert.equal(moved.path, '/workspace/new');
  assert.deepEqual(moved.metadata, { label: 'kept' });
  await sandbox.files.remove('/workspace/tree');
  assert.equal(calls[0].payload.destination, '/workspace/new');
  await assert.rejects(sandbox.files.rename('/workspace/old', '/etc/out'), ConfigurationError);
  await assert.rejects(sandbox.files.remove('/workspace'), ConfigurationError);
  wrong = true;
  await assert.rejects(sandbox.files.rename('/workspace/old', '/workspace/new'), ProtocolError);
  assert.equal(calls.length, 3);
});

test('requires authenticated HTTPS origin and TLS material', () => {
  for (const url of ['http://localhost', 'https://user@localhost', 'https://localhost/path']) {
    assert.throws(() => new Client(url, { token: 'x', certFile, keyFile }), ConfigurationError);
  }
  assert.throws(() => new Client('https://localhost', { token: '', certFile, keyFile }), ConfigurationError);
  assert.throws(() => new Client('https://localhost', { token: 'x', certFile: '/missing', keyFile }), ConfigurationError);
});

test('binds v2 run to authenticated capability digest and encodes input bytes', async () => {
  const sdk = client();
  const calls = [];
  sdk._exchange = async (method, path, payload) => {
    calls.push({ method, path, payload });
    if (path === '/v1/capabilities') return capabilities;
    return { id: 'job', state: 'succeeded', backend: 'firecracker-linux',
      exit_code: 0, timed_out: false, duration_ms: 1, output: '',
      output_truncated: false, protocol_ok: true, guest_result: { stdout: 'ok' } };
  };
  const result = await sdk.run({ entrypoint: '/bin/sh', args: ['-c', 'cat /input/x'],
    inputFiles: [{ path: 'x', data: new TextEncoder().encode('ok') }] });
  assert.equal(calls[0].path, '/v1/capabilities');
  assert.equal(calls[1].path, '/v2/jobs');
  assert.equal(calls[1].payload.artifact_manifest_sha256, digest);
  assert.equal(calls[1].payload.input_files[0].data, 'b2s=');
  assert.equal(result.succeeded, true);
  assert.equal(result.guestResult.stdout, 'ok');
});

test('requires explicit legacy path and rejects unsupported jobs', async () => {
  const sdk = client();
  const calls = [];
  sdk._exchange = async (method, path) => {
    calls.push(path);
    if (path === '/v1/capabilities') return { ...capabilities, methods: [] };
    return { id: 'job', state: 'failed', backend: 'firecracker-linux',
      exit_code: 1, timed_out: false, duration_ms: 1, output: '',
      output_truncated: false, protocol_ok: true };
  };
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh' }), UnsupportedCapability);
  assert.deepEqual(calls, ['/v1/capabilities']);
  const result = await sdk.runLegacy({ entrypoint: '/bin/sh' });
  assert.equal(result.succeeded, false);
  assert.equal(calls[1], '/v1/jobs');
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh', network: 'all' }), UnsupportedCapability);
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh', inputFiles: [{ path: '../x', data: new Uint8Array() }] }), ConfigurationError);
});

test('explicit template skips capability lookup and validates digest', async () => {
  const sdk = client();
  const calls = [];
  sdk._exchange = async (_, path) => { calls.push(path); throw new TemplateMismatch(409, 'template_mismatch', 'stale'); };
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh' }, {
    template: { backend: 'firecracker-linux', artifactManifestSha256: digest }
  }), TemplateMismatch);
  assert.deepEqual(calls, ['/v2/jobs']);
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh' }, {
    template: { backend: 'firecracker-linux', artifactManifestSha256: 'bad' }
  }), ConfigurationError);
});

test('rejects malformed success data and oversized input', async () => {
  const sdk = client();
  sdk._exchange = async (_, path) => path === '/v1/capabilities' ? capabilities : { state: 'succeeded' };
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh' }), ProtocolError);
  await assert.rejects(sdk.run({ entrypoint: '/bin/sh', inputFiles: [{ path: 'x', data: new Uint8Array(512 * 1024 + 1) }] }), ConfigurationError);
});

test('background command handles bind IDs, resume output and wait for one terminal', async () => {
  const sdk = client();
  const session = new Session(sdk, sessionInfo);
  const commandId = 'c'.repeat(24);
  const info = { id: commandId, session_id: sessionId, state: 'running' };
  let killed = false;
  sdk._exchange = async (method, path) => {
    if (path.endsWith('/start')) return info;
    if (path.endsWith('/commands')) return { session_id: sessionId, commands: [info] };
    if (method === 'DELETE') { const accepted = !killed; killed = true; return { killed: accepted }; }
    return { info };
  };
  let wrong = false;
  sdk._events = async function* (path) {
    if (path.endsWith('after=0')) yield { kind: 'output', value: { session_id: sessionId, command_id: commandId,
      sequence: wrong ? 2 : 1, stream: 'stdout', data_base64: 'AP8=' } };
    yield { kind: 'result', value: { info: { ...info, state: 'succeeded' }, complete: true, next_sequence: 1,
      result: { session_id: sessionId, result: { ...success, id: commandId } } } };
  };
  const handle = await session.startCommand({ entrypoint: '/bin/sh', args: ['-c', 'printf data'] });
  assert.equal((await session.listCommands())[0].id, handle.id);
  assert.equal((await session.connectCommand(handle.id)).id, handle.id);
  assert.equal(await handle.kill(), true);
  assert.equal(await handle.kill(), false);
  const events = [];
  for await (const event of handle.events()) events.push(event);
  assert.deepEqual(events[0].data, new Uint8Array([0, 255]));
  assert.equal(events[1].result.id, commandId);
  assert.equal(events[1].result.succeeded, true);
  const resumed = [];
  for await (const event of handle.events(1)) resumed.push(event);
  assert.equal(resumed.length, 1);
  wrong = true;
  await assert.rejects(handle.wait(), ProtocolError);
});

test('E2B Bash commands expose PID, incremental callbacks, exit errors and cached waits', async () => {
  const { CommandExitError } = await import('./index.js');
  const commands=[];
  const session={id:sessionId,created:{backend:'firecracker-linux',artifactManifestSha256:digest},_client:{capabilities:async()=>({allowed_entrypoints:['/bin/bash'],limits:{max_timeout_ms:30000}})},
    async listCommands(){return commands.map(c=>c.info);},
    async startCommand(request){
      const native={id:'c'.repeat(24),info:{id:'c'.repeat(24),session_id:sessionId,pid:42,state:'running',entrypoint:request.entrypoint,args:request.args,environment:request.environment,cwd:request.cwd},
        iterations:0,async poll(){return {info:this.info};},async kill(){if(this.info.state!=='running')return false;this.info.state='cancelled';return true;},
        async *events(){this.iterations++;yield {sequence:1,stream:'stdout',data:new Uint8Array([111,107,226])};
          yield {sequence:2,stream:'stdout',data:new Uint8Array([130,172])};yield {sequence:3,stream:'stderr',data:Buffer.from('warning')};
          this.info.state='succeeded';yield {sequence:3,result:{id:this.id,exitCode:request.args.at(-1).includes('exit 7')?7:0,guestResult:{}}};}};
      commands.push(native);return native;
    }};
  const sandbox=new Sandbox(session),out=[];
  const final=await sandbox.commands.run('printf data',{envs:{KEY:'value'},cwd:'/workspace/sub',onStdout:s=>out.push(s)});
  assert.deepEqual(final,{stdout:'ok€',stderr:'warning',exitCode:0});assert.equal(out.join(''),'ok€');
  const handle=await sandbox.commands.run('exit 7',{background:true});
  assert.equal(handle.pid,42);
  for(let i=0;i<2;i++)await assert.rejects(handle.wait(),e=>e instanceof CommandExitError&&e.exitCode===7&&e.stdout==='ok€');
  assert.equal(commands[1].iterations,1);
  assert.equal(await sandbox.commands.kill(999),false);
  await assert.rejects(sandbox.commands.connect(999),e=>e instanceof APIError&&e.status===404);
  await assert.rejects(sandbox.commands.run('forbidden',{stdin:true}),UnsupportedCapability);
});

test('interactive stdin preserves bytes, confirms EOF and never retries timed-out input', async () => {
  const { CommandHandle, TimeoutException } = await import('./index.js');
  const sdk=client(),calls=[],receipts=new Map();
  let pending=false,foreign=false,last;
  sdk._exchange=async (method,path,payload)=>{
    calls.push({method,path,payload});let sequence;
    if(method==='POST'){
      sequence=receipts.size+1;last=payload;
      receipts.set(sequence,{session_id:sessionId,command_id:'c'.repeat(24),sequence,state:'pending',written_bytes:0,closed:false});
    }else{
      sequence=Number(path.split('/').at(-1));
      if(!pending)Object.assign(receipts.get(sequence),{state:last.close?'closed':'delivered',written_bytes:Buffer.from(last.data_base64,'base64').length,closed:last.close});
    }
    return {...receipts.get(sequence),...(foreign?{command_id:'d'.repeat(24)}:{})};
  };
  const info={id:'c'.repeat(24),session_id:sessionId,state:'running',pid:42};
  const session=new Session(sdk,sessionInfo);session.listCommands=async()=>[info];
  const native=new CommandHandle(session,info),facade=new Sandbox(session);
  await native.sendStdin(new Uint8Array([0,255]));assert.equal(calls[0].payload.data_base64,'AP8=');
  await facade.commands.sendStdin(42,'环境');assert.equal(Buffer.from(last.data_base64,'base64').toString(),'环境');
  await facade.commands.closeStdin(42);assert.equal(last.close,true);
  pending=true;await assert.rejects(native.sendStdin(Buffer.from('once'),{requestTimeoutMs:20}),TimeoutException);
  assert.equal(calls.filter(call=>call.method==='POST').length,4);
  assert.equal((await native.pollStdin(4)).state,'pending');pending=false;assert.equal((await native.pollStdin(4)).written_bytes,4);
  foreign=true;await assert.rejects(native.submitStdin(new Uint8Array()),ProtocolError);foreign=false;
  await assert.rejects(native.sendStdin(new Uint8Array(16385)),ConfigurationError);
  await assert.rejects(facade.commands.closeStdin(99),error=>error instanceof APIError&&error.status===404);
});

test('lifecycle info and paginator retain real metadata and convert timeout units', async () => {
  const sdk=client(),calls=[];
  const value={...sessionInfo,memory_mib:128,vcpus:1,guest_protocol:'fc-agent/v2',max_expires_at:'2026-10-30T00:10:00Z'};
  const replies=[{sessions:[value],next_cursor:'cursor1'},{sessions:[{...value,id:'c'.repeat(24)}]},value,value];
  sdk._exchange=async(method,path,payload)=>{calls.push({method,path,payload});return replies.shift();};
  const paginator=Sandbox.list({client:sdk,limit:1,order:'asc'});
  assert.equal(paginator.hasNext,true);
  const first=(await paginator.nextItems())[0];assert.equal(first.sandboxId,sessionId);assert.equal(first.cpuCount,1);assert.equal(first.memoryMB,128);assert.equal(first.envdVersion,'fc-agent/v2');
  assert.ok(first.startedAt instanceof Date&&first.endAt<=first.maxEndAt);assert.deepEqual(first.lifecycle,{onTimeout:'kill',autoResume:false});
  assert.equal(paginator.nextToken,'cursor1');assert.equal((await paginator.nextItems())[0].sandboxId,'c'.repeat(24));assert.equal(paginator.hasNext,false);
  await assert.rejects(paginator.nextItems());
  const sandbox=new Sandbox(new Session(sdk,{...sessionInfo,createdAt:value.created_at,expiresAt:value.expires_at}));
  assert.deepEqual(await sandbox.getInfo(),first);assert.equal(await sandbox.setTimeout(3000),undefined);assert.deepEqual(calls.at(-1).payload,{ttl_ms:3000});
  assert.ok(calls[1].path.includes('cursor=cursor1'));
  for(const options of [{limit:0},{limit:101},{order:'random'},{nextToken:'!'}])assert.throws(()=>Sandbox.list({client:sdk,...options}),ConfigurationError);
  assert.throws(()=>Sandbox.list({client:sdk,query:{metadata:{x:'y'}}}),UnsupportedCapability);
  await assert.rejects(sandbox.setTimeout(0),ConfigurationError);
});
