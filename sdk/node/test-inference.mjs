import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Client, Session, InferenceError, ProtocolError, ConfigurationError, TransportError, APIError} from './index.js';

const fixture = JSON.parse(readFileSync(new URL('../../tests/fixtures/inference-sdk.json', import.meta.url), 'utf8'));
const sid = fixture.session.id, iid = fixture.result.invocation.id;
const clone = value => structuredClone(value);
function setup(replies, network = 'proxy') {
  const client = Object.create(Client.prototype), calls = [];
  client._timeout = 360000;
  client._exchange = async (method, path, body, accepted, timeout, signal) => {
    calls.push({method, path, body: clone(body), signal});
    if (signal?.aborted) throw new TransportError('cancelled');
    const next = replies.shift();
    if (next instanceof Error) throw next;
    return typeof next === 'function' ? next(calls.at(-1)) : clone(next);
  };
  const info = {...fixture.session, artifactManifestSha256: fixture.session.artifact_manifest_sha256, network};
  return {client, session: new Session(client, info), calls};
}

test('inference sends a fixed identity and preserves exact amounts in independent history', async () => {
  const {session, client, calls} = setup([fixture.capabilities, fixture.result, fixture.bill, fixture.bill]);
  const result = await session.ml.invoke('model', {query: 'hi'}, {invocationId: iid, timeoutMs: 1000});
  assert.equal(result.taskId, sid); assert.equal(result.invocationId, iid);
  assert.deepEqual(result.data, {answer: 'ok'});
  assert.equal(result.invocation.settled_units, '9007199254741066');
  assert.deepEqual(calls[1].body, {id: iid, endpoint: 'model', payload: {query: 'hi'}, timeout_ms: 1000});
  assert.equal(calls[1].path, `/v2/sessions/${sid}/ml/invocations`);
  assert.equal((await session.ml.bill()).settled_units, '9007199254741066');
  assert.equal((await client.getInferenceBill(sid)).closed, true);
  assert.ok(calls.slice(2).every(call => call.path === `/v2/ml/bills/${sid}`));
});

test('inference generated identities survive lost replies and HTTP rejections without replay', async () => {
  for (const failure of [new TransportError('lost'), new APIError(409, 'inference_replay', 'already known')]) {
    const {session, calls} = setup([fixture.capabilities, failure]);
    await assert.rejects(session.ml.invoke('model', {query: 'hi'}), error => {
      assert.ok(error instanceof InferenceError);
      assert.match(error.invocationId, /^[0-9a-f]{24}$/);
      assert.equal(error.invocationId, calls[1].body.id);
      assert.equal(error.taskId, sid); assert.equal(error.cause, failure);
      assert.equal(error.deliveryUnknown, true);
      return true;
    });
    assert.equal(calls.length, 2);
  }
});

test('inference snapshots plain JSON before capability IO', async () => {
  const payload = {query: 'hi'};
  const {session, calls} = setup([() => { payload.query = 'changed while waiting'; return clone(fixture.capabilities); }, fixture.result]);
  await session.ml.invoke('model', payload, {invocationId: iid});
  assert.deepEqual(calls[1].body.payload, {query: 'hi'});
});

test('inference rejects lossy custom or oversized JSON without making requests', async () => {
  const cycle = []; cycle.push(cycle);
  let invoked = false;
  const getter = Object.defineProperty({}, 'secret', {enumerable: true, get() { invoked = true; return 'bad'; }});
  for (const payload of [NaN, Infinity, 2 ** 54, 1n, undefined, {bad: undefined}, '\ud800', cycle, new Date(), new Map(),
      getter, {toJSON() { invoked = true; return {}; }}, [,,], {query: 'a'.repeat(256 << 10)}]) {
    const {session, calls} = setup([]);
    await assert.rejects(session.ml.invoke('model', payload, {invocationId: iid}), error => {
      assert.ok(error instanceof InferenceError && error.cause instanceof ConfigurationError);
      assert.equal(error.deliveryUnknown, false); return true;
    });
    assert.equal(calls.length, 0);
  }
  assert.equal(invoked, false);
  const {session, calls} = setup([]);
  await assert.rejects(session.ml.invoke('model', {}, {invocationId: 'bad'}), ConfigurationError);
  await assert.rejects(session.ml.invoke('https://provider.invalid', {}, {invocationId: iid}), InferenceError);
  await assert.rejects(session.ml.invoke('model', {}, {invocationId: iid, timeoutMs: true}), InferenceError);
  assert.equal(calls.length, 0);
});

test('Linux v8 preserves signed native inference capability', async () => {
  const cap = clone(fixture.capabilities);
  cap.artifact_manifest_protocol = 'osv-sandbox-artifacts/v8';
  const {session} = setup([cap, fixture.result]);
  const result = await session.ml.invoke('model', {query:'hi'}, {invocationId:iid, timeoutMs:1000});
  assert.deepEqual(result.data,{answer:'ok'});
});

test('inference checks owner capabilities aliases and limits before POST', async () => {
  for (const name of ['old-profile', 'other-session', 'wrong-template', 'disabled', 'unknown-alias', 'size', 'timeout', 'network']) {
    const cap = clone(fixture.capabilities);
    if (name === 'old-profile') cap.artifact_manifest_protocol = 'osv-sandbox-artifacts/v6';
    if (name === 'other-session') cap.session_id = 'e'.repeat(24);
    if (name === 'wrong-template') cap.artifact_manifest_sha256 = 'e'.repeat(64);
    if (name === 'disabled') cap.features.remote_inference = false;
    const {session, calls} = setup([cap], name === 'network' ? 'none' : 'proxy');
    await assert.rejects(session.ml.invoke(name === 'unknown-alias' ? 'other' : 'model', {query: name === 'size' ? 'x'.repeat(200) : 'hi'},
      {invocationId: iid, timeoutMs: name === 'timeout' ? 1001 : 0}), error => {
      assert.ok(error instanceof InferenceError); assert.equal(error.deliveryUnknown, false); return true;
    });
    assert.ok(calls.every(call => call.method === 'GET'));
  }
});

test('inference validates result bindings and accounting before returning data', async () => {
  for (const name of ['task', 'id', 'endpoint', 'price-number', 'settled', 'unfinished', 'unstarted', 'duration', 'zero-start', 'nonfinite-output']) {
    const result = clone(fixture.result), invoice = result.invocation;
    if (name === 'task') result.task_id = 'e'.repeat(24);
    if (name === 'id') invoice.id = 'e'.repeat(24);
    if (name === 'endpoint') invoice.endpoint = 'other';
    if (name === 'price-number') invoice.price.request_units = 9007199254740993;
    if (name === 'settled') invoice.settled_units = '0';
    if (name === 'unfinished') delete invoice.finished_at;
    if (name === 'unstarted') invoice.dispatched = false;
    if (name === 'duration') invoice.duration_ms = -1;
    if (name === 'zero-start') invoice.started_at = '0001-01-01T00:00:00Z';
    if (name === 'nonfinite-output') result.data = Infinity;
    const {session, calls} = setup([fixture.capabilities, result]);
    await assert.rejects(session.ml.invoke('model', {query: 'hi'}, {invocationId: iid}), error => {
      assert.ok(error instanceof InferenceError && error.cause instanceof ProtocolError);
      assert.equal(error.invocationId, iid); assert.equal(error.deliveryUnknown, true); return true;
    });
    assert.equal(calls.length, 2);
  }
});

test('inference history preserves pending uncertain balances and rejects corrupt bills', async () => {
  const bill = clone(fixture.bill), invoice = bill.invocations[0];
  Object.assign(invoice, {state: 'reserved', dispatched: false, http_status: 0, output_bytes: 0, settled_units: '0'});
  delete invoice.finished_at;
  Object.assign(bill, {closed: false, settled_units: '0', held_units: invoice.reserved_units});
  let {session} = setup([bill]);
  assert.equal((await session.ml.bill()).held_units, '9007199254741405');
  Object.assign(invoice, {state: 'uncertain', code: 'inference_restarted', finished_at: '2026-11-07T00:00:01Z'});
  bill.closed = true;
  ({session} = setup([bill]));
  assert.equal((await session.ml.bill()).invocations[0].state, 'uncertain');
  for (const edit of [b => b.held_units = '0', b => b.budget_units = '1', b => b.task_id = 'e'.repeat(24), b => b.invocations.push(b.invocations[0]),
      b => b.invocations[0].reserved_units = '09007199254741405', b => b.invocations[0].reserved_units = '18446744073709551616']) {
    const broken = clone(bill); edit(broken);
    ({session} = setup([broken]));
    await assert.rejects(session.ml.bill(), ProtocolError);
  }
  const oversized = clone(fixture.bill), entry = oversized.invocations[0];
  Object.assign(entry, {output_bytes: entry.max_output_bytes + 1, settled_units: entry.reserved_units});
  oversized.settled_units = entry.reserved_units;
  ({session} = setup([oversized]));
  await assert.rejects(session.ml.bill(), ProtocolError);
});

test('inference propagates cancellation and deadline without replay', async () => {
  for (const timeout of [false, true]) {
    const controller = new AbortController();
    const {session, calls} = setup([fixture.capabilities, ({signal}) => new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => reject(new TransportError('cancelled')), {once: true});
      if (!timeout) queueMicrotask(() => controller.abort());
    })]);
    // Keep the process alive until the simulated pending HTTP request settles.
    const keep = setTimeout(() => {}, 1000);
    try {
      await assert.rejects(session.ml.invoke('model', {}, {invocationId: iid, signal: controller.signal, requestTimeoutMs: timeout ? 10 : 1000}), error => {
        assert.ok(error instanceof InferenceError); assert.equal(error.invocationId, iid); assert.equal(error.deliveryUnknown, true); return true;
      });
      assert.equal(calls.length, 2);
    } finally { clearTimeout(keep); }
  }
  const controller = new AbortController(); controller.abort();
  const {session, calls} = setup([]);
  await assert.rejects(session.ml.invoke('model', {}, {invocationId: iid, signal: controller.signal}), error => {
    assert.equal(error.deliveryUnknown, false); return true;
  });
  assert.equal(calls.length, 1); // Only the aborted capability exchange was attempted.
});
