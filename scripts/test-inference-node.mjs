/** Actual Node SDK mTLS -> API/root Unix RPC -> TLS model; constructed VM owner. */
import {readFileSync, existsSync} from 'node:fs';
import assert from 'node:assert/strict';
import {Client, Session, InferenceError, APIError} from '../sdk/node/index.js';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const make = (token = 'inference-test-token') => new Client(config.url, {token, certFile: config.cert, keyFile: config.key, caFile: config.ca});
const client = make(), session = new Session(client, {...config.session, artifactManifestSha256: config.session.artifact_manifest_sha256});
const sid = session.id, identity = n => n.toString(16).padStart(24, '0');
const check = (name, value) => { assert.ok(value, name); console.log('PASS node ' + name); };
const entry = (bill, number) => bill.invocations.find(value => value.id === identity(number));
async function wait(action) {
  const deadline = Date.now() + 5000;
  for (;;) {
    const result = await action();
    if (result) return result;
    assert.ok(Date.now() < deadline, 'state observation timed out');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}
const result = await session.ml.invoke('model', {query: 'hi'}, {invocationId: identity(1)});
check('known-id-exact-money', result.taskId === sid && result.invocationId === identity(1) && result.data.answer === 'ok' &&
  typeof result.invocation.settled_units === 'string' && BigInt(result.invocation.settled_units) > 2n**53n);
await assert.rejects(session.ml.invoke('model', {query: 'hi'}, {invocationId: identity(1)}), error => {
  check('duplicate-no-replay', error instanceof InferenceError && error.invocationId === identity(1) && error.code === 'inference_replay' && error.deliveryUnknown); return true;
});
await assert.rejects(session.ml.invoke('other', {}, {invocationId: identity(4)}), error => {
  check('alias-denied-before-submit', error instanceof InferenceError && !error.deliveryUnknown); return true;
});
await assert.rejects(make('inference-other-token').getInferenceBill(sid), error => {
  check('other-tenant-history-hidden', error instanceof APIError && error.status === 404); return true;
});
const controller = new AbortController();
const pending = session.ml.invoke('model', {mode: 'pending'}, {invocationId: identity(2), signal: controller.signal});
// Attach rejection handling before cancelling so it cannot become unhandled.
const failed = pending.then(() => { throw new Error('pending model completed'); }, error => error);
await wait(() => existsSync(config.pending_marker));
check('bill-observable-with-pending-model', entry(await session.ml.bill(), 2)?.state === 'reserved');
controller.abort();
const failure = await failed;
const terminal = await wait(async () => { const value = entry(await session.ml.bill(), 2); return value?.state === 'uncertain' && value; });
check('AbortSignal-preserves-held-budget', failure instanceof InferenceError && failure.invocationId === identity(2) && failure.deliveryUnknown && terminal.settled_units === '0');
const large = await session.ml.invoke('model', {mode: 'unicode'}, {invocationId: identity(3)});
check('expanded-JSON-response', large.data.text === '\u2028'.repeat(140000) && large.invocation.output_bytes < 512 << 10);
await session.close();
await assert.rejects(client.capabilities(), error => error instanceof APIError && error.status === 503);
const bill = await session.ml.bill();
check('history-after-session-and-discovery-end', bill.closed && bill.invocations.length === 3 && BigInt(bill.held_units) > 0n);
assert.equal((await make().getInferenceBill(sid)).settled_units, bill.settled_units);
