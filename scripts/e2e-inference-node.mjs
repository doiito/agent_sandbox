/** Installed host Node SDK against an actual running, root-owned KVM session. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const {Client, InferenceError} = await import(pathToFileURL(config.release + '/sdk/node/index.js'));
const client = new Client(config.url, {token: readFileSync(config.root + '/secrets/token', 'utf8'),
  caFile: config.root + '/tls/ca.crt', certFile: config.root + '/tls/client.crt', keyFile: config.root + '/tls/client.key'});
const session = await client.connectSession(config.session_id), checks = [];
const check = (name, condition) => {assert.ok(condition, name); checks.push(name);};
const id = n => n.toString(16).padStart(24, '0');
const value = await session.ml.invoke('model', {}, {invocationId: id(201)});
check('actual-owner-exact-money', value.taskId === session.id && value.data.answer === 'ok' && BigInt(value.invocation.settled_units) > 2n**53n);
await assert.rejects(session.ml.invoke('model', {}, {invocationId: id(201)}), error => {
  check('known-ID-never-replayed', error instanceof InferenceError && error.invocationId === id(201) && error.code === 'inference_replay'); return true;
});
const controller = new AbortController();
const pendingEvents = () => readFileSync(config.root + '/results/upstream-events.jsonl', 'utf8').trim().split('\n').filter(line => JSON.parse(line).event === 'model-pending').length;
const pendingBefore = pendingEvents();
const pending = session.ml.invoke('model', {mode: 'pending'}, {invocationId: id(202), signal: controller.signal});
const failed = pending.then(() => {throw new Error('pending call completed');}, error => error);
const deadline = Date.now() + 10000;
for (;;) {
  const bill = await session.ml.bill();
  if (bill.invocations.find(row => row.id === id(202))?.state === 'reserved' && pendingEvents() > pendingBefore) break;
  assert.ok(Date.now() < deadline, 'pending bill was not observable');
  await new Promise(resolve => setTimeout(resolve, 25));
}
controller.abort();
const error = await failed;
check('AbortSignal-keeps-known-ID', error instanceof InferenceError && error.invocationId === id(202) && error.deliveryUnknown);
for (;;) {
  const receipt = (await session.ml.bill()).invocations.find(row => row.id === id(202));
  if (receipt?.state === 'uncertain') {check('cancel-retains-full-budget', receipt.settled_units === '0' && BigInt(receipt.reserved_units) > 0n); break;}
  assert.ok(Date.now() < deadline, 'cancel did not drain');
  await new Promise(resolve => setTimeout(resolve, 25));
}
console.log(JSON.stringify({passed: true, cases: checks, session_id: session.id}));
