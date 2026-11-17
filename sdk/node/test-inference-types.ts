import {Client, Session, InferenceError, type InferenceResult, type InferenceBill} from './index.js';
declare const client: Client;
declare const session: Session;
async function invoke(): Promise<string> {
  const controller = new AbortController();
  const result: InferenceResult = await session.ml.invoke('model', {query: 'hi'}, {signal: controller.signal, invocationId: 'a'.repeat(24)});
  const bill: InferenceBill = await client.getInferenceBill(result.taskId);
  const units: string = bill.settled_units;
  await session.ml.bill({requestTimeoutMs: 1000});
  await session.capabilities({signal: controller.signal});
  // @ts-expect-error JSON must not silently convert BigInt.
  await session.ml.invoke('model', 1n);
  // @ts-expect-error Monetary units are decimal strings.
  const lossy: number = bill.held_units;
  return units;
}
function failure(error: InferenceError): string {
  const uncertain: boolean = error.deliveryUnknown;
  return error.taskId + error.invocationId + uncertain;
}
void invoke; void failure;
