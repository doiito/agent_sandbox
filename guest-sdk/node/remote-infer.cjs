'use strict';
// Fixed guest-only route. Built-in HTTP performs one request, without agents,
// redirects, environment proxies, credentials or application-level retries.
const http = require('node:http');
const {randomBytes} = require('node:crypto');
const contract = require('./inference-contract.cjs');
const {APIError, ConfigurationError, TransportError, ProtocolError, UnsupportedCapability,
  InferenceError, inferenceId, inferenceJSON, inferenceBill, inferenceReceipt,
  inferenceKeys, inferencePolicyDocument, INFERENCE_ENDPOINT} = contract;
const HOST = 'inference.osv.invalid', MAX_BODY = (512 << 10) * 2 + (64 << 10);
let taskId;

function options(value, allowed) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) {
    throw new ConfigurationError('invalid inference options');
  }
  return value;
}

async function bounded(value, action) {
  const {requestTimeoutMs = 35000, signal} = value;
  if (typeof requestTimeoutMs !== 'number' || !Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0 || requestTimeoutMs > 300000 ||
      signal !== undefined && !(signal instanceof AbortSignal)) throw new ConfigurationError('invalid inference deadline or signal');
  const controller = new AbortController(), abort = () => controller.abort();
  const timer = setTimeout(abort, requestTimeoutMs);
  timer.unref();
  if (signal?.aborted) abort();
  signal?.addEventListener('abort', abort, {once: true});
  try { return await action(controller.signal); }
  finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

function exchange(method, path, value, signal) {
  if (!['GET /v1/bill', 'GET /v1/policy', 'POST /v1/invoke'].includes(`${method} ${path}`)) throw new ConfigurationError('invalid inference route');
  const data = value === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(value));
  if (data.length > (256 << 10) + 8192) throw new ConfigurationError('encoded inference request exceeds limit');
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (failure, answer) => {
      if (done) return;
      done = true;
      if (failure) reject(failure); else resolve(answer);
    };
    const request = http.request({hostname: '127.0.0.1', port: 3128, method, path: `http://${HOST}${path}`,
      agent: false, signal, maxHeaderSize: 16384, insecureHTTPParser: false,
      headers: {Host: HOST, 'Content-Type': 'application/json', 'Content-Length': data.length, Connection: 'close'}}, response => {
      const fail = message => { finish(new ProtocolError(message)); response.destroy(); request.destroy(); };
      const names = new Set();
      for (let i = 0; i < response.rawHeaders.length; i += 2) {
        const name = response.rawHeaders[i].toLowerCase();
        if (names.has(name)) { fail('duplicate inference response header'); return; }
        names.add(name);
      }
      const length = response.headers['content-length'];
      if (typeof length !== 'string' || !/^(0|[1-9][0-9]{0,7})$/.test(length) || Number(length) > MAX_BODY ||
          response.headers['transfer-encoding'] !== undefined || (response.headers['content-encoding'] ?? 'identity') !== 'identity' ||
          response.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
        fail('invalid inference response framing'); return;
      }
      const chunks = [];
      let received = 0;
      response.on('data', chunk => {
        received += chunk.length;
        if (received > MAX_BODY || received > Number(length)) fail('inference response exceeds limit');
        else chunks.push(chunk);
      });
      response.on('error', () => finish(new TransportError('incomplete inference response')));
      response.on('aborted', () => finish(new TransportError('incomplete inference response')));
      response.on('end', () => {
        if (done) return;
        try {
          if (received !== Number(length)) throw new ProtocolError('incomplete inference response body');
          const bytes = Buffer.concat(chunks), text = bytes.toString('utf8');
          if (!Buffer.from(text).equals(bytes)) throw new ProtocolError('invalid inference UTF-8');
          let answer;
          try { answer = JSON.parse(text); } catch { throw new ProtocolError('invalid inference JSON'); }
          if (response.statusCode !== 200) {
            if (answer?.protocol !== 'osv-sandbox-inference-error/v1' || typeof answer.error?.code !== 'string' || !/^[a-z0-9_]{1,64}$/.test(answer.error.code)) throw new ProtocolError('invalid inference error response');
            throw new APIError(response.statusCode, answer.error.code, 'guest inference request rejected');
          }
          finish(undefined, answer);
        } catch (cause) { finish(cause); }
      });
    });
    request.on('error', () => finish(new TransportError('guest inference transport failed')));
    request.end(data); // Ends the HTTP body, never half-closes the socket.
  });
}

async function readBill(signal) {
  const value = await exchange('GET', '/v1/bill', undefined, signal);
  const result = inferenceBill(value, taskId ?? value?.task_id);
  taskId = result.task_id;
  return result;
}

function bill(value = {}) {
  return bounded(options(value, ['requestTimeoutMs', 'signal']), readBill);
}

function policy(value = {}) {
  return bounded(options(value, ['requestTimeoutMs', 'signal']), async signal =>
    inferencePolicyDocument(await exchange('GET', '/v1/policy', undefined, signal)));
}

async function invoke(endpoint, payload, value = {}) {
  const opts = options(value, ['invocationId', 'timeoutMs', 'requestTimeoutMs', 'signal']);
  const {invocationId = randomBytes(12).toString('hex'), timeoutMs = 0} = opts;
  inferenceId(invocationId);
  let attempted = false;
  try {
    if (typeof endpoint !== 'string' || !INFERENCE_ENDPOINT.test(endpoint) || !Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 30000) throw new ConfigurationError('invalid inference alias or timeout');
    const {snapshot, size} = inferenceJSON(payload, 256 << 10);
    return await bounded(opts, async signal => {
      const task = (await readBill(signal)).task_id;
      const current = inferencePolicyDocument(await exchange('GET', '/v1/policy', undefined, signal));
      if (!current.endpoints.some(item => item.name === endpoint)) throw new UnsupportedCapability('inference alias is not authorized');
      if (size > current.max_request_bytes || timeoutMs > current.timeout_ms) throw new ConfigurationError('inference payload or timeout exceeds tenant policy');
      if (signal.aborted) throw new TransportError('inference observation deadline elapsed');
      attempted = true;
      const result = await exchange('POST', '/v1/invoke', {id: invocationId, endpoint, payload: snapshot, timeout_ms: timeoutMs}, signal);
      inferenceKeys(result, ['protocol', 'task_id', 'invocation', 'data']);
      if (result.protocol !== 'osv-sandbox-inference-invoke/v1' || result.task_id !== task) throw new ProtocolError('invalid inference result binding');
      inferenceReceipt(result.invocation);
      if (result.invocation.id !== invocationId || result.invocation.endpoint !== endpoint || result.invocation.state !== 'succeeded') throw new ProtocolError('invalid inference result invocation');
      const data = inferenceJSON(result.data, 4 << 20, ProtocolError).snapshot;
      return Object.freeze({taskId: task, invocationId, invocation: Object.freeze(result.invocation), data});
    });
  } catch (cause) { throw new InferenceError(taskId, invocationId, cause, attempted); }
}

module.exports = {invoke, bill, policy, ml: Object.freeze({invoke, bill, policy}),
  APIError, ConfigurationError, TransportError, ProtocolError, UnsupportedCapability, InferenceError};
