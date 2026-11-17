#!/opt/node/bin/node
'use strict';
// Persistent REPL evaluation; control fd 3/4 never shares stdout or stdin.
// The guest supervisor owns this untrusted process and all its descendants.
const fs = require('node:fs');
const repl = require('node:repl');
const stream = require('node:stream');
const net = require('node:net');
const util = require('node:util');
const domain = require('node:domain');
const {AsyncLocalStorage} = require('node:async_hooks');
const ts = process.argv[2] === 'typescript' ? require('/opt/typescript/lib/typescript.js') : null;
const language = ts ? 'typescript' : 'javascript';
const FRAME_LIMIT = 96 * 1024;
const SOURCE_LIMIT = 64 * 1024;
const RESULT_LIMIT = 32 * 1024;

function emit(value) {
  const data = Buffer.from(JSON.stringify(value));
  if (data.length > FRAME_LIMIT) throw new Error('kernel result exceeds frame limit');
  const header = Buffer.alloc(4); header.writeUInt32BE(data.length);
  for (const part of [header, data]) {
    for (let offset = 0; offset < part.length;) {
      const count = fs.writeSync(4, part, offset, part.length - offset);
      if (count <= 0) throw new Error('kernel control output closed');
      offset += count;
    }
  }
}

async function* queuedRequests(onInterrupt) {
  let buffer = Buffer.alloc(0);
  const queue = [];
  let ended = false, failure = null, wake = null;
  const notify = () => {if (wake) {const accept = wake; wake = null; accept();}};
  // Register raw event callbacks before any REPL evaluation. Input delivery
  // must stay independent of the promises/domains that V8 evaluation cancels.
  const input = new net.Socket({fd: 3, readable: true, writable: false, allowHalfOpen: true});
  const fail = error => {failure = error; ended = true; notify(); input.destroy();};
  input.on('error', fail);
  input.on('end', () => {
    if (buffer.length) fail(new Error('truncated kernel control frame'));
    else {ended = true; notify();}
  });
  input.on('data', data => {
    try {
      buffer = Buffer.concat([buffer, data]);
      while (buffer.length >= 4) {
        const size = buffer.readUInt32BE();
        if (size === 0 || size > FRAME_LIMIT) throw new Error('kernel request exceeds frame limit');
        if (buffer.length < size + 4) break;
        const value = JSON.parse(buffer.subarray(4, 4 + size).toString('utf8'));
        buffer = buffer.subarray(4 + size);
        if (value && !Array.isArray(value) && Object.keys(value).join(',') === 'interrupt'
            && Number.isSafeInteger(value.interrupt) && value.interrupt > 0) {
          onInterrupt(value.interrupt); continue;
        }
        if (!value || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'code,env'
            || typeof value.code !== 'string' || Buffer.byteLength(value.code) > SOURCE_LIMIT
            || !value.env || Array.isArray(value.env) || typeof value.env !== 'object'
            || Object.keys(value.env).length > 64
            || Object.entries(value.env).some(([key, item]) => !key || key.length > 128
              || key.includes('=') || key.includes('\0') || typeof item !== 'string'
              || item.includes('\0') || Buffer.byteLength(item) > 8192)) {
          throw new Error('invalid kernel execution request');
        }
        if (queue.length >= 1) throw new Error('kernel request queue exceeded');
        queue.push(value); notify();
      }
      if (buffer.length > FRAME_LIMIT + 4) throw new Error('kernel control buffer exceeded');
    } catch (error) {fail(error);}
  });
  for (;;) {
    if (queue.length) {yield queue.shift(); continue;}
    if (failure) throw failure;
    if (ended) return;
    await new Promise(accept => {wake = accept;});
  }
}

async function main() {
  const input = new stream.PassThrough();
  const output = new stream.Writable({write(_data, _encoding, callback) {callback();}});
  // Node 22's REPL routes synchronous throws/await rejections through its
  // domain instead of its eval callback. Bind that route explicitly, too.
  // This pinned-version adapter is covered by actual throw/rejection tests.
  const evaluationDomain = domain.create();
  const resultContext = new AsyncLocalStorage();
  let rejectEvaluation = null;
  const server = repl.start({prompt: '', input, output, terminal: false,
    useGlobal: false, ignoreUndefined: true, breakEvalOnSigint: true, domain: evaluationDomain});
  evaluationDomain.on('error', error => {
    const origin = resultContext.getStore();
    if (rejectEvaluation && origin?.cellCount === activeCount) rejectEvaluation(error);
    else {console.error('kernel background error:', error); process.exit(2);}
  });
  server.context.console = console;
  server.context.display = data => {
    const current = resultContext.getStore();
    if (!current) throw new Error('display requires a cell task context');
    current.result(data, false);
  };
  let executionCount = 0;
  let activeCount = 0, abortCurrent = null, queuedCancellation = null;
  emit({type: 'ready', protocol: 'osv-code-kernel/v2', language, version: process.versions.node});
  for await (const request of queuedRequests(count => {
    if (count === activeCount && abortCurrent) {
      emit({type: 'interrupt_ack', execution_count: count});
      abortCurrent();
    } else if (activeCount === 0 && count === executionCount + 1) queuedCancellation = count;
  })) {
    executionCount++;
    const cellCount = executionCount;
    activeCount = cellCount;
    if (queuedCancellation === cellCount) {
      queuedCancellation = null; activeCount = 0;
      emit({type: 'interrupt_ack', execution_count: cellCount});
      emit({type: 'error', execution_count: cellCount, name: 'Error',
        value: 'Script execution was interrupted before evaluation', traceback: ''});
      emit({type: 'done', execution_count: cellCount});
      continue;
    }
    let results = 0, resultBytes = 0;
    function result(data, main) {
      if (!data || Array.isArray(data) || typeof data !== 'object'
          || Object.keys(data).length === 0 || Object.keys(data).length > 16
          || Object.keys(data).some(key => key.length > 128 || !key.includes('/'))) {
        throw new Error('display requires a bounded MIME dictionary');
      }
      const bytes = Buffer.byteLength(JSON.stringify(data));
      if (results >= 16 || resultBytes + bytes > RESULT_LIMIT) throw new Error('code result budget exceeded');
      results++; resultBytes += bytes;
      emit({type: 'result', data, is_main_result: main, execution_count: cellCount});
    }
    const previous = new Map(Object.keys(request.env).map(key => [key, process.env[key]]));
    try {
      Object.assign(process.env, request.env);
      let code = request.code;
      if (ts) {
        const compiled = ts.transpileModule(code, {reportDiagnostics: true,
          compilerOptions: {target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS}});
        const errors = compiled.diagnostics.filter(item => item.category === ts.DiagnosticCategory.Error);
        if (errors.length) throw new SyntaxError(ts.flattenDiagnosticMessageText(errors[0].messageText, '\n'));
        code = compiled.outputText;
      }
      const value = await resultContext.run({result, cellCount}, () => new Promise((accept, reject) => {
        let settled = false, callbackCalled = false;
        rejectEvaluation = error => {settled = true; reject(error);};
        emit({type: 'execution_state', execution_count: cellCount, state: 'evaluating'});
        server.eval(code + '\n', server.context, '<cell-' + executionCount + '>',
          (error, data) => {
            callbackCalled = true;
            if (error) rejectEvaluation(error instanceof repl.Recoverable ? error.err : error);
            else Promise.resolve(data).then(value => {settled = true; accept(value);}, rejectEvaluation);
          });
        emit({type: 'execution_state', execution_count: cellCount, state: 'event_loop'});
        // Async cancellation stays in the event loop. Process SIGINT is only
        // the supervisor's fallback for synchronous CPU evaluation, where the
        // pinned REPL/V8 watchdog is already active. No process signal listener
        // is installed/restored across that watchdog's transition.
        if (!settled) {
          abortCurrent = () => {
            if (!callbackCalled) server.emit('SIGINT');
            else rejectEvaluation(new Error('Script execution was interrupted by supervisor'));
          };
        }
      }));
      if (value !== undefined) {
        result({'text/plain': util.inspect(value, {depth: 5, maxArrayLength: 64, maxStringLength: 4096,
          breakLength: 100, colors: false, customInspect: true})}, true);
      }
    } catch (error) {
      emit({type: 'error', execution_count: cellCount, name: String(error?.name || 'Error').slice(0, 128),
        value: String(error?.message || error).slice(0, 4096),
        traceback: String(error?.stack || error).slice(-8192)});
    } finally {
      abortCurrent = null;
      activeCount = 0;
      rejectEvaluation = null;
      for (const [key, value] of previous) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
      }
    }
    await Promise.all([process.stdout, process.stderr].map(output =>
      new Promise((accept, reject) => output.write('', error => error ? reject(error) : accept()))));
    emit({type: 'done', execution_count: executionCount});
  }
  server.close();
  input.end();
}

main().catch(error => {console.error('kernel protocol failure:', error); process.exit(2);});
