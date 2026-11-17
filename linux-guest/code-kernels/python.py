#!/opt/python/bin/python3.12
"""Persistent Python kernel. Control is fd 3/4; user stdin/out stay separate.

This process is not a security boundary. Its supervisor owns framing, output,
deadlines and descendants; all results remain untrusted tenant data.
"""
import ast
import asyncio
import base64
import contextvars
import inspect
import json
import os
import reprlib
import signal
import struct
import sys
import traceback

FRAME_LIMIT = 96 * 1024
SOURCE_LIMIT = 64 * 1024
RESULT_LIMIT = 32 * 1024
RESULTS_LIMIT = 16
ACTIVE_TASK = None
RESULTS_CONTEXT = contextvars.ContextVar('osv-cell-results', default=None)
MIME_METHODS = {
    'text/html': '_repr_html_', 'text/markdown': '_repr_markdown_',
    'image/svg+xml': '_repr_svg_', 'image/png': '_repr_png_',
    'image/jpeg': '_repr_jpeg_', 'application/pdf': '_repr_pdf_',
    'text/latex': '_repr_latex_', 'application/json': '_repr_json_',
    'application/javascript': '_repr_javascript_',
}


async def receive(reader):
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError as error:
        if not error.partial:
            raise EOFError from error
        raise ValueError('truncated kernel control header') from error
    size = struct.unpack('!I', header)[0]
    if size == 0 or size > FRAME_LIMIT:
        raise ValueError('kernel request exceeds frame limit')
    value = json.loads(await reader.readexactly(size))
    if (not isinstance(value, dict) or set(value) != {'code', 'env'}
            or not isinstance(value['code'], str) or len(value['code'].encode()) > SOURCE_LIMIT
            or not isinstance(value['env'], dict) or len(value['env']) > 64
            or any(not isinstance(k, str) or not isinstance(v, str) or not k or '=' in k
                   or '\0' in k + v or len(k) > 128 or len(v.encode()) > 8192
                   for k, v in value['env'].items())):
        raise ValueError('invalid kernel execution request')
    return value


def emit(value):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()
    if len(data) > FRAME_LIMIT:
        raise ValueError('kernel result exceeds frame limit')
    pending = memoryview(struct.pack('!I', len(data)) + data)
    while pending:
        written = os.write(4, pending)
        if written <= 0:
            raise BrokenPipeError('kernel control output closed')
        pending = pending[written:]


class Results:
    def __init__(self, execution_count):
        self.execution_count = execution_count
        self.count = 0
        self.bytes = 0

    def send(self, data, main):
        if not isinstance(data, dict) or not data or len(data) > 16:
            raise ValueError('display requires a bounded MIME dictionary')
        encoded = json.dumps(data, ensure_ascii=True, allow_nan=False).encode()
        if self.count >= RESULTS_LIMIT or self.bytes + len(encoded) > RESULT_LIMIT:
            raise ValueError('code result budget exceeded')
        self.count += 1
        self.bytes += len(encoded)
        emit({'type': 'result', 'data': data, 'is_main_result': main,
              'execution_count': self.execution_count})


def mime(value):
    formatter = reprlib.Repr()
    formatter.maxstring = formatter.maxother = 4096
    formatter.maxlist = formatter.maxtuple = formatter.maxdict = 64
    result = {'text/plain': formatter.repr(value)}
    bundle = getattr(value, '_repr_mimebundle_', None)
    if callable(bundle):
        data = bundle()
        if isinstance(data, tuple):
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError('_repr_mimebundle_ must return MIME data')
        result.update(data)
    else:
        for name, method in MIME_METHODS.items():
            formatter = getattr(value, method, None)
            if callable(formatter):
                data = formatter()
                if isinstance(data, tuple):
                    data = data[0]
                if data is not None:
                    result[name] = data
    for name, data in list(result.items()):
        if not isinstance(name, str) or len(name) > 128 or '/' not in name:
            raise ValueError('invalid display MIME type')
        if isinstance(data, bytes) and name in {'image/png', 'image/jpeg', 'application/pdf'}:
            result[name] = base64.b64encode(data).decode('ascii')
        elif name != 'application/json' and not isinstance(data, str):
            raise ValueError('display format must contain text or encoded image data')
    return result


async def evaluate(code, namespace, filename, results):
    tree = ast.parse(code, filename, 'exec')
    last = tree.body.pop() if tree.body and isinstance(tree.body[-1], ast.Expr) else None
    flags = ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
    if tree.body:
        pending = eval(compile(tree, filename, 'exec', flags), namespace)
        if inspect.isawaitable(pending):
            await pending
    if last is not None:
        expression = ast.Expression(last.value)
        value = eval(compile(expression, filename, 'eval', flags), namespace)
        if inspect.isawaitable(value):
            value = await value
        if value is not None:
            namespace['_'] = value
            results.send(mime(value), True)


async def cell(code, namespace, filename, results):
    global ACTIVE_TASK
    ACTIVE_TASK = asyncio.current_task()
    token = RESULTS_CONTEXT.set(results)
    try:
        await evaluate(code, namespace, filename, results)
    except BaseException as error:
        if isinstance(error, asyncio.CancelledError):
            error = KeyboardInterrupt('execution interrupted')
        # Catch in the task so KeyboardInterrupt/SystemExit cannot stop the
        # event loop and strand the next execution's completion callback.
        emit({'type': 'error', 'execution_count': results.execution_count,
              'name': type(error).__name__, 'value': str(error)[:4096],
              'traceback': ''.join(traceback.format_exception(error))[-8192:]})
    finally:
        RESULTS_CONTEXT.reset(token)
        ACTIVE_TASK = None


def interrupt(_signal, frame):
    if ACTIVE_TASK is None:
        return
    # asyncio's default first SIGINT only cancels the task, which cannot stop
    # a CPU loop without an await. Raise while executing a cell; cancel while
    # suspended in the event loop. Unresponsive native code needs supervisor
    # escalation and an explicitly failed context.
    if asyncio.current_task(loop=ACTIVE_TASK.get_loop()) is ACTIVE_TASK:
        while frame is not None:
            if frame.f_code.co_filename.startswith('<cell-'):
                raise KeyboardInterrupt('execution interrupted')
            frame = frame.f_back
    # SIGINT may arrive while the loop is blocked in epoll. Calling cancel()
    # alone schedules callbacks without waking that selector; PEP 475 can then
    # restart the wait for its original (possibly very long) timeout. The
    # thread-safe scheduling path also writes the loop's wakeup pipe.
    ACTIVE_TASK.get_loop().call_soon_threadsafe(ACTIVE_TASK.cancel)


def display(*values, raw=False):
    results = RESULTS_CONTEXT.get()
    if results is None:
        raise RuntimeError('display requires a cell task context')
    for value in values:
        results.send(value if raw else mime(value), False)


async def serve():
    count = 0
    namespace = {'__name__': '__main__', '__builtins__': __builtins__}
    user_context = contextvars.copy_context()
    reader = asyncio.StreamReader(limit=FRAME_LIMIT + 4)
    transport, _ = await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader),
        os.fdopen(3, 'rb', buffering=0, closefd=False))
    emit({'type': 'ready', 'protocol': 'osv-code-kernel/v2',
          'language': 'python', 'version': '3.12.16'})
    try:
        while True:
            try:
                request = await receive(reader)
            except EOFError:
                return
            count += 1
            results = Results(count)
            namespace['display'] = display
            previous = {key: os.environ.get(key) for key in request['env']}
            try:
                os.environ.update(request['env'])
                task = asyncio.create_task(
                    cell(request['code'], namespace, '<cell-' + str(count) + '>', results),
                    context=user_context)
                await task
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            for output in (sys.__stdout__, sys.__stderr__):
                try:
                    output.flush()
                except (OSError, ValueError):
                    pass
            emit({'type': 'done', 'execution_count': count})
    finally:
        transport.close()


def main():
    signal.signal(signal.SIGINT, interrupt)
    asyncio.run(serve())


if __name__ == '__main__':
    main()
