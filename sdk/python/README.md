# Python 客户端

## 受控远程推理

此入口处于未发布的接入阶段，guest、签名模板及同候选部署验收继续进行。只有实际 session 的 `features.remote_inference` 为 true 才可调用；现有旧模板不自动获得推理许可。客户端只提交配置中的端点别名，不接受提供方 URL 或模型凭据。

```python
from osv_sandbox_client import InferenceError

invocation_id = "0123456789abcdef01234567"  # 在发送前保存；每个新调用使用新 ID
try:
    result = session.ml.invoke("model", {"query": "hello"},
                               invocation_id=invocation_id,
                               timeout_ms=1000, request_timeout=5)
    print(result.data, result.invocation_id)
except InferenceError as exc:
    # POST 尝试后的失败不自动重发。账单可能仍显示 reserved，随后变为 uncertain。
    bill = client.get_inference_bill(exc.task_id)
    print(exc.invocation_id, exc.delivery_unknown, bill)

bill = session.ml.bill()  # 会话结束后仍可查询；新进程也可通过 client/task ID 查询
```

省略 `invocation_id` 时在任何网络请求前本地生成，成功结果及异常均保留 ID；格式错误的显式 ID 在本地报配置错误。`InferenceError.cause` 保留原异常，`status`/`code` 给出可用的 HTTP 信息，`delivery_unknown` 表示尝试过 POST 但未获得经校验的成功结果，不证明账单不存在。金额、价格、预留和占用单位都保持规范十进制字符串，Python 可在需要计算时显式转为 `int`。

payload 使用普通 JSON 数据，深度最多 64，不接受非有限数、超出安全整数范围的数字、非字符串键、自定义编码对象或循环引用；需要大整数时用字符串。SDK 在等待能力响应前复制 payload。`request_timeout` 是本次观察请求的秒数，默认 35；`timeout_ms` 是服务端模型期限，0 使用租户默认值。超时后先按已知 ID 查账，不把重发当作继续观察。

## 原生持久代码上下文

`session.code` 支持签名Linux v5和含代码能力的v6模板，提供异步提交和独立观察。默认shell模板不含解释器，使用代码前须从目录显式选择已安装的 `linux-code` 模板，或由管理员将它配置为默认模板。rc74仍为v5；功能与发布状态见[同包验证记录](../../docs/validation/2026-11-06-code-template-rc74.md)。

`session.capabilities(request_timeout=10)`返回带session_id的实际绑定模板能力，代码发现使用这个入口；它先确认当前owner状态，再核对backend/签名摘要。新VM准入因模板到期停止时，原会话仍按自己的租期和权限受控使用，不由该接口延长寿命。全局`client.capabilities(template=...)`仍检查新准入有效期。该新增接口需配套升级服务端。

```python
from osv_sandbox_client import Sandbox, SessionRequest, TemplateSelector

# client 已配置服务端地址、mTLS 和当前租户凭据。
entry = next(row for row in client.templates()['templates']
             if row['id'] == 'linux-code' and row['available'])
cap = entry['capabilities']
session = client.create_session(SessionRequest(ttl_ms=180000),
    template=TemplateSelector(cap['backend'], cap['artifact_manifest_sha256']))
sandbox = Sandbox(session)
context = sandbox.create_code_context(language="python", cwd="/workspace")
result = sandbox.run_code("value = 40\nvalue + 2", context=context,
                          on_stdout=lambda message: print(message.line), timeout=60)
print(result.text, result.logs.stdout, result.error)
sandbox.restart_code_context(context)
print(sandbox.list_code_contexts())
sandbox.remove_code_context(context.id)
```

E2B `language` 与 `context` 互斥，缺省使用持久Python默认上下文；三种语言为python/javascript/typescript。create等待实际idle，restart等待下一代次idle，remove等待`code_not_found`，不会把ACK或会话消失当作完成。准备等待最多40秒，`request_timeout` 为每次HTTP请求的秒数，默认10秒。

`timeout` 使用秒，默认60、0关闭执行期限、最大300，均受会话TTL约束。回调依序同步调用，消息含line/timestamp/error，timestamp为客户端接收时间；不支持async回调。富结果提供text/html/json等字段、规范字段raw及原MIME的mime_data。用户代码异常放在Execution.error；运行时故障、输出淘汰、超时明确抛异常，未公开的execution_count保持None。JSON/错误/日志to_json辅助方法沿固定上游形式返回JSON字符串。

提交或观察不确定、回调异常、超时和KeyboardInterrupt会独立取消已知执行并查询终态，取消确认最多8秒；无法确认则请求关闭会话并抛CodeCleanupError（含original_error、cleanup_error、execution），不会假称已清理。异常也可携带execution句柄。同步回调本身无法安全强制打断；独立定时线程在deadline取消guest，函数在回调返回后报告超时。原生句柄仍保留独立观察、不自动取消的语义。

```python
import time

# session 已绑定允许 Python 的签名代码模板。
ctx = session.code.default("python")
while ctx.state == "starting":
    time.sleep(0.02)
    ctx = session.code.get(ctx.id)
if ctx.state != "idle":
    raise RuntimeError(f"context is {ctx.state}: {ctx.failure}")
execution = session.code.execute(ctx, "value = 40\nvalue + 2", timeout_ms=60000)
cursor = 0
while True:
    page = execution.poll(cursor)
    if page["events_evicted"]:
        raise RuntimeError("execution output was evicted")
    print(page["events"])
    cursor = page["next_sequence"]
    if page["status"] != "running" and cursor == page["last_sequence"]:
        break
    time.sleep(0.02)
```

`create(language='python', cwd='/workspace', context_id=None)`、`get(id)`、`list()`、`restart(ctx)`、`remove(ctx)` 返回或使用不可修改的 `CodeContext` 快照。新建/重启立即返回真实过渡状态；需轮询get直到idle再执行。restart/remove/execute使用快照generation，过期代次明确失败，不会刷新后偷偷重试。`remove` 的ACK表示已安排清理，继续get观察404才能确认上下文已移除。

`execute(ctx, source, execution_id=None, environment=None, timeout_ms=60000)`返回 `CodeExecution`；`cancel()`只确认取消请求已接受，继续poll至真实终态才确认执行停止。`timeout_ms=0`不设执行期限，会话TTL继续生效。请求超时用 `request_timeout` 秒（默认10秒），包括初次能力查询，每个请求仍受Client上限约束。

提交请求之后的异常附带 `exc.execution`，可凭它查询或取消；从未自动重放代码。创建回包异常附带 `exc.context_id` 和 `exc.session_id`，支持get找回。也可事先提供24位hex ID。`connect_execution(ctx, id)`恢复同一绑定的观察句柄，查询本身不创建任务。原生观察断开不会自动停止执行。

stdout/stderr事件data为base64，保留任意二进制；result事件data为MIME映射，`application/json`保留结构和Python整数。用户error事件和传输异常分开。每页最多64事件，完成状态仍可能有后续页；事件淘汰明确标识。四上下文、256执行ID/会话、64KiB源码/输出及300秒执行上限由服务约束。

本地双SDK证据及实际VM待验收范围见[原生SDK验证](../../docs/validation/2026-11-05-code-native-sdks.md)。

签名模板声明 `features.file_watch` 时，可使用 `session.start_file_watch('/workspace', recursive=True, include_entry=True)`；句柄 `poll(after)` 返回最多64条事件和 `next_sequence`，向前确认游标会释放旧事件，每个监听只允许一个消费者；`stop()` 返回是否首次停止。`session.list_file_watches()` 可找回本会话的有界监听记录。

E2B 显式适配层使用 `watch = sandbox.files.watch_dir('/workspace', recursive=True, include_entry=True)`、`watch.get_new_events()` 和 `watch.stop()`。事件有相对 `name`、`FilesystemEventType` 枚举以及可选 `entry`；停止后获取事件报错。Python监听默认随会话结束；每会话最多4个活动监听、每监听256事件/64KiB队列。溢出明确报错，已交付有效事件不会静默丢弃。inotify可合并重复操作，entry为处理时元数据；递归新增目录登记前的变化无法保证捕获。自定义用户、网络挂载和单次请求超时选项目前明确拒绝。

`osv_sandbox_client.py` 只依赖 Python 3.10+ 标准库。服务器离线包在 `sdk/python/` 提供同一文件；目标机器不需要 pip 下载。使用方需要可信 CA、客户端证书与私钥、租户 bearer，并从受信渠道取得这三类凭据。不要把凭据写进发布包。

```python
from osv_sandbox_client import Client, InputFile, JobRequest

client = Client(
    "https://sandbox.example",
    token="<从秘密管理器读取的 bearer>",
    ca_file="/secure/ca.crt",
    cert_file="/secure/client.crt",
    key_file="/secure/client.key",
)
capabilities = client.capabilities()
if not client.doctor()["ready"]:
    raise RuntimeError("sandbox is not ready")
result = client.run(JobRequest(
    "/bin/sh", args=("-c", "cat /input/prompt.txt"),
    input_files=(InputFile("prompt.txt", b"hello"),),
))
if not result.succeeded:
    raise RuntimeError(f"job {result.id} ended in {result.state}")
print(result.guest_result["stdout"])
```

将包内 `sdk/python/` 加入 `PYTHONPATH` 后即可导入。`run()` 每次查询已认证能力并使用 v2 绑定当前签名模板；可传 `template=TemplateSelector(backend, digest)` 指定先前取得的模板，模板切换时抛出 `TemplateMismatch`，不会自动重试或降级。旧 v1 仅通过显式 `run_legacy()` 调用。HTTP 200 代表返回了任务结果，实际是否成功须检查 `result.succeeded`。`doctor()` 在服务未就绪的 HTTP 503 情况下仍返回检查报告。

Linux 后端还支持原生持久会话。`create_session()` 查询能力并绑定签名模板，`connect_session(id)` 重新查询当前租户可见的会话；会话对象提供 `info()`、`run(SessionCommand(...))` 和 `close()`。会话单次剩余 TTL 最多 300 秒，总寿命还受不可延长的 VM 上限约束，工作区在同一会话内持续存在；关闭后不得继续使用。示例：

```python
from osv_sandbox_client import SessionCommand, SessionRequest

session = client.create_session(SessionRequest(ttl_ms=30000))
try:
    first = session.run(SessionCommand('/bin/sh', ('-c', 'echo hello > /workspace/hello')))
    second = client.connect_session(session.id).run(
        SessionCommand('/bin/sh', ('-c', 'cat /workspace/hello')))
    session.write_file('/workspace/data.bin', b'\x00\xff')
    if session.read_file('/workspace/data.bin') != b'\x00\xff':
        raise RuntimeError('file roundtrip failed')
    assert 'data.bin' in session.list_files()
    assert session.stat_file('/workspace/data.bin') == {'kind': 'file', 'size': 2}
    session.delete_file('/workspace/data.bin')
    if not first.succeeded or not second.succeeded:
        raise RuntimeError('session command failed')
finally:
    session.close()
```

`read_file()` / `write_file()` 只访问 `/workspace` 下的普通文件，单文件最多 512 KiB；写入完成后原子替换目标。`make_dir()` 在该工作区内最多逐级创建 16 层目录，返回最终目录是否新建；`list_files()` 只列直接子项，最多 256 个名称和 64 KiB 名称字节；`stat_file()` 返回普通文件/目录类型与长度，`delete_file()` 仅删除普通文件。路径越界、链接跟随和跨挂载访问会被拒绝。`rename_file(path, destination)` 移动文件、目录或链接本身，保留 inode 元数据，返回目标文件信息；目标父目录必须已存在。`remove_path(path)` 递归删除目录树、文件或链接本身，不跟随链接，最多访问 4096 个条目、32 层目录；超限返回 `file_operation_limit`（413），可能已有部分删除。两者均禁止操作 workspace 根。产物导出、网络出口、快照和完整 E2B 兼容仍未交付。会话状态只在当前 API 进程的租期内有效。

## 固定 E2B 2.51.0 显式适配层

`Sandbox` 是随本客户端提供的独立适配类，需显式传入已配置的原生 `Client`；它不是未经修改的官方 `e2b` 包。

```python
from osv_sandbox_client import Sandbox

sandbox = Sandbox.create('firecracker-linux', client=client, timeout=30)
try:
    info = sandbox.files.write('/workspace/deep/hello', 'hello')
    assert info.path == '/workspace/deep/hello'
    assert sandbox.is_running()
    assert sandbox.files.exists(info.path)
    text = sandbox.files.read(info.path)
    raw = sandbox.files.read(info.path, format='bytes')  # bytearray
    details = sandbox.files.get_info(info.path)
    assert details.size == 5 and details.type == 'file'
    assert any(entry.path == info.path for entry in sandbox.files.list('/workspace/deep'))
finally:
    sandbox.kill()
```

当前支持运行态 session 的 `create`/`connect`、`is_running`、`kill`、`files.read` 的 UTF-8 文本/字节模式、`files.exists`、`files.make_dir`、内存文本/字节的 `files.write`、最多 16 项/512 KiB 的 `files.write_files`，以及默认选项下单层 `files.list`、`files.get_info`、保留元数据的 `files.rename` 和有界递归 `files.remove`。文件信息包含类型、长度、Linux mode/权限、属主、属组和 UTC 修改时间；列表与单项信息可报告符号链接及目标文本，不跟随链接。特殊 inode 的类型为 `None`。`write`/`write_files` 可带最多 16 项、16 KiB 的可打印 ASCII `metadata`，原子写入 `user.e2b.*` 属性；列表和单项信息返回这些属性。写入自动创建父目录，批量按顺序执行；失败时先前成功的写入可能保留，不可自动重试。`/workspace` 路径与单文件 512 KiB 限制仍生效；不存在返回 `False`，认证/权限/传输错误不转换为 `False`。暂停恢复、流式写入、递归列表、自定义用户/文件请求超时选项和端口 URL 均显式抛出 `UnsupportedCapability`。代码上下文要求前述签名 v5 模板。固定矩阵的分子只随双语言真实 KVM 证据更新。


## 后台命令与实时输出

```python
command = session.start_command(SessionCommand('/bin/sh', ('-c', 'printf first; sleep 1; printf last')))
for event in command.events():
    if event.stream is not None:
        consume(event.stream, event.data)  # bytes，stdout/stderr 分开
    if event.result is not None:
        print(event.result.exit_code)
# 可用 session.connect_command(command.id) 重连，events(after=N) 按序号续读
# command.kill() 请求取消；command.wait() 等待 guest 收尾后的终态
```

`list_commands()` 返回当前会话最后 32 条命令，旧完成记录自动淘汰；查询/观察不会重新执行命令。关闭输出迭代器只停止观察，后台命令继续受会话租期管理；需要停止时显式调用 `kill()`，其布尔值表示是否首次接受取消，随后 `wait()` 确认进程已收尾。`wait()` 返回包含非零退出、超时或取消状态的原生 `JobResult`。

每个会话同时执行一条命令，期间其他执行与文件操作返回 busy；观察和取消仍可用。输出受服务端字节预算（最大 64 KiB）和 256 条数据事件限制，超限明确截断。事件通过真实 SSE 到达，含连续序号、stdout/stderr 和原始字节；收到终态后才确认完成。后台命令在 session close、TTL 或控制连接丢失时随 VM 清理。Linux session 的 `SessionCommand` 支持 `environment` 与 `cwd`，其边界见下文；交互 stdin 用法见下文。


## Bash 与 E2B 命令

离线 Linux 模板内置真实静态 GNU Bash 5.3，租户需获准 `/bin/bash`。显式适配层的 `commands.run` 使用 Bash `-l -c`；支持 `envs`、`cwd`、stdout/stderr UTF-8 回调以及 `background=True`。`commands.list()` 仅列仍运行的命令，`pid` 是 guest 实际进程号；`commands.connect(pid)` 可重新观察，`commands.kill(pid)` 取消，缺失或已结束返回 False。后台 Python 回调传给 `handle.wait(on_stdout=..., on_stderr=...)`。

```python
from osv_sandbox_client import CommandExitException, TimeoutException
handle = sandbox.commands.run('a=(hello world); printf "%s" "${a[1]}"', background=True,
                              envs={'APP_MODE': 'offline'}, cwd='/workspace', timeout=0)
try:
    result = handle.wait(on_stdout=print)
    assert handle.wait() is result  # 缓存结果，不重复执行或回调
except CommandExitException as error:
    print(error.exit_code, error.stdout, error.stderr, error.error)
```

`timeout` 单位秒，默认 60，0/None 不额外限制观察；`TimeoutException` 仅结束观察，运行进程可重连。服务端执行上限和会话 TTL 仍生效。`handle.disconnect()` 停止当前观察，不取消进程。自定义用户、PTY 暂不支持。

原生 session 的 `SessionCommand(environment=..., cwd=...)` 仅影响该子进程。环境最多 32 项、总计 8 KiB、每值 1 KiB，名称为 ASCII 标识符；cwd 必须为 guest 内绝对路径、最多 1024 字节，降权后切换目录，缺目录/无权限会启动失败。默认 `/workspace`，不影响下次命令。能力分别为 `session_environment` 与 `session_working_directory`；一次性job使用下文的独立字段与能力。


## 交互 stdin

`SessionCommand(..., interactive_stdin=True)` 或 E2B `commands.run(..., stdin=True, background=True)` 显式创建输入管道，默认关闭。能力为 `interactive_stdin`，不扩展一次性 jobs 或旧同步 session.run（该接口拒绝启用交互输入）。

```python
handle = sandbox.commands.run('cat', background=True, stdin=True, timeout=0)
sandbox.commands.send_stdin(handle.pid, 'hello\n')  # UTF-8 文本
handle.send_stdin(b'\x00\xff')                     # 字节原样传输
handle.close_stdin()                             # 显式 EOF
result = handle.wait()
```

原生命令句柄也提供 `send_stdin(bytes, request_timeout=None)` / `close_stdin(request_timeout=None)`；E2B commands 和句柄接受文本/bytes，返回 None。每块最多16KiB、每命令最多1MiB和256次事务，一次最多一份未确认输入；超过队列信用返回429 busy，关闭输入后写返回409 stdin_closed，未启用返回409 stdin_unavailable，已结束/缺失进程404。提前关闭管道的进程会返回写入失败。确认表示已进入管道，不等于程序已消费。

慢读输入不会阻塞输出观察/kill；断开输出观察不关闭输入。`request_timeout`（秒）限制当前输入提交/确认等待，超时不会重发或取消命令。POST 结果不确定时可能已写入，切勿直接重试。原生 `submit_stdin(data, close=False)` 返回带序号的票据，`poll_stdin(sequence)` 可继续查询 pending/delivered/closed/failed 与实际 written_bytes；已知票据的等待超时可安全继续查询。未取得票据的提交传输失败无法直接确认结果，应由应用幂等协议或取消命令处理。已有服务端执行上限/会话租期继续生效，未完成事务随进程结束或取消失败。


## 会话列表、信息与期限

```python
sandbox.set_timeout(30)  # 从现在重设剩余秒数；返回 None
info = sandbox.get_info()
print(info.sandbox_id, info.memory_mb, info.cpu_count, info.end_at, info.max_end_at)
pages = Sandbox.list(client=client, limit=10, order='desc')
while pages.has_next:
    for item in pages.next_items():
        print(item.sandbox_id, item.state)
```

原生 `client.list_sessions(limit=20, cursor=None, order='desc')` 返回 sessions（SessionInfo对象）和 next_cursor；`session.set_timeout(ttl_ms)` 返回最新信息。E2B分页器通过 `next_token` 恢复，并提供 has_next/next_items。只列当前租户会话，asc/desc按整个集合的创建时间排序。分页冻结有界ID集合，后续页跳过已删除/过期项并刷新信息，不混入后来创建的会话；每页1..100项，快照30秒/每租户8份/全局128份。游标过期、淘汰或属于其他租户明确报错，不静默重启分页；不能并发推进同一分页器。

每次剩余TTL为1..300秒；平台可用 session_max_lifetime_ms降低 VM 总寿命上限（默认不超过600秒），warm会话还扣除原始host/guest剩余窗口的守护余量。max_end_at是不可延长的实际上限，超过返回400 timeout_exceeds_lifetime，不会截短后假装成功。初始短TTL可以延长，缩短/到期将销毁正在运行的命令和VM；执行自身timeout仍独立，已过期/外租户返回404，不能复活。VM回收确认不确定时沿用既有短暂配额隔离。

信息提供真实ID、模板、CPU/内存和UTC起止时间。兼容字段 envd_version 如实提供项目 fc-agent 协议（v2/v3），本项目不运行envd；这仍是显式facade。只支持当前运行态与默认选项，暂停恢复、metadata筛选和自定义请求选项继续显式未支持。

## Linux 一次性 job 输入

`JobRequest(environment=..., cwd=..., stdin=bytes)` 同时支持冷启动与 pristine warm job；能力分别为 `environment`、`working_directory`、`stdin`。例如：

```python
result = client.run(JobRequest('/bin/sh', ('-c', 'printf "%s|%s|" "$KEY" "$PWD"; wc -c'),
    environment={'KEY': 'offline'}, cwd='/input', stdin=b'\x00\xff',
    input_files=(InputFile('marker', b'data'),)))
print(result.guest_result, result.startup_mode)
```

环境最多32项/8KiB，值最多1KiB、名称64字节；清空继承环境后应用默认PATH/HOME/LANG和本次变量。cwd最多1024字节，须为guest绝对路径，降权后切换；不存在或拒绝访问返回guest执行错误，不自动建目录或回退。默认/workspace。OSv不支持cwd，OSv保留环境前缀和签名特性规则继续生效。

固定stdin最多16KiB，显式空bytes产生管道EOF，省略为/dev/null。输入通过非阻塞父端与输出/期限共同推进；数据写完关闭，程序可不读完输入，成功不代表已消费全部数据。它不启用交互输入、重试或会话保留。新任务使用新VM。`startup_mode`只保留服务器实际报告的warm/cold，旧冷路径未报告时为None；这些功能信息不证明启动性能目标达标。

## 受控网络 fetch

`client.fetch_network(url, method="POST", body=b"{}", headers={"Content-Type":"application/json"}, timeout_ms=10000)` 使用同一认证 API，返回 `NetworkFetchResult`，包含上游 `status`、二进制 `body`、报头和有界计数。远端4xx/5xx仍返回真实HTTP结果；策略/配额/上游连接失败使用既有APIError。缺省不跟随重定向，不自动重试。先检查 capabilities 的 `network_fetch_policy`；没有授权时抛UnsupportedCapability。它不修改guest网络。见[egress配置](../../docs/EGRESS.zh-CN.md)。


## 多签名模板

`client.templates()`返回租户可见的已安装模板、可用状态和各自能力；`client.capabilities(template=selector)`查询特定签名摘要。缺省run使用管理员配置的默认模板，默认模板隐藏或不可用时不会自动选中其他项。

```python
from osv_sandbox_client import JobRequest, TemplateSelector
catalog = client.templates()
entry = next(row for row in catalog['templates']
             if row['available'] and row['capabilities']['backend'] == 'firecracker-osv')
cap = entry['capabilities']
selected = TemplateSelector(cap['backend'], cap['artifact_manifest_sha256'])
value = client.run(JobRequest('/python3.12.so', ('-c', 'import numpy; print(numpy.arange(4).sum())'),
                              memory_mib=512), template=selected)
print(value.guest_result, value.template_id, value.artifact_manifest_sha256)
```

模板ID用于发现，执行绑定backend与摘要。新签名job响应回显实际绑定，SDK核对一致性；旧响应可省略这些字段。proxy使用所选模板的在线能力。Linux session固定创建模板，E2B命令的Bash/交互输入能力也查询该模板。OSv科学模板当前为x64一次性任务；见[ADR-0060](../../docs/adr/0060-multi-template-catalog-and-shared-capacity.md)。

## 原生 TCP 端口

`session.ports`需要已签名v6的端口能力及租户显式端口白名单，仅连接同一VM的IPv4 loopback。沿用原客户端mTLS/CA/bearer，使用标准库HTTP/1.1升级，不需要额外安装库。rc74包不含此能力；[端口合同](../../docs/contracts/port-tunnel-v1.md)及新候选验收进度决定实际可用性。

```python
with session.ports.open(8080, max_bytes=1 << 20, timeout_ms=10000,
                        idle_timeout_ms=5000) as tunnel:
    tunnel.write(b'GET / HTTP/1.0\r\n\r\n')
    tunnel.close_write()
    while True:
        frame = tunnel.read_frame()
        if frame.kind == 'data':
            consume_bytes(frame.data)  # 每帧1..16384字节，不隐式累积输出。
        elif frame.kind == 'finished':
            if frame.info['status'] != 'completed':
                raise RuntimeError(frame.info['error'])
            break
        # eof仅结束反向应用数据，继续读取finished；此时仍可写自己的方向。
```

每条通道允许一个读操作和一个写操作并行；`write`一次接受1..16384字节，`close_write`发送协议EOF。重复EOF/超额输入在本地拒绝，部分传输绝不自动重试。`request_timeout`为握手/控制请求秒数，`timeout_ms`从open开始约束整条通道，包括无人读写时；不会延长session租期。

open失败的异常携带`error.connection`，保留已生成的`id`和`port`。也可事先生成24位小写hex ID并传`connection_id`，用`session.ports.connection(port, id)`构造引用，无须再次打开即可调用`info()`/`cancel()`。控制请求不等待DATA锁、不重新发现新准入能力，支持cancel-before-open。取消ACK可能为cancelling，须查询终态；未收到完整finished的断线不算成功。`close()`和上下文退出只关闭本地传输，不能当作guest已完成清理的证明。

## 浏览器预览授权

在已认证且报告 features.port_preview 的 v6 Linux 会话中，使用 `grant = session.ports.create_preview(8080, ttl_ms=60000)` 创建授权，向获授权的浏览器提供 `grant.bootstrap_url`。这个 URL 是一次性凭据，不要记录到日志。`grant.info()` 返回状态，`grant.revoke()` 撤销浏览器授权；两者均不重发 secret，不延长租期。授权归 API 会话所有，客户端进程退出不会自动撤销。

创建只发送一次 POST。异常上的 `exc.preview` 保留已知 ID；也可用 `session.ports.preview(8080, preview_id)` 取得已有授权的查询/撤销句柄。创建结果未知时查询或撤销原 ID，不重放 POST；丢失的 bootstrap secret 无法恢复。request_timeout 缺省 10 秒，且受客户端请求上限约束。TTL 为 1000..300000ms，受创建时会话剩余租期限制。撤销确认的是授权状态，guest 物理清理仍由底层端口生命周期负责。

入口配置、离线 DNS/TLS 及限制见项目 `docs/PREVIEW.zh-CN.md`；安装包内同名文档位于 docs。rc74 不含此功能，新候选整包验收仍需完成。原生预览没有映射为 E2B get_host，兼容矩阵保持 28/34。
# 会话产物归档

源码新增有界 tar 导出，新签名 Linux v8 模板须启用 `workspace-artifacts-v1`。新离线包和当前实机验收仍待完成；rc90 包不包含本节接口。支持文件或目录、空目录和二进制内容；每会话最多两个归档、每个 tar 含开销最多 32 MiB、1024 个条目。创建、读取和删除均沿用会话权限与 TTL。

```python
artifact = session.create_artifact("/workspace/results")
try:
    archive_bytes = session.download_artifact(artifact)
    with open("results.tar", "wb") as output:
        output.write(archive_bytes)
finally:
    session.delete_artifact(artifact.id)
```

`read_artifact(id, offset, length)` 返回最多 512 KiB 的 base64 块、块/归档 SHA256、总大小与 EOF；`download_artifact` 校验每块及完整归档摘要。SDK 不自动解包或删除。创建不隐式重试，缓存随会话关闭释放；检测到工作区变化会拒绝导出，运行中文件树不承诺原子快照。只读下载取消不终止 VM。
