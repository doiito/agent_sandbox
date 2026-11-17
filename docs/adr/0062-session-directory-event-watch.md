# ADR-0062：会话目录事件订阅

状态：Accepted（实现与本批功能验收通过；完整目标继续跟踪）；日期：2026-11-04；需求 FILE-02、API-01/02/03、QA-02/03、REL-04。

## 问题与契约

固定 E2B 2.51.0 的 `files.watch_dir/watchDir` 要求目录事件、停止句柄及错误传播。Python 句柄获取自上次调用后的事件，Node 句柄依次等待回调、在结束时调用一次 onExit；事件类型为 create/write/chmod/rename/remove，相对名称与可选 entry。固定上游句柄及摘要保存在 `assets/contracts/e2b-2.51.0/watch-source-lock.json`。原34项分母保持，只有双语言真实同包行为通过才增加兼容分子。

现有 guest 主控制连接在执行命令时同步处理，host 的 session owner RPC 也可能被同步 run 占用。把 watch 做成长时间 file 操作会阻塞执行，轮询列表则会漏掉短暂文件与同大小写入。因此事件来自 guest inotify，并使用独立 vsock 端口和独立短 launcher RPC；执行与捕获同时进行。

## 客体与资源

新增签名 Linux 特性 `workspace-watch-v1`，使用 artifact v4 显式声明；旧 v1/v3 行为保留，v4只允许已知特性，proxy仍按独立特性判断。root launcher 仅为签名支持的 Linux session 配置 watch 端口，旧 guest、OSv 和一次性 job 不宣称支持。pristine 未领用时不得创建订阅；prepare 后使用当前 binding，legacy session 沿用独占 VM、host CID和私有 vsock桥的信任边界。

每 session 至多4个活动订阅；每递归订阅至多128个目录，路径/深度/帧/队列均有界。目录从受限 `/workspace` 的 held fd 打开，不跟随路径 symlink，不扩大到 input/proc/根镜像；事件中的 symlink自身可报告。inotify真实事件按接收顺序编号，允许内核合并重复通知，不虚构每系统调用一条事件。递归目录新增/移入要登记；内部移动更新相对路径，移出/删除撤销对应监控。不能继续可靠跟踪或内核/传输/host队列溢出时明确终止并报告，不悄悄丢失后继续。

guest 服务与执行连接分离；使用有限缓冲与非阻塞 poll，不持有全局/工作区锁等待事件。取消、EOF、watch timeout、session TTL/close、pristine binding失效或VM关闭均释放 inotify fd、目录fd和线程。未领用池无 tenant watch，使用过的 VM不回池。现有资源账本与独占 UID 不新增另一套容量计算。

## 控制面与 SDK

原生 API提供 session 内 create/list/poll/stop，watch ID不可跨租户或跨session使用。launcher采用经过Unix peer检查的短连接，按tenant/session从实际manager获取对象，不占用原owner长连接，不自动延长session。该连接也提供只读 session-info，使同步run期间MCP能查询实际模板身份；原owner连接仍独占生命周期，heartbeat继续检查guest。root持有guest流与有界事件记录，poll快速返回连续序号/终态；客户端确认游标后释放旧记录，不能用慢poll无限积累内存。每watch为单一游标消费者，向前确认后旧游标返回冲突，不支持多读者重放。

递归新增或移入目录的登记与后续写入之间存在inotify固有窗口，不保证还原登记前发生的子树操作；应用需要先建立目录、等待事件或完成登记，再依赖后续子树捕获。无法可靠处理的跨目录拓扑变化明确终止。entry是事件处理时的best effort元数据，并非每个系统调用的原子快照；编码超帧时允许省略。

Python原生句柄及E2B适配支持get_new_events/stop和有界可取消获取；Node原生/适配依次await回调，将回调拒绝交给onExit并停止watch，onExit最多一次。recursive和includeEntry按明确能力实现；网络挂载/user自定义等当前不支持的选项显式拒绝。MCP通过同一API与会话绑定操作，不直接访问launcher或guest。目录事件属于guest文件状态，不能替代host可信审计。

## 验证与交付

先自评审，再验证真实inotify的短暂文件、写入/chmod/rename/delete、递归变化、symlink/path、队列溢出、慢消费者和取消；协议模拟只能验证分帧/绑定，不能替代实际内核事件。Go验证manager/launcher/API租户与session归属、容量、独立RPC和生命周期；双SDK按固定句柄语义覆盖回调失败、cursor与stop。

产品变更生成新双架构musl+mimalloc guest和离线包，所有真实依赖留项目目录。冻结后一次完整CI，最终ARM无NIC QEMU验证实际inotify与功能，x64同包cold/warm、命令执行同时事件捕获及零残留验收。已验收rc68保持历史证据和回滚；原40项、完整性能/64MiB/生产条件不因此关闭。自评审见[记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。

实际验收见[rc70](../../PUBLIC-QUALIFICATION.md#private-evidence)：完整CI、ARM48组及x64同包cold/warm通过；rc69失败与两次验收脚本补记保留。E2B23/34，原40项与性能/生产不关闭。
