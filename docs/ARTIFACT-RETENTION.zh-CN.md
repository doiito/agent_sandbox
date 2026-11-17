# 验收产物回收

2026-11-17 KVM事件API观察的原有内核/调度/CFS分析结束后，又回收154,349,568字节分配块的重复展开trace。原压缩业务归档逐字验证并保留；首次沙箱视图3进程检查及删除后补查294宿主进程的零引用结果分别保留，不混称删除前全局检查。清理器已要求完整宿主视图的最低进程数量。见[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)和[观察结果](../PUBLIC-QUALIFICATION.md#private-evidence)；`python3 build/validation/kvm-residency-api-analysis-r1/retire-kernel-trace.py restore` 可恢复。实际依赖及当前候选未删除。

2026-11-17 历史rc90两架构重复stage的166项载荷全部逐字匹配项目内保留的验签包，296个宿主进程无FD/映射/挂载引用且无权限遗漏后回收。按实际inode/link排除仍被其他保留路径使用的块，扣除新证据，估算净释放1,124,986,880字节（约1.05GiB）；目录元数据另计。当前rc92 stage及八个静态控制面程序摘要保持，旧rc90原包和全部失败/通过证据保留。见[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)及[完整保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)；需要时用 `python3 build/validation/kvm-residency-analysis-r1/retire-old-stages.py restore` 仅从项目内保留包恢复，不下载。该批是此前完成的重复stage，不与前轮回收重复计数。

2026-11-17 Go/内核完整 133 请求关联完成后，展开内核 trace 与保留业务归档中的成员逐字核对，289 个宿主进程无引用且无权限遗漏，再回收 156,246,016 字节（约149MiB）。原始归档、Go trace、压缩事件头和分析结果保留；复算恢复工具先核对归档/成员摘要。此数单独计项目盘，不重复计前轮回收。见[收据](../PUBLIC-QUALIFICATION.md#private-evidence)及[验证记录](../PUBLIC-QUALIFICATION.md#private-evidence)。

同日可选 CPU 放置的 ARM 无 NIC 14项功能结束后，静态测试 ELF、BusyBox、init及日志逐项证明保留，284个宿主进程无引用且无权限遗漏，再删除重复验证 initrd/展开目录4份文件，另回收28,987,392字节（约27.6MiB）。只计本轮验证副本，不重复计旧磁盘基线收益；实际依赖、测试程序和原始结果保留。见[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)。

该策略的功能控制终态后，7份重复程序与传输包全部成员逐项匹配保留程序/源文件，307个宿主进程无引用且无权限遗漏，再回收112,959,488字节（约107.7MiB）。正在执行的ABBA输入未动，真实依赖及全部原始失败/通过结果保留；见[保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)和[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)。此数只计本轮新建测试副本，不重复计旧磁盘基线收益。

预定532任务ABBA未过筛选并完成产品恢复复核后，6个实际实验ELF、两份ABBA程序副本及传输包均匹配保留归档或源文件，289个宿主进程无引用且无权限遗漏，再删除9份展开文件。扣除53,178,368字节实验归档，净减少99,880,960字节（约95.3MiB）。历史程序路径通过[保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)映射到归档成员；实际应用依赖和当前候选未动，全部原始失败/通过结果保留。见[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)。

2026-11-11 [监督路径实际API对照](../PUBLIC-QUALIFICATION.md#private-evidence)四臂终态、输入/归档及资源复核后，删除指定机20项参考文件和传输包，回收230,182,912字节。287个本地宿主进程无引用后，传输内容逐项匹配项目资产，再删除本地包，另回收36,601,856字节。后续代码读取六套QEMU完成，290个宿主进程无引用后回收12处副本，扣除保留证据后净减少76,013,568字节。实际agent/C库、来源/签名参考、测试程序归档及原始结果继续保留。[指定机收据](../PUBLIC-QUALIFICATION.md#private-evidence) · [传输回收](../PUBLIC-QUALIFICATION.md#private-evidence) · [定向VM回收](../PUBLIC-QUALIFICATION.md#private-evidence)

2026-11-11 [独立监督程序双架构QEMU](../PUBLIC-QUALIFICATION.md#private-evidence)完成10套通过和2套已诊断失败后，必要实际程序按内容去重归档，源输入/日志保留，运行库逐项匹配项目资产。294个宿主进程引用检查无遗漏后回收24处rootfs/initrd副本、41979个文件，扣除保留证据后估算净释放4,852,789,248字节，约4.52GiB。本数属于本轮创建后清理的测试副本，不重复计作旧磁盘基线收益。新双架构bundle、基础/代码镜像、实际库与源码继续保留。[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence) · [明确计划](../PUBLIC-QUALIFICATION.md#private-evidence) · [保留输入索引](../PUBLIC-QUALIFICATION.md#private-evidence)

2026-11-11 普通 mimalloc 的2048次真实API操作及1024次启动诊断完成后，独立核对8个终态夹具，无运行服务、VM/job、cgroup、临时凭据或安装副本。18项参考输入逐一匹配项目保留资产，经指定机进程/FD/映射/挂载检查后删除远端重复输入及传输包，估算释放227,930,112字节，约217MiB。随后281个本地宿主进程检查无引用、无权限遗漏，18项传输内容逐字匹配项目资产后删除本地包，另回收35,512,320字节，约34MiB。实际程序、C库、镜像、39项源码归档和原始结果均保留。[验收记录](../PUBLIC-QUALIFICATION.md#private-evidence) · [指定机收据](../PUBLIC-QUALIFICATION.md#private-evidence) · [本地回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)

按用户要求，功能开发和验收的空档持续清理已确认无用的中间产物、失败夹具和重复副本。失败诊断完成后即回收大文件；不等正式发布才清理。

2026-11-11 的 rc82 System 分配器对照构建及 4 项实际测试完成后，核对项目 assets 中的实际 agent，压缩归档并复核测试 ELF，再检查 292 个宿主进程，确认无引用和权限遗漏。已回收该轮独立构建缓存的 437 个文件，扣除新增证据后估算净释放 74,272,768 字节，约 70.8 MiB。实际库、源码、依赖和 agent 均保留在项目，后续真实任务 A/B 尚待执行。 [回收收据](../PUBLIC-QUALIFICATION.md#private-evidence) · [保留输入](../PUBLIC-QUALIFICATION.md#private-evidence)

随后实际 API ABBA 完成 32 个会话和 2048 次正式操作。指定机五个终态夹具核对无运行服务、VM/job、cgroup 或临时凭据，原 A1 失败安装的 90 项 payload 和参考文件、远端参考输入均逐项匹配保留资产。宿主引用检查通过后删除三处重复目录，按独立 inode 估算释放指定机 1,597,775,872 字节，约 1.49 GiB。此数只计本轮新建测试副本，项目内参考 agent、镜像、固定来源及原始失败/通过归档继续保留。 [实际任务验收](../PUBLIC-QUALIFICATION.md#private-evidence) · [回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)

普通 mimalloc（secure=0）的同源码构建和 4 项实际静态 allocator 测试通过后，保留项目 assets 中的 agent、C 静态库和编译来源，将实际测试 ELF 压缩归档并复核。295 个宿主进程检查无引用、无权限遗漏后，回收该独立缓存的 297 个文件，扣除保留证据后估算净释放项目盘 59,502,592 字节，约 56.7 MiB。该配置的实际 API 测量仍待执行，参考二进制和库继续保留。 [回收收据](../PUBLIC-QUALIFICATION.md#private-evidence) · [实际测试程序索引](../PUBLIC-QUALIFICATION.md#private-evidence)

每轮验收完成、失败根因确认或候选替换后，将产物回收作为该轮收尾步骤：记录仍需保留的输入与证据，执行显式回收计划及宿主引用检查，清理后复查当前候选和门禁引用。继续使用的编译缓存按实际构建需要保留。

当前保留规则：

- 项目真实运行依赖、固定源码/许可证、实际库与当前镜像保存在项目目录。
- 保留正在验收的候选、最近有效基线及现行门禁明确引用的文件；按实际引用判断，不能仅按日期或 rc 编号删除。
- 结束的验证任务保留原始日志、结果、输入摘要及必要的测试 ELF/源码归档，再回收展开文件系统、启动磁盘、重复安装目录和传输副本。
- 过期或失败完整包无当前引用时，核对已有候选摘要并归档必要清单/签名元数据后删除。历史文档直接链接的证据文件继续保留。
- 清理前核对进程、文件描述符、映射和挂载引用；清理记录包含路径、理由与估算回收空间。

显式回收计划的宿主引用检查可使用 `python3 scripts/check-validation-artifact-references.py --plan results/<phase>/retirement-plan.json`。计划的 `targets` 是项目相对路径与理由的二元列表；该工具只检查和写记录，不删除文件、不读取进程参数。应在能看到宿主进程的命名空间运行；普通隔离命令中没有可见进程不能作为宿主零引用证明。无引用、无权限遗漏及归档验证通过后，再由该阶段回收已确认的文件。

2026-11-07 已回收的 QEMU 夹具见 results/2026-11-07-preview-candidate/qemu-retirement.json；旧候选与展开副本清单见 results/2026-11-07-obsolete-cleanup/。当前 rc75 验收、rc74 基线和 E2B 仍引用的 rc70 不在这批旧包回收范围。

同日空档复查进一步回收 rc71、早期 mimalloc 和 Python 退出诊断的已结束编译缓存、重复传输包及过时镜像分块。删除 3016 个文件，按独立 inode 和仍存活的硬链接计算，扣除新保留证据后净回收约 1.16 GiB。独有测试 ELF、验证脚本和传输元数据已归档并逐项校验；清单、摘要及结果见 [空档回收记录](../PUBLIC-QUALIFICATION.md#private-evidence) 和 [保留输入索引](../PUBLIC-QUALIFICATION.md#private-evidence)。编译缓存可由项目内的固定源码与依赖离线重新生成。普通受限命令的进程检查只覆盖其可见命名空间；宿主引用复查单独记录在同目录 host-reference-check.json。

随后第二轮空档回收删除 64 个文件，包括 24 份已被后续候选替代且现行门禁不再引用的离线包、旧传输副本、过时生成镜像及已有逐字相同 gzip 副本的测试 ELF，净回收约 4.02 GiB。保留 rc75 当前候选、rc74 基线、E2B 所需 rc70、文档直接链接的历史包及全部 assets。已保存旧包签名清单、SDK/配置/文档与包内容索引；[回收记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[保留元数据索引](../PUBLIC-QUALIFICATION.md#private-evidence) 和宿主引用检查均在同一目录。

第三轮空档回收清理 12 个明确路径、9852 个文件，净回收约 1.54 GiB：旧 native Rust 测试及增量缓存、已结束的 CPython 构建对象和重复展开源码、rc72 验证缓存、已被替代的 rc43/rc44/rc72/rc73 传输副本。保留当前双架构 musl release 缓存、全部 assets、当前候选及基线和原始结果。独有测试 ELF、构建配置、源码生成差异与传输元数据按内容去重归档并完整核验；268 个宿主进程检查无引用、无权限遗漏。编译对象仅保留删除前的 inode、大小和时间清单，避免为无用缓存读取全部冷数据；源文件、传输包和保留证据另有摘要。见 [回收记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[明确清单](../PUBLIC-QUALIFICATION.md#private-evidence) 和 [保留输入索引](../PUBLIC-QUALIFICATION.md#private-evidence)。回收量按独立 inode、存活硬链接及新增证据占用计算，不把共享磁盘上其他项目的空间变化计入。

随后 guest 推理组件验收按同样规则收尾：删除 7 个明确路径中的 7029 个文件，估计回收 491339776 字节验证产物；保留约 15.1 MiB 的实际程序归档及全部原始日志、输入和失败诊断。ARM SDK 夹具的运行库使用只读 staging 硬链接，cpio 持有独立字节快照，避免再复制一份 385 MiB 的展开运行时；回收估算不把仍在 assets 存活的硬链接算作释放。272 个宿主进程检查无引用、无权限遗漏。见 [阶段回收记录](../PUBLIC-QUALIFICATION.md#private-evidence) 和 [程序索引](../PUBLIC-QUALIFICATION.md#private-evidence)。

v7 镜像构建后再次回收 4 个明确目录、12117 个文件，扣除保留证据后净回收约 1.65 GiB：已被 r2 替代的双架构 Linux r1 镜像、已诊断的 OSv r1 失败安装，以及 r1/r2 已结束的 CPython 编译工作目录。保留当前 r2 实际镜像、运行库、模块、固定源码、rc75/rc74/rc70 基线及全部原始日志；旧镜像清单、构建配置、源码差异和诊断程序按内容去重归档并完整核验。281 个宿主进程检查无引用、无权限遗漏，替代镜像 SHA256SUMS 全部通过。见 [回收记录](../PUBLIC-QUALIFICATION.md#private-evidence) 和 [保留证据索引](../PUBLIC-QUALIFICATION.md#private-evidence)。

同轮 ARM 功能验证结束后，归档实际静态 ELF、init 脚本及串口日志，再清理两个 QEMU 工作目录与展开 ELF，扣除证据后净回收约 58.8 MiB。272 个宿主进程检查无引用、无权限遗漏。见 [QEMU 回收记录](../PUBLIC-QUALIFICATION.md#private-evidence)；两批合计净回收约 1.71 GiB。该轮三套已签名模板 stage 随后在 rc76 完整离线包生成/验签后完成替换，回收见下段。

rc76 收尾回收两个已替代的 v7 stage、53 个文件，41 份重复内容逐项匹配到当前完整候选，12 份不同元数据归档，净回收 1168429056 字节；282 个宿主进程检查无引用、无权限遗漏。实际 ARM 包完成50组QEMU后，再归档六个去重测试程序及串口日志，清理三套由 init/bootstrap 摘要确认的已结束 QEMU 临时目录、172 个文件，净回收3817971712字节；290个宿主进程检查无引用、无权限遗漏。两批合计约4.64GiB，见 [stage记录](../PUBLIC-QUALIFICATION.md#private-evidence)及[QEMU记录](../PUBLIC-QUALIFICATION.md#private-evidence)。rc76完整包/真实资产仍用于失败复核和新候选增量传输，rc75/rc74/rc70有效基线及全部真实依赖继续保留。

rc77 完成完整 CI、双架构完整包与 ARM 真包 50 组 QEMU 后，回收验收临时目录并保留五个实际程序及日志，净回收 1,850,712,064 字节。随后清理 rc76/rc77 的四个重复展开 stage、294 个文件；每个文件的内容均核对到仍保留的对应完整签名包，272 个宿主进程无引用、无权限遗漏，扣除新证据后净回收 2,613,727,232 字节。两批本地合计约 4.16 GiB；见 [QEMU 收据](../PUBLIC-QUALIFICATION.md#private-evidence)、[stage 收据](../PUBLIC-QUALIFICATION.md#private-evidence)及[保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)。远端已诊断的 rc76r2 失败安装另回收约 1.20 GiB，已闭账 ledger 与诊断保留，空间不计入本地。rc77 当前完整包、rc76 增量传输基包、rc75/rc74/rc70 基线、项目内实际镜像/库/固定源码继续保留；远端 KVM 尚未完成，见 [rc77 状态](../PUBLIC-QUALIFICATION.md#private-evidence)。

2026-11-09 OCI 首阶段按模板顺序验证两架构五套真实签名输入，每套完成独立宿主引用检查后立即回收新建的 source/layout/imported 重复镜像，未累计保留约 5.59 GiB 临时副本。另清理已诊断 schema 驱动失败夹具、结束的 QEMU、重复测试 ELF 和未使用开发 CLI，共 25 个文件；保留压缩实际 ELF、元数据与原始失败/通过日志，272 个宿主进程无引用、无权限遗漏，扣除保留证据净移除 219,189,248 字节。真实资产、完整候选、固定 schema/许可证和两个当前静态 CLI 均保留。见[验收记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)和[保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)。本轮临时副本是为本轮测试新建的，不把创建后删除的总量当作对先前磁盘基线的额外净收益。

同日 registry 阶段五套独立进程均先停止再检查宿主引用，按套立即回收本轮约9.29GiB临时对象/安装副本。随后清理QEMU、重复测试ELF、临时私钥/凭据和已逐成员核对的重复上游压缩包，共21个文件；实际测试ELF压缩归档后完整校验，279个宿主进程无引用、无权限遗漏，净移除41,160,704字节。私钥/凭据不归档，只保留公有测试证书、元数据摘要与脱敏日志；官方registry程序/许可证及两个静态CLI留在项目。见[验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)和[保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)。创建后清理的测试总量不作为对原磁盘基线的额外净收益。

rc78完成完整CI、双架构包、本地实际安装CLI和ARM真包51组后，清理11个明确路径、507个文件，包括两个重复stage、首次失败与后续通过的QEMU目录、三套结束的诊断夹具、诊断源码副本及重复ELF。两个stage的151份文件全部逐字匹配仍保留的签名包，独立bootstrap先保存到dist。实际执行的原/新测试程序、诊断差异和日志按摘要去重归档并复核，临时MCP私钥/凭据不归档；271个宿主进程无引用、无权限遗漏。扣除61,812,736字节证据后，项目卷净释放1,389,400,064字节（约1.29GiB）；另清理/tmp验证副本3,782,541,312字节（约3.52GiB），这部分属于tmpfs，不计入项目磁盘收益。当前rc78、有效基线、原始结果及项目内真实依赖均保留。见[本轮验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)、[明确清单](../PUBLIC-QUALIFICATION.md#private-evidence)和[恢复索引](../PUBLIC-QUALIFICATION.md#private-evidence)。

随后验收调度工具完成普通用户定向覆盖和四个真实systemd短任务，停止并退休全部测试单元后，清理三套已结束验证目录、63份重复文件。全部现存字节匹配保留的实际任务归档，270个宿主进程无引用、无权限遗漏，扣除新增元数据后净回收266,240字节。首轮失败、实际worker和源码/设计证据保留；不把这些调度测试计为产品KVM验收。见[专项记录](../PUBLIC-QUALIFICATION.md#private-evidence)和[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)。

导入模板夹具随后逐模板回收新建layout，并在停止实际namespace探针/核对引用后删除实际安装与导入副本；当前传输包本地精确重建及计划生成结束后也立即回收重建目录。这些是本轮创建后回收的验证副本。另在rc78包接替后删除三个无用传输文件：旧rc77上传包及literal、新rc78未压缩literal，共154,406,912字节；旧29份输入另存压缩归档，旧literal逐字证明可从保留的原签名包与recipe恢复，新literal逐字匹配当前压缩包。282个宿主进程无引用、无权限遗漏，扣除3,518,464字节证据后净释放150,888,448字节；其中84,926,464字节来自此前的旧rc77副本，69,480,448字节为本轮重复文件。当前约38.9MiB压缩包、全部签名候选/有效基线和真实依赖保留，见[阶段记录](../PUBLIC-QUALIFICATION.md#private-evidence)与[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)。

同日按用户再次提出的磁盘要求，空档复查回收rc74、rc76已被替代的上传包及重复literal，并删除已结束OTLP QEMU的重复initrd与展开副本。两个旧literal均逐字证明可从保留的原签名tar和recipe恢复；49份独有上传输入及QEMU init脚本另存压缩归档，全部成员重新校验。287个宿主进程检查无引用、无权限遗漏。删除9个此前已存在的文件，共340,496,384字节，扣除7,057,408字节保留证据后净回收333,438,976字节，约318MiB；本次清理自身产生的一个不完整归档也已证明被完整归档覆盖后删除，其3,473,408字节不计入对原磁盘基线的收益。rc78双架构完整包重新计算SHA-256并与构建收据一致；所有有效基线、真实依赖、当前传输包及OTLP原始失败日志/收据保留。OTLP两个失败结果仍为失败，不能将副本回收记为功能通过。见[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)、[保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)及[清理后复核](../PUBLIC-QUALIFICATION.md#private-evidence)。后续继续在每轮验证、构建和失败诊断的收尾与空档执行此规则，功能与性能验证仍优先。

随后OTLP三信号组件及Prometheus快照修复完成native/ARM和独立Collector验收，立即回收25个明确路径中的40个文件。11份实际ELF与init按13个独立内容对象保留压缩原字节并逐项核验；删除已结束QEMU副本、9份临时私钥及已核对原始程序/README的重复官方压缩包。290个宿主进程检查无引用、无权限遗漏，扣除64,344,064字节证据后，占用较清理前净减少167,006,208字节，约159.27MiB；这包括本轮新建后回收的验证副本，不全部归为对更早磁盘基线的收益。官方Collector程序、许可证和来源锁定文件、真正依赖、当前签名包和原始失败/通过证据继续保留在项目。见[阶段记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)及[程序索引](../PUBLIC-QUALIFICATION.md#private-evidence)。

API接入随后完成33项native/同名ARM及真实非root API与官方Collector验收，收尾回收24个明确路径，42份普通文件和2个已停止scripted socket。8份实际ELF与init按10个独立对象归档并核验，删除四套QEMU副本及10份临时私钥；263个宿主进程无引用、无权限遗漏，宿主Unix表也已确认socket停止。扣除55,615,488字节证据，占用较清理前净减少140,296,192字节（约133.80MiB），其中本轮创建后回收的副本不全部算作对更早磁盘基线的收益。实际依赖、当前候选和原始失败/通过结果继续保留。见[API验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)、[程序索引](../PUBLIC-QUALIFICATION.md#private-evidence)及[清理后复核](../PUBLIC-QUALIFICATION.md#private-evidence)。

## 2026-11-10 原账单恢复与rc79重复安装回收

指定机原关账意图先由实际签名launcher恢复，10次调用与计费总额、未决保留及原provider事件不变，闭账导出核验后才执行清理。前两次恢复夹具失败、原六次E2E失败与最终成功证据分别保留，见[本轮验证](../PUBLIC-QUALIFICATION.md#private-evidence)。

[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)绑定六份停止的验证安装，各84项payload与保留签名包逐项相同，宿主FD/映射/挂载无引用且无权限遗漏。持有全局验证批次锁后删除这些releases及废弃测试凭据，原results、闭账账本和候选包保留。唯一文件分配块估算回收7,797,456,896字节（约7.26GiB），仅计指定机，不计入本地项目卷收益。

rc80本地两个已结束的stage及未压缩literal共154文件已逐字匹配保留签名包/压缩传输包，291个宿主进程检查无引用、无权限遗漏后回收。分配块估算释放1,390,657,536字节，约1.30GiB；候选摘要清理后复核通过，见[收据](../PUBLIC-QUALIFICATION.md#private-evidence)与[明确计划](../PUBLIC-QUALIFICATION.md#private-evidence)。指定机新15套KVM通过后也已回收各自新建的安装/导入副本和测试凭据，[最终只读检查](../PUBLIC-QUALIFICATION.md#private-evidence)确认服务停止且无job/cgroup；这批创建后删除的测试总量不重复算作对旧磁盘基线的额外净收益。

rc80双架构签名包与独立bootstrap仍在dist，musl/mimalloc、v7运行时和实际构建依赖仍在项目。自动生成的验证work/plan/log/lock可以放入受控/tmp并在子进程回收后删除；不将应用真正依赖移到/tmp。QEMU目录和独有验证程序副本待对应引用核查、实际ELF证据归档后再清理。

## 2026-11-10 HTTP错误契约验证收尾

本轮native race、双架构静态编译和实际两架构非root API进程验证结束后，回收4个明确验证目录、23个文件，含终态QEMU副本及4份临时私钥。独有native测试ELF与公有配置/init按内容去重归档并逐项核验，当前5个静态API/探针/ARM测试程序、实际依赖及全部原始失败/通过结果保留。宿主引用检查无FD/映射/挂载引用且无权限遗漏，私钥及包含它的生成initrd不归档。扣除程序归档后，分配块估算占用减少82,554,880字节（约78.7MiB），元数据占用另计；都是本轮新建后回收的验证副本，不将其当作对旧磁盘基线的额外净收益。见[验收记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)及[程序/输入索引](../PUBLIC-QUALIFICATION.md#private-evidence)。

## 2026-11-10 rc81完整REST契约本地验收收尾

[rc81本地验收](../PUBLIC-QUALIFICATION.md#private-evidence)全部结束后，回收21个明确路径，包括两架构重复stage、实际安装副本、终态定向/完整QEMU夹具、此前未启动QEMU的编译失败夹具、已结束native测试展开ELF及临时凭据。全部payload逐项匹配保留的完整签名包；独有实际ELF及公开输入按46个内容对象压缩归档并逐项复核。宿主FD/映射/挂载及Unix socket表检查无引用、无权限遗漏。首次归档准备因沙箱权限失败且未删除文件，原记录保留；获准宿主读取后继续完成。归档中的一份重复完整ARM包又逐字匹配到dist并去重，未重复保留大文件。

扣除67,084,288字节程序归档后，项目卷分配块估算净减少2,713,518,080字节（约2.53GiB），另释放/tmp的1,983,619,072字节（约1.85GiB），不将tmpfs算入项目盘。各项都是本轮创建后清理的验证副本，不计为对更早磁盘基线的额外收益。rc81双架构包及独立bootstrap清理后重新计算摘要通过，rc80完整指定机基线和其余有效基线、项目内实际库/镜像/固定源码、全部原始失败和通过结果继续保留。私钥、测试认证配置及含密钥initrd不归档；官方schema/许可证、Collector/registry及实际依赖仍在项目。见[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)、[明确清单](../PUBLIC-QUALIFICATION.md#private-evidence)、[程序索引](../PUBLIC-QUALIFICATION.md#private-evidence)和[宿主引用检查](../PUBLIC-QUALIFICATION.md#private-evidence)。

随后[rc81指定机原15套同包KVM](../PUBLIC-QUALIFICATION.md#private-evidence)通过，夹具逐套停止服务、确认job/cgroup为空，再删除重复安装及测试凭据，OCI导入副本另有引用核查。[独立最终宿主复查](../PUBLIC-QUALIFICATION.md#private-evidence)确认15个根目录无残留，当前支持范围完整功能基线推进至rc81；rc80和其余旧有效基线继续保留。

该批次结束后，归档并逐项核验32份公开执行输入/元数据，bootstrap匹配保留dist程序；未压缩literal的每一字节均证明可从保留的原签名tar与recipe恢复。宿主引用检查通过后回收本地两个冗余传输文件，扣除新归档净减少110,747,648字节，约105.6MiB；指定机两个同类文件另回收110,845,952字节，约105.7MiB，不计入本地。[回收收据](../PUBLIC-QUALIFICATION.md#private-evidence)与[明确计划/保留索引](../PUBLIC-QUALIFICATION.md#private-evidence)绑定当前候选和原执行输入，原15套worker/业务归档均保留。先前本地精确重建验证的新建约1.22GiB副本也已在计划检查后及时回收。各项是本轮创建后清理的测试副本，不重复计作对原磁盘基线的额外收益；真正依赖继续保存在项目。
