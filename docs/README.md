# IRezygisk 定制文档索引

本目录记录 `hugoxue1/IRezygisk` 相对上游
[`PerformanC/ReZygisk`](https://github.com/PerformanC/ReZygisk) 的全部定制。任何影响注入时序、APatch
接口、SELinux、模块包格式或上游同步的修改，都必须先更新这里，不能只保存在提交信息或聊天记录中。

当前文档：

- [`APatch_Domainless_协同改造说明_2026-08-14.md`](./APatch_Domainless_协同改造说明_2026-08-14.md)：
  APatch minimal-v1、early-loader-v1、直接 Zygote 注入、无 live-policy 模块模式、回退和真机门禁。

当前源码候选为 `v1.0.0-i24` / 561。它保留 i22 的 ELF-entry/FD identity fail-safe 和 i23 的跨 ABI
handoff stop 状态机，只在目标通过 `SCM_RIGHTS` 收到 Zygote 标签会话端点后，用目标内 `fcntl` 明确
读取 `F_GETFD`、按需清除 `FD_CLOEXEC`，并再次读取复核。任一步失败或复核仍有 CLOEXEC 都在 exec
前关闭新端点并安全退出注入；不会新增 live-policy、permissive domain、持久命名 socket，也不改变
daemon action、模块/companion ABI 或 FD hiding。下文 i14/i15 对“端点自然跨 exec”的描述属于历史设计
假设；i15 的真机结果证明 SCM_RIGHTS/Zygote socket 标签路径可行，不等于证明所有 Android/OEM 都不会
在该端点设置 CLOEXEC。i24 尚未构建或真机复验，不能描述成稳定发布或 Android 11--16 全部实测通过。

当前已通过的双模块底座为 `v1.0.0-i18` / 555（IRezygisk + CkbSmartN）；三模块复验确认注入、daemon、
Assistant 清理和 CkbSmartN companion 均正常，但暴露 MIUI 不发布 `init.svc_debug_pid.*` 时的假重启状态
误报。`v1.0.0-i19` / 556 已在源码提交 `3694e3c` 修复，当前仍是待刷入真机候选。domainless 配套最低
版本 APatch 19076，并要求 boot 中实际运行
KernelPatch 0.13.12/d12。i10/d11 真机已证伪：目标完成 self-claim 后，stack-backed task_ext授权在OEM exec
AVC边界仍未命中；精确原厂kernel反汇编已排除state9 ABI、flags/class/permission错误。i11沿用既有
tracer/ABI handoff，只把安装门禁提升到d12 claimed-permit协议。`i1` 暴露
early-loader 环境与 `SIGCHLD` 问题，`i2` 暴露 direct tracer 无界等待，
`i3` 增加全事务硬期限/可恢复 detach/版本 stamp 后，真机又证明固定 500 微秒全 `/proc` discovery 会在
APatch 同步启动窗口阻断 OEM 后续启动；`i4` 使用 2/5/20 ms 分级退避，并与 19070 的 OEM gate 后 arm
时序配套。APatch 19070 + KernelPatch 0.13.6 的禁用 loader 基线已真机通过；i4 到达 gate 后 daemon
启动后失败并熔断恢复。i5 跳过相同 namespace 后仍失败，证明 setns 不是主因；最后同步边界进入旧 d06
跨任务 `grant_task_auth(pid)`。i6 改为 APD stage 一次性 ticket、目标 Zygote 在 remote syscall 中 self-claim，
再执行 loader open/mmap；API 25 四 ABI clean Release 和包内容已通过。i6 真机已安全启动并完成双 ABI
ticket stage，但 APatch gate 后 arm 太晚，两个 tracer 在 self-claim 前错过 linker 窗口并安全退出；因此
仍不是稳定发布。i7 改为 init pre-exec rendezvous，真机确认 hold/stage/self-claim 可达，但 64 位路径被
SELinux 严格 exec ptrace 拒绝，32 位路径又在目标仍是原生 64 位 init 时提前选择 32 位 tracer；fail-open
让系统启动但没有任何 Zygote maps。i8 曾配合 d09 增加只限一次严格 `process:ptrace` 的 task-local 授权，
pre-exec 总用原生 tracer，异 ABI只在 `PTRACE_EVENT_EXEC` 停点交给 `trace-postexec`；同时修复残留 PID
重复处理和 state.json。19073/d09 真机随后证明 SID-changing exec 实际走 flags=0 的普通 AVC，且 `ssid`
属于 tracer，d09 因而无法命中；i8 冻结不再测试。i9 配合d10仍被current SID的OEM exec顺序假设阻断，
19074/d10真机已证伪且i9不再安装。i10/d11随后也在PID718 self-claim后被同一exec ptrace拒绝证伪。
i11保留loader/ABI handoff修复并与d12的bit12/stage bit3 claimed permit协议配套。真机已经证明双目标
stage/self-claim/PTRACE_EVENT_EXEC与32位ABI handoff成功，失败点是用户态`wait_linker_ready()`的512次
syscall计数在约150ms提前耗尽。i12删除这个非时间型门槛后，真机64位已在约1.61秒确认GOT解析；随后
暴露Zygote原生SELinux禁止遍历`/data/adb`，remote open返回EACCES，错误回滚遗漏PC又导致primary
SIGSEGV并连带杀死32位目标。i13由tracer读取ELF并匿名传入目标，恢复完整寄存器/GOT和部分映射，并把
每个APD rendezvous固定为一次消费；真机随后证明其注入库仍在exec后从Zygote重连`/data/adb`，且32位
持久socket没有进入Android FD ignore集合，两个tombstone均以`Unable to get socket name`终止。
i14改为init上下文pre-exec建立并认证daemon stream、跨exec/跨ABI传递FD，app fork显式扩展
`fds_to_ignore`，system_server/USAP只在自身FD扫描时精确排除该控制FD，child回调后关闭；关键hook缺失
则整体回滚。monitor还同时校验进程状态与当前service PID，构建循环任一ABI失败即失败。仍保留
3.5s/4s/5.5s/6s多层看门狗，不得与APatch19075/d11或更旧boot混装。i14/551最终ZIP为538,931字节，
SHA-256 `CEDA0949AD9DDA88B74581289B38B5D697C293B3AED4E3433300326550BCF127`；当前仅完成离线验收，
真机双ABI状态不能在刷入前预先宣称通过。

i14/551 真机已经把失败边界精确推进到继承 socket 的 SELinux 对象标签：两个目标都完成 self-claim、
pre-exec `DomainlessSession`、`PTRACE_EVENT_EXEC`、GOT 解析和匿名 ELF 映射，但 init 域创建的客户端
socket 在 exec 后仍带 `u:r:init:s0` 标签，64/32 位 Zygote 对该 FD 的 read/write 同时被原生 SELinux
拒绝，入口因此报告“not a connected stream socket”并安全回滚。i15不新增policy或KernelPatch能力；
zygiskd在既有Zygote sockcreate context下创建专用socketpair，经原始pre-exec连接用`SCM_RIGHTS`交付新
端点，目标在exec前关闭init标签旧连接，只让Zygote标签端点跨exec/跨ABI保留。i15/552最终ZIP为
540,770字节，SHA-256 `E2BD699C1AC8ED5BEC3549C6B28739E852055F7660B296F3B67D406F9411AB9C`；
199 entries、99组sidecar和12个核心ELF审计通过。随后真机已经确认 i15 双 ABI adopted/injected/maps、
Zygote/system_server 稳定和 `boot_completed=1`，所以 i15 是通过的注入底座。

i15 上启用 CkbSmartN 后，arm32 模块能加载，arm64 在真实 app-specialize child 中仍被 CSOLoader 拒绝；
同一裁剪依赖并使用 Android packed relocations 的 SO 在独立 CSOLoader 与 Android 原生 linker 中均能加载。
i16 不按插件名特判：zygiskd 随模块清单用 `SCM_RIGHTS` 交付预打开只读 FD，child 仍先走 CSOLoader，
仅在失败时用 Android `android_dlopen_ext` 的 `USE_LIBRARY_FD|FORCE_LOAD` 通用回退。最终 i16 ZIP 为
599,952 字节，SHA-256 `F3EB2E141698B6A3B9F12BEB0A9E9AFDE4433655C4349C504B1BB47FF934633F`；
99 组 sidecar 零 mismatch，四 ABI Release 通过。CkbSmartN arm64 用同一 FD 回退调用在真机诊断进程中
0.333 秒加载并解析两个 Zygisk 入口。i16 尚未完成重启后的真实回调/Bridge 验收，不得写成稳定发布。

仓库角色：

- `upstream`：官方 ReZygisk，只用于抓取和对照；
- `origin`：`git@github.com:hugoxue1/IRezygisk.git`，保存可复刻的定制提交；
- APatch 配套实现与版本矩阵以 `E:/ckb_workspace/APatch/docs` 中的协同方案为准。

未通过 APatch/ReZygisk 双仓构建、无模块基线、ReZygisk 单模块、ckbsmart、Assistant 和 Hunter
分层回归前，不得把实验实现描述成稳定发布。
