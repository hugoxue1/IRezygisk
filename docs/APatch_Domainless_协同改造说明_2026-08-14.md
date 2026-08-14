# IRezygisk / APatch domainless 协同改造说明

日期：2026-08-14

上游基线：ReZygisk `e42886f`（v1.0.0 / versionCode 537）

配套版本：APatch 19067、KernelPatch 0.13.5 任务级授权 v2

目标远程：`git@github.com:hugoxue1/IRezygisk.git`

## 1. 目标和非目标

目标不是修改 Hunter、伪造 SELinuxFS、改名固定域或删除模块功能，而是在真实运行状态下同时满足：

1. APatch 保持 `effective=minimal-v1`，live policy 不创建 `magisk`、`magisk_file`、
   `magisk_log_file` 或替代固定域；
2. ReZygisk 32/64 位实际注入 Zygote，ckbsmart、Zygisk Assistant 和标准 Zygisk API 生命周期可用；
3. APatch 模式不加载 ReZygisk `sepolicy.rule`，避免 `SYSTEM_SERVER_EXECMEM`、
   `ZYGISK_NEXT_POLICY`、`STATUS_SEQUENCE_POLICYLOAD` 和 `RAW_AVD_SEQUENCE`；
4. 旧 ReZygisk/旧 APatch、Magisk、KernelSU 与依赖旧 root-domain ABI 的模块仍有明确 legacy 路径；
5. 任一早期阶段失败都恢复 init、禁用故障模块并保留诊断，不杀 Zygote、不循环 Recovery。

不能承诺所有历史 Magisk 模块在零修改时仍保持 Hunter CLEAN。硬编码固定域或自行提交宽
`sepolicy.rule` 的模块必须移植到新 ABI，或者继续走可检测的 legacy fallback。

## 2. 已证实的问题链

19064 在 minimal-v1 中启动官方 ReZygisk。monitor 以
`PTRACE_SEIZE(1, ..., PTRACE_O_TRACEFORK)` 跟踪 PID 1；init 子任务执行 SELinux 域转换时，检查主体跨越
了 KernelPatch 当前任务 token，产生大量 `process ptrace` AVC 并卡 MI 首屏。19065 降级 minimal-v0 后
消除了该风暴，但 OEM per-boot 门禁让 monitor 晚于 Zygote，只有进程、没有注入。19066 恢复兼容
profile 的 pre-Zygote 时序后，monitor PID 713 早于 Zygote 727/728，两个 Zygote maps 均出现
`libzygisk.so`，功能恢复；代价是 monitor/zygiskd 运行于 `u:r:magisk:s0`，Hunter 真实命中
`MAGISK_CONTEXT`。

官方 `sepolicy.rule` 还包含：

```text
allow zygote adb_data_file dir search
allow zygote adb_data_file file *
allow zygote zygote process execmem
allow system_server system_server process execmem
...
```

所以只删除 `allow zygote magisk ...` 最多去掉产品 context，仍会留下独立策略与 policy-load 证据，不能
满足最终目标。

## 3. 选择的架构

### 3.1 双后端，不覆盖上游 legacy 行为

IRezygisk 保留两条后端：

- `legacy-init-trace`：官方 PID 1 ptrace、官方 `sepolicy.rule`，供 Magisk、KernelSU、旧 APatch 使用；
- `apatch-domainless-v1`：由 APatch early-loader 启动，不跟踪 PID 1，不加载模块 policy，只直接发现和
  附加真实 Zygote。

APatch 不按 `rezygisk` 模块 ID 写特例，而实现可供以后其他 loader 复用的 `early-loader-v1`。

### 3.2 APatch 私有 broker 协议

活动模块可提供根目录 `apatch-early-loader.json`：

```json
{
  "schema": 1,
  "mode": "domainless-v1",
  "entry64": "bin/zygisk-ptrace64",
  "entry32": "bin/zygisk-ptrace32",
  "arguments": ["monitor-domainless"]
}
```

APD 在基础 minimal-v1 已激活、但 OEM per-boot 门禁和普通模块阶段尚未开始时：

1. 只扫描逻辑活动模块，拒绝 `disable/remove`、越界路径、符号链接、非 root owner、group/world writable
   entrypoint、未知 schema 或同时存在 legacy `sepolicy.rule` 的声明；
2. 派生隐藏 broker 子进程，通过匿名 stdin 交付 superkey 和经过验证的 manifest；superkey 不写磁盘、
   命令行或模块环境；
3. broker 与 loader 建立 `SOCK_SEQPACKET`/socketpair，loader 只得到该 FD；
4. loader 发送 `READY` 后 broker 才向同步父阶段确认 `ARMED`，父阶段随后归还 init；
5. loader 发现目标后请求 `AUTHORIZE_ZYGOTE(pid, abi)`；broker 必须重新核对 PID 存活、PPID 1、UID 0、
   `/proc/<pid>/exe` 为对应 `app_process32/64`、SELinux context 为 `u:r:zygote:s0`，然后调用现有
   `SUPERCALL_SU_TASK=0x1011`，使用空 scontext 给该任务建立不继承 token；
6. 只有 broker 返回成功后 loader 才允许 ptrace/inject。模块永远拿不到 superkey。

KernelPatch 0.13.5 的 `task_su()` 已以 `KP_TASK_AUTH_ORIGIN_TASK_SU` 和 `inherit=false` 建立 token；因此
第一阶段不需要新增内核 ABI。若真机证明现有 task token 仍不足，必须先形成新的安全设计文档，不能静默
改成宽全局 allow。

### 3.3 直接 Zygote 注入

domainless monitor 在 init 继续启动前先进入 armed 状态，然后以低开销 `/proc` 观察发现
`app_process32/64`：

1. 请求 broker 授权并再次验证 PID；
2. `PTRACE_SEIZE + PTRACE_INTERRUPT` 只附加目标 Zygote，不跟踪 PID 1 或其他 init 子任务；
3. 若仍处于 linker/`__libc_init` 窗口，复用现有 GOT-break + CSOLoader 注入；
4. 若已经越过该窗口，只允许非破坏的 late-attach 路径或报告失败，禁止杀 Zygote；
5. 注入完成立即 detach；monitor 继续观察 Zygote 重启，但按现有 retry 上限防止无限循环。

IRezygisk APatch 模式必须从已带 token 的 Zygote 中完成必要操作，且 token 不继承给 app/system_server
子任务。模块库应尽量在 Zygote 父进程预加载并继承，不能为了兼容把 token 广播给应用进程。

### 3.4 无 live-policy 包模式

安装脚本在检测到支持 `early-loader-v1` 的 APatch 时：

- 安装 `apatch-early-loader.json` 和 domainless marker；
- 不把 `sepolicy.rule` 放入模块目录；
- 普通 `post-fs-data.sh` 不再重复启动 legacy monitor；
- Magisk、KernelSU、旧 APatch 继续安装官方 `sepolicy.rule` 并使用 legacy monitor。

模块包仍保持一个仓库、一个代码基线和两个运行后端，不把 APatch 变成 IRezygisk 专用实现。

### 3.5 non-inheritable token 与 Zygisk API 通道

KernelPatch token 只授权真实 Zygote 且 `inherit=false`。app、system_server 和 USAP 子任务不能继承 root
token；如果让每个子任务重新连接 `/data/adb/rezygisk/*.sock`，又会因为没有模块 `sepolicy.rule` 而被
SELinux 拒绝。解决办法不是给应用授权，而是把通信能力限制在 Zygisk 回调生命周期内：

1. 注入后的 Zygote 建立一条 `DomainlessSession` 控制连接；zygiskd 为它 fork 专用 handler，主 daemon
   继续处理状态查询和 Zygote 重启；
2. 控制 FD 随 fork 进入子任务，仅在受信任模块的 pre/post 回调期间使用；post 回调结束立即关闭并解除
   共享映射，普通应用代码拿不到控制通道；
3. 所有子任务通过 `MAP_SHARED` 中的原子 futex 串行化同一字节流。锁记录 Linux TID；持锁线程崩溃后，
   下一调用方确认 TID 已消失再接管，避免全局死锁；
4. companion 不复用控制字节流。daemon 创建独立 `socketpair`，用 `SCM_RIGHTS` 分别交给模块 companion
   和调用方；控制锁随后立即释放；
5. APatch 19067 不给 app/system_server 发 token，也不增加任何 live-policy allow。

这里保留的是最小 IPC 能力，不是 root 能力。升级时若修改 FD 清理、fork/USAP 或 Zygisk API 生命周期，
必须重新审计“post 后应用不可见”这一不变量。

## 4. package_config 契约

APatch 的空 `package_config` 是合法 0 条配置。IRezygisk 必须把空文件视为成功空集合；只有真实 open/read
错误才失败。读取非空文件时继续跳过六列 header，并兼容末列空 `sctx`。不得在每个 Zygote fork 重复
打印误导性的 `ENOENT`。

## 5. 兼容矩阵

| 组合 | 后端 | APatch profile | live module policy | 预期 |
|---|---|---|---|---|
| 新 APatch + IRezygisk | domainless-v1 | minimal-v1 | 无 | 目标路径 |
| 新 APatch + 旧 ReZygisk | legacy | minimal-v0 | 有 | 功能优先，可检测 |
| 旧 APatch + IRezygisk | legacy | 原行为 | 有 | 不要求新 ABI |
| Magisk/KernelSU + IRezygisk | legacy | 不适用 | 官方规则 | 保持上游兼容 |
| 新 APatch + 无旧 ABI 模块 | 无 early loader | minimal-v1 | 仅真实模块规则 | 原行为 |
| safe mode | 禁止启动 | 安全路径 | 无 | 不自动恢复模块 |

## 6. Hunter 验收门禁

验收只读取真实内核状态，不修改 FingerprintCheck/Hunter。目标必须同时满足：

- `contextEvidence` 不含 1/2/8/9；
- `accessEvidence` 不命中 ReZygisk 引入的 3/10，也不恢复 APatch 11/12/13 组合；
- 无 `SYSTEM_SERVER_EXECMEM`、`ZYGISK_NEXT_POLICY`；
- 本轮无模块 policy commit，status sequence/policyload 与无模块 minimal-v1 基线一致；
- ReZygisk monitor/daemon 状态成功，32/64 Zygote maps 有真实注入库；
- ckbsmart、Assistant 分层功能回归通过；
- 设备完成三次冷启动，无 `/data/extm set_policy_failed`、ptrace AVC 风暴或 Recovery。

任何一项未满足，只能记录实际证据，不能通过过滤 SELinuxFS、修改检测器或改名伪装通过。

## 7. 失败与回退

- manifest/entrypoint 校验失败：不启动 loader，禁用该模块，APatch 保持 minimal-v1；
- loader 未在有界时间发送 READY：终止 broker/loader，禁用模块，归还 init；
- PID 校验失败或授权失败：拒绝请求，不调用 ptrace；
- 注入窗口错过：detach 并报告，不杀 Zygote；
- 旧模块仍含 legacy token：APatch 继续 19065/19066 的 minimal-v0 fallback；
- 不能在同一 boot 先 minimal-v1 失败、再热加载 compat 掩盖问题。

## 8. 上游同步清单

每次同步官方 ReZygisk 后，必须人工重放并核对：

1. `loader/src/ptracer/main.c`：双 monitor/trace 后端入口；
2. `loader/src/ptracer/monitor.c`：direct 模式、PID 生命周期、retry 与 status；
3. `loader/src/ptracer/ptracer.c` / `utils.c`：直接 attach、linker 窗口、late failure 安全；
4. `module/src/customize.sh` / `post-fs-data.sh` / `sepolicy.rule`：APatch domainless 条件安装；
5. `zygiskd/src/root_impl/apatch.c`：空 CSV/header/空 sctx 契约；
6. APatch `early-loader-v1` schema/broker 协议版本；
7. 先构建官方基线，再重放定制并完整构建，禁止直接覆盖目录。

## 9. 已实现文件与本轮坑点

实现锚点：

- `loader/src/ptracer/main.c`、`monitor.c`、`ptracer.c`、`utils.c`：domainless monitor、只发现真实
  Zygote、native ABI 免二次 exec、linker 窗口超时和 fail-open detach；
- `loader/src/common/daemon.c`、`loader/src/injector/entry.c`、`hook.c`：持久 session、进程共享 futex、
  post 后关闭子任务控制 FD；
- `zygiskd/src/zygiskd.c`、`constants.h`：专用 session handler 与独立 companion socketpair；
- `module/src/customize.sh`、`post-fs-data.sh`、`apatch-early-loader.json`：19067+ domainless 安装分支；
- `zygiskd/src/root_impl/apatch.c`：空 `package_config` 合法化。

本轮必须保留的坑点：

1. 直接附加已完成 linker 的 Zygote 后继续等 GOT 二次解析，会长期停住关键进程；现在先判断 GOT 是否已
   指向 libc，并设置 2 秒/512 syscall 上限，失败只 detach；
2. non-inheritable token 会使子任务重新连接 daemon 被 SELinux 拒绝；不能把 token 改成继承，而应采用
   上述有生命周期的持久 IPC；
3. Android API 25 NDK 头文件没有 `PTHREAD_MUTEX_ROBUST` 和相关函数；不能为编过而提高最低 Android
   版本，现改为 API 25 可用的原子 futex，并实现崩溃持锁接管；
4. 持久 FD 若留到 post 回调之后，会把 daemon 控制面暴露给普通应用；必须在 app/system_server 子任务
   的 post 末尾关闭，companion 使用独立 FD；
5. 把 zygiskd fork/exec 放到发现 Zygote 之后会浪费极窄注入窗口；native ABI daemon 必须在 APatch 仍
   阻塞 init 时预启动，同 ABI tracer 直接 fork 调用、避免再次 exec；
6. 模块 ID 保留 `rezygisk` 以兼容既有安装、模块数据和卸载逻辑，展示名使用 `IRezygisk`；不要为改名
   复制出第二套模块目录。
7. ZIP 同时携带 32/64 entry 声明，但单 ABI 设备不会提取另一套二进制；安装脚本必须按实际 ABI 删除
   未安装的 manifest entry，否则 APatch 的 fail-closed 路径审计会正确禁用整个 early loader。

8. APatch early-loader 由 init/APD 直接派生，不经过模块 `post-fs-data.sh`；其继承的 `PATH` 不保证包含
   `/data/adb/ap/bin`。ReZygisk 的 APatch root backend 会先验证该目录是否在 `PATH`，即使随后用绝对路径
   `/data/adb/apd` 执行也会提前拒绝。domainless monitor 必须在启动 daemon 前补入 APatch bin，同时保留
   原 Android PATH；不能删除 root backend 的环境校验来掩盖启动契约缺失。
9. domainless monitor 不 seize PID 1，短命 daemon/tracer 子进程退出后 `waitpid(-1, ..., WNOHANG)` 返回
   `ECHILD` 是正常的“当前队列已排空”。旧 listener 只在 `STOPPED` 时 break，会在 `TRACING` 下拿
   `pid=-1` 继续循环，造成 CPU/日志风暴并永远无法扫描 Zygote。所有 `waitpid` 错误都必须结束本次排空；
   非 `ECHILD` 错误另行记录。
10. `/proc` 枚举会遇到没有 `exe` 的内核线程和正在退出的进程。通用 `get_program()` 会把每次预期的
    `ENOENT` 写入日志，不适合高频 discovery；domainless scanner 使用静默 `readlink`，只把真实协议、
    daemon 和注入失败写入日志。
11. 状态展示不能以“该 ABI 的 daemon 已经 fork”为设备支持判据。`zygote64_32` 设备从首个状态更新就
    应同时显示 64/32，未注入时均为警告；只有收到对应 `ZYGOTE*_INJECTED` 且 daemon 存活才显示成功。

### 9.1 `v1.0.0-i1` 首次真机失败与 `i2` 修复

MI 9（Android 11，`ro.zygote=zygote64_32`）安装 APatch 19067 与 IRezygisk
`v1.0.0-i1-538-939ab21-release` 后能够进入系统，但模块卡片只显示
`Monitor: ✅, ReZygisk 64-bit: ⚠️`，没有 32 位状态。只读 ADB 取证确认两个 Zygote 均存在，
`zygisk-ptrace32/64` 与 `zygiskd32/64` 文件也完整，但没有 monitor/daemon 常驻，Zygote maps 未注入。

持久日志给出直接证据：

```text
zygiskd64: APatch's APD binary is not in PATH
zygiskd64: No root implementation found.
zygiskd64: Unsupported environment: Unknown root implementation
zygisk-ptrace64: waitpid failed with 10: No child processes
zygisk-ptrace64: process -1 received unknown sigchld_status ...
```

同时出现大量 `/proc/<kernel-thread>/exe: ENOENT`。这不是单纯 UI 问题，而是三段连续故障：APatch
环境未满足 backend 检查，64 位 daemon 退出；listener 随后在 `ECHILD` 上死循环；32 位发现和两种 ABI
注入均不再发生。`i2` 在 monitor 侧补齐 PATH、修正 waitpid 排空、静默预期 `/proc` 竞态，并按
`ro.zygote` 预置 ABI 展示。修复不修改 APatch/KernelPatch ABI、不增加 live-policy，也不触碰设备；用户
安装新 ZIP 后仍须重启并以进程、state.json、32/64 maps 和实际模块功能联合验收。

构建状态：`i1` 虽在 Android API 25 目标上通过四 ABI 构建，但首次真机失败。`i2` 源码提交
`eea79b957282f6a97b19f8e23f62cb009be6599b` 已重新 clean Release 通过 arm64-v8a、armeabi-v7a、x86、
x86_64，产物为 `IRezygisk-v1.0.0-i2-539-eea79b9-release.zip`，SHA-256 为
`EE211615F298B2B99826A355C2E572B88EAE7C69C83CB365EBACB4C6549DA0CD`。四种 ELF class/machine 与目录
一致，ZIP 内 99 个 payload hash 全部复算通过；`misaki.sig` 为空，表示该测试包未配置模块私钥，安装时
仍由 `verify.sh` 执行逐文件 SHA-256。代码编译通过不等于真机通过。APatch 19067 + IRezygisk 的单模块
32/64 注入、ckbsmart、Assistant、Hunter 和三次冷启动门禁仍待验证，在此之前不得标为稳定版。
