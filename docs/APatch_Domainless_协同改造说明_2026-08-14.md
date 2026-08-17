# IRezygisk / APatch domainless 协同改造说明

日期：2026-08-14

上游基线：ReZygisk `e42886f`（v1.0.0 / versionCode 537）

当前最终真机基线：APatch 19096/3215d2a + KernelPatch 0.13.23/d23 + IRezygisk
`v1.0.0-i21`/558/`ba2e29b` + CkbSmartN 0.101.20 + Zygisk Assistant 2.1.5-apatch1。i21 已完成
32/64 位注入、原子状态数据报、缺失 debug PID 容错、幂等有界 `module.prop` 状态重写以及三模块共存
回归。i15–i20 是问题收敛历史，不再作为交付基线；CkbSmartN 长期 daemon/Binder 与 Assistant
denylist 清理仍按各自业务边界验收，不能回写成 IRezygisk 通用加载失败。

目标远程：`git@github.com:hugoxue1/IRezygisk.git`

## 1. 目标和非目标

目标不是修改 Hunter、伪造 SELinuxFS、改名固定域或删除模块功能，而是在真实运行状态下同时满足：

1. APatch 保持 `effective=minimal-v1`，live policy 不创建 `magisk`、`magisk_file`、
   `magisk_log_file` 或替代固定域；
2. ReZygisk 32/64 位实际注入 Zygote并承载标准 Zygisk API；ckbsmart 等超出标准 API 的复合插件另按
   daemon、Binder、策略和业务能力分层验收；
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
5. loader 发现目标后请求 `STAGE_ZYGOTE(pid, abi)`；broker 必须重新核对 PID、PPID 1、UID 0、对应
   `app_process32/64`、`u:r:zygote:s0` 和 starttime，再调用 `STAGE_TASK_AUTH=0x1124`；kernel 只登记
   identity/PID/随机一次性 ticket，不写目标任务；
6. broker 返回 `STAGED pid ticket` 后，loader 把 ticket 交给对应 ABI tracer；tracer 必须先让已停止的
   Zygote remote syscall `CLAIM_TASK_AUTH=0x1125`，成功后才 open/mmap loader。模块永远拿不到 superkey。

该路径最低要求 KernelPatch 0.13.7 和 `TASK_AUTH_SELF_CLAIM_V1` bit 7。旧 `task_su()` 会改写目标
cred/capability/seccomp，d06 grant 又会跨任务写 stack-backed `task_ext`，二者均禁止；缺少 bit 7 时必须
fail-closed，不能静默改成旧命令或宽全局 allow。

### 3.3 直接 Zygote 注入

存在 OEM per-boot 重建 gate 时，domainless monitor 在 gate READY 后、Zygote 创建前进入 armed；没有
该 gate 时由 APatch 直接 arm。monitor 以有界分级退避的 `/proc` 观察发现 `app_process32/64`：

1. 请求 broker stage ticket 并再次验证 PID/starttime；
2. `PTRACE_SEIZE + PTRACE_INTERRUPT` 只附加目标 Zygote，不跟踪 PID 1 或其他 init 子任务；
3. 在 linker/`__libc_init` 窗口停住目标后，先 remote syscall self-claim；成功后复用 GOT-break +
   CSOLoader 注入；
4. 若已经越过该窗口，只允许非破坏的 late-attach 路径或报告失败，禁止杀 Zygote；
5. 注入完成立即 detach；monitor 继续观察 Zygote 重启，但按现有 retry 上限防止无限循环。

IRezygisk APatch 模式必须在 Zygote 自领取 token 后完成必要操作，且 token 不继承给 app/system_server
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

### 9.2 `i2` 已通过 APatch backend，19067 失败归因 broker 生命周期

19067 + i2 的第二轮 ADB 证据依次出现 `AP_EARLY_LOADER_ARMED ... abis=[64,32]`、
`zygiskd64: APatch root implementation found`、`Loading arm64 modules` 和 `sent root/modules info`。
这证明 9.1 的 PATH/ECHILD/ABI 展示修复已生效。随后 broker、monitor 和 daemon 恰好在 APatch 记录
`AP_PER_BOOT_GATE_DEFER` 后同时消失，Zygote maps 仍为空；根因是 APatch 19067 broker 没有脱离 init
同步 post-fs-data 的 process group/cgroup，父 APD 返回后被 init 清理，不是 IRezygisk 再次启动失败。

APatch 19068 已在 broker 启动时使用独立 process group 并切换 cgroup；协议和 IRezygisk i2 二进制均
未改变，因此设备上已安装的 i2 不需要重装。下一次发布 IRezygisk 新 ZIP 时，安装脚本的 domainless
最低 APatch 版本必须从 19067 提高到 19068，并同步提升 IRezygisk 构建号/版本代号；在 19068 真机闭环
完成前不额外发布 i3，避免把“只提高安装门禁”的新包误写成已验证功能修复。legacy APatch、Magisk 和
KernelSU 分支仍保持官方回退，不受该最低版本调整影响。

### 9.3 19068 启用 i2 后 MI 首屏循环，i2 不再是可启用候选

19068 使 broker 持续存活后，i2 的 64 位 daemon 成功运行，但失败遗留 state.json 始终为
`daemon64=1, zygote64=0`；禁用 IRezygisk 后同一 APD 正常启动。direct tracer 的 2 秒计时只包围 linker
轮询，不能中断其内部阻塞 `waitpid()`，也不覆盖 initial stop、remote syscall/call 和 GOT break。当前
实现因此可能永久停住 Zygote，且 cleanup 无法到达；“没有 EXITKILL”并不等于 fail-open。

同时，APatch broker 对 Zygote 的授权实际落到 KernelPatch `task_su()`，该函数会远程改写 cred、全
capability 和 seccomp 后才写 non-inheritable token，不是文档原先假设的纯 task-auth。IRezygisk 后续
不得继续围绕现有 direct attach 增加轮询频率或 sleep。必须先改成可证明有界、可恢复的 pre-exec 捕获，
并与 APatch/KernelPatch 成对解决纯授权语义；在此之前不发布 i3，也不得要求用户重新启用 i2。

### 9.4 `i3` 有界 tracer、纯授权配套与构建缓存门禁

`i3` 已把 direct transaction 的期限提升为一条 4 秒绝对 deadline，所有 ptrace `waitpid`、initial
stop、linker stepping、remote syscall/call 和注入共享该期限。失败后最多再用 300 ms 获取恢复 stop，
恢复可能改写的 GOT，随后 detach + SIGCONT；不使用 `PTRACE_O_EXITKILL`，失败目标是让 Zygote 继续启动。

该修复必须与 APatch 19069 / KernelPatch 0.13.6 成套使用。0.13.6 的纯 delegated task-auth UAPI 只写
nonce-bound、non-inheritable token；不再调用会改写 cred/capability/seccomp 的 `task_su()`。i3 安装脚本
把 domainless 最低 APatch 版本提升到 19069。安装新版 APK 仍不足以更新内核：必须从原厂 boot 重新修补并
刷入 0.13.6，且先在 IRezygisk 禁用状态确认基础启动与能力位。

构建时发现 Make 的旧对象不依赖 `ZKSU_VERSION`，首次改成 i3 的 ZIP 仍可能夹带 i2 ELF；该包已拒绝。
`loader/Makefile` 和 `zygiskd/Makefile` 现以每架构 version stamp 作为对象依赖，随后执行 API 25 四 ABI
clean Release。最终 ZIP 为 `IRezygisk-v1.0.0-i3-540-fcbcbfd-release.zip`，SHA-256
`6F208BCD1A2C91202F65311D7A4CB1C841489C0D461208D8FD57C6E2AAB252D6`；arm64 daemon 与 ptracer 的内嵌
版本字符串均为 i3。测试包未配置模块私钥，仍由既有逐文件 SHA-256 校验保护内容。

当前状态是“已构建、未真机、未提交、未 push”，不是稳定发布。首次只启用 IRezygisk；若首轮启动失败，
重新启动时 APatch 19069 的跨 boot 熔断应自动禁用责任模块，不能据此省略失败日志和 state.json 取证。

### 9.5 安装后不要假设旧 `disable` 会继承

19069 真机安装 i3 时，APatch boot-mode installer 会先删除活动模块的 `disable`，再留下 staged update；
因此安装前禁用 i2 不代表安装后 i3 仍禁用。首轮高风险测试流程固定为“安装 → 不重启 → 核对 staged
版本/manifest/32+64 payload 哈希 → 重新禁用 → 核对其他 Zygisk 模块均禁用 → 明确开启 i3 后才重启”。
本轮七个关键 payload 哈希均与最终 i3 ZIP 一致，禁用标记已通过 ADB 恢复。

### 9.6 `i3` 在 Zygote 出现前阻塞启动，`i4` 修正 discovery 负载与 arm 时序

只启用 i3 的首次冷启动没有进入 Android。下一 boot 中 APatch 19069 的 `armed/tripped` 熔断自动禁用
`rezygisk`，设备成功恢复，证明恢复边界有效。失败 boot 依次出现 broker READY、monitor armed、
zygiskd64 找到 APatch 并发送模块信息；但没有 `AP_PER_BOOT_GATE_READY`、Zygote/app_process、
`AP_EARLY_LOADER_TASK_AUTH` 或 direct tracer 事件。state.json 为 daemon64=1、zygote64=0。故障发生在
direct transaction 之前，不能继续修改 4 秒 ptrace deadline 猜测修复。

源码审计发现 domainless loop 在未注入阶段固定 `usleep(500)`，每秒最多 2000 次完整枚举 `/proc`；而
APatch 19069 又在 init 同步 post-fs-data APD 归还前启动 monitor。在 MI 9 的 4.14 内核/OEM 启动窗口中，
该组合使 procfs/任务表竞争覆盖了 per-boot 重建和 Zygote 创建。此前静默跳过无 exe 只消除了日志风暴，
没有降低扫描成本。失败日志开头的 MIUI init 子进程 SIGABRT 在禁用模块的成功 boot 中同样存在，已通过
对照排除。

`i4` 保留 direct tracer、daemon session、纯 task-auth 和 fail-open 清理，只改变 discovery 调度：启动后
首秒每 2 ms 扫描，1～5 秒每 5 ms，之后每 20 ms；32/64 均注入后每 100 ms 处理状态。配套 APatch 19070
在检测到 OEM gate 时，只于同步阶段提升 staged 模块，实际 arm 移到 `wait_for_rebuild()` 成功之后；没有
gate 的设备保持直接 arm，legacy/Magisk/KernelSU 后端完全不变。

完整 Release 结果：`IRezygisk-v1.0.0-i4-541-fcbcbfd-release.zip`，513,046 字节，SHA-256
`ECAB26AF1B2FE882B9E9D0507325D7EE2653CF752CE3E3A3DF1A072D7E088512`。API 25 的 arm64-v8a、
armeabi-v7a、x86、x86_64 均重新编译；99 个 payload hash 通过，module.prop 为 i4/541，arm64 ptracer
内嵌 i4 版本与 `discovery backoff` 字符串。domainless 安装门禁提升到 APatch 19070；KernelPatch 仍要求
0.13.6，本轮无内核 ABI 变化。

APatch 19070 禁用 loader 基线已真机通过：Manager/APD 19070、KP d06、Hook functional=2/ABI 3、profile
401/402 均为 mode/state 2/2，旧 i3 保持 disable 且系统无 monitor/zygiskd。i4 自身仍是“已构建、未真机、
未提交、未 push”；i3 禁止再次启用。i4 首轮只允许与 APatch 19070 成套，安装后先确认 disable，再单独
启用。验收必须同时看到 gate READY、deferred arm、task-auth、两种 ABI injected/maps 与 boot_completed，
不能只看 Manager 开关。

### 9.7 i4 的新断点是重复进入相同 mount namespace，i5 只在等值时短路

i4 的真实失败 boot 已到 `AP_PER_BOOT_GATE_READY`、`AP_EARLY_LOADER_DEFERRED_ARM`、broker、2/5/20 ms
monitor 和 zygiskd64 exec；最后一行是 `Welcome to ReZygiskd64`。没有 root implementation、Zygote、
task-auth 或 direct tracer，下一 boot 由熔断恢复。

Welcome 后第一条源码操作是 `switch_mount_namespace(1)`。在线核对 PID 1、APD 与调用 shell 的 nsfs inode
均为 `4026531840`，说明 domainless daemon 已继承 global mount namespace。i5 的通用 helper 先 stat
`/proc/self/ns/mnt` 与目标；dev/inode 相同直接返回并打印 skip，不同仍执行原 setns。该判断不绑定 MI 9、
Android 11 或 4.14，也不改变非 APatch/不同 namespace 的行为。i4 禁止复测，i5 必须以单模块验证该推断。

i5 clean Release 产物为 `IRezygisk-v1.0.0-i5-542-fcbcbfd-release.zip`，513,590 字节，SHA-256
`5098A3EA4B0D667D6A8F92A2658539842563BAFD69AE35BBE676C30A2516EC06`。API 25 四 ABI通过，199 个
entry、99 组 payload hash 全部一致；module.prop i5/542，arm64 daemon/ptracer 分别内嵌 namespace skip
与 discovery backoff。首次编译缺标准 stat 头被 `-Werror` 阻止，没有把失败构建当成可安装包。

### 9.8 i5 证伪 setns 主因，i6 改为 Zygote self-claim

i5 已实际跳过相同 mount namespace，但失败日志仍停在 `ReZygiskd64 already running` 后，未出现
task-auth、tracer、injection 或 Welcome。故 9.7 的 setns 结论只保留为兼容优化，不再作为根因。最后同步
链进入 APD 对 Zygote 的 d06 `grant_task_auth(pid)`；该 ABI 跨任务写另一个运行任务的 `task_ext`，已从
KernelPatch 0.13.7 撤销。没有 pstore，因此不声称知道具体锁死指令，但 19070/d06/i5 禁止继续测试。

i6 的 APatch domainless backend 改用 stage/self-claim：monitor 请求 APD stage，经完整 Zygote 身份审计后
获得一次性 ticket；ticket 传给对应 ABI tracer；tracer 停住 Zygote、找到 syscall gadget 后，先在目标
上下文 remote syscall 执行 `CLAIM_TASK_AUTH`。只有 KernelPatch 确认 ticket 与 `current` task identity 匹配并
一次消费后，才继续 remote open/mmap 注入库。这样 APD 不再写目标任务，Zygote 也不会在获得授权前读取
受保护模块文件。错误/重放 ticket fail-closed，legacy ReZygisk 后端不传 ticket，保持原兼容路径。

i6 为 `v1.0.0-i6` / 543，domainless 最低 APatch 提升至 19071，并要求 boot 内 KernelPatch 0.13.7 的 bit 7
`TASK_AUTH_SELF_CLAIM_V1`。新旧协议不能混装；d06/bit 6 不再接受。API 25 四 ABI Release 已通过，产物
`build/out/IRezygisk-v1.0.0-i6-543-fcbcbfd-release.zip`，564,030 字节，SHA-256
`F2307B96748D2DE48118CE17A323F692F60E4B898B13982D5D5CB174F6AEF5FC`。

打包过程另发现 `${moduleId}` 一类模板在 Windows/MSYS 下可能原样进入 ZIP。模板现改用 `@MODULE_ID@`、
`@MODULE_NAME@`、`@VERSION_NAME@`、`@VERSION_CODE@` 显式替换，最终 `module.prop` 已复核为 rezygisk、i6/543。
构建成功不代表真机通过；首次只允许与 19071/d07 成套、单模块、熔断保护冷启动。

### 9.9 i6 真机到达双 stage，但 monitor 启动过晚

i6/543 与 19071/d07 成套重启后 Android 正常完成，monitor 和 zygiskd32/64 都存活，两个 daemon 均发送
READY。APD 对 Zygote64 PID 716、Zygote32 PID 717 均成功记录 `TASK_STAGED`。两个 ABI tracer 随后都在
`wait_linker_ready()` 报 `Timed out waiting for __libc_init resolution` 并安全 detach，没有进入
`inject_on_main()`，所以没有 remote self-claim、没有 libzygisk maps；UI 正确显示 Monitor ✅、64/32 ⚠️。

这证明 i6 的 daemon readiness、broker target audit、ticket 传递和 fail-open 生效，但不证明 claim 本身。
APatch 当前在 OEM gate 310 ms READY 后才 spawn monitor，而 dmesg 的首次 app_process exec 已在 25.213 秒；
一次性 linker 窗口已经过去。后续协同改造要把安全 watcher 前移到 app_process exec 前，仍须保持独立
process group/cgroup、低压力退避、deadline/detach 和 stage/self-claim，不能靠延长等待或恢复破坏性路径。

### 9.10 i7：init pre-exec rendezvous，取代事后扫描（历史设计，已真机证伪）

i7/544 不再尝试把 gate 后 monitor 做得更快，而是与 APatch 19072、KernelPatch d08 建立确定性启动协议：

1. APatch 在 init 同步 post-fs-data 返回前按 manifest ABI 和标准 `ro.zygote` 值为 zygote service 排队
   `ctl.sigstop_on`；d08 的两个 no-op trigger 保证双 service 请求在 class start 前处理。
2. monitor 不扫描 `/proc`，只轮询与 `ro.zygote` 映射一致的
   `init.svc_debug_pid.zygote[_secondary]`。APD 仍独立验证 UID 0、PPID 1、T/t、pre-exec init exe、
   `u:r:init:s0`、ABI、service、starttime，并只为该目标 stage 一次性 ticket。
3. tracer 使用 `PTRACE_SEIZE` 并在 attach 时设置 `PTRACE_O_TRACEEXEC`。Linux 允许忽略从非
   signal-delivery-stop 的 ptrace restart 传入的信号，所以实现显式 `kill(SIGCONT)` 唤醒 group-stop；若
   随后出现 SIGCONT delivery-stop，则抑制 handler 交付并保持 syscall tracing。
4. 目标在 exec 前 remote syscall self-claim；恢复寄存器后只接受准确 `PTRACE_EVENT_EXEC`，然后复用现有
   linker/GOT 注入。ticket 在 exec 前已消费，不二次 claim，也不会继承给 fork 出的应用。
5. `RELEASE_PREEXEC_ZYGOTE` 同时承担成功释放和认证 monitor 的失败 abort。stage 被拒绝、tracer 失败、
   4 秒期限、5.5 秒父监督、6/15 秒 broker watchdog、FD EOF/进程退出都会触发
   `sigstop_off + SIGCONT`，避免把 Zygote 留在 recovery 风险状态。

兼容策略按能力而非设备型号：标准 `zygote64`、`zygote32`、`zygote64_32`、`zygote32_64` 均映射；安装
阶段按设备 ABI 裁剪 manifest；Android 9+ 仍需实际探测 init 字符串和 app_process 文件。旧 Android、非标准
OEM init 或缺 d08 bit 8 时，APatch 禁用本 provider 并正常启动。legacy Magisk/KernelSU 后端保持上游路径，
不强制进入 APatch domainless 协议。

打包门槛提升为 APatch 19072；版本为 i7/544。API 25 的 arm64-v8a、armeabi-v7a、x86_64、x86 四 ABI
Release 已通过，ZIP 的 module.prop、manifest 和四 ABI payload 已核对。该结果只说明离线构建完整，尚无
真机注入成功证据。首次测试必须先完成 19072+d08 零模块启动，再只启用 i7；i1～i6 不再复测。本轮未
commit、未 push。

### 9.11 i7 真机证伪：不是继续增加 timeout

19072/d08/i7 在 MI 9 `zygote64_32` 上同时取得两个 pre-exec debug PID，APD 对 PID 713/714 完成 stage，
monitor 与两个 daemon 均启动。64 位 PID 713 还成功执行了目标内 self-claim，随后才出现
`u:r:init:s0 -> u:r:zygote:s0` 的严格 `process:ptrace` 拒绝并以 127 退出；这说明 rendezvous 和 ticket
协议有效，失败不再是“发现太晚”。

secondary PID 714 在 exec 前仍是原生 64 位 init，i7 却根据将来的 Zygote32 ABI exec 了 32 位 tracer，
导致 `process_vm_readv: Bad address` 和 syscall gadget 查找失败。APD 最终释放两个 service，系统启动；
后续真实 32/64 Zygote 没有 `libzygisk.so` maps。该 fail-open 是安全成功，不是功能成功。

另有两个次生缺陷：release 后残留的 debug PID 被重新 stage/release，引发假重启熔断；monitor reason 的
JSON 行带尾逗号。i7/544 至此冻结，不得再通过 sleep、加大 deadline 或重复刷机试错。

### 9.12 i8：原生 pre-exec tracer + post-exec ABI handoff（loader 修复保留，d09 配套已证伪）

i8/545 与 19073/d09 成套。APD stage 请求 d09 的一次性 strict-exec-ptrace flag；目标 self-claim 后，内核
只允许这一 task 的第一次严格 `process:ptrace` 跨域检查，不添加 SELinux 规则，也不让权限继承给应用。
IRezygisk 侧的状态机为：

1. domainless monitor 按设备原生 ABI运行；每个 pre-exec service child 都还是 init ABI，所以 fork 出的
   tracer直接调用同 ABI `trace_zygote_preexec()`，不按未来 ABI 提前 exec 另一个 tracer。
2. pre-exec tracer 读取 init maps、remote self-claim、恢复寄存器并捕获准确 `PTRACE_EVENT_EXEC`。
3. 新 app_process 与 tracer ABI相同则直接等待 linker；不同则在 EXEC 停点排队 SIGSTOP，
   `PTRACE_DETACH(..., SIGSTOP)` 后把同一 tracer 进程 exec 为 `zygisk-ptrace32/64 trace-postexec`。
4. postexec tracer接管已完成 ABI/SID 转换且仍停止的目标，继续 linker/GOT 注入；ticket 已消费，绝不
   二次 claim。任何错误继续 bounded detach/SIGCONT，monitor/APD watchdog 仍作最后释放。
5. 每个 service 记录最近完成 PID，属性残留不再重试，但不同的新 PID仍能处理；state.json 尾逗号已修。

这套逻辑以当前 tracer ABI和 `ro.zygote` 的未来 ABI比较，覆盖单/双 32/64 标准模式，没有 Xiaomi、
Android 11、固定 PID 或固定时间判断。legacy Magisk/KernelSU 后端仍使用上游流程；APatch domainless
安装才删除 live `sepolicy.rule`，ZIP 中保留该文件不代表活动策略加载它。

`common.mk` 已提升到 i8/545，`MIN_APATCH_DOMAINLESS_VERSION=19073`。API 25 arm64-v8a、armeabi-v7a、
x86_64、x86 全部 Release 通过；最终 ZIP 为
`IRezygisk-v1.0.0-i8-545-fcbcbfd-release.zip`，527,057 字节，SHA-256
`C4E306EF0AF7BCD5FDC0E6EC39AEDB7E6421A9676656A893B1AABF46B059718F`，199 entries、99 组 sidecar
复算无误。该结论仍是离线通过；必须在 19073 重新从原厂 boot 修补并刷入 d09、零模块启动成功后，
再只启用 i8 验证双 ABI maps。i7-544 与 APatch 19072 已移入 `ckbsoft/obsolete`，主输出目录只留 i8/19073；
本轮未 commit、未 push。后续 19073/d09 真机已经证明 strict 分支无法匹配实际 AOSP exec 请求，因此
i8/545 不再安装测试；其 tracer/handoff 修复由 i9 继承。

### 9.13 i9：与 d10 exec-transition 协议成套

IRezygisk 本身不负责放行 SELinux。i9/546 的注入状态机与 i8 相同：原生 ABI tracer完成 pre-exec
self-claim 和 EXEC 捕获，异 ABI只在 EXEC 停点交给 `trace-postexec`，并保留 stale PID 去重与合法 JSON。
版本提升的目的，是阻止已经构建的 i8 被装到 19073/d09 上继续试错。

配套内核 d10 不再声称 exec 使用 strict。APatch 19074 在验证 service/PID/PPID/UID/stop state/exe/context/
starttime/ABI 后，请求 stage bit 1；d10 从 live policy 解析 Zygote tsid，将一次预算绑定到 self-claimed
current target，只匹配 flags=0、精确 `process:ptrace` 和该 tsid。普通 token 的 current_sid==ssid 与 strict
拒绝规则不变。IRezygisk 不接触 feature bit 细节，只通过安装器的最低 APatch 19074 阻止旧协议混装。

该历史候选的 `common.mk` 为 i9/546、`MIN_APATCH_DOMAINLESS_VERSION=19074`。API 25 的 arm64-v8a、
armeabi-v7a、x86_64、x86 已 clean Release通过；产物
`IRezygisk-v1.0.0-i9-546-fcbcbfd-release.zip` 为527,045字节，SHA-256
`E9C16F4ED520337D1BFA44B1A7A277F7F7394B87C71E6E7F64C10E3CA8E76BE8`，199 entries、99组 sidecar
复算无误，四 ABI ptracer/zygiskd版本串均为 i9/546。真机只能在
19074+d10 零模块 boot 正常后安装 i9，先验证双 ABI maps，再逐层恢复其他模块与 Hunter。代码、文档仍
未 commit、未 push。

### 9.14 i10：与 d11 OEM exec 顺序兼容协议成套

19074/d10 真机已到达 rendezvous、stage和目标内self-claim，但PID 713仍因
`init -> zygote process:ptrace`以127退出。旧i7已经足以证明这个共用exec边界，故i9不再安装试错。
APD的tracer-failed release和系统替代Zygote启动正常，问题收敛为d10依赖current SID仍处于旧域的顺序假设。

i10/547不修改i9的native pre-exec tracer、EXEC ABI handoff、PID去重或JSON逻辑，只把
`MIN_APATCH_DOMAINLESS_VERSION`提升到19075。配套d11发布bit11、只接受stage bit2/marker2；exec例外
不再依赖current SID相对关系，并只兼容flags=0或精确strict，同时保留current task self-claim、boot nonce、
non-inherit、live Zygote tsid、different tracer ssid、exact process/ptrace和one-shot预算。该门禁确保i10
不会在19074/d10上进入已知失败路径。

本轮i10 Release产物为`IRezygisk-v1.0.0-i10-547-fcbcbfd-release.zip`，527,086字节，SHA-256
`6BD7554BED4F85349DF7FEBD57B58925F5EAF8C4A5F6BEC3A662C0139BC6492A`。ZIP含199 entries，99组
payload/sidecar全部复算一致；arm64-v8a、armeabi-v7a、x86、x86_64的zygiskd/libzygisk/ptracer均存在，
daemon与ptracer均含i10/547版本串，customize门禁为19075。该证据不替代d11真机和双ABI maps验证。

### 9.15 i11：与 d12 claimed-permit 协议成套

19075/d11真机上，PID718已完成APD stage和目标内self-claim，但随后仍发生
`init -> zygote process:ptrace`拒绝。原厂kernel的kallsyms/反汇编确认state9参数、flags=0、process类和
ptrace位全部正确；若task_ext token仍可读，d11 exact path或普通task-auth至少应命中一条。两者同时未命中，
说明继续修改IRezygisk等待时间、ABI handoff或AVC常量都不是正确方向。

i11/548不修改i10的native pre-exec tracer、32/64 EXEC handoff、PID去重、熔断和JSON状态机，只把
`MIN_APATCH_DOMAINLESS_VERSION`提升到19076。配套d12发布bit12、只接受stage bit3；目标self-claim后随机
ticket失效，内核自有claimed permit精确绑定task identity/PID、live Zygote tsid和process:ptrace，一次消费。
因此模块本身继续保持跨arm/arm64/x86/x86_64的同一实现，设备差异由APatch/KernelPatch能力门禁处理。

i11 Release产物为`IRezygisk-v1.0.0-i11-548-fcbcbfd-release.zip`，527,092字节，SHA-256
`0637ED5A9F2D2DB5733BA713B85CE1B3A4BF0AF4EEFF976675F77957FF17980C`。ZIP含199 entries，99组payload/sidecar
SHA-256逐项复算全部一致；四ABI的zygiskd/libzygisk/ptracer完整，八个daemon/ptracer均含i11/548版本串，
module.prop为i11/548，customize门禁为19076。
它必须与19076/d12成套刷入；i10 staged update应由i11覆盖后再重启，避免把已证伪版本继续带入测试。

### 9.16 i11 真机失败边界与 i12：按 linker 事件等待，不按 syscall 次数猜测

2026-08-15 23:50 的持久启动日志确认设备实际运行 APatch/APD 19076 与 KernelPatch d12。i11 对 64 位
PID 718 和 32 位 PID 719 都依次完成 `TASK_STAGED`、目标内 self-claim 和确定的
`PTRACE_EVENT_EXEC`；32 位路径还正确完成了从原生 64 位 tracer 到 `zygisk-ptrace32` 的 ABI handoff。
这证明 d12 claimed permit、APD broker、双 Zygote rendezvous 和跨 ABI 交接均已工作，不能再修改
APatch/KernelPatch 的 SELinux 授权条件。

两个 ABI 随后都停在同一个 IRezygisk 用户态条件：`wait_linker_ready()` 报
`Timed out waiting for __libc_init resolution`。64 位从 EXEC 到退出约 149 ms，32 位约 143 ms；源码中的
`syscall_steps >= 512` 先于 2 秒时间上限耗尽。精确 EXEC rendezvous 本来就位于动态 linker 装载和重定位
依赖之前；不同 Android/OEM linker 在这段路径产生的 syscall 数量不是 ABI 契约，不能作为失败判据。

i12/549 删除 512 次计数门槛，成功条件只保留 `__libc_init` GOT 值真实发生解析变化。为防止异常 linker
卡住，仍保留 3.5 秒单次等待上限，并受外层 4 秒 ptrace deadline、5.5 秒 monitor watchdog 和 APD 6 秒
staged-target watchdog 约束；任一层超时都恢复/分离 tracer、释放 Zygote hold 并继续启动。该实现没有手机
型号、Android 版本、固定 PID、ABI 特判或 sleep，arm/arm64/x86/x86_64 使用同一事件条件。

i12 Release 产物为 `IRezygisk-v1.0.0-i12-549-fcbcbfd-release.zip`，527,029 字节，SHA-256
`0CC8BEFABBD9F961CE4E4D513D5E6780B2A1C5DE0E706F7865C4685853D66557`。ZIP 的 99 组 payload/sidecar
SHA-256 全部复算一致；module.prop 为 i12/549，domainless 最低 APatch 仍为 19076。arm64/arm ptracer
SHA-256 分别为 `4670A454C708C56E316729C43C82CD96130EBC309157985F897C1865B5D70DEC`、
`8085402DEA523D0AA901C8249B3EB60BC39D95CA5D0BA49E107D4E281B44F0B1`。该产物仍需真机确认两个 GOT
解析、注入完成和 Zygote maps；在此之前不启用业务 Zygisk 模块。

### 9.17 i12 真机推进到载荷访问，i13 改为匿名传输并补全失败回滚

i12/549已在19076/d12上真实运行，系统最终`boot_completed=1`。64位PID717完成stage、self-claim、
`PTRACE_EVENT_EXEC`后，于约1.61秒看到`Resolved __libc_init`，证明9.16的事件等待修复有效。随后
`inject_on_main()`让已转换为`u:r:zygote:s0`的目标直接打开
`/data/adb/modules/rezygisk/lib64/libzygisk.so`，内核记录对`adb_data_file:dir search`的AVC拒绝，remote
`openat`返回`-13/EACCES`。这不是再次超时，也不是d12许可失败：d12的一次许可只覆盖exec边界的精确
`process:ptrace`，Android原生策略本就不应让Zygote遍历`/data/adb`。

该失败又暴露两个次生缺陷。第一，GOT陷阱后的错误路径恢复了GOT值，却没有把保存寄存器中的PC从故意的
非法break地址改回真实`__libc_init`；detach后PID717因此SIGSEGV。第二，primary崩溃后init在32位handoff
期间SIGKILL PID718；monitor随后又把替代Zygote当作可重新stage目标，broker正确返回`invalid-release`，
却覆盖了UI中的首个真实失败原因。最终替代PID2068/2069均无libzygisk maps。

i13/550采用同一套跨架构匿名载荷路径：有权限的tracer在自身上下文只读打开ELF，目标只执行匿名
`mmap`；tracer按PT_LOAD把精确文件字节写入目标，保留零填充BSS，在本地完成现有重定位后按ELF flags
`mprotect`。Zygote不再open/mmap`/data/adb`文件，maps也不出现模块路径；不依赖task token跨exec存活，
不增加SELinux规则、机型、Android版本、PID、ABI或sleep特判。Android Zygote原生需要JIT并具有自身
`execmem`能力；未知OEM若仍拒绝最终RX保护，现有多层watchdog会安全退出并保留原生拒绝。

失败恢复同时改为：进入GOT trap后立即把完整备份寄存器PC设回真实`__libc_init`，所有后续错误先恢复
寄存器；匿名映射的解析、重定位、保护或入口解析失败均主动`munmap`；GOT仍重复恢复。每个init
rendezvous service只消费一次，替代Zygote不再向已完成broker重放stage/release，且仅在曾成功注入的
目标后来死亡时才更新“需要重启”状态。

i13四ABI clean Release已通过，产物
`IRezygisk-v1.0.0-i13-550-fcbcbfd-release.zip`为526,908字节，SHA-256
`348BE7F1B1619E12287D4007DC5C7A2B2B5D254C5B3F7EF69C5CA4B5DA6AA7BC`。199 entries、99组sidecar、
四ABI daemon/ptracer版本串全部通过；arm64/arm ptracer SHA-256分别为
`5DDC95D1BCF792ABE036E47B088E871D8C2B9D5A65A338DB66AADB630D59A237`、
`54A33918507E25B5A0A97BE270F793746792A5AF69F3149A0A092A1A79B437FF`。最低domainless APatch仍为19076，
APatch与KernelPatch无需重刷。该结果仍是待真机候选；只允许覆盖i12后单模块重启验证双ABI。

安装后、重启前已只读核对：`modules_update/rezygisk`为i13/550，arm64/arm的ptracer、daemon、libzygisk
六个核心文件SHA-256与最终ZIP逐项一致；IRezygisk无`disable/remove`，Zygisk Assistant与ckbsmart仍有
`disable`。安装器会同步更新活动目录`module.prop`，所以重启前UI显示i13不能证明新二进制已运行；必须以
重启后的进程版本、启动日志和双Zygote状态为准。

### 9.18 i13 真机 FD 崩溃根因与 i14：exec 前建立持久 daemon 通道

i13/550 真机证明匿名 ELF 传输本身已经越过上一轮载荷文件边界，但没有完成整个 IPC 生命周期迁移。
64 位匿名 loader 和入口均已到达，注入库随后仍从已是 `u:r:zygote:s0` 的进程重新连接
`/data/adb/rezygisk/cp64.sock`，再次触发 `zygote -> adb_data_file:dir search` 拒绝。32 位路径能够建立
`DomainlessSession`，却把一个没有可接受本地名称、也没有加入 Android ignore 集合的 Unix socket 留在
Zygote。`tombstone_10`（PID2642）与`tombstone_11`（PID717）均记录 32 位 Zygote 在首个 fork 的
`FileDescriptorTable::Create()` 中 SIGABRT，JNI fatal message 为`(zygote) Unable to get socket name`。
因此 i13 的“anonymous mapped/entry reached”不是功能成功，旧包冻结。

i14/551 把控制通道改成一次完整的 exec-transition handoff：

1. pre-exec tracer 在 init service child 仍可遍历`/data/adb`时，remote 创建 AF_UNIX stream、绑定唯一
   abstract client name，连接对应 cp32/cp64 daemon，发送`DomainlessSession`并确认 ack；FD 不设
   CLOEXEC，随目标 exec 保留。ARM32 remote mmap使用`mmap2`，其余ABI使用`mmap`。
2. 同ABI路径把FD直接作为匿名注入入口第4参数；跨ABI路径通过`--domainless-fd`交给postexec tracer。
   注入库只接管并验证这个已连接stream，不再从Zygote解析或连接任何`/data/adb`路径。入口必须同时完成
   daemon握手与关键PLT hook；任一步失败都关闭FD、卸载匿名映射、恢复GOT/PC/寄存器并fail-open启动。
3. app fork把控制FD追加到已有`fds_to_ignore`；system_server与USAP的ignore集合在native内部构造，无法
   从JNI扩展，所以只在libandroid_runtime扫描当前进程`/proc/self/fd`时精确隐藏这一个数字FD。该hook
   不隐藏其他目录、其他进程或其他FD；fork child完成可信pre/post回调后立即关闭通道。若关键`fork`或
   `readdir` hook不可用，domainless注入在Android执行前整体回滚，避免再次制造Zygote fatal。
4. monitor不再只用`kill(pid, 0)`判断成功；它同时拒绝`/proc/PID/stat`中的Z/X状态，并要求PID仍等于
   对应`init.svc_debug_pid.*`属性，防止僵尸或已被替换PID显示假绿色。

Android的FD检查会枚举`/proc/self/fd`并拒绝未列入ignore的异常socket；system_server/USAP又各自在
native层建立ignore集合，这正是不能只修app JNI参数的原因。实现依据AOSP公开机制，不含MI9、Android11、
固定PID/SID、地址、FD号或延时白名单；APatch最低版本仍为19076，KernelPatch仍为d12，legacy
Magisk/KernelSU路径不要求继承FD。

构建系统也补上发布门禁：loader/zygiskd四ABI循环启用fail-fast，任一子make失败立即使总构建失败；
对象版本stamp继续阻止旧对象混入。i14已完成四ABIclean Release，最终ZIP
`IRezygisk-v1.0.0-i14-551-fcbcbfd-release.zip`为538,931字节，SHA-256
`CEDA0949AD9DDA88B74581289B38B5D697C293B3AED4E3433300326550BCF127`。199 entries、99组sidecar
逐项复算一致，12个核心ELF的class/machine与arm64、arm32、x86_64、x86目录一致，版本载体均为i14，
无i13/550残留。该结论是完整离线候选，不冒充真机通过；首次只覆盖IRezygisk并保持其他Zygisk模块
禁用，重启后必须同时验证双ABI preexec-session/adopted/injected/maps、Zygote存活与boot_completed。

### 9.19 i14 真机 socket 标签边界与 i15 SCM_RIGHTS 替换通道

i14/551 于 2026-08-16 09:43 的真机日志证明 64 位 PID715 与 32 位 PID716 均完成目标 self-claim、
pre-exec daemon session、`PTRACE_EVENT_EXEC`、`__libc_init`解析和匿名ELF映射。两个目标随后分别出现：

```text
zygote -> init:unix_stream_socket { read write } denied
inherited APatch domainless fd is not a connected stream socket
injector entry rejected daemon session
```

这说明“已连接FD跨exec”只消除了`/data/adb`路径遍历，不能改变socket对象在创建时确定的SELinux标签。
客户端在init service child内由`socket()`创建，因此对象仍标为`u:r:init:s0`；exec后的Zygote即使已经
持有FD，也不能对该对象执行read/write。i14按设计fail-open，系统完成启动，当前双Zygote存活且本boot
没有新增Zygote tombstone，但注入状态为0。

i15/552保留i14全部FD sanitizer和失败回滚，只替换会跨exec的端点：zygiskd本来就在创建监听socket前
把thread sockcreate context设置为`u:r:zygote:s0`。`DomainlessSession` handler现在在该上下文创建
专用`socketpair`，通过旧pre-exec连接用`SCM_RIGHTS`发送一端；目标仍在init域时用remote `recvmsg()`
收取新FD、关闭旧init标签连接，再读取新通道ack并进入exec。跨ABI handoff得到的是Zygote标签端点，
不需要live policy、KernelPatch新增许可、路径重连或机型特判。

四ABI clean Release与最终审计已通过：
`IRezygisk-v1.0.0-i15-552-fcbcbfd-release.zip`为540,770字节，SHA-256
`E2BD699C1AC8ED5BEC3549C6B28739E852055F7660B296F3B67D406F9411AB9C`；199 entries、99组sidecar零
mismatch，12个核心ELF class/machine正确，包内无i14/551残留。该结果仍是待真机候选。

### 9.20 i15 真机通过与 ckbsmart 分层结果

i15/552 真机已经同时满足双 ABI daemon session adopted、injection completed、匿名 maps 与
`state.json` Zygote64/32=`1`。继承控制 FD 的对象标签为 `u:r:zygote:s0`，i14 的
`zygote -> init:unix_stream_socket` AVC 消失；两个 Zygote 与 system_server 稳定，系统完成启动且无新增
目标 tombstone。i15 不再是“待真机候选”，而是当前通过的 IRezygisk 基线。

启用 ckbsmart v0.101.17/5484 后，IRezygisk 四项状态仍为 `1`，但模块自身出现两个独立失败：arm64
`arm64-v8a.so` 被 `zygisk-core64` 报告加载失败，现场只有 32 位 companion；`lspd` 以
`u:r:zygote:s0` 启动后又被拒绝对 `serial_service:service_manager` 执行 `{ find add }`，随后
`ServiceManager.addService()` 抛出 `SecurityException` 并退出。这证明 module enumeration、32 位
companion 或绿色框架状态都不能替代业务模块验收。

后续不得为单个模块恢复固定 Magisk 域或把一次性 Zygote permit 扩张成长期插件权限。标准 Zygisk API
问题归 IRezygisk 通用层；自有 Java daemon、Binder 服务、`sepolicy.rule`、脚本与业务结果归插件自身。
完整门禁见 `APatch/docs/APatch_定制插件兼容性注意事项_2026-08-16.md` 与工作区交接 102。

### 9.21 i15 的 CkbSmartN arm64 第二层边界与 i16 通用 linker 回退

CkbSmartN 先用 `--as-needed` 去掉未使用的 `libmediandk/libandroid`，把 arm64 `DT_NEEDED` 收敛为
`liblog/libdl/libc`，并使用 Android packed relocations。该 SO 在独立 CSOLoader 中可加载，但刷入后的
i15 真实 app-specialize child 仍快速报告 `Failed to load module`；arm32 同时正常。系统、双 Zygote、
system_server、`rezygiskd` 和专属 `ckbsmart_daemon` 均稳定，无 RescueParty 或目标崩溃。这说明第一层
依赖超限已修，但 CSOLoader 与 Android linker 对大型 C++ 模块图仍存在通用语义差异。

诊断显示 arm64 SO 有 118 个全局构造，原生加载约执行 17,742 次 `mprotect`。不能用固定 sleep、模块名
白名单或每个插件一套 shim 解决。i16 保持 CSOLoader 为主路径，仅在它返回失败时进入通用回退：

1. zygiskd 已在受信上下文预先打开每个模块 SO；`ReadModules` 现在为每个路径追加一个 SCM_RIGHTS FD；
2. child 使用 `android_dlopen_ext(path, RTLD_NOW|RTLD_LOCAL, extinfo)`，extinfo 只启用
   `ANDROID_DLEXT_USE_LIBRARY_FD|ANDROID_DLEXT_FORCE_LOAD`，不让 Zygote 重新遍历 `/data/adb`；
3. 成功回退后用 handle 解析标准两个入口。模块可能在构造阶段把自身从 Android solist 隐藏，所以
   ReZygisk 把 `DLCLOSE_MODULE_LIBRARY` 视为逻辑提示并保留映射，避免对失效 handle 调用 `dlclose`；
4. CSOLoader Release 保留 WARN/ERROR/FATAL 日志，正常成功路径仍不输出 DEBUG/INFO，后续可以直接看到
   主路径失败点和回退是否生效。

i16/553 四 ABI Release 编译成功。最终包
`build/out/IRezygisk-v1.0.0-i16-553-fcbcbfd-release.zip` 为 599,952 字节，SHA-256
`F3EB2E141698B6A3B9F12BEB0A9E9AFDE4433655C4349C504B1BB47FF934633F`；232 个 ZIP entries（含目录），
99 组 payload/sidecar 全部匹配。配套 CkbSmartN 正式直载包没有 shim/payload，大小 4,199,196 字节，
SHA-256 `C8C3093F639C6FC862DBBD1DC843B7BE81BD424200324EA886D30C943A104792`。其 arm64 SO 在真机诊断进程
用完全相同的 FD + `android_dlopen_ext` 路径 0.333 秒加载成功，`zygisk_module_entry` 与
`zygisk_companion_entry` 均非空。该证据仍不替代 i16 重启后的 app/system_server 回调、Bridge、AVC 与
tombstone 验收。

### 9.22 i16 真机排除结果与下一版 fallback 卸载契约

i16 与 Zygisk Assistant、CkbSmartN 同时启用后，`com.zhenxi.hunter` 已在 APatch Manager 中设置
`exclude=1`。Hunter 主进程、app zygote、twin 和 isolated service 的 `mountinfo` 均不再包含模块目录或
ART APEX 的 dex2oat bind mount，证明 package_config、namespace 分离及 Assistant companion 清理链
有效。但四个进程的 VMA 仍同时保留 Assistant 和 CkbSmartN arm64 SO 的文件 backing，Hunter 因而报告
`Mem Find Mark`。

加载日志给出了共同条件：两个模块都先被 CSOLoader 拒绝，再由 i16 的
`android_dlopen_ext(..., ANDROID_DLEXT_USE_LIBRARY_FD|ANDROID_DLEXT_FORCE_LOAD)` 回退加载。9.21 为规避
可能失效的 handle，把 `DLCLOSE_MODULE_LIBRARY` 降级成了逻辑提示；真机结果证明该设计只能保证稳定
加载，不能履行标准 Zygisk 的 child 侧卸载契约。APatch 排除与 solist 清理不会消除内核 VMA backing。

下一版采用下列通用约束：

1. 只有模块明确设置 `DLCLOSE_MODULE_LIBRARY` 才进入真实卸载；
2. 必须等对应 post 回调完整返回后才调用 `dlclose()`，避免仍在模块栈内卸载；
3. 检查 `dlclose()` 返回值，成功后清空 handle；失败时记录模块和 linker 错误并保持可诊断状态；
4. 不按包名、模块名、PID、ABI 或 Hunter 写分支；主 CSOLoader 路径保持原有行为；
5. 完整重启后同时验证目标进程稳定、module callbacks、companion、mountinfo、maps/map_files 与 tombstone。

同轮 core 还出现过打开 `/proc/<zygiskd>/fd/<mount-ns-fd>` 的 EACCES；Assistant companion 随后补救成功。
这说明 namespace 清理的最终效果已达成，但 core 的 namespace FD 交付仍需单独修复/验证，不能用最终
mountinfo 干净倒推所有中间路径都成功。

SELinux 检测页面同时给出 `decision=CLEAN`、`product=NONE`，但列出 `SYSTEM_SERVER_EXECMEM` 等启发式
风险码。该策略来自 CkbSmartN/LSPlant 的真实功能前提，属于系统全局 policy；ReZygisk/Assistant 的应用
排除无法隐藏，且禁止通过伪造 SELinuxFS 或修改检测器处理。

i17/554 已实现上述契约：`UpdateMountNamespace` 响应改成“状态字节 + SCM_RIGHTS namespace FD”，child
直接对收到的 FD 执行 `setns()`；fallback 模块的 post 回调返回后，显式 opt-in 才执行 `dlclose()`，并把
真实结果写入 Release 可见日志。无入口点的 fallback handle 也会立即关闭，不再遗留无用映射。实现没有
模块名、应用名、PID 或 ABI 特判。

四 ABI Release 构建成功；最终本地提交后必须重新构建
`build/out/IRezygisk-v1.0.0-i17-554-<commit>-release.zip`，避免包内版本仍指向修改前提交。ZIP 的 232 个
entries 和 99 组 payload/sidecar 是发布门禁；最终文件名、大小与 SHA-256 统一记录在工作区交接 102，
不在本仓库提交内形成“包哈希依赖提交、提交又依赖包哈希”的循环。当前设备未连接，本节结论仅到
“构建候选”；完整重启前不得把 namespace EACCES 消失或 Hunter VMA 清零写成已通过。

### 9.23 i17 与 CkbSmartN 并发启动暴露的 Monitor 数据报协议缺陷

i17 单独启用时系统正常启动，Monitor、64 位和 32 位状态均为绿色；恢复 CkbSmartN、继续保持 Zygisk
Assistant 禁用后，系统仍完成启动、双 `zygiskd` 和 `lspd` 也实际存活，但状态页把两个 daemon 都显示为
`not running`。同一时刻 `zygisk-ptrace64 monitor-domainless` 持续输出：

```text
Got EAGAIN while reading from fd 4, retrying...
```

真机日志尾部 2000 行中有 916 行该警告。Assistant 在本轮差分中始终禁用，因此它不是这个故障的触发
代码；CkbSmartN 只是增加了上报的模块字段，使原有竞态稳定暴露。

根因是 Monitor 使用非阻塞 `SOCK_DGRAM`，但 i17 的 64 位和 32 位 daemon 各自把一条状态消息拆成多个
独立 `sendto()`：命令、root 长度、root 字符串、模块数以及每个模块的长度和名称。两个 daemon 并发启动
时，这些数据报可以在接收队列中交错。接收端读取命令后又用面向字节流的 `read_loop()` 继续拼字段，
不仅可能把另一 ABI 的字段当成本消息，还会在队列暂时为空时无限重试 `EAGAIN`。`SOCK_DGRAM` 的消息
边界不能按 `SOCK_STREAM` 方式解析，这是通用协议错误，不是某个插件需要特殊分支。

i18/555 把 daemon info 和 error info 分别编码为单个原子数据报；Monitor 先用
`recvmsg(MSG_PEEK|MSG_TRUNC|MSG_DONTWAIT)` 获取一条完整数据报长度，再一次性接收并在内存中做有界解析。
消息最大 128 KiB，字符串最大 `PATH_MAX`，模块数最大 4096；短包、超长包、尾随字节和分配失败都
fail-closed 丢弃，不再进入 `read_loop()`。新环境信息全部解析成功后才原子替换旧状态，发送函数也返回
真实 `sendto()` 结果。四 ABI Release 编译已经通过；真机刷入并完整重启前，i18 仍只能标记为构建候选。

当前 i17 设备虽然 `sys.boot_completed=1` 且 ADB 可用，但仍在产生 EAGAIN 日志洪泛，不应作为长期运行
基线。ADB 序列号显示 `unknown` 来自 CkbSmartN 的属性隐藏行为，不等于 ADB 断连。验证顺序必须是：
先用 i18 + CkbSmartN、保持 Assistant 禁用完成冷启动和状态验收；确认日志洪泛消失、双 daemon 变绿后，
再单独恢复 Assistant 做第二次重启和 Hunter 排除复验。

### 9.24 i18 + CkbSmartN 真机通过

用户仅覆盖安装 i18，保持 CkbSmartN 启用、Zygisk Assistant 禁用后完成完整重启。真机 boot ID 为
`4ca4f465-5fe6-4518-bb48-3ba318367a56`；启动约 5 分钟后的证据为：

- `sys.boot_completed=1`，SELinux Enforcing；活动 `module.prop` 为
  `v1.0.0-i18 (555-7519396-release)`；
- `state.json` 中 daemon64/32 与 Zygote64/32 全部为 1，两个 ABI 的模块列表都只包含
  `zygisk_ckbsmart`；Assistant 的 `disable` 文件存在；
- Zygote64/32 PID 715/716、Monitor PID 797、zygiskd64/32 PID 799/800、system_server PID 2157、
  `lspd` PID 1374 均持续存活；CkbSmartN 双 ABI companion 已建立；
- 本次启动全量 logcat 中 `Got EAGAIN while reading`、非法/短 Monitor packet 和发送失败全部为 0；
  稳定期再次检查最近 4000 行仍全部为 0；
- 5 秒 `/proc/<pid>/stat` 采样中 Monitor 仅增加 3 个 CPU tick、logd 仅增加 2 个，i17 忙循环和日志
  洪泛已经消失；
- `serial` Binder 服务存在；多个 64 位 app child 均记录 fallback 模块真实卸载成功。

crash buffer 中的非 PID 1 `init` 子进程 SIGABRT 是同机 MIUI 成功/失败启动都会出现的已知基线噪声，
APatch 台账 SV2-085 已有禁用 IRezygisk 的对照；本轮不能据此否定稳定状态。ADB 仍以 `unknown` 为序列号，
但 transport 为 `device` 且命令正常，这是 CkbSmartN 属性隐藏结果。

因此 i18 的 Monitor 原子数据报修复以及 i17 的 namespace/unload 改造在 **IRezygisk + CkbSmartN** 组合上
完成真机验收。该结论不包含 Assistant；下一步只能单独启用 Assistant 后再完整重启，复验双 ABI 状态、
EAGAIN、Hunter mountinfo/maps 和目标崩溃，禁止同时改变其他模块。

### 9.25 三模块复验暴露缺失 debug PID 的假重启与 i19 修复

恢复 Zygisk Assistant 后完成完整重启，boot ID 为
`68bb9a4f-aded-4fb7-85e2-5d77d6d549c8`。IRezygisk i18、Zygisk Assistant
`v2.1.5-apatch1 (5ec463e-release)` 和 CkbSmartN `v0.101.17 (5484)` 均启用；
`sys.boot_completed=1`、SELinux Enforcing，`state.json` 的 daemon64/32 与 Zygote64/32 全部为 1，两个
ABI 的模块列表都同时包含 `zygisk-assistant` 和 `zygisk_ckbsmart`。全量日志中 Monitor EAGAIN、非法/短
数据报、daemon 发送失败以及 namespace FD 接收/切换错误均为 0，说明 Assistant 没有重新触发 i17/i18
已修复的两类协议问题。

模块卡片仍出现 `Injected Zygote restarted ... reboot required`，但这次不是 Zygote 真重启。64/32 位
Zygote PID 716/717 从启动后持续存活，`init.svc.zygote` 与 `init.svc.zygote_secondary` 均为 `running`；
与此同时，本机两个 `init.svc_debug_pid.*` 属性始终为空。i18 的
`domainless_target_is_current_and_live()` 在 `/proc/<pid>/stat` 已确认目标存活后，仍要求至少一个同 ABI
debug PID 属性精确等于目标 PID；属性缺失会直接返回 false，清掉一次性 target 并写入永久警告。稍后到达
的 `ZYGOTE*_INJECTED` 数据报又把绿色状态恢复为 1，于是形成“状态全绿但仍显示重启警告”的矛盾。

i19/556 按可证明证据修复这一通用状态机：

1. `/proc/<pid>/stat` 不存在或处于 zombie/dead 状态时仍判定目标已丢失；
2. OEM 发布有效正数 debug PID 时仍将其视为权威 generation；若它与记忆 PID 不同，则判定已替换；
3. 属性为空、暂未发布、非数字或非正数时不再作为重启证据，继续使用已确认的 `/proc` 存活结果；
4. 不按 Assistant、CkbSmartN、机型、固定 PID 或延时特判，真实 Zygote 死亡及明确新 PID 的检测语义不变。

源码提交为 `3694e3c`。本节当前只能确认 i18 三模块运行面正常并定位 UI/target bookkeeping 缺陷；i19
完成四 ABI Release 与包审计后仍需覆盖刷入、完整重启，确认警告不再产生且三模块状态保持全绿，才能把
i19 标记为真机通过。

## 9.26 i20：标准模块加载与回调的顶层授权窗口

i19 只修正缺失 `init.svc_debug_pid.*` 时的状态误报；它不解决 CkbSmartN 为 LSPlant/Dobby 写入全局
`system_server execmem` 后产生的策略检测。i20/557 与 APatch 19081、KernelPatch d13 成套引入通用
task-local 窗口，不按模块名或 hook 引擎定制。

domainless Zygote 注入成功后，loader 用 0x1126 把 d13 已消费的 exec marker 激活为 non-authorizing
carrier。`hook_unloader()` 在模块 DSO 重定位和构造函数前 begin、结束后 end 并恢复 carrier。Zygote
child 的 `rz_run_modules_pre/post()` 各使用一次私有预算；pre 结束恢复，post 结束永久撤销。任一 begin
失败就跳过模块代码；已打开的 FULL 窗口若无法 end，进程 `_exit(127)`，不能带权限继续进入应用代码。

Magisk/KernelSU 及非 domainless 路径的 helper 为 no-op，保持现有行为。d13 feature bit 或 APatch
版本不匹配时，APD/IRezygisk 门禁拒绝 provider，不允许把 19076/d12 与 i20 静默混装。当前四 ABI loader
Release 已编译通过，但最终包必须在 i20 源码 commit 后 clean rebuild，并完成目标机冷启动后才能写真机
通过。

## 9.27 i21：module.prop 状态重写必须有界且幂等

19090 失败启动时出现的新 tombstone 与 APatch V7 是两条独立问题。`zygisk-ptrace64` 以 SIGABRT 退出，
FORTIFY 明确报告 `strcat` 写过 0 字节剩余缓冲区；活动 `module.prop` 的 description 前已经累积 12 个
`[Injected Zygote restarted ...]` 前缀。旧 Monitor 每次启动把新状态追加到旧 description，又用两个
1024 字节静态 section 和无界 `strcat` 重建文件，因此重复启动最终必然越界，并由安装器/健康检查创建
`disable`，表现为 IRezygisk 突然不工作。

i21/558 只修 IRezygisk 自己的状态文件实现，不承担 Assistant 或 CkbSmartN 兼容：

1. 用 `getline` 读取完整 `module.prop` 行，避免 1024 字节行缓冲截断；
2. 解析 description 时移除已有的 Monitor 状态前缀，新状态采用替换而不是累加；
3. 每次准备环境先清空 section，所有拼接统一检查剩余容量，超限记录错误并安全退出；
4. description 缺失时拒绝覆盖原文件，不用半截内容继续运行；
5. 新增 4 项回归契约，覆盖幂等替换、动态整行读取、全部有界拼接和版本单调性。

四 ABI Release 已完成编译与链接。最终 ZIP 必须从包含本节和源码修复的提交 clean rebuild；真机验收需
确认 `disable` 不再产生、description 始终只有一个状态前缀、无新增 `zygisk-ptrace` tombstone，并与
APatch 19091/d20 的通用脚本 V7 分开判定。

## 9.28 i21 最终真机验收与未来模块边界

i21/558/`ba2e29b` 已先在 APatch 19092/d20 的单模块启动中完成真机验收：Monitor、64/32 位 daemon 与
Zygote 状态全绿，`description` 中 `Monitor:` 只有一个，旧重启前缀为 0，未产生新的
`zygisk-ptrace` tombstone。之后升级到最终 APatch 19096/d23，并逐个恢复 CkbSmartN 0.101.20 和
Assistant 2.1.5-apatch1；最终 boot 的两个 ABI 模块清单都同时包含 `zygisk_ckbsmart` 与
`zygisk-assistant`，没有 Monitor EAGAIN、状态越界、目标 AVC 或新 tombstone。

当前正式 IRezygisk 包为：

```text
IRezygisk-v1.0.0-i21-558-ba2e29b-release.zip
size   = 615,554 bytes
sha256 = B5F70E43CAE407412A40AF9CA6128731A4C4FF42960BC93C024857B2CD4442C8
```

这里的 IRezygisk 改造是通用 loader/runtime 适配，不是 CkbSmartN 或 Assistant 名称特判。以后符合标准
Zygisk API 的模块默认不需要修改；只有模块依赖固定 Magisk domain、提交 live policy、启动长期特权
daemon/系统 Binder 服务，或绕过标准 module/companion 生命周期时，才需要模块侧声明并适配自己的
额外能力。统一判断矩阵见工作区
`docs/工程项目总览/103_APatch_模块兼容责任边界与接入矩阵_2026-08-17.md`。
