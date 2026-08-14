# IRezygisk 定制文档索引

本目录记录 `hugoxue1/IRezygisk` 相对上游
[`PerformanC/ReZygisk`](https://github.com/PerformanC/ReZygisk) 的全部定制。任何影响注入时序、APatch
接口、SELinux、模块包格式或上游同步的修改，都必须先更新这里，不能只保存在提交信息或聊天记录中。

当前文档：

- [`APatch_Domainless_协同改造说明_2026-08-14.md`](./APatch_Domainless_协同改造说明_2026-08-14.md)：
  APatch minimal-v1、early-loader-v1、直接 Zygote 注入、无 live-policy 模块模式、回退和真机门禁。

当前定制代号为 `v1.0.0-i2`，配套最低版本 APatch 19067。`i1` 首次真机启动暴露了 early-loader
环境契约和 `SIGCHLD` 排空问题；`i2` 已完成源码修复和四 ABI clean Release，真机复验状态以协同改造
说明末尾为准。完成分层真机回归前，它仍是测试候选，不是稳定发布。

仓库角色：

- `upstream`：官方 ReZygisk，只用于抓取和对照；
- `origin`：`git@github.com:hugoxue1/IRezygisk.git`，保存可复刻的定制提交；
- APatch 配套实现与版本矩阵以 `E:/ckb_workspace/APatch/docs` 中的协同方案为准。

未通过 APatch/ReZygisk 双仓构建、无模块基线、ReZygisk 单模块、ckbsmart、Assistant 和 Hunter
分层回归前，不得把实验实现描述成稳定发布。
