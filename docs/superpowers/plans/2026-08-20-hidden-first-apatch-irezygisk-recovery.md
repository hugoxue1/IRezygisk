# Hidden-first APatch/IRezygisk Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the no-live-policy generic early-loader and make the existing IRezygisk session FD explicitly inheritable across target exec without changing Vendor or Zygisk module interfaces.

**Architecture:** APatch restores only its early-loader files to the pre-shell, pre-permissive-domain boundary while retaining the independent Vendor service broker. IRezygisk retains i22/i23 and adds a bounded remote `fcntl` verification immediately after SCM_RIGHTS receipt.

**Tech Stack:** Rust/Android APD, C/Android ptrace and AF_UNIX, Gradle/NDK release builds.

**Spec:** `docs/superpowers/specs/2026-08-20-hidden-first-apatch-irezygisk-recovery-design.md`

## Global Constraints

- Hiding is the first priority; no live permissive domain or new policy rule.
- Vendor remains isolated behind exact MODULE_SCRIPT origin 10.
- Do not modify KernelPatch, Vendor, CkbSmartN or Assistant production files.
- Do not change Zygisk module ABI, daemon actions 0-9, companion protocol or FD hiding.
- Do not run tests or device validation; the user owns runtime testing.
- Build artifacts after code review, but never describe build success as runtime success.

---

### Task 1: Restore APatch generic early-loader boundary

**Files:**
- Modify: `E:/ckb_workspace/.worktrees/apatch-service-preload/APatch/apd/src/early_loader.rs`
- Modify: `E:/ckb_workspace/.worktrees/apatch-service-preload/APatch/apd/src/cli.rs`
- Modify: `E:/ckb_workspace/.worktrees/apatch-service-preload/APatch/apd/src/policy_profile.rs`
- Modify: `E:/ckb_workspace/.worktrees/apatch-service-preload/APatch/docs/IRezygisk_APatch_domainless协同改造方案_2026-08-14.md`

**Interfaces:**
- Consumes: exact early-loader implementation at APatch commit `931c7ef`.
- Produces: validated provider launched directly by the init-owned broker with only `APATCH_EARLY_LOADER_FD`; no connector command and no dedicated permissive SELinux type.

- [ ] Restore the three production files' early-loader-specific content to the `931c7ef` boundary using an `apply_patch` generated from Git objects.
- [ ] Preserve all `service_broker.rs`, linked-staging, Vendor and module-script changes.
- [ ] Add a superseding documentation note explaining that the shell/permissive-domain rounds were withdrawn for hidden-first compatibility.
- [ ] Perform read-only diff review only; do not run tests.
- [ ] Commit the AP-only change.

### Task 2: Make the IRezygisk session endpoint explicitly inheritable

**Files:**
- Modify: `loader/src/ptracer/ptracer.c`
- Modify: `common.mk`
- Modify: `docs/APatch_Domainless_协同改造说明_2026-08-14.md`
- Modify: `docs/README.md`

**Interfaces:**
- Consumes: `remote_recv_fd()` result and existing `remote_syscall()` gadget.
- Produces: `remote_make_fd_inheritable(pid, regs, gadget, fd) -> bool`, which requires successful `F_GETFD`, clears `FD_CLOEXEC` if present, re-reads, and rejects any surviving bit.

- [ ] Add the bounded remote `fcntl` helper and call it immediately after SCM_RIGHTS receipt, before the old transport is closed.
- [ ] Keep i22/i23 ELF-entry, identity and cross-ABI code unchanged.
- [ ] Advance the module version monotonically and document the hidden-first recovery; label old cross-exec assumptions as historical rather than deleting them.
- [ ] Perform read-only diff review only; do not run tests.
- [ ] Commit the IRezygisk-only change.

### Task 3: Independent scope review and developer builds

**Files:**
- No source edits unless review identifies a direct violation of the spec.

**Interfaces:**
- Consumes: Task 1 and Task 2 commits.
- Produces: one APatch release APK and one IRezygisk release ZIP for user-owned runtime testing.

- [ ] Review that AP production diff excludes `service_broker.rs`, KernelPatch and Vendor.
- [ ] Review that IRezygisk diff excludes module ABI, companion, hook and module enumeration code.
- [ ] Build APatch release without running tests or verifier suites.
- [ ] Build IRezygisk release without running tests.
- [ ] Record version, size, SHA-256 and signing continuity; state explicitly that runtime is unverified.

