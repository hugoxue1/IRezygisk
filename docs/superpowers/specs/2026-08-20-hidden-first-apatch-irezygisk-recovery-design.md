# Hidden-first APatch/IRezygisk recovery design

## Objective

Restore the last proven no-live-policy IRezygisk compatibility boundary while
keeping the Vendor private preload path isolated and functional. Hiding takes
priority over Vendor convenience; generic Zygisk module behavior must never be
changed to satisfy a Vendor HAL.

## Proven history

- IRezygisk i15 completed dual-ABI injection without adding live SELinux
  policy.
- i18 completed an IRezygisk + CkbSmartN boot, and the following three-module
  run enumerated both CkbSmartN and Assistant on both ABIs.
- Vendor fixes are confined to APatch's private service broker/origin-10 path.
  They do not require the later early-loader shell or permissive-domain work.
- The APatch commits after `931c7ef` changed the generic early-loader in four
  rounds (`8e64b6a`, `38631d0`, `33f69ae`, `34a6b95`). The final round added a
  visible permissive `apatch_early_loader` SELinux domain.

## Architecture

### APatch

Restore only the generic early-loader launch path to the `931c7ef` behavior:
the already validated provider is executed directly by the init-owned broker,
with the private connected FD and no live-policy domain creation. Remove the
shell connector command and the dedicated permissive-domain profile changes.

Do not revert or modify the private service broker, linked staging, Vendor HAL
path validation, protocol 4/15, KernelPatch, or Vendor module sources. Vendor
continues to require exact MODULE_SCRIPT origin 10; the generic early-loader
does not gain that origin.

### IRezygisk

Keep the current i22/i23 ELF-entry rendezvous, cross-ABI stop draining, socket
identity guard, anonymous payload mapping, companion protocol, module ABI and
FD hiding. Do not restore the i21 cleanup bug that could close a linker-reused
descriptor.

Immediately after the target receives the zygote-labelled session endpoint by
SCM_RIGHTS, remotely read `F_GETFD`, clear `FD_CLOEXEC` with `F_SETFD` when
present, and re-read the flags. Any syscall failure or surviving CLOEXEC bit is
a mandatory pre-exec channel failure. This makes the intended i15 cross-exec
contract explicit without introducing a persistent named socket or live
policy. Existing identity checks remain the final fail-safe against descriptor
reuse.

## Hidden and compatibility invariants

- No new SELinux type, permissive domain, allow rule or module `sepolicy.rule`.
- No fixed or long-lived abstract socket name.
- Persistent DomainlessSession remains the anonymous zygote-labelled
  socketpair endpoint.
- Existing daemon actions 0 through 9 and their wire framing do not change.
- Standard Zygisk module ABI v1-v5, callback order, `connectCompanion()`,
  module ordering and companion ownership do not change.
- Existing anonymous ELF load, `/proc/self/fd` filtering and `fds_to_ignore`
  behavior do not change.
- CkbSmartN and Assistant sources are not modified.
- APatch service broker, KernelPatch and Vendor production sources are not
  modified by the IRezygisk repair.
- Failures remain fail-open for Android boot: restore the target and release
  the staged rendezvous; never restart Zygote to claim success.

## Delivery boundary

The user owns runtime testing. This task performs code edits, independent
read-only review and release builds only; it does not run unit, integration,
device-runtime or full verifier suites. Build success is not reported as
runtime success.

