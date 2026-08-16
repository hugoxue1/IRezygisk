#include "daemon.h"
#include "logging.h"
#include "misc.h"

#include "hook.h"
#include "ptrace_clear.h"

__attribute__((visibility("default")))
int entry(void *addr, size_t size, int tango_flag, int inherited_domainless_fd) {
  LOGD("ReZygisk%s library injected, version %s", tango_flag ? " [TANGO]" : "", ZKSU_VERSION);

  start_addr = addr;
  block_size = size;

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    LOGD("Supported kernel version %d.%d.%d, sending seccomp event", version.major, version.minor, version.patch);

    perform_ptrace_message_clear();
  }

  if (!rezygiskd_init_domainless_session(inherited_domainless_fd) ||
      !rezygiskd_zygote_injected()) {
    LOGE("ReZygiskd is not running");

    rezygiskd_release_domainless_session_in_child();
    return 0;
  }

  /* Do not install Zygote hooks until daemon IPC is known-good.  A failed
     channel must leave the booting process functionally untouched. */
  LOGD("start plt hooking");
  if (!hook_functions(inherited_domainless_fd >= 0)) {
    LOGE("mandatory Zygote PLT hooks are unavailable");
    rezygiskd_release_domainless_session_in_child();
    return 0;
  }

  LOGD("Zygisk library execution done, addr: %p, size: %zu", addr, size);
  return 1;
}
