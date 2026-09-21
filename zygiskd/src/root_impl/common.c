#include "common.h"

#include <unistd.h> /* sleep */

#include "../utils.h"
#include "apatch.h"
#include "kernelsu.h"
#include "magisk.h"

static struct root_impl impl;

void root_impls_setup(void) {
  struct root_impl_state state_ksu;
  struct root_impl_state state_apatch;
  struct root_impl_state state_magisk;

  /* [CKB-MOD] Transient-detection retry: the manager swaps /data/adb/apd
     during early boot and PATH/bin links may not be fully assembled when
     the monitor launches us. A single-shot detection at that moment
     misreads APatch as Inexistent/Abnormal, the daemon exits with
     "Unknown root implementation", and the module stays unavailable
     until the next zygote restart (observed in the field as intermittent
     "IRezygisk unavailable" + CRC exposure windows). Retry with backoff
     while nothing is Supported before concluding None. */
  int attempt = 0;
  for (;;) {
    ksu_get_existence(&state_ksu);
    apatch_get_existence(&state_apatch);
    magisk_get_existence(&state_magisk);

    int supported = (state_ksu.state == Supported ? 1 : 0) +
                    (state_apatch.state == Supported ? 1 : 0) +
                    (state_magisk.state == Supported ? 1 : 0);

    if (supported >= 1 || attempt >= 10) break;

    attempt++;

    LOGW("Root implementation detection inconclusive (attempt %d/10), retrying in 1s", attempt);

    sleep(1);
  }

  /* INFO: Check if it's only one supported, if not, it's multile and that's bad.
            Remember that true here is equal to the integer 1. */
  if ((state_ksu.state == Supported ? 1 : 0) + (state_apatch.state == Supported ? 1 : 0) + (state_magisk.state == Supported ? 1 : 0) >= 2) {
    impl.impl = Multiple;
  } else if (state_ksu.state == Supported) {
    impl.impl = KernelSU;
    impl.variant = state_ksu.variant;
  } else if (state_apatch.state == Supported) {
    impl.impl = APatch;
  } else if (state_magisk.state == Supported) {
    impl.impl = Magisk;
    impl.variant = state_magisk.variant;
  } else {
    impl.impl = None;
  }

  switch (impl.impl) {
    case None: {
      LOGI("No root implementation found.\n");

      break;
    }
    case Multiple: {
      LOGI("Multiple root implementations found.\n");

      break;
    }
    case KernelSU: {
      LOGI("KernelSU root implementation found.\n");

      break;
    }
    case APatch: {
      LOGI("APatch root implementation found.\n");

      break;
    }
    case Magisk: {
      LOGI("Magisk root implementation found.\n");

      break;
    }
  }
}

void get_impl(struct root_impl *uimpl) {
  *uimpl = impl;
}

bool uid_granted_root(uid_t uid) {
  switch (impl.impl) {
    case KernelSU: {
      return ksu_uid_granted_root(uid);
    }
    case APatch: {
      return apatch_uid_granted_root(uid);
    }
    case Magisk: {
      return magisk_uid_granted_root(uid);
    }
    default: {
      return false;
    }
  }
}

bool uid_should_umount(uid_t uid, const char *const process) {
  switch (impl.impl) {
    case KernelSU: {
      return ksu_uid_should_umount(uid);
    }
    case APatch: {
      return apatch_uid_should_umount(uid, process);
    }
    case Magisk: {
      return magisk_uid_should_umount(process);
    }
    default: {
      return false;
    }
  }
}

bool uid_is_manager(uid_t uid) {
  switch (impl.impl) {
    case KernelSU: {
      return ksu_uid_is_manager(uid);
    }
    case APatch: {
      return apatch_uid_is_manager(uid);
    }
    case Magisk: {
      return magisk_uid_is_manager(uid);
    }
    default: {
      return false;
    }
  }
}

void root_impl_cleanup(void) {
  if (impl.impl == KernelSU) ksu_cleanup();
}
