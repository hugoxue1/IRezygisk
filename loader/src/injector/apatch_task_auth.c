#include "apatch_task_auth.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include "logging.h"

#define APATCH_SUPERCALL_NR 45
#define APATCH_SUPERCALL_MAGIC ((long)0x1158 << 16)
#define APATCH_ACTIVATE_ZYGOTE_CARRIER 0x1126
#define APATCH_BEGIN_CHILD_CALLBACK_AUTH 0x1127
#define APATCH_END_CHILD_CALLBACK_AUTH 0x1128

static bool callback_auth_enabled = false;

static bool task_local_supercall(long command, long argument) {
  errno = 0;
  long result = syscall(APATCH_SUPERCALL_NR, NULL,
                        APATCH_SUPERCALL_MAGIC | command, argument);
  if (result == 0) return true;
  LOGE("APatch task-local command 0x%lx failed: result=%ld errno=%d",
       command, result, errno);
  return false;
}

bool apatch_task_auth_activate_zygote_carrier(void) {
  if (!task_local_supercall(APATCH_ACTIVATE_ZYGOTE_CARRIER, 0)) return false;
  callback_auth_enabled = true;
  LOGI("APatch Zygisk callback carrier activated");
  return true;
}

bool apatch_task_auth_begin_callback(void) {
  if (!callback_auth_enabled) return true;
  return task_local_supercall(APATCH_BEGIN_CHILD_CALLBACK_AUTH, 0);
}

bool apatch_task_auth_end_callback(bool keep_carrier) {
  if (!callback_auth_enabled) return true;
  return task_local_supercall(APATCH_END_CHILD_CALLBACK_AUTH,
                              keep_carrier ? 1 : 0);
}

bool apatch_task_auth_enabled(void) {
  return callback_auth_enabled;
}
