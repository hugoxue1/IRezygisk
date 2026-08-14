#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>

#include <linux/futex.h>
#include <linux/un.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "logging.h"
#include "misc.h"
#include "socket_utils.h"

#include "daemon.h"

#define SOCKET_FILE_NAME LP_SELECT("cp32", "cp64") ".sock"
#define DOMAINLESS_MARKER "/data/adb/modules/rezygisk/.apatch-domainless-v1"

struct domainless_channel {
  _Atomic int owner;
};

static struct domainless_channel *domainless_channel = NULL;
static int domainless_session_fd = -1;
static bool domainless_session_released = false;

static int domainless_futex_wait(_Atomic int *address, int expected) {
  return syscall(SYS_futex, (int *)address, FUTEX_WAIT, expected, NULL, NULL, 0);
}

static void domainless_futex_wake(_Atomic int *address) {
  syscall(SYS_futex, (int *)address, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static bool domainless_lock() {
  if (domainless_channel == NULL) return false;

  for (;;) {
    int self = (int)syscall(SYS_gettid);
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(&domainless_channel->owner, &expected, self,
                                                memory_order_acquire, memory_order_relaxed)) {
      return true;
    }

    int owner = atomic_load_explicit(&domainless_channel->owner, memory_order_acquire);
    if (owner > 1 && kill(owner, 0) == -1 && errno == ESRCH) {
      expected = owner;
      if (atomic_compare_exchange_strong_explicit(&domainless_channel->owner, &expected, 0,
                                                  memory_order_acq_rel, memory_order_relaxed)) {
        domainless_futex_wake(&domainless_channel->owner);
      }
      continue;
    }

    if (domainless_futex_wait(&domainless_channel->owner, owner) == -1 &&
        errno != EAGAIN && errno != EINTR) {
      PLOGE("domainless channel futex wait");
      return false;
    }
  }
}

static void domainless_unlock() {
  if (domainless_channel == NULL) return;

  atomic_store_explicit(&domainless_channel->owner, 0, memory_order_release);
  domainless_futex_wake(&domainless_channel->owner);
}

static void rezygiskd_disconnect(int fd) {
  close(fd);
  if (domainless_session_fd >= 0 && domainless_channel != NULL) {
    domainless_unlock();
  }
}

static int rezygiskd_connect(uint8_t retry) {
  if (domainless_session_released) return -1;

  if (domainless_session_fd >= 0) {
    if (!domainless_lock()) return -1;

    int fd = dup(domainless_session_fd);
    if (fd == -1) {
      domainless_unlock();
      return -1;
    }
    return fd;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };
  /*
    INFO: Application must assume that sun_path can hold _POSIX_PATH_MAX characters.

    Sources:
     - https://pubs.opengroup.org/onlinepubs/009696699/basedefs/sys/un.h.html
  */
  strcpy(addr.sun_path, TMP_PATH "/" SOCKET_FILE_NAME);

  retry++;
  while (--retry) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
      PLOGE("socket");

      return -1;
    }

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
      PLOGE("connect (retry: %d)", retry);

      close(fd);

      if (!retry) return -1;

      sleep(1);
    }

    return fd;
  }

  return -1;
}

bool rezygiskd_init_domainless_session() {
  if (access(DOMAINLESS_MARKER, F_OK) == -1) return true;
  if (domainless_session_fd >= 0) return true;

  struct domainless_channel *channel = mmap(NULL, sizeof(*channel), PROT_READ | PROT_WRITE,
                                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (channel == MAP_FAILED) {
    PLOGE("mmap domainless channel");
    return false;
  }

  int fd = rezygiskd_connect(5);
  if (fd == -1) {
    munmap(channel, sizeof(*channel));
    return false;
  }
  if (write_uint8_t(fd, (uint8_t)DomainlessSession) == -1) {
    close(fd);
    munmap(channel, sizeof(*channel));
    return false;
  }

  uint8_t accepted = 0;
  if (read_uint8_t(fd, &accepted) == -1 || accepted != 1) {
    close(fd);
    munmap(channel, sizeof(*channel));
    return false;
  }

  domainless_channel = channel;
  domainless_session_fd = fd;
  LOGI("APatch domainless daemon session established");
  return true;
}

void rezygiskd_release_domainless_session_in_child() {
  if (domainless_session_fd < 0) return;

  close(domainless_session_fd);
  domainless_session_fd = -1;
  domainless_session_released = true;
  if (domainless_channel != NULL) {
    munmap(domainless_channel, sizeof(*domainless_channel));
    domainless_channel = NULL;
  }
}

/* TODO: We should unify all of those */
#define safe_write(fn, name, ret_type)             \
  if (fn == -1) {                                  \
    LOGE("Failed to write " name " to ReZygiskd"); \
                                                   \
    rezygiskd_disconnect(fd);                      \
                                                   \
    ret_type;                                      \
  }

#define safe_read(fn, name, ret_type)               \
  if (fn == -1) {                                   \
    LOGE("Failed to read " name " from ReZygiskd"); \
                                                    \
    rezygiskd_disconnect(fd);                       \
                                                    \
    ret_type;                                       \
  }

bool rezygiskd_zygote_injected() {
  int fd = rezygiskd_connect(5);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteInjected), "ZygoteInjected action", return false);

  rezygiskd_disconnect(fd);

  return true;
}

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return 0;

  safe_write(write_uint8_t(fd, (uint8_t)GetProcessFlags), "GetProcessFlags action", return 0);
  safe_write(write_uint32_t(fd, (uint32_t)uid), "uid", return 0);
  safe_write(write_string(fd, process), "process name", return 0);

  uint32_t res = 0;
  safe_read(read_uint32_t(fd, &res), "process flags", return 0);

  rezygiskd_disconnect(fd);

  return res;
}

void rezygiskd_get_info(struct rezygisk_info *info) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) {
    info->running = false;

    return;
  }

  info->running = true;

  safe_write(write_uint8_t(fd, (uint8_t)GetInfo), "GetInfo action", return);

  uint32_t flags = 0;
  safe_read(read_uint32_t(fd, &flags), "info flags", return);

  if (flags & (1 << 28)) info->root_impl = ROOT_IMPL_APATCH;
  else if (flags & (1 << 29)) info->root_impl = ROOT_IMPL_KERNELSU;
  else if (flags & (1 << 30)) info->root_impl = ROOT_IMPL_MAGISK;
  else info->root_impl = ROOT_IMPL_NONE;

  safe_read(read_uint32_t(fd, (uint32_t *)&info->pid), "pid", return);

  safe_read(read_size_t(fd, &info->modules.modules_count), "modules count", return);
  if (info->modules.modules_count == 0) {
    info->modules.modules = NULL;

    rezygiskd_disconnect(fd);

    return;
  }

  info->modules.modules = (char **)malloc(sizeof(char *) * info->modules.modules_count);
  if (!info->modules.modules) {
    PLOGE("allocating modules name memory");

    info->modules.modules_count = 0;

    rezygiskd_disconnect(fd);

    return;
  }

  for (size_t i = 0; i < info->modules.modules_count; i++) {
    char *module_name = read_string(fd);
    if (module_name == NULL) {
      PLOGE("reading module name");

      goto info_cleanup;
    }

    char module_path[PATH_MAX];
    snprintf(module_path, sizeof(module_path), "/data/adb/modules/%s/module.prop", module_name);

    free(module_name);

    FILE *module_prop = fopen(module_path, "r");
    if (!module_prop) {
      PLOGE("failed to open module prop file %s", module_path);

      goto info_cleanup;
    }

    info->modules.modules[i] = NULL;

    char line[1024];
    while (fgets(line, sizeof(line), module_prop) != NULL) {
      if (strncmp(line, "name=", strlen("name=")) != 0) continue;

      size_t name_len = strlen(line + strlen("name="));
      if (name_len == 0 || line[name_len + strlen("name=") - 1] != '\n') {
        LOGE("Invalid module name in %s", module_path);

        fclose(module_prop);

        goto info_cleanup;
      }

      info->modules.modules[i] = strndup(line + strlen("name="), name_len - 1);
      if (info->modules.modules[i] == NULL) {
        PLOGE("allocate memory for module name from %s", module_path);

        fclose(module_prop);

        goto info_cleanup;
      }

      break;
    }

    if (info->modules.modules[i] == NULL) {
      PLOGE("failed to read module name from %s", module_path);

      fclose(module_prop);

      goto info_cleanup;
    }

    fclose(module_prop);

    continue;

    info_cleanup:
      info->modules.modules_count = i;
      free_rezygisk_info(info);

      break;
  }

  rezygiskd_disconnect(fd);
}

void free_rezygisk_info(struct rezygisk_info *info) {
  for (size_t i = 0; i < info->modules.modules_count; i++) {
    free(info->modules.modules[i]);
  }

  free(info->modules.modules);
  info->modules.modules = NULL;
  info->modules.modules_count = 0;
}

bool rezygiskd_read_modules(struct zygisk_modules *modules) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ReadModules), "ReadModules action", return false);

  size_t len = 0;
  safe_read(read_size_t(fd, &len), "modules count", return false);

  modules->modules = malloc(len * sizeof(char *));
  if (!modules->modules) {
    PLOGE("allocating modules name memory");

    rezygiskd_disconnect(fd);

    return false;
  }
  modules->modules_count = len;

  for (size_t i = 0; i < len; i++) {
    char *lib_path = read_string(fd);
    if (!lib_path) {
      PLOGE("reading module lib_path");

      modules->modules_count = i;
      free_modules(modules);

      rezygiskd_disconnect(fd);

      return false;
    }

    modules->modules[i] = lib_path;
  }

  rezygiskd_disconnect(fd);

  return true;
}

void free_modules(struct zygisk_modules *modules) {
  for (size_t i = 0; i < modules->modules_count; i++) {
    free(modules->modules[i]);
  }

  free(modules->modules);
  modules->modules = NULL;
  modules->modules_count = 0;
}

int rezygiskd_connect_companion(size_t index) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)RequestCompanionSocket), "RequestCompanionSocket action", return -1);
  safe_write(write_size_t(fd, index), "companion index", return -1);

  if (domainless_session_fd >= 0) {
    int companion_fd = read_fd(fd);
    rezygiskd_disconnect(fd);
    return companion_fd;
  }

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "companion socket result", return -1);
  if (res == 1) return fd;
  else {
    rezygiskd_disconnect(fd);

    return -1;
  }
}

int rezygiskd_get_module_dir(size_t index) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)GetModuleDir), "GetModuleDir action", return -1);
  safe_write(write_size_t(fd, index), "module index", return -1);

  int dirfd = read_fd(fd);

  rezygiskd_disconnect(fd);

  return dirfd;
}

void rezygiskd_zygote_restart() {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteRestart), "ZygoteRestart action", return);

  rezygiskd_disconnect(fd);
}

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)UpdateMountNamespace), "UpdateMountNamespace action", return false);
  safe_write(write_uint32_t(fd, (uint32_t)getpid()), "pid", return false);
  safe_write(write_uint8_t(fd, (uint8_t)nms_state), "mount namespace state", return false);

  uint32_t target_pid = 0;
  safe_read(read_uint32_t(fd, &target_pid), "target pid", return false);

  uint32_t target_fd = 0;
  safe_read(read_uint32_t(fd, &target_fd), "target fd", return false);

  if (target_fd == 0) {
    LOGE("Failed to get target fd");

    rezygiskd_disconnect(fd);

    return false;
  }

  snprintf(buf, buf_size, "/proc/%u/fd/%u", target_pid, target_fd);

  rezygiskd_disconnect(fd);

  return true;
}

bool rezygiskd_remove_module(size_t index) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)RemoveModule), "RemoveModule action", return false);
  safe_write(write_size_t(fd, index), "module index", return false);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "remove module result", return false);

  rezygiskd_disconnect(fd);

  return res == 1;
}

#undef safe_read
#undef safe_write
