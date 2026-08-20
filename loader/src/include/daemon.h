#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>

#include <unistd.h>

/* Private monitor transport used only by an APatch-domainless zygiskd exec.
 * The monitor duplicates the child endpoint here before exec; zygiskd marks
 * it close-on-exec immediately after startup so companions never inherit it. */
#define REZYGISKD_DOMAINLESS_MONITOR_FD 196

enum rezygiskd_actions {
  ZygoteInjected,
  GetProcessFlags,
  GetInfo,
  ReadModules,
  RequestCompanionSocket,
  GetModuleDir,
  ZygoteRestart,
  UpdateMountNamespace,
  RemoveModule,
  DomainlessSession
};

struct zygisk_modules {
  char **modules;
  int *module_fds;
  size_t modules_count;
};

enum root_impl {
  ROOT_IMPL_NONE,
  ROOT_IMPL_APATCH,
  ROOT_IMPL_KERNELSU,
  ROOT_IMPL_MAGISK
};

struct rezygisk_info {
  struct zygisk_modules modules;
  enum root_impl root_impl;
  pid_t pid;
  bool running;
};

enum mount_namespace_state {
  Clean,
  Mounted
};

#define TMP_PATH "/data/adb/rezygisk"

static inline const char *rezygiskd_get_path() {
  return TMP_PATH;
}

bool rezygiskd_zygote_injected();

bool rezygiskd_init_domainless_session(int inherited_fd);

int rezygiskd_get_domainless_session_fd();

void rezygiskd_release_domainless_session_in_child();

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process);

void rezygiskd_get_info(struct rezygisk_info *info);

void free_rezygisk_info(struct rezygisk_info *info);

bool rezygiskd_read_modules(struct zygisk_modules *modules);

void free_modules(struct zygisk_modules *modules);

int rezygiskd_connect_companion(size_t index);

int rezygiskd_get_module_dir(size_t index);

void rezygiskd_zygote_restart();

int rezygiskd_update_mns(enum mount_namespace_state nms_state);

bool rezygiskd_remove_module(size_t index);

#endif /* DAEMON_H */
