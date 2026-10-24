#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <dlfcn.h>
#include <android/dlext.h>
#include <regex.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <unistd.h>

#include <csoloader.h>
#include <plti.h>

#include "daemon.h"
#include "misc.h"
#include "module.h"
#include "apatch_task_auth.h"

#include "art_method.h"
#include "cpp_strings.h"
#include "registers.h"

void *start_addr = NULL;
size_t block_size = 0;

/* INFO: Flag indices */
enum {
  POST_SPECIALIZE,
  APP_FORK_AND_SPECIALIZE,
  APP_SPECIALIZE,
  SERVER_FORK_AND_SPECIALIZE,
  DO_REVERT_UNMOUNT,
  SKIP_FD_SANITIZATION,
  MODULES_PREPARED,

  FLAG_MAX
};

#define MAX_FD_SIZE 1024
#define MAX_REGISTER_INFO 64
#define MAX_IGNORE_INFO 64
#define MAX_EXEMPTED_FDS 128

struct register_info {
  regex_t regex;
  char *symbol;
  void *callback;
  void **backup;
};

struct ignore_info {
  regex_t regex;
  char *symbol;
};

struct zygisk_context {
  JNIEnv *env;
  union {
    void *ptr;
    struct app_specialize_args_v5 *app;
    struct server_specialize_args_v1 *server;
  } args;

  const char *process;

  int pid;
  uint32_t flags;
  uint32_t info_flags;
  uint8_t allowed_fds[MAX_FD_SIZE];
  int exempted_fds[MAX_EXEMPTED_FDS];
  size_t exempted_fds_count;

  pthread_mutex_t hook_info_lock;
  struct register_info register_info[MAX_REGISTER_INFO];
  size_t register_info_count;
  struct ignore_info ignore_info[MAX_IGNORE_INFO];
  size_t ignore_info_count;
};

/* INFO: Current context */
static struct zygisk_context *g_ctx = NULL;

/* INFO: Helper macros for flags */
#define FLAG_SET(ctx, f) ((ctx)->flags |= (1u << (f)))
#define FLAG_GET(ctx, f) (((ctx)->flags & (1u << (f))) != 0)

#define DCL_PRE_POST(name)                                   \
  static void rz_## name ##_pre(struct zygisk_context *ctx); \
  static void rz_## name ##_post(struct zygisk_context *ctx)

/* INFO: Early declarations */
static void rz_init(struct zygisk_context *ctx, JNIEnv *env, void *args);
static void rz_cleanup(struct zygisk_context *ctx);

DCL_PRE_POST(run_modules);
DCL_PRE_POST(fork);
DCL_PRE_POST(app_specialize);
DCL_PRE_POST(nativeForkAndSpecialize);
DCL_PRE_POST(nativeSpecializeAppProcess);
DCL_PRE_POST(nativeForkSystemServer);

#undef DCL_PRE_POST

static inline bool is_zygote_child(struct zygisk_context *ctx) {
  return ctx->pid <= 0;
}

struct plt_hook_entry {
  const char *lib_path;
  const char *symbol;
  void *new_func;
  void **backup;
};

struct jni_hook_entry {
  char *class_name;
  JNINativeMethod *methods;
  size_t methods_count;
};

struct plti plti_ctx;

static struct plt_hook_entry *plt_hook_list = NULL;
static size_t plt_hook_list_count = 0;

static struct jni_hook_entry *jni_hook_list = NULL;
static size_t jni_hook_list_count = 0;

struct rezygisk_module *zygisk_modules = NULL;
size_t zygisk_module_length = 0;

static bool should_unmap_zygisk = false;
static bool enable_unloader = false;

/* INFO: Helper function to add to PLT hook list */
static bool plt_hook_list_add(const char *lib_path, const char *symbol, void *new_func, void **backup) {
  struct plt_hook_entry *new_plt_hook_list = realloc(plt_hook_list, (plt_hook_list_count + 1) * sizeof(struct plt_hook_entry));
  if (!new_plt_hook_list) {
    LOGE("Failed to reallocate buffer for PLT hook list");

    return false;
  }
  plt_hook_list = new_plt_hook_list;

  plt_hook_list[plt_hook_list_count].lib_path = lib_path;
  plt_hook_list[plt_hook_list_count].symbol = symbol;
  plt_hook_list[plt_hook_list_count].new_func = new_func;
  plt_hook_list[plt_hook_list_count].backup = backup;
  plt_hook_list_count++;

  return true;
}

/* INFO: Helper function to add to JNI hook list */
static void jni_hook_list_add(const char *class_name, JNINativeMethod *methods, size_t count) {
  struct jni_hook_entry *new_jni_hook_list = realloc(jni_hook_list, (jni_hook_list_count + 1) * sizeof(struct jni_hook_entry));
  if (!new_jni_hook_list) {
    LOGE("Failed to reallocate buffer for JNI hook list");

    return;
  }
  jni_hook_list = new_jni_hook_list;

  jni_hook_list[jni_hook_list_count].class_name = strdup(class_name);
  if (!jni_hook_list[jni_hook_list_count].class_name) {
    LOGE("Failed to duplicate class name for hook list");

    return;
  }

  jni_hook_list[jni_hook_list_count].methods = malloc(count * sizeof(JNINativeMethod));
  if (!jni_hook_list[jni_hook_list_count].methods) {
    LOGE("Failed to allocate memory for methods in hook list");

    free(jni_hook_list[jni_hook_list_count].class_name);

    return;
  }

  memcpy(jni_hook_list[jni_hook_list_count].methods, methods, count * sizeof(JNINativeMethod));

  jni_hook_list[jni_hook_list_count].methods_count = count;
  jni_hook_list_count++;
}

static bool update_mnt_ns(enum mount_namespace_state mns_state, bool dry_run) {
  int updated_ns = rezygiskd_update_mns(mns_state);
  if (updated_ns == -1) {
    PLOGE("Failed to update mount namespace");

    return false;
  }

  if (dry_run) {
    close(updated_ns);

    return true;
  }

  char *mns_state_str = "unknown";
  if (mns_state == Clean) mns_state_str = "clean";
  if (mns_state == Mounted) mns_state_str = "mounted";

  LOGD("set mount namespace from received fd=[%d]: %s", updated_ns, mns_state_str);

  if (setns(updated_ns, CLONE_NEWNS) == -1) {
    PLOGE("Failed to set received mount namespace fd=[%d]", updated_ns);

    close(updated_ns);

    return false;
  }

  close(updated_ns);

  return true;
}

/* INFO: Hook function declarations */
#define DCL_HOOK_FUNC(ret, func, ...) \
  ret (*old_##func)(__VA_ARGS__);     \
  ret new_##func(__VA_ARGS__)

/* INFO: ReZygisk already performs a fork in zygisk_context::fork_pre, because of that,
           we avoid duplicate fork in nativeForkAndSpecialize and nativeForkSystemServer
           by caching the pid in fork_pre function and only performing fork if the pid
           is non-0, or in other words, if we (libzygisk.so) already forked.
*/
DCL_HOOK_FUNC(int, fork) {
  return (g_ctx && g_ctx->pid >= 0) ? g_ctx->pid : old_fork();
}

static bool is_self_fd_directory(DIR *dir) {
  int fd = dirfd(dir);
  if (fd < 0) return false;

  char fd_link[64];
  char target[PATH_MAX];
  snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", fd);
  ssize_t length = readlink(fd_link, target, sizeof(target) - 1);
  if (length < 0 || (size_t)length >= sizeof(target)) return false;
  target[length] = '\0';

  char expected[64];
  snprintf(expected, sizeof(expected), "/proc/%d/fd", getpid());
  return strcmp(target, "/proc/self/fd") == 0 || strcmp(target, expected) == 0;
}

/* nativeForkSystemServer and nativeForkUsap build fds_to_ignore internally and
   do not expose a JNI array that ReZygisk can extend. Hide only our private
   control descriptor from Android's /proc/self/fd enumeration while the
   descriptor exists. App forks still receive the explicit fds_to_ignore entry. */
DCL_HOOK_FUNC(struct dirent *, readdir, DIR *dir) {
  for (;;) {
    struct dirent *entry = old_readdir(dir);
    if (entry == NULL) return entry;

    int control_fd = rezygiskd_get_domainless_session_fd();
    if (control_fd < 0) return entry;

    char control_name[16];
    snprintf(control_name, sizeof(control_name), "%d", control_fd);
    if (strcmp(entry->d_name, control_name) != 0 || !is_self_fd_directory(dir))
      return entry;

    LOGV("Hiding internal domainless fd %d from Zygote FD scan", control_fd);
  }
}

/* INFO: file_path is a std::string in the actual class. We represent it as opaque bytes. */
#ifdef __LP64__
  #define STD_STRING_SIZE 24
#else
  #define STD_STRING_SIZE 12
#endif

struct FileDescriptorInfo {
  const int fd;
  const struct stat stat;
  /* INFO: std::string, actually */
  char file_path_storage[STD_STRING_SIZE];
  const int open_flags;
  const int fd_flags;
  const int fs_flags;
  const off_t offset;
  const bool is_sock;
};

/* INFO: This hook avoids that umounted overlays made by root modules lead to Zygote
           to Abort its operation as it cannot open anymore.

   SOURCES:
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/fd_utils.cpp#346
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/fd_utils.cpp#544
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#2329
*/
DCL_HOOK_FUNC(void, _ZNK18FileDescriptorInfo14ReopenOrDetach, void *_this, void *fail_fn) {
  const int fd = *(const int *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, fd));
  const void *file_path_std_string = (const void *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, file_path_storage));
  const char *file_path = read_std_string(file_path_std_string);
  const bool is_sock = *(const bool *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, is_sock));

  if (is_sock)
    goto bypass_fd_check;

  if (strncmp(file_path, "/memfd:/boot-image-methods.art", strlen("/memfd:/boot-image-methods.art")) == 0)
    goto bypass_fd_check;

  if (access(file_path, F_OK) == -1) {
    LOGD("Failed to open file %s, detaching it", file_path);

    close(fd);

    return;
  }

  bypass_fd_check:
    old__ZNK18FileDescriptorInfo14ReopenOrDetach(_this, fail_fn);
}

static void unhook_functions(void);
/* INFO: Self-unloading is not a direct task, it requires the utilization of tail
           optimization, which requires the signature to be the same as munmap, or
           else munmap will be executed and will try to reach our code, leading to
           a segmentation fault.

         To counter that, we hook pthread_attr_setstacksize, which is called around
           when the VM daemon starts, to allow this to happen before the app can
           execute code.
*/
DCL_HOOK_FUNC(int, pthread_attr_setstacksize, void *target, size_t size) {
  int res = old_pthread_attr_setstacksize((pthread_attr_t *)target, size);
  LOGV("Call pthread_attr_setstacksize in [tid, pid]: %d, %d", gettid(), getpid());

  if (!enable_unloader) return res;

  /* INFO: Only perform unloading on the main thread */
  if (gettid() != getpid()) return res;

  if (should_unmap_zygisk) {
    unhook_functions();

    csoloader_deinit();

    if (!should_unmap_zygisk) {
      LOGW("Failed to unmap libzygisk.so, skipping munmap");

      enable_unloader = false;

      free(zygisk_modules);
      zygisk_modules = NULL;

      plti_deinit(&plti_ctx);

      return res;
    }

    /* INFO: Modules might use libzygisk.so after postAppSpecialize. We can only
               free it when we are really before our unmap. */
    free(zygisk_modules);
    zygisk_modules = NULL;

    plti_deinit(&plti_ctx);

    LOGD("unmap libzygisk.so loaded at %p with size %zu", start_addr, block_size);

    [[clang::musttail]] return munmap(start_addr, block_size);
  }

  return res;
}

static void initialize_jni_hook(void);
DCL_HOOK_FUNC(char *, strdup, const char *str) {
  if (strcmp(str, "com.android.internal.os.ZygoteInit") == 0) {
    LOGV("strdup %s", str);

    initialize_jni_hook();
  }

  return old_strdup(str);
}

static void hook_unloader(void);
/*
  INFO: Our goal is to get called after libart.so is loaded, but before ART actually starts running.
          If we are too early, we won't find libart.so in maps, and if we are too late, we could make other
          threads crash if they try to use the PLT while we are in the process of hooking it.
          For this task, hooking property_get was chosen as there are lots of calls to this, so it's
          relatively unlikely to break.

        After we succeed in getting called at a point where libart.so is already loaded, we will ignore
          the rest of the property_get calls.
  SOURCES:
   - https://github.com/aosp-mirror/platform_frameworks_base/blob/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/jni/AndroidRuntime.cpp#L1266
   - https://github.com/aosp-mirror/platform_frameworks_base/blob/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/jni/AndroidRuntime.cpp#L791
*/
DCL_HOOK_FUNC(int, property_get, const char *key, char *value, const char *default_value) {
  hook_unloader();

  return old_property_get(key, value, default_value);
}

#undef DCL_HOOK_FUNC

static bool can_hook_jni = false;
static jint MODIFIER_NATIVE = 0;
static jmethodID member_getModifiers = NULL;

void hook_jni_methods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods) {
  if (!can_hook_jni) return;

  jclass clazz = (*env)->FindClass(env, clz);
  if (!clazz) {
    (*env)->ExceptionClear(env);

    memset(methods, 0, numMethods * sizeof(JNINativeMethod));

    return;
  }

  JNINativeMethod hooks[32];
  size_t hooks_count = 0;

  for (int i = 0; i < numMethods; i++) {
    bool is_static = false;

    JNINativeMethod *nm = &methods[i];
    jmethodID mid = (*env)->GetMethodID(env, clazz, nm->name, nm->signature);
    if (!mid) {
      (*env)->ExceptionClear(env);
      mid = (*env)->GetStaticMethodID(env, clazz, nm->name, nm->signature);
      is_static = true;
    }

    if (!mid) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      continue;
    }

    jobject method = (*env)->ToReflectedMethod(env, clazz, mid, is_static);
    jint modifier = (*env)->CallIntMethod(env, method, member_getModifiers);
    if ((*env)->ExceptionCheck(env) || (modifier & MODIFIER_NATIVE) == 0) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      (*env)->DeleteLocalRef(env, method);

      continue;
    }

    void *art_method = amethod_from_reflected_method(env, method);
    if (hooks_count < 32)
      hooks[hooks_count++] = *nm;

    void *orig = amethod_get_data((uintptr_t)art_method);
    nm->fnPtr = orig;

    LOGV("replaced %s %s orig %p: %s", clz, nm->name, orig, nm->signature);

    (*env)->DeleteLocalRef(env, method);
  }

  if (hooks_count == 0) {
    (*env)->DeleteLocalRef(env, clazz);

    return;
  }

  (*env)->RegisterNatives(env, clazz, hooks, (jint)hooks_count);
  (*env)->DeleteLocalRef(env, clazz);
}

/* INFO: JNI method hook definitions */
#include "jni_hooks.h"

static void initialize_jni_hook(void) {
  jint (*get_created_java_vms)(JavaVM **, jsize, jsize *) = (jint (*)(JavaVM **, jsize, jsize *))dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
  if (!get_created_java_vms) {
    struct maps_info *maps = parse_maps_safe("self");
    if (!maps) {
      LOGE("Failed to scan maps for plt_hook_register_v4");

      return;
    }

    for (size_t i = 0; i < maps->length; i++) {
      struct map_entry *map = &maps->maps[i];
      if (map->path && !strstr(map->path, "/libnativehelper.so")) continue;

      /* TODO: Add RTLD_NOLOAD? */
      void *handle = dlopen(map->path, RTLD_LAZY);
      if (!handle) {
        LOGE("Failed to dlopen %s: %s", map->path, dlerror());

        break;
      }

      get_created_java_vms = (jint (*)(JavaVM **, jsize, jsize *))dlsym(handle, "JNI_GetCreatedJavaVMs");
      dlclose(handle);

      break;
    }

    free_maps(maps);

    if (!get_created_java_vms) {
      LOGE("Failed to find JNI_GetCreatedJavaVMs");

      return;
    }
  }

  JavaVM *vm = NULL;
  jsize num = 0;
  jint res = get_created_java_vms(&vm, 1, &num);
  if (res != JNI_OK || !vm) return;

  JNIEnv *env = NULL;
  res = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
  if (res != JNI_OK || !env) return;

  jclass classMember = (*env)->FindClass(env, "java/lang/reflect/Member");
  if (classMember) member_getModifiers = (*env)->GetMethodID(env, classMember, "getModifiers", "()I");

  jclass classModifier = (*env)->FindClass(env, "java/lang/reflect/Modifier");
  if (classModifier) {
    jfieldID fieldId = (*env)->GetStaticFieldID(env, classModifier, "NATIVE", "I");
    if (fieldId) MODIFIER_NATIVE = (*env)->GetStaticIntField(env, classModifier, fieldId);
  }

  (*env)->DeleteLocalRef(env, classMember);
  (*env)->DeleteLocalRef(env, classModifier);

  if (!member_getModifiers || MODIFIER_NATIVE == 0) return;

  if (!amethod_init(env)) {
    LOGE("failed to init amethod");

    return;
  }

  can_hook_jni = true;
  do_hook_zygote(env);

  /* INFO: ART leaks through libc strings from ReZygisk. We immediately
             clear them here. */
  registers_clear();
}

/* INFO: Module registration and API functions */
static void api_plt_hook_register(const char *regex, const char *symbol, void *fn, void **backup) {
  if (!g_ctx || !regex || !symbol || !fn || g_ctx->register_info_count >= MAX_REGISTER_INFO) return;

  regex_t re;
  if (regcomp(&re, regex, REG_NOSUB) != 0) return;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  g_ctx->register_info[g_ctx->register_info_count].regex = re;
  g_ctx->register_info[g_ctx->register_info_count].symbol = strdup(symbol);
  g_ctx->register_info[g_ctx->register_info_count].callback = fn;
  g_ctx->register_info[g_ctx->register_info_count].backup = backup;
  g_ctx->register_info_count++;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);
}

static void api_plt_hook_exclude(const char *regex, const char *symbol) {
  if (!g_ctx || !regex || g_ctx->ignore_info_count >= MAX_IGNORE_INFO) return;

  regex_t re;
  if (regcomp(&re, regex, REG_NOSUB) != 0) return;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  g_ctx->ignore_info[g_ctx->ignore_info_count].regex = re;
  g_ctx->ignore_info[g_ctx->ignore_info_count].symbol = symbol ? strdup(symbol) : NULL;
  g_ctx->ignore_info_count++;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);
}

static bool api_plt_hook_commit(void) {
  if (!g_ctx || g_ctx->register_info_count == 0) return false;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  struct maps_info *map_infos = parse_maps_safe("self");
  if (!map_infos) {
    LOGE("Failed to scan maps for self");

    pthread_mutex_unlock(&g_ctx->hook_info_lock);

    return false;
  }

  bool any_failed = false;
  for (size_t i = 0; i < map_infos->length; i++) {
    struct map_entry *map = &map_infos->maps[i];
    if (map->offset != 0 || !map->is_private || !(map->perms & PROT_READ)) continue;

    for (size_t r = 0; r < g_ctx->register_info_count; r++) {
      struct register_info *reg = &g_ctx->register_info[r];
      if (regexec(&reg->regex, map->path, 0, NULL, 0) != 0) continue;

      bool ignored = false;
      for (size_t ig = 0; ig < g_ctx->ignore_info_count; ig++) {
        struct ignore_info *ign = &g_ctx->ignore_info[ig];
        if (regexec(&ign->regex, map->path, 0, NULL, 0) != 0) continue;
        if (ign->symbol && strcmp(ign->symbol, reg->symbol) != 0) continue;

        ignored = true;

        break;
      }

      if (!ignored && !plti_add_hook(&plti_ctx, map->path, reg->symbol, reg->callback, reg->backup)) {
        LOGE("Failed to register PLT hook for %s in %s", reg->symbol, map->path);

        any_failed = true;
      }
    }
  }

  free_maps(map_infos);

  /* INFO: Clear register_info and ignore_info */
  for (size_t i = 0; i < g_ctx->register_info_count; i++) {
    regfree(&g_ctx->register_info[i].regex);
    free(g_ctx->register_info[i].symbol);
  }
  g_ctx->register_info_count = 0;

  for (size_t i = 0; i < g_ctx->ignore_info_count; i++) {
    regfree(&g_ctx->ignore_info[i].regex);
    free(g_ctx->ignore_info[i].symbol);
  }
  g_ctx->ignore_info_count = 0;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);

  return !any_failed;
}

static void api_plt_hook_register_v4(dev_t dev, ino_t inode, const char *symbol, void *fn, void **backup) {
  if (!g_ctx || !symbol || !fn) return;

  struct maps_info *maps = parse_maps_safe("self");
  if (!maps) {
    LOGE("Failed to scan maps for plt_hook_register_v4");

    return;
  }

  uintptr_t lib_start = 0;
  const char *lib_path = NULL;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];
    if (entry->dev != dev || entry->inode != inode) continue;

    lib_start = entry->start;
    lib_path = entry->path;

    break;
  }

  if (!lib_path) {
    LOGE("Failed to find library with dev %zu and inode %zu for hook %s", (size_t)dev, (size_t)inode, symbol);

    free_maps(maps);

    return;
  }

  char *lib_path_copy = strdup(lib_path);
  if (!lib_path_copy) {
    LOGE("Failed to duplicate library path for hook %s: %s", symbol, lib_path);

    free_maps(maps);

    return;
  }

  free_maps(maps);

  if (!plti_add_manual_lib(&plti_ctx, lib_path_copy, lib_start)) {
    LOGE("Failed to add manual library for hook %s: %s", symbol, lib_path_copy);

    free(lib_path_copy);

    return;
  }

  char *symbol_copy = strdup(symbol);
  if (!symbol_copy) {
    LOGE("Failed to duplicate symbol name for hook %s in %s", symbol, lib_path_copy);

    free(lib_path_copy);

    return;
  }

  if (!plt_hook_list_add(lib_path_copy, symbol_copy, fn, backup)) {
    LOGE("Failed to add plt_hook entry for %s in %s", symbol, lib_path_copy);

    free(lib_path_copy);
    free(symbol_copy);

    return;
  }
}

static void api_exempt_fd(int fd) {
  if (!g_ctx) return;

  if (FLAG_GET(g_ctx, POST_SPECIALIZE) || FLAG_GET(g_ctx, SKIP_FD_SANITIZATION)) return;
  if (!FLAG_GET(g_ctx, APP_FORK_AND_SPECIALIZE)) return;
  if (g_ctx->exempted_fds_count >= MAX_EXEMPTED_FDS) return;

  g_ctx->exempted_fds[g_ctx->exempted_fds_count++] = fd;

  return;
}

static bool api_plt_hook_commit_v4(void) {
  if (!g_ctx) return false;

  bool any_failed = false;
  for (size_t i = 0; i < plt_hook_list_count; i++) {
    struct plt_hook_entry *entry = &plt_hook_list[i];
    if (!plti_add_hook(&plti_ctx, entry->lib_path, entry->symbol, entry->new_func, entry->backup)) {
      LOGE("Failed to register plt_hook \"%s\" in %s with PLTI", entry->symbol, entry->lib_path);

      any_failed = true;
    }
  }

  if (plt_hook_list) {
    for (size_t i = 0; i < plt_hook_list_count; i++) {
      free((void *)plt_hook_list[i].lib_path);
      free((void *)plt_hook_list[i].symbol);
    }

    free(plt_hook_list);
    plt_hook_list = NULL;
    plt_hook_list_count = 0;
  }

  return !any_failed;
}

/* INFO: Avoid common mistakes of not utilizing implementation member (impl) when calling
           any Zygisk API functions by logging that error. */
#define RZID_MAGIC ('R' + 'Z' + 'I' + 'D')
#define ENCODE_ID(id) ((void *)((size_t)(id) + RZID_MAGIC))
#define DECODE_ID(ptr) ((size_t)(ptr) - RZID_MAGIC)

static int api_connect_companion(void *id) {
  if (!g_ctx) return -1;

  if ((size_t)id < RZID_MAGIC || (size_t)id >= RZID_MAGIC + zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return -1;
  }

  return rezygiskd_connect_companion(DECODE_ID(id));
}

static void api_set_option(void *id, enum rezygisk_options opt) {
  if (!g_ctx) return;

  if ((size_t)id < RZID_MAGIC || (size_t)id >= RZID_MAGIC + zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return;
  }

  switch (opt) {
    case FORCE_DENYLIST_UNMOUNT: {
      FLAG_SET(g_ctx, DO_REVERT_UNMOUNT);

      break;
    }
    case DLCLOSE_MODULE_LIBRARY: {
      struct rezygisk_module *m_lib = &zygisk_modules[DECODE_ID(id)];
      m_lib->unload = true;

      break;
    }
  }
}

static int api_get_module_dir(void *id) {
  if (!g_ctx) return -1;

  if ((size_t)id < RZID_MAGIC || (size_t)id >= RZID_MAGIC + zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return -1;
  }

  return rezygiskd_get_module_dir(DECODE_ID(id));
}

static uint32_t api_get_flags(void) {
  if (!g_ctx) return 0;

  return (g_ctx->info_flags & ~PRIVATE_MASK);
}

bool rezygisk_module_register(struct rezygisk_api *api, struct rezygisk_abi const *target_module) {
  if (!g_ctx || !api || !target_module || target_module->api_version > REZYGISK_API_VERSION) return false;

  LOGD("Registering module with API version %ld", target_module->api_version);

  struct rezygisk_module *m = &zygisk_modules[DECODE_ID(api->impl)];
  m->abi = *target_module;
  m->api = *api;

  api->hook_jni_native_methods = hook_jni_methods;
  if (target_module->api_version >= 4) {
    api->plt_hook_register_v4 = api_plt_hook_register_v4;
    api->exempt_fd = api_exempt_fd;
    api->plt_hook_commit = api_plt_hook_commit_v4;
  } else {
    api->plt_hook_register = api_plt_hook_register;
    api->plt_hook_exclude = api_plt_hook_exclude;
    api->plt_hook_commit = api_plt_hook_commit;
  }

  api->connect_companion = api_connect_companion;
  api->set_option = api_set_option;

  if (target_module->api_version >= 2) {
    api->get_module_dir = api_get_module_dir;
    api->get_flags = api_get_flags;
  }

  return true;
}

/* INFO: Signal mask helper */
static int sigmask(int how, int signum) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signum);

  return sigprocmask(how, &set, NULL);
}

static bool load_modules_only(void);

static void rz_fork_pre(struct zygisk_context *ctx) {
  /* INFO: Do our own fork before loading any 3rd party code.
              First block SIGCHLD, unblock after original fork is done.
  */
  sigmask(SIG_BLOCK, SIGCHLD);
  ctx->pid = old_fork();
  if (ctx->pid != 0 || FLAG_GET(ctx, SKIP_FD_SANITIZATION)) return;

  /* INFO: Record all open fds */
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("Failed to open /proc/self/fd");

    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir))) {
    int fd = parse_int(entry->d_name);
    if (fd == -1) continue;

    if (fd >= MAX_FD_SIZE) {
      close(fd);

      continue;
    }

    ctx->allowed_fds[fd] = 1;
  }

  /* INFO: The dirfd should not be allowed */
  int dfd = dirfd(dir);
  if (dfd >= 0 && dfd < MAX_FD_SIZE) ctx->allowed_fds[dfd] = 0;

  closedir(dir);
}

static void mark_fds_allowed(struct zygisk_context *ctx, JNIEnv *env, jintArray fdsArray) {
  if (!fdsArray) return;

  jint *arr = (*env)->GetIntArrayElements(env, fdsArray, NULL);
  jint len = (*env)->GetArrayLength(env, fdsArray);

  for (jint i = 0; i < len; ++i) {
    int fd = arr[i];
    if (fd >= 0 && fd < MAX_FD_SIZE) ctx->allowed_fds[fd] = 1;
  }

  (*env)->ReleaseIntArrayElements(env, fdsArray, arr, JNI_ABORT);
}

static void rz_sanitize_fds(struct zygisk_context *ctx) {
  if (FLAG_GET(ctx, SKIP_FD_SANITIZATION)) return;

  int control_fd = rezygiskd_get_domainless_session_fd();
  if (control_fd >= 0 && control_fd < MAX_FD_SIZE)
    ctx->allowed_fds[control_fd] = 1;

  if (FLAG_GET(ctx, APP_FORK_AND_SPECIALIZE)) {
    jintArray fdsToIgnore = ctx->args.app->fds_to_ignore ? *ctx->args.app->fds_to_ignore : NULL;
    mark_fds_allowed(ctx, ctx->env, fdsToIgnore);

    jint extra_fds[MAX_EXEMPTED_FDS + 1];
    size_t extra_fds_count = 0;
    for (size_t i = 0; i < ctx->exempted_fds_count; i++)
      extra_fds[extra_fds_count++] = ctx->exempted_fds[i];

    /* A connected AF_UNIX client socket has no filesystem name on its local
       endpoint unless it was explicitly bound. Android's Zygote FD table
       rejects unlisted sockets before fork. Keep the private control channel
       available for trusted callbacks, but tell Android not to inspect or
       reopen it. The child closes it immediately after post-specialize. */
    if (control_fd >= 0) {
      bool duplicate = false;
      for (size_t i = 0; i < extra_fds_count; i++) {
        if (extra_fds[i] == control_fd) duplicate = true;
      }
      if (!duplicate) extra_fds[extra_fds_count++] = control_fd;
      if (control_fd < MAX_FD_SIZE) ctx->allowed_fds[control_fd] = 1;
    }

    /* Android L does not expose fds_to_ignore. It is still safe because the
       pre-exec channel has an explicit abstract local socket name; only write
       through the pointer on platform signatures that actually provide it. */
    if (ctx->args.app->fds_to_ignore != NULL && extra_fds_count > 0) {
      jint len = fdsToIgnore ? (*ctx->env)->GetArrayLength(ctx->env, fdsToIgnore) : 0;
      jintArray newArray = (*ctx->env)->NewIntArray(ctx->env, (jsize)(len + extra_fds_count));
      if (newArray) {
        if (fdsToIgnore && len > 0) {
          jint *arr = (*ctx->env)->GetIntArrayElements(ctx->env, fdsToIgnore, NULL);
          (*ctx->env)->SetIntArrayRegion(ctx->env, newArray, 0, len, arr);
          (*ctx->env)->ReleaseIntArrayElements(ctx->env, fdsToIgnore, arr, JNI_ABORT);
          (*ctx->env)->DeleteLocalRef(ctx->env, fdsToIgnore);
        }

        (*ctx->env)->SetIntArrayRegion(ctx->env, newArray, len,
                                      (jsize)extra_fds_count, extra_fds);
        for (size_t i = 0; i < extra_fds_count; i++) {
          int fd = extra_fds[i];
          if (fd >= 0 && fd < MAX_FD_SIZE) ctx->allowed_fds[fd] = 1;
        }

        *ctx->args.app->fds_to_ignore = newArray;
        FLAG_SET(ctx, SKIP_FD_SANITIZATION);
      }
    }
  }

  if (ctx->pid != 0) return;

  /* INFO: Close all forbidden fds to prevent crashing */
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("Failed to open /proc/self/fd");

    return;
  }

  int dfd = dirfd(dir);
  struct dirent *entry;
  while ((entry = readdir(dir))) {
    int fd = parse_int(entry->d_name);
    if (fd < 0 || fd >= MAX_FD_SIZE || fd == dfd || ctx->allowed_fds[fd]) continue;

    close(fd);

    LOGW("Closed leaked fd: %d", fd);
  }

  closedir(dir);
}

static void rz_fork_post(struct zygisk_context *ctx __attribute__((unused))) {
  sigmask(SIG_UNBLOCK, SIGCHLD);
  g_ctx = NULL;
}

static bool load_modules_only(void) {
  struct zygisk_modules ms;
  if (!rezygiskd_read_modules(&ms)) {
    LOGE("Failed to read modules from ReZygiskd");

    return false;
  }

  zygisk_modules = (struct rezygisk_module *)malloc(ms.modules_count * sizeof(struct rezygisk_module));
  if (!zygisk_modules) {
    LOGE("Failed to allocate memory for modules");

    free_modules(&ms);

    return false;
  }

  for (size_t i = 0; i < ms.modules_count; i++) {
    const char *lib_path = ms.modules[i];
    /* Successfully loaded modules stay in daemon order while failed entries
       are removed immediately. The live daemon index therefore equals the
       number of modules already retained, not the immutable snapshot index. */
    size_t daemon_module_index = zygisk_module_length;
    struct rezygisk_module *module = &zygisk_modules[zygisk_module_length];
    memset(module, 0, sizeof(*module));

    bool loaded_by_csoloader = csoloader_load(&module->lib, lib_path);
    if (!loaded_by_csoloader) {
      /* Some valid Zygisk modules contain large or unusual C++ relocation and
         constructor graphs that CSOLoader cannot reproduce in Zygote even
         though Android's linker accepts them.  Retry through an fd so linker
         namespaces and the /data/adb path do not become compatibility gates. */
      LOGW("CSOLoader rejected module [%s]; retrying with Android linker", lib_path);

      int library_fd = ms.module_fds[i];
      /* [2026-10-18 07g-B] Restage the module into an anonymous memfd before
         handing it to the Android linker. A /data/adb-backed fd makes the
         linker map the module with a file-backed VMA whose pathname (and the
         soinfo realpath fed to dl_iterate_phdr) exposes the module path in
         every target process — observed live as
         /data/adb/modules/zygisk_ckbsmart/zygisk/arm64-v8a.so x3 in a Soul
         6.38.0 capture (docs 07g §一). Copying the bytes into a
         memfd_create("jit-cache") gives the mapping the same anonymous
         backing and display name as ART's own JIT regions, which appear in
         every normal process. The path string passed to android_dlopen_ext is
         set to the memfd name as well, so soinfo realpath matches /proc/maps
         and no second channel leaks the original path. Failure here is
         fail-open: staging is a stealth improvement, never a load-correctness
         gate, so any error falls back to the original fd and path. */
      int staged_fd = -1;
      char staged_path[64];
      if (library_fd >= 0) {
        int mfd = (int)syscall(__NR_memfd_create, "jit-cache", 0);
        if (mfd >= 0) {
          if (lseek(library_fd, 0, SEEK_SET) == (off_t)-1) {
            LOGW("Module fd rewind failed [%s]: %s", lib_path, strerror(errno));
          }
          char copy_buf[65536];
          ssize_t rn;
          bool copy_ok = true;
          off_t total = 0;
          while ((rn = read(library_fd, copy_buf, sizeof(copy_buf))) > 0) {
            off_t wn_total = 0;
            while (wn_total < rn) {
              ssize_t wn = write(mfd, copy_buf + wn_total, (size_t)(rn - wn_total));
              if (wn < 0) {
                if (errno == EINTR) continue;
                copy_ok = false;
                break;
              }
              wn_total += wn;
            }
            if (!copy_ok) break;
            total += rn;
          }
          if (rn < 0) copy_ok = false;
          if (copy_ok && total > 0 && lseek(mfd, 0, SEEK_SET) == 0) {
            staged_fd = mfd;
            strncpy(staged_path, "/memfd:jit-cache", sizeof(staged_path) - 1);
            staged_path[sizeof(staged_path) - 1] = '\0';
            LOGI("Module [%s] restaged into memfd (%lld bytes)", lib_path, (long long)total);
          } else {
            if (!copy_ok || total <= 0)
              LOGW("memfd staging failed for [%s]; using original fd (fail-open)", lib_path);
            else
              LOGW("memfd rewind failed for [%s]; using original fd (fail-open)", lib_path);
            close(mfd);
          }
        } else {
          LOGW("memfd_create unavailable; using original fd (fail-open) [%s]", lib_path);
        }
      }
      const char *linker_path = staged_fd >= 0 ? staged_path : lib_path;
      int linker_fd = staged_fd >= 0 ? staged_fd : library_fd;
      module->android_linker_path = strdup(linker_path);
      if (!module->android_linker_path) {
        LOGE("Failed to retain Android linker module path [%s]", lib_path);
      } else if (linker_fd >= 0) {
        android_dlextinfo extinfo = {
          .flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD,
          .library_fd = linker_fd
        };
        module->android_linker_handle =
          android_dlopen_ext(module->android_linker_path,
                             RTLD_NOW | RTLD_LOCAL, &extinfo);
      }

      if (staged_fd >= 0) {
        /* The kernel holds the mapping; the staged fd is only needed for the
           dlopen call itself. Keep the original daemon fd untouched. */
        close(staged_fd);
        staged_fd = -1;
      }

      if (!module->android_linker_handle) {
        LOGE("Android linker fallback failed for module [%s]: %s",
             lib_path, dlerror());
        free(module->android_linker_path);
        memset(module, 0, sizeof(*module));

        /* INFO: In case a module failed to load, update the list of available modules
             in ReZygiskd to avoid a mismatch between the loaded modules in ReZygisk
             Zygote library and the available modules in ReZygiskd. */
        rezygiskd_remove_module(daemon_module_index);

        continue;
      }

      LOGI("Loaded module [%s] with Android linker fallback", lib_path);
    }

    void *entry = loaded_by_csoloader
      ? csoloader_get_symbol(&module->lib, "zygisk_module_entry")
      : dlsym(module->android_linker_handle, "zygisk_module_entry");
    if (!entry) {
      LOGE("Failed to find entry point in module [%s]", lib_path);

      if (loaded_by_csoloader) {
        csoloader_unload(&module->lib);
      } else {
        dlerror();
        if (dlclose(module->android_linker_handle) != 0)
          LOGE("Failed to unload fallback module without an entry point [%s]: %s",
               lib_path, dlerror());
        free(module->android_linker_path);
      }
      memset(module, 0, sizeof(*module));

      rezygiskd_remove_module(daemon_module_index);

      continue;
    }

    module->api.register_module = rezygisk_module_register;
    module->api.impl = ENCODE_ID((void *)zygisk_module_length);
    module->zygisk_module_entry = (void (*)(void *, void *))entry;

    LOGD("Loaded module [%s]. Entry: %p", lib_path, entry);

    module->unload = false;
    zygisk_module_length++;
  }

  free_modules(&ms);

  return true;
}

static void rz_run_modules_pre(struct zygisk_context *ctx) {
  if (!apatch_task_auth_begin_callback()) {
    LOGE("Skipping module pre-specialize callbacks: APatch task-local authorization unavailable");
    return;
  }

  for (size_t i = 0; i < zygisk_module_length; i++) {
    rz_module_call_on_load(&zygisk_modules[i], ctx->env);

    if (FLAG_GET(ctx, APP_SPECIALIZE)) rz_module_call_pre_app_specialize(&zygisk_modules[i], ctx->args.app);
    else if (FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE)) rz_module_call_pre_server_specialize(&zygisk_modules[i], ctx->args.server);
  }

  if (!apatch_task_auth_end_callback(true)) {
    LOGE("APatch failed to close the pre-specialize authorization window");
    _exit(127);
  }
  FLAG_SET(ctx, MODULES_PREPARED);
}

static void rz_run_modules_post(struct zygisk_context *ctx) {
  FLAG_SET(ctx, POST_SPECIALIZE);

  if (!FLAG_GET(ctx, MODULES_PREPARED)) {
    if (apatch_task_auth_enabled() && !apatch_task_auth_end_callback(false)) {
      LOGE("APatch failed to discard an unused child-callback carrier");
      _exit(127);
    }
    return;
  }
  if (!apatch_task_auth_begin_callback()) {
    LOGE("Skipping module post-specialize callbacks: APatch task-local authorization unavailable");
    if (!apatch_task_auth_end_callback(false)) _exit(127);
    return;
  }

  size_t modules_unloaded = 0;
  for (size_t i = 0; i < zygisk_module_length; i++) {
    struct rezygisk_module *m = &zygisk_modules[i];

    if (FLAG_GET(ctx, APP_SPECIALIZE)) rz_module_call_post_app_specialize(m, ctx->args.app);
    else if (FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE)) rz_module_call_post_server_specialize(m, ctx->args.server);

    if (!m->unload) {
      if (m->android_linker_handle) {
        /* Android's linker owns this mapping. Keep it alive because module
           hooks may still point into it after post-specialize. */
        LOGD("Keeping Android-linker fallback module mapped: %s", rz_module_name(m));
        free(m->android_linker_path);
        m->android_linker_path = NULL;
      } else {
        LOGD("Abandoning module library at %p", &m->lib);
        csoloader_abandon(&m->lib);
      }

      continue;
    }

    if (m->android_linker_handle) {
      /* The module explicitly opted into the standard Zygisk unload contract,
         and its post-specialize callback has returned. Android's linker owns
         this handle, so it must also own the physical unmap. Keeping only a
         logical unload leaves file-backed VMAs visible in every target child. */
      const char *module_path = rz_module_name(m);
      dlerror();
      int unload_result = dlclose(m->android_linker_handle);
      const char *unload_error = unload_result == 0 ? NULL : dlerror();

      if (unload_result == 0) {
        LOGI("Unloaded Android-linker fallback module: %s", module_path);
        m->android_linker_handle = NULL;
        modules_unloaded++;
      } else {
        LOGE("Failed to unload Android-linker fallback module [%s]: %s",
             module_path, unload_error ? unload_error : "unknown linker error");
      }

      free(m->android_linker_path);
      m->android_linker_path = NULL;
      continue;
    }

    if (!csoloader_unload(&m->lib)) {
      LOGE("Failed to unload module library");

      continue;
    }

    modules_unloaded++;
  }

  if (zygisk_module_length > 0)
    LOGD("Modules unloaded: %zu/%zu", modules_unloaded, zygisk_module_length);

  /* system_server 在 post-specialize 之后仍需要 execmem 以支持 LSPlant/Dobby 等
     模块的运行时代码修改（hook 系统服务）。普通 App 必须永久撤销 carrier——
     不可信应用代码不得携带任何特权继续执行。 */
  bool is_system_server = FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE);
  if (!apatch_task_auth_end_callback(is_system_server)) {
    LOGE("APatch failed to close the post-specialize authorization window%s",
         is_system_server ? " (system_server persistent grant)" : "");
    _exit(127);
  }
}

static void rz_app_specialize_pre(struct zygisk_context *ctx) {
  FLAG_SET(ctx, APP_SPECIALIZE);

  /* INFO: Isolated services have different UIDs than the main apps. Because
              numerous root implementations base themselves in the UID of the
              app, we need to ensure that the UID sent to ReZygiskd to search
              is the app's and not the isolated service, or else it will be
              able to bypass DenyList.

           All apps, and isolated processes, of *third-party* applications will
             have their app_data_dir set. The system applications might not have
             one, however it is unlikely they will create an isolated process,
             and even if so, it should not impact in detections, performance or
             any area.
  */
  uid_t uid = *ctx->args.app->uid;
  if (IS_ISOLATED_SERVICE(uid) && ctx->args.app->app_data_dir) {
    /* INFO: If the app is an isolated service, we use the UID of the
               app's process data directory, which is the UID of the
               app itself, which root implementations actually use.
    */
    const char *data_dir = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, NULL);
    if (!data_dir) {
      LOGE("Failed to get app data directory");

      return;
    }

    struct stat st;
    if (stat(data_dir, &st) == -1) {
      PLOGE("Failed to stat app data directory [%s]", data_dir);

      (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, data_dir);

      return;
    }

    uid = st.st_uid;
    LOGD("Isolated service being related to UID %d, app data dir: %s", uid, data_dir);

    (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, data_dir);
  }

  ctx->info_flags = rezygiskd_get_process_flags(uid, ctx->process);
  /* INFO: To ensure we are really using a clean mount namespace, we use
              the first process it as reference for clean mount namespace,
              before it even does something, so that it will be clean yet
              with expected mounts.

           To avoid duplication, we will bypass this update_mnt_ns if we
             are going to execute it later, as the app will be in the
             denylist.
  */
  if ((ctx->info_flags & PROCESS_IS_FIRST_STARTED) == PROCESS_IS_FIRST_STARTED &&
      (ctx->info_flags & PROCESS_ON_DENYLIST) == 0 &&
      (ctx->info_flags & PROCESS_IS_MANAGER) == 0
  ) {
    update_mnt_ns(Clean, true);
  }

  if ((ctx->info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
    LOGD("Manager process detected. Notifying that Zygisk has been enabled.");


    /* INFO: This environment variable is related to Magisk Zygisk/Manager. It
               it used by Magisk's Zygisk to communicate to Magisk Manager whether
               Zygisk is working or not, allowing Zygisk modules to both work properly
               and for the manager to mark Zygisk as enabled.

             However, to enhance capabilities of root managers, it is also set for
               any other supported manager, so that, if they wish, they can recognize
               if Zygisk is enabled.
    */
    setenv("ZYGISK_ENABLED", "1", 1);
  }

  /* INFO: Modules only have two "start off" points from Zygisk, preSpecialize and
             postSpecialize. In preSpecialize, the process still has privileged
             permissions, and therefore can execute mount/umount/setns functions.
             If we update the mount namespace AFTER executing them, any mounts made
             will be lost, and the process will not have access to them anymore.

           In postSpecialize, while still could have its mounts modified with the
             assistance of a Zygisk companion, it will already have the mount
             namespace switched by then, so there won't be issues.

           Knowing this, we update the mns before execution, so that they can still
             make changes to mounts in DenyListed processes without being reverted.
  */
  bool in_denylist = (ctx->info_flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST;
  if (in_denylist) {
    FLAG_SET(ctx, DO_REVERT_UNMOUNT);
    update_mnt_ns(Clean, false);
  }

  /* INFO: Executed after setns to ensure a module can update the mounts of an
              application without worrying about it being overwritten by setns.
  */
  rz_run_modules_pre(ctx);

  /* INFO: The modules may request that although the process is NOT in
              the DenyList, it has its mount namespace switched to the clean
              one.

              So to ensure this behavior happens, we must also check after the
              modules are loaded and executed, so that the modules can have
              the chance to request it.
  */
  if (!in_denylist && FLAG_GET(ctx, DO_REVERT_UNMOUNT))
    update_mnt_ns(Clean, false);
}

static void rz_app_specialize_post(struct zygisk_context *ctx) {
  rz_run_modules_post(ctx);

  /* Domainless children may use the inherited control channel only while
     trusted Zygisk callbacks are executing. Do not expose it to app code. */
  rezygiskd_release_domainless_session_in_child();

  /* INFO: Allow the process name string to be released */
  (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->nice_name, ctx->process);
  g_ctx = NULL;
}

static void rz_nativeSpecializeAppProcess_pre(struct zygisk_context *ctx) {
  ctx->process = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->nice_name, NULL);
  LOGV("pre specialize [%s]", ctx->process);

  FLAG_SET(ctx, SKIP_FD_SANITIZATION);
  rz_app_specialize_pre(ctx);
}

static void rz_nativeSpecializeAppProcess_post(struct zygisk_context *ctx) {
  LOGV("post specialize [%s]", ctx->process);
  rz_app_specialize_post(ctx);
}

static void rz_nativeForkSystemServer_pre(struct zygisk_context *ctx) {
  LOGV("pre forkSystemServer");
  FLAG_SET(ctx, SERVER_FORK_AND_SPECIALIZE);

  rz_fork_pre(ctx);
  if (!is_zygote_child(ctx)) return;

  rz_run_modules_pre(ctx);

  rz_sanitize_fds(ctx);
}

static void rz_nativeForkSystemServer_post(struct zygisk_context *ctx) {
  if (ctx->pid == 0) {
    LOGV("post forkSystemServer");

    rz_run_modules_post(ctx);
    rezygiskd_release_domainless_session_in_child();
  }

  rz_fork_post(ctx);
}

static void rz_nativeForkAndSpecialize_pre(struct zygisk_context *ctx) {
  ctx->process = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->nice_name, NULL);
  LOGV("pre forkAndSpecialize [%s]", ctx->process);
  FLAG_SET(ctx, APP_FORK_AND_SPECIALIZE);

  rz_fork_pre(ctx);
  if (!is_zygote_child(ctx)) return;

  rz_app_specialize_pre(ctx);
  rz_sanitize_fds(ctx);
}

static void rz_nativeForkAndSpecialize_post(struct zygisk_context *ctx) {
  if (ctx->pid == 0) {
    LOGV("post forkAndSpecialize [%s]", ctx->process);
    rz_app_specialize_post(ctx);
  }

  rz_fork_post(ctx);
}

static void rz_init(struct zygisk_context *ctx, JNIEnv *env, void *args) {
  memset(ctx, 0, sizeof(struct zygisk_context));

  ctx->env = env;
  ctx->args.ptr = args;
  ctx->pid = -1;
  pthread_mutex_init(&ctx->hook_info_lock, NULL);

  g_ctx = ctx;
}

static void rz_cleanup(struct zygisk_context *ctx) {
  g_ctx = NULL;

  if (!is_zygote_child(ctx)) return;

  should_unmap_zygisk = true;

  /* INFO: Unhook JNI methods */
  for (size_t i = 0; i < jni_hook_list_count; i++) {
    struct jni_hook_entry *entry = &jni_hook_list[i];
    jclass jc = (*ctx->env)->FindClass(ctx->env, entry->class_name);
    if (jc) {
      if (entry->methods_count > 0 && (*ctx->env)->RegisterNatives(ctx->env, jc, entry->methods, (jint)entry->methods_count) != 0) {
        LOGE("Failed to restore JNI hook of class [%s]", entry->class_name);

        should_unmap_zygisk = false;
      }

      (*ctx->env)->DeleteLocalRef(ctx->env, jc);
    }

    free(entry->class_name);
    free(entry->methods);
  }

  free(jni_hook_list);
  jni_hook_list = NULL;
  jni_hook_list_count = 0;

  for (size_t i = 0; i < ctx->register_info_count; i++) {
    regfree(&ctx->register_info[i].regex);
    free(ctx->register_info[i].symbol);
  }
  ctx->register_info_count = 0;

  for (size_t i = 0; i < ctx->ignore_info_count; i++) {
    regfree(&ctx->ignore_info[i].regex);
    free(ctx->ignore_info[i].symbol);
  }
  ctx->ignore_info_count = 0;

  if (plt_hook_list) {
    for (size_t i = 0; i < plt_hook_list_count; i++) {
      free((void *)plt_hook_list[i].lib_path);
      free((void *)plt_hook_list[i].symbol);
    }

    free(plt_hook_list);
    plt_hook_list = NULL;
    plt_hook_list_count = 0;
  }

  /* INFO: Strip out all API function pointers */
  for (size_t i = 0; i < zygisk_module_length; i++) {
    memset(&zygisk_modules[i], 0, sizeof(zygisk_modules[i]));
  }

  enable_unloader = true;
  pthread_mutex_destroy(&ctx->hook_info_lock);
}

/* INFO: PLT hook commit helper */

static bool hook_register(const char *lib_name, const char *symbol, bool is_prefix, void *new_func, void **backup) {
  if (!(is_prefix ? plti_add_hook_by_prefix : plti_add_hook)(&plti_ctx, lib_name, symbol, new_func, backup)) {
    LOGE("Failed to register plt_hook \"%s\" with PLTI", symbol);

    return false;
  }

  LOGD("Registered plt_hook for symbol \"%s\" in library \"%s\"", symbol, lib_name);

  return true;
}

static bool hook_unregister(const char *lib_name, const char *symbol, bool is_prefix, void **backup) {
  if (!(is_prefix ? plti_remove_hook_by_prefix : plti_remove_hook)(&plti_ctx, lib_name, symbol, backup)) {
    LOGE("Failed to unregister plt_hook \"%s\" with PLTI", symbol);

    should_unmap_zygisk = false;

    return false;
  }

  LOGD("Unregistered plt_hook for symbol \"%s\" in library \"%s\"", symbol, lib_name);

  return true;
}

#define PLT_HOOK_REGISTER_SYM(LIB, SYM, NAME, IS_PREFIX)                       \
  hook_register(LIB, SYM, IS_PREFIX, (void *)new_##NAME, (void **)&old_##NAME)

#define PLT_HOOK_REGISTER(LIB, SYM, IS_PREFIX)     \
  PLT_HOOK_REGISTER_SYM(LIB, #SYM, SYM, IS_PREFIX)

#define PLT_HOOK_UNREGISTER_SYM(LIB, SYM, NAME, IS_PREFIX)   \
  hook_unregister(LIB, SYM, IS_PREFIX, (void **)&old_##NAME)

#define PLT_HOOK_UNREGISTER(LIB, SYM, IS_PREFIX)     \
  PLT_HOOK_UNREGISTER_SYM(LIB, #SYM, SYM, IS_PREFIX)

bool hook_functions(bool require_domainless_fd_hook) {
  plti_init(&plti_ctx);

  if (!plti_add_lib(&plti_ctx, "libandroid_runtime.so")) return false;

  bool fork_hooked = PLT_HOOK_REGISTER("libandroid_runtime.so", fork, false);
  bool readdir_hooked = PLT_HOOK_REGISTER("libandroid_runtime.so", readdir, false);
  if (require_domainless_fd_hook && (!fork_hooked || !readdir_hooked)) {
    /* A persistent daemon descriptor without both fork emulation and the
       precise FD-scan exclusion can make Android abort the Zygote. Roll back
       every hook installed so far and reject the injection before init runs. */
    if (readdir_hooked)
      PLT_HOOK_UNREGISTER("libandroid_runtime.so", readdir, false);
    if (fork_hooked)
      PLT_HOOK_UNREGISTER("libandroid_runtime.so", fork, false);
    return false;
  }
  PLT_HOOK_REGISTER("libandroid_runtime.so", strdup, false);
  PLT_HOOK_REGISTER("libandroid_runtime.so", property_get, false);
  PLT_HOOK_REGISTER_SYM("libandroid_runtime.so", "_ZNK18FileDescriptorInfo14ReopenOrDetach", _ZNK18FileDescriptorInfo14ReopenOrDetach, true);
  return true;
}

static void hook_unloader(void) {
  if (!plti_add_lib(&plti_ctx, "libart.so")) {
    LOGE("Failed to add libart.so to PLTI");

    return;
  }

  PLT_HOOK_REGISTER("libart.so", pthread_attr_setstacksize, false);

  PLT_HOOK_UNREGISTER("libandroid_runtime.so", property_get, false);

  /* Load modules once in Zygote so all children inherit the mappings. APatch's
     parent carrier opens a one-use task-local window for module relocations
     and constructors; the restored carrier itself cannot authorize access. */
  if (!apatch_task_auth_begin_callback()) {
    LOGE("Skipping Zygisk module load: APatch task-local authorization unavailable");
  } else if (!load_modules_only()) {
    LOGE("Failed to load modules in hook_unloader");
  }
  if (!apatch_task_auth_end_callback(true)) {
    LOGE("APatch failed to close the Zygisk module-load authorization window");
    _exit(127);
  }

  LOGD("ReZygisk unloader hooked successfully");
}

static void unhook_functions(void) {
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", fork, false);
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", readdir, false);
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", strdup, false);
  PLT_HOOK_UNREGISTER_SYM("libandroid_runtime.so", "_ZNK18FileDescriptorInfo14ReopenOrDetach", _ZNK18FileDescriptorInfo14ReopenOrDetach, true);
  PLT_HOOK_UNREGISTER("libart.so", pthread_attr_setstacksize, false);
}
