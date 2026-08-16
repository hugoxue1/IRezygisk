#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include <unistd.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "daemon.h"
#include "socket_utils.h"
#include "utils.h"

#include "monitor.h"

#define SOCKET_NAME "init_monitor"

#define STOPPED_WITH(sig, event) (WIFSTOPPED(sigchld_status) && (sigchld_status >> 8 == ((sig) | ((event) << 8))))

static bool update_status(const char *message);

const char *monitor_stop_reason = NULL;

struct environment_information {
  char *root_impl;
  char **modules;
  uint32_t modules_len;
};

static struct environment_information environment_information64;
static struct environment_information environment_information32;

enum ptracer_tracing_state {
  TRACING,
  STOPPING,
  STOPPED,
  EXITING
};

enum ptracer_tracing_state tracing_state = TRACING;
static bool domainless_monitor_active = false;

struct rezygiskd_status {
  bool supported;
  bool zygote_injected;
  bool daemon_running;
  pid_t daemon_pid;
  char *daemon_info;
  char *daemon_error_info;
};

struct rezygiskd_status status64 = {
  .supported = false,
  .zygote_injected = false,
  .daemon_running = false,
  .daemon_pid = -1,
  .daemon_info = NULL,
  .daemon_error_info = NULL
};
struct rezygiskd_status status32 = {
  .supported = false,
  .zygote_injected = false,
  .daemon_running = false,
  .daemon_pid = -1,
  .daemon_info = NULL,
  .daemon_error_info = NULL
};

int monitor_epoll_fd;
bool monitor_events_running = true;
typedef void (*monitor_event_callback_t)();

bool monitor_events_init() {
  monitor_epoll_fd = epoll_create(1);
  if (monitor_epoll_fd == -1) {
    PLOGE("epoll_create");

    return false;
  }

  return true;
}

bool monitor_events_register_event(monitor_event_callback_t event_cb, int fd, uint32_t events) {
  struct epoll_event ev = {
    .data.ptr = (void *)event_cb,
    .events = events
  };

  if (epoll_ctl(monitor_epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    PLOGE("epoll_ctl");

    return false;
  }

  return true;
}

void monitor_events_stop() {
  monitor_events_running = false;
}

void monitor_events_loop() {
  struct epoll_event events[2];
  while (monitor_events_running) {
    int nfds = epoll_wait(monitor_epoll_fd, events, 2, -1);
    if (nfds == -1 && errno != EINTR) {
      PLOGE("epoll_wait");

      monitor_events_running = false;

      break;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].events & (EPOLLERR | EPOLLHUP)) {
        LOGE("Failed event on fd %d: %s", ((struct epoll_event *)&events[i])->data.fd, strerror(errno));

        monitor_events_running = false;

        break;
      }

      ((monitor_event_callback_t)events[i].data.ptr)();

      if (!monitor_events_running) break;
    }
  }

  if (monitor_epoll_fd >= 0) close(monitor_epoll_fd);
  monitor_epoll_fd = -1;
}

int monitor_sock_fd;

bool rezygiskd_listener_init() {
  monitor_sock_fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (monitor_sock_fd == -1) {
    PLOGE("socket create");

    return false;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };

  size_t sun_path_len = sprintf(addr.sun_path, "%s/%s", rezygiskd_get_path(), SOCKET_NAME);

  socklen_t socklen = sizeof(sa_family_t) + sun_path_len;
  if (bind(monitor_sock_fd, (struct sockaddr *)&addr, socklen) == -1) {
    PLOGE("bind socket");

    return false;
  }

  return true;
}

void rezygiskd_listener_callback() {
  while (1) {
    uint8_t cmd;
    ssize_t nread = TEMP_FAILURE_RETRY(read(monitor_sock_fd, &cmd, sizeof(cmd)));
    if (nread == -1) {
      if (errno == EINTR || errno == EWOULDBLOCK) break;

      PLOGE("read socket");

      continue;
    }

    switch (cmd) {
      case START: {
        if (tracing_state == STOPPING) {
          LOGI("Continue tracing init");

          tracing_state = TRACING;
        } else if (tracing_state == STOPPED) {
          LOGI(domainless_monitor_active ? "Start direct Zygote discovery" : "Start tracing init");

          if (!domainless_monitor_active) ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK);

          tracing_state = TRACING;
        }

        update_status(NULL);

        break;
      }
      case STOP: {
        if (tracing_state == TRACING) {
          LOGI("Stop tracing requested");

          tracing_state = domainless_monitor_active ? STOPPED : STOPPING;
          monitor_stop_reason = "user requested";

          if (!domainless_monitor_active) ptrace(PTRACE_INTERRUPT, 1, 0, 0);
          update_status(NULL);
        }

        break;
      }
      case EXIT: {
        LOGI("Prepare for exit ...");

        tracing_state = EXITING;
        monitor_stop_reason = "user requested";

        update_status(NULL);
        monitor_events_stop();

        break;
      }
      case ZYGOTE64_INJECTED:
      case ZYGOTE32_INJECTED: {
        LOGI("Received Zygote%s injected command", cmd == ZYGOTE64_INJECTED ? "64" : "32");

        struct rezygiskd_status *status = cmd == ZYGOTE64_INJECTED ? &status64 : &status32;
        status->zygote_injected = true;

        update_status(NULL);

        break;
      }
      case DAEMON64_SET_INFO:
      case DAEMON32_SET_INFO: {
        LOGD("Received ReZygiskd%s info", cmd == DAEMON64_SET_INFO ? "64" : "32");

        struct rezygiskd_status *daemon_status =
          cmd == DAEMON64_SET_INFO ? &status64 : &status32;

        uint32_t root_impl_len;
        if (read_uint32_t(monitor_sock_fd, &root_impl_len) != sizeof(root_impl_len)) {
          LOGE("read ReZygiskd%s root impl len", cmd == DAEMON64_SET_INFO ? "64" : "32");

          break;
        }

        struct environment_information *environment_information = cmd == DAEMON64_SET_INFO ? &environment_information64 : &environment_information32;
        if (environment_information->root_impl) {
          LOGD("freeing old ReZygiskd%s root impl", cmd == DAEMON64_SET_INFO ? "64" : "32");

          free((void *)environment_information->root_impl);
          environment_information->root_impl = NULL;
        }

        environment_information->root_impl = malloc(root_impl_len + 1);
        if (environment_information->root_impl == NULL) {
          PLOGE("malloc ReZygiskd%s root impl", cmd == DAEMON64_SET_INFO ? "64" : "32");

          break;
        }

        if (read_loop(monitor_sock_fd, (void *)environment_information->root_impl, root_impl_len) != (ssize_t)root_impl_len) {
          LOGE("read ReZygiskd%s root impl", cmd == DAEMON64_SET_INFO ? "64" : "32");

          free((void *)environment_information->root_impl);
          environment_information->root_impl = NULL;

          break;
        }

        environment_information->root_impl[root_impl_len] = '\0';
        LOGD("ReZygiskd%s root impl: %s", cmd == DAEMON64_SET_INFO ? "64" : "32", environment_information->root_impl);

        if (read_uint32_t(monitor_sock_fd, &environment_information->modules_len) != sizeof(environment_information->modules_len)) {
          LOGE("read ReZygiskd%s modules len", cmd == DAEMON64_SET_INFO ? "64" : "32");

          free((void *)environment_information->root_impl);
          environment_information->root_impl = NULL;

          break;
        }

        if (environment_information->modules) {
          LOGD("freeing old ReZygiskd%s modules", cmd == DAEMON64_SET_INFO ? "64" : "32");

          for (size_t i = 0; i < environment_information->modules_len; i++) {
            free((void *)environment_information->modules[i]);
          }

          free((void *)environment_information->modules);
          environment_information->modules = NULL;
        }

        environment_information->modules = malloc(environment_information->modules_len * sizeof(char *));
        if (environment_information->modules == NULL) {
          PLOGE("malloc ReZygiskd%s modules", cmd == DAEMON64_SET_INFO ? "64" : "32");

          free((void *)environment_information->root_impl);
          environment_information->root_impl = NULL;

          break;
        }

        bool info_complete = true;
        for (size_t i = 0; i < environment_information->modules_len; i++) {
          uint32_t module_name_len;
          if (read_uint32_t(monitor_sock_fd, &module_name_len) != sizeof(module_name_len)) {
            LOGE("read ReZygiskd%s module name len", cmd == DAEMON64_SET_INFO ? "64" : "32");

            goto set_info_modules_cleanup;
          }

          environment_information->modules[i] = malloc(module_name_len + 1);
          if (environment_information->modules[i] == NULL) {
            PLOGE("malloc ReZygiskd%s module name", cmd == DAEMON64_SET_INFO ? "64" : "32");

            goto set_info_modules_cleanup;
          }

          if (read_loop(monitor_sock_fd, (void *)environment_information->modules[i], module_name_len) != (ssize_t)module_name_len) {
            LOGE("read ReZygiskd%s module name", cmd == DAEMON64_SET_INFO ? "64" : "32");

            goto set_info_modules_cleanup;
          }

          environment_information->modules[i][module_name_len] = '\0';
          LOGD("ReZygiskd%s module %zu: %s", cmd == DAEMON64_SET_INFO ? "64" : "32", i, environment_information->modules[i]);

          continue;

          set_info_modules_cleanup:
            info_complete = false;
            free((void *)environment_information->root_impl);
            environment_information->root_impl = NULL;

            for (size_t j = 0; j < i; j++) {
              free((void *)environment_information->modules[j]);
            }

            free((void *)environment_information->modules);
            environment_information->modules = NULL;

            break;
        }

        if (info_complete) {
          daemon_status->daemon_running = true;
          LOGI("ReZygiskd%s readiness confirmed", cmd == DAEMON64_SET_INFO ? "64" : "32");
        }

        update_status(NULL);

        break;
      }
      case DAEMON64_SET_ERROR_INFO:
      case DAEMON32_SET_ERROR_INFO: {
        LOGD("Received ReZygiskd%s error info", cmd == DAEMON64_SET_ERROR_INFO ? "64" : "32");

        uint32_t error_info_len;
        if (read_uint32_t(monitor_sock_fd, &error_info_len) != sizeof(error_info_len)) {
          LOGE("read ReZygiskd%s error info len", cmd == DAEMON64_SET_ERROR_INFO ? "64" : "32");

          break;
        }

        struct rezygiskd_status *status = cmd == DAEMON64_SET_ERROR_INFO ? &status64 : &status32;
        if (status->daemon_error_info) {
          LOGD("freeing old ReZygiskd%s error info", cmd == DAEMON64_SET_ERROR_INFO ? "64" : "32");

          free(status->daemon_error_info);
          status->daemon_error_info = NULL;
        }

        status->daemon_error_info = malloc(error_info_len + 1);
        if (status->daemon_error_info == NULL) {
          PLOGE("malloc ReZygiskd%s error info", cmd == DAEMON64_SET_ERROR_INFO ? "64" : "32");

          break;
        }

        if (read_loop(monitor_sock_fd, status->daemon_error_info, error_info_len) != (ssize_t)error_info_len) {
          LOGE("read ReZygiskd%s error info", cmd == DAEMON64_SET_ERROR_INFO ? "64" : "32");

          free(status->daemon_error_info);
          status->daemon_error_info = NULL;

          break;
        }

        status->daemon_error_info[error_info_len] = '\0';
        LOGD("ReZygiskd%s error info: %s", cmd == DAEMON64_SET_ERROR_INFO ? "64" : "32", status->daemon_error_info);

        update_status(NULL);

        break;
      }
    }
  }
}

void rezygiskd_listener_stop() {
  if (monitor_sock_fd >= 0) close(monitor_sock_fd);
  monitor_sock_fd = -1;
}

#define MAX_RETRY_COUNT 5

#define CREATE_ZYGOTE_START_COUNTER(abi)             \
  struct timespec last_zygote##abi = {               \
    .tv_sec = 0,                                     \
    .tv_nsec = 0                                     \
  };                                                 \
                                                     \
  int count_zygote ## abi = 0;                       \
  bool should_stop_inject ## abi() {                 \
    struct timespec now = {};                        \
    clock_gettime(CLOCK_MONOTONIC, &now);            \
    if (now.tv_sec - last_zygote ## abi.tv_sec < 30) \
      count_zygote ## abi++;                         \
    else                                             \
      count_zygote ## abi = 0;                       \
                                                     \
    last_zygote##abi = now;                          \
                                                     \
    return count_zygote##abi >= MAX_RETRY_COUNT;     \
  }

CREATE_ZYGOTE_START_COUNTER(64)
CREATE_ZYGOTE_START_COUNTER(32)

static bool ensure_daemon_created(bool is_64bit) {
  struct rezygiskd_status *status = is_64bit ? &status64 : &status32;
  if (status->daemon_pid != -1) {
    if (status->daemon_running)
      LOGI("ReZygiskd%s ready", is_64bit ? "64" : "32");

    return status->daemon_running;
  }

  pid_t pid = fork();
  if (pid < 0) {
    PLOGE("create ReZygiskd%s", is_64bit ? "64" : "32");

    return false;
  }

  if (pid == 0) {
    char daemon_name[PATH_MAX] = "./bin/zygiskd";
    strcat(daemon_name, is_64bit ? "64" : "32");

    execl(daemon_name, daemon_name, NULL);

    PLOGE("exec ReZygiskd%s failed", is_64bit ? "64" : "32");

    exit(1);
  }

  status->supported = true;
  status->daemon_pid = pid;
  /* Legacy mode historically treats a successful fork as sufficient.  The
     APatch domainless path has a stricter boundary: do not authorize or stop
     a booting Zygote until the daemon has completed namespace/root/module
     setup and sent DAEMON*_SET_INFO back to this monitor. */
  status->daemon_running = !domainless_monitor_active;
  if (domainless_monitor_active) {
    LOGI("ReZygiskd%s launch requested (pid %d); waiting for readiness",
         is_64bit ? "64" : "32", pid);
  }

  return status->daemon_running;
}

#define CHECK_DAEMON_EXIT(abi)                                    \
  if (status##abi.supported && pid == status##abi.daemon_pid) {   \
    char status_str[64];                                          \
    parse_status(sigchld_status, status_str, sizeof(status_str)); \
                                                                  \
    LOGW("daemon" #abi " pid %d exited: %s", pid, status_str);    \
    status##abi.daemon_running = false;                           \
                                                                  \
    if (!status##abi.daemon_error_info) {                         \
      status##abi.daemon_error_info = strdup(status_str);         \
      if (!status##abi.daemon_error_info) {                       \
        LOGE("malloc daemon" #abi " error info failed");          \
                                                                  \
        return;                                                   \
      }                                                           \
    }                                                             \
                                                                  \
    continue;                                                     \
  }

#define APP_PROCESS "/system/bin/app_process"
#define APP_PROCESS_64 APP_PROCESS "64"
#define APP_PROCESS_32 APP_PROCESS "32"

#define PRE_INJECT(abi, is_64)                                        \
  if (strcmp(program, APP_PROCESS_ ## abi) == 0) {                    \
    tracer = "./bin/zygisk-ptrace" # abi;                             \
    is_tango = false;                                                 \
                                                                      \
    if (should_stop_inject ## abi()) {                                \
      LOGW("Zygote" # abi " restart too much times, stop injecting"); \
                                                                      \
      tracing_state = STOPPING;                                       \
      monitor_stop_reason = "Zygote crashed";                         \
      ptrace(PTRACE_INTERRUPT, 1, 0, 0);                              \
                                                                      \
      break;                                                          \
    }                                                                 \
                                                                      \
    if (!ensure_daemon_created(is_64)) {                              \
      LOGW("ReZygiskd " #abi "-bit not running, stop injecting");     \
                                                                      \
      tracing_state = STOPPING;                                       \
      monitor_stop_reason = "ReZygiskd not running";                  \
      ptrace(PTRACE_INTERRUPT, 1, 0, 0);                              \
                                                                      \
      break;                                                          \
    }                                                                 \
  }

#define PRE_INJECT_TANGO                                           \
  if (strcmp(program, "/system_ext/bin/tango_translator") == 0) {  \
    tracer = "./bin/zygisk-ptrace32";                              \
    is_tango = true;                                               \
                                                                   \
    if (should_stop_inject32()) {                                  \
      LOGW("Tango restart too many times, stop injecting");        \
                                                                   \
      tracing_state = STOPPING;                                    \
      monitor_stop_reason = "Zygote crashed";                      \
      ptrace(PTRACE_INTERRUPT, 1, 0, 0);                           \
                                                                   \
      break;                                                       \
    }                                                              \
                                                                   \
    if (!ensure_daemon_created(false)) {                           \
      LOGW("ReZygiskd 32-bit not running, stop injecting");        \
                                                                   \
      tracing_state = STOPPING;                                    \
      monitor_stop_reason = "ReZygiskd not running";               \
      ptrace(PTRACE_INTERRUPT, 1, 0, 0);                           \
                                                                   \
      break;                                                       \
    }                                                              \
  }

int sigchld_signal_fd;
struct signalfd_siginfo sigchld_fdsi;
int sigchld_status;

pid_t *sigchld_process;
size_t sigchld_process_count = 0;

static bool claim_init_tracer() {
  if (ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK) == -1) {
    /* INFO: In cases where, for example, 2 ReZygisks were executed, the second
               process won't be able to seize init due to limitations of ptrace.
               In this case, we should just exit the second process to avoid
               conflicts. */
    if (errno == EPERM) {
      LOGW("Another process is already tracing init");

      update_status("❌ Multiple Zygisks functioning");
    } else {
      PLOGE("failed to seize init");
    }

    return false;
  }

  return true;
}

bool sigchld_listener_init() {
  sigchld_process = NULL;

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    PLOGE("set sigprocmask");

    return false;
  }

  sigchld_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sigchld_signal_fd == -1) {
    PLOGE("create signalfd");

    return false;
  }

  return true;
}

void sigchld_listener_callback() {
  while (1) {
    ssize_t s = read(sigchld_signal_fd, &sigchld_fdsi, sizeof(sigchld_fdsi));
    if (s == -1) {
      if (errno == EAGAIN) break;

      PLOGE("read signalfd");

      continue;
    }

    if (s != sizeof(sigchld_fdsi)) {
      LOGE("read %zu != %zu", s, sizeof(sigchld_fdsi));

      continue;
    }

    if (sigchld_fdsi.ssi_signo != SIGCHLD) {
      LOGE("No sigchld received");

      continue;
    }

    int pid;
    while ((pid = waitpid(-1, &sigchld_status, __WALL | WNOHANG)) != 0) {
      if (pid == -1) {
        /* ECHILD only means the current queue is drained.  The domainless
           monitor does not keep PID 1 seized, so this is the normal state
           after a short-lived daemon/tracer child exits.  Falling through
           with pid == -1 would spin forever and misclassify it as a child. */
        if (errno != ECHILD) PLOGE("waitpid");
        break;
      }

      if (pid == 1) {
        if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_FORK)) {
          long child_pid;

          ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid);

          LOGV("Forked %ld", child_pid);
        } else if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP) && tracing_state == STOPPING) {
          if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("failed to detach init");

          tracing_state = STOPPED;

          LOGI("Stopped tracing init");

          continue;
        }

        if (WIFSTOPPED(sigchld_status)) {
          if (WPTEVENT(sigchld_status) == 0) {
            if (WSTOPSIG(sigchld_status) != SIGSTOP && WSTOPSIG(sigchld_status) != SIGTSTP && WSTOPSIG(sigchld_status) != SIGTTIN && WSTOPSIG(sigchld_status) != SIGTTOU) {
              LOGW("Injecting signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));

              ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(sigchld_status));

              continue;
            } else {
              LOGW("Suppressing stop signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));
            }
          }

          ptrace(PTRACE_CONT, pid, 0, 0);
        }

        continue;
      }

      CHECK_DAEMON_EXIT(64)
      CHECK_DAEMON_EXIT(32)

      pid_t state = 0;
      for (size_t i = 0; i < sigchld_process_count; i++) {
        if (sigchld_process[i] != pid) continue;

        state = sigchld_process[i];

        break;
      }

      if (state == 0) {
        LOGV("New process %d attached", pid);

        for (size_t i = 0; i < sigchld_process_count; i++) {
          if (sigchld_process[i] != 0) continue;

          sigchld_process[i] = pid;

          goto ptrace_process;
        }

        pid_t *new_sigchld_process = (pid_t *)realloc(sigchld_process, sizeof(pid_t) * (sigchld_process_count + 1));
        if (new_sigchld_process == NULL) {
          PLOGE("realloc sigchld_process");

          continue;
        }
        sigchld_process = new_sigchld_process;

        sigchld_process[sigchld_process_count] = pid;
        sigchld_process_count++;

        ptrace_process:

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
        ptrace(PTRACE_CONT, pid, 0, 0);

        continue;
      } else {
        if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_EXEC)) {
          char program[PATH_MAX];
          if (get_program(pid, program, sizeof(program)) == -1) {
            LOGW("failed to get program %d", pid);

            continue;
          }

          LOGV("%d program %s", pid, program);

          const char *tracer = NULL;
          bool is_tango = false;

          do {
            if (tracing_state != TRACING) {
              LOGD("Stopped injecting %d because status is not set to tracing", pid);

              break;
            }

            PRE_INJECT(64, true)
            PRE_INJECT(32, false)
            PRE_INJECT_TANGO

            if (tracer != NULL) {
              LOGD("Stopping %d (program: %s, tracer: %s, tango: %s)", pid, program, tracer, is_tango ? "yes" : "no");

              kill(pid, SIGSTOP);
              ptrace(PTRACE_CONT, pid, 0, 0);
              waitpid(pid, &sigchld_status, __WALL);

              if (!STOPPED_WITH(SIGSTOP, 0)) {
                LOGE("Failed to stop process %d", pid);

                break;
              }

              LOGD("Detaching %d", pid);
              ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);

              {
                sigchld_status = 0;
                int p = fork_dont_care();

                if (p == 0) {
                  char pid_str[32];
                  sprintf(pid_str, "%d", pid);

                  LOGI("exec tracer command: %s trace %s --restart%s", tracer, pid_str, is_tango ? " --tango" : "");

                  /* INFO: Only restart companions if it's not the first time */
                  if ((strcmp(program, APP_PROCESS_64) == 0 && count_zygote64 > 1) || ((strcmp(program, APP_PROCESS_32) == 0 || is_tango) && count_zygote32 > 1)) {
                    if (is_tango) {
                      execl(tracer, basename(tracer), "trace", pid_str, "--restart", "--tango", NULL);
                    } else {
                      execl(tracer, basename(tracer), "trace", pid_str, "--restart", NULL);
                    }
                  } else {
                    if (is_tango) {
                      execl(tracer, basename(tracer), "trace", pid_str, "--tango", NULL);
                    } else {
                      execl(tracer, basename(tracer), "trace", pid_str, NULL);
                    }
                  }

                  PLOGE("exec");

                  kill(pid, SIGKILL);
                  exit(1);
                } else if (p == -1) {
                  PLOGE("fork");

                  kill(pid, SIGKILL);
                }
              }
            }
          } while (false);
        } else {
          char status_str[64];
          parse_status(sigchld_status, status_str, sizeof(status_str));

          LOGW("process %d received unknown sigchld_status %s", pid, status_str);
        }

        for (size_t i = 0; i < sigchld_process_count; i++) {
          if (sigchld_process[i] != pid) continue;

          sigchld_process[i] = 0;

          break;
        }

        if (WIFSTOPPED(sigchld_status)) {
          LOGV("detach process %d", pid);

          ptrace(PTRACE_DETACH, pid, 0, 0);
        }
      }
    }
  }
}

void sigchld_listener_stop() {
  if (sigchld_signal_fd >= 0) close(sigchld_signal_fd);
  sigchld_signal_fd = -1;

  if (sigchld_process != NULL) free(sigchld_process);
  sigchld_process = NULL;
  sigchld_process_count = 0;
}

static char pre_section[1024];
static char post_section[1024];

#define WRITE_STATUS_ABI(suffix)                                                     \
  if (status ## suffix.supported) {                                                  \
    strcat(status_text, ", ReZygisk " # suffix "-bit: ");                            \
                                                                                     \
    if (tracing_state != TRACING) strcat(status_text, "❌");                         \
    else if (status ## suffix.zygote_injected && status ## suffix.daemon_running)    \
      strcat(status_text, "✅");                                                     \
    else strcat(status_text, "⚠️");                                                  \
                                                                                     \
    if (!status ## suffix.daemon_running) {                                          \
      if (status ## suffix.daemon_error_info) {                                      \
        strcat(status_text, "(ReZygiskd: ");                                         \
        strcat(status_text, status ## suffix.daemon_error_info);                     \
        strcat(status_text, ")");                                                    \
      } else {                                                                       \
        strcat(status_text, "(ReZygiskd: not running)");                             \
      }                                                                              \
    }                                                                                \
  }

static bool update_status(const char *message) {
  FILE *prop = fopen("/data/adb/modules/rezygisk/module.prop", "w");
  if (prop == NULL) {
    PLOGE("failed to open prop");

    return false;
  }

  if (message) {
    fprintf(prop, "%s[%s] %s", pre_section, message, post_section);
    fclose(prop);

    return true;
  }

  char status_text[256] = "Monitor: ";
  switch (tracing_state) {
    case TRACING: {
      strcat(status_text, "✅");

      break;
    }
    case STOPPING: [[fallthrough]];
    case STOPPED: {
      strcat(status_text, "⛔");

      break;
    }
    case EXITING: {
      strcat(status_text, "❌");

      break;
    }
  }

  WRITE_STATUS_ABI(64)
  WRITE_STATUS_ABI(32)

  fprintf(prop, "%s[%s] %s", pre_section, status_text, post_section);
  fclose(prop);

  if (environment_information64.root_impl || environment_information32.root_impl) {
    FILE *json = fopen("/data/adb/rezygisk/state.json", "w");
    if (json == NULL) {
      PLOGE("failed to open state.json");

      return false;
    }

    fprintf(json, "{\n");
    fprintf(json, "  \"root\": \"%s\",\n", environment_information64.root_impl ? environment_information64.root_impl : environment_information32.root_impl);

    fprintf(json, "  \"monitor\": {\n");
    fprintf(json, "    \"state\": \"%d\"", tracing_state);
    if (monitor_stop_reason) fprintf(json, ",\n    \"reason\": \"%s\"\n", monitor_stop_reason);
    else fprintf(json, "\n");

    if (status64.supported || status32.supported)
      fprintf(json, "  },\n");
    else
      fprintf(json, "  }\n");


    if (status64.supported || status32.supported) {
      fprintf(json, "  \"rezygiskd\": {\n");
      if (status64.supported) {
        fprintf(json, "    \"64\": {\n");
        fprintf(json, "      \"state\": %d,\n", status64.daemon_running);
        if (status64.daemon_error_info) fprintf(json, "      \"reason\": \"%s\",\n", status64.daemon_error_info);
        fprintf(json, "      \"modules\": [");

        if (environment_information64.modules) for (uint32_t i = 0; i < environment_information64.modules_len; i++) {
          if (i > 0) fprintf(json, ", ");
          fprintf(json, "\"%s\"", environment_information64.modules[i]);
        }

        fprintf(json, "]\n");
        fprintf(json, "    }");
        if (status32.supported) fprintf(json, ",\n");
        else fprintf(json, "\n");
      }

      if (status32.supported) {
        fprintf(json, "    \"32\": {\n");
        fprintf(json, "      \"state\": %d,\n", status32.daemon_running);
        if (status32.daemon_error_info) fprintf(json, "      \"reason\": \"%s\",\n", status32.daemon_error_info);
        fprintf(json, "      \"modules\": [");

        if (environment_information32.modules) for (uint32_t i = 0; i < environment_information32.modules_len; i++) {
          if (i > 0) fprintf(json, ", ");
          fprintf(json, "\"%s\"", environment_information32.modules[i]);
        }

        fprintf(json, "]\n");
        fprintf(json, "    }\n");
      }

      fprintf(json, "  },\n");

      fprintf(json, "  \"zygote\": {\n");
      if (status64.supported) {
        fprintf(json, "    \"64\": %d", status64.zygote_injected);
        if (status32.supported && status32.zygote_injected) fprintf(json, ",\n");
        else fprintf(json, "\n");
      }
      if (status32.supported && status32.zygote_injected) {
        fprintf(json, "    \"32\": %d\n", status32.zygote_injected);
      }
      fprintf(json, "  }\n");
    }

    fprintf(json, "}\n");

    fclose(json);
  } else {
    if (remove("/data/adb/rezygisk/state.json") == -1 && errno != ENOENT) {
      PLOGE("failed to remove state.json");
    }
  }

  LOGI("status updated: %s", status_text);

  return true;
}

static bool prepare_environment() {
  FILE *orig_prop = fopen("/data/adb/modules/rezygisk/module.prop", "r");
  if (orig_prop == NULL) {
    PLOGE("failed to open orig prop");

    return false;
  }

  bool after_description = false;

  char line[1024];
  while (fgets(line, sizeof(line), orig_prop) != NULL) {
    if (strncmp(line, "description=", strlen("description=")) == 0) {
      strcat(pre_section, "description=");
      strcat(post_section, line + strlen("description="));
      after_description = true;

      continue;
    }

    if (after_description) strcat(post_section, line);
    else strcat(pre_section, line);
  }

  fclose(orig_prop);

  return true;
}

#define DOMAINLESS_BROKER_FD_ENV "APATCH_EARLY_LOADER_FD"
#define DOMAINLESS_MAX_TARGETS 64
#define DOMAINLESS_DISCOVERY_BURST_US 2000
#define DOMAINLESS_DISCOVERY_WARM_US 5000
#define DOMAINLESS_DISCOVERY_IDLE_US 20000
#define DOMAINLESS_AUTH_TIMEOUT_MS 750
#define DOMAINLESS_TRACE_TIMEOUT_MS 5500

static pid_t domainless_targets[DOMAINLESS_MAX_TARGETS];
static bool domainless_target_is64[DOMAINLESS_MAX_TARGETS];
static bool domainless_expect64 = false;
static bool domainless_expect32 = false;

struct domainless_zygote_service {
  const char *name;
  const char *debug_pid_prop;
  bool is_64bit;
  pid_t completed_pid;
  bool rendezvous_consumed;
};

static struct domainless_zygote_service domainless_services[2];
static size_t domainless_service_count = 0;

static bool domainless_read_line(int fd, char *buf, size_t size) {
  if (size == 0) return false;

  size_t used = 0;
  while (used + 1 < size) {
    char c;
    ssize_t nread = read(fd, &c, 1);
    if (nread == -1 && errno == EINTR) continue;
    if (nread != 1) return false;
    if (c == '\n') break;

    buf[used++] = c;
  }

  buf[used] = '\0';
  return true;
}

static int domainless_open_broker() {
  const char *raw_fd = getenv(DOMAINLESS_BROKER_FD_ENV);
  if (raw_fd == NULL || *raw_fd == '\0') {
    LOGE("%s is missing", DOMAINLESS_BROKER_FD_ENV);

    return -1;
  }

  char *end = NULL;
  errno = 0;
  long parsed = strtol(raw_fd, &end, 10);
  if (errno != 0 || end == raw_fd || *end != '\0' || parsed < 3 || parsed > INT_MAX) {
    LOGE("invalid %s value", DOMAINLESS_BROKER_FD_ENV);

    return -1;
  }

  int fd = (int)parsed;
  if (dprintf(fd, "READY 1\n") < 0) {
    PLOGE("send READY to APatch early-loader broker");

    return -1;
  }

  char response[128];
  if (!domainless_read_line(fd, response, sizeof(response)) || strcmp(response, "OK READY") != 0) {
    LOGE("APatch early-loader broker rejected READY");

    return -1;
  }

  /* The monitor keeps this descriptor, but its tracer and daemon exec children
     must not inherit it and accidentally keep the APD broker alive. */
  int flags = fcntl(fd, F_GETFD);
  if (flags != -1) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

  return fd;
}

static bool domainless_stage_target(int broker_fd, const char *service, pid_t pid,
                                    bool is_64bit, uint32_t *ticket) {
  LOGI("Requesting APatch pre-exec self-claim ticket for %s/Zygote%s target %d",
       service, is_64bit ? "64" : "32", pid);
  if (dprintf(broker_fd, "STAGE_PREEXEC_ZYGOTE %s %d %d\n",
              service, pid, is_64bit ? 64 : 32) < 0) {
    PLOGE("request Zygote authorization ticket");

    return false;
  }

  struct pollfd response_poll = {
    .fd = broker_fd,
    .events = POLLIN | POLLHUP
  };
  int ready;
  do {
    ready = poll(&response_poll, 1, DOMAINLESS_AUTH_TIMEOUT_MS);
  } while (ready == -1 && errno == EINTR);
  if (ready <= 0 || !(response_poll.revents & (POLLIN | POLLHUP))) {
    if (ready == 0) LOGE("APatch authorization staging timed out for Zygote %d", pid);
    else PLOGE("wait for APatch authorization staging of Zygote %d", pid);
    monitor_stop_reason = "APatch authorization staging unavailable";
    tracing_state = STOPPED;
    update_status(NULL);

    return false;
  }

  char response[128];
  if (!domainless_read_line(broker_fd, response, sizeof(response))) {
    LOGE("APatch early-loader broker disconnected");

    return false;
  }

  int response_pid = -1;
  unsigned response_ticket = 0;
  char response_service[32] = { 0 };
  char trailing = '\0';
  if (sscanf(response, "STAGED %31s %d %u %c", response_service, &response_pid,
             &response_ticket, &trailing) != 3 ||
      strcmp(response_service, service) != 0 || response_pid != pid ||
      response_ticket == 0 || response_ticket > INT32_MAX) {
    LOGW("APatch denied Zygote %d authorization staging: %s", pid, response);

    return false;
  }

  *ticket = (uint32_t)response_ticket;
  return true;
}

static bool domainless_release_target(int broker_fd, const char *service, pid_t pid, bool success) {
  if (dprintf(broker_fd, "RELEASE_PREEXEC_ZYGOTE %s %d %s\n",
              service, pid, success ? "OK" : "FAIL") < 0) {
    PLOGE("request APatch Zygote rendezvous release");
    kill(pid, SIGCONT);
    return false;
  }

  struct pollfd response_poll = {
    .fd = broker_fd,
    .events = POLLIN | POLLHUP
  };
  int ready;
  do {
    ready = poll(&response_poll, 1, DOMAINLESS_AUTH_TIMEOUT_MS);
  } while (ready == -1 && errno == EINTR);
  if (ready <= 0 || !(response_poll.revents & (POLLIN | POLLHUP))) {
    LOGE("APatch rendezvous release timed out for %s/%d", service, pid);
    kill(pid, SIGCONT);
    return false;
  }

  char response[128];
  char response_service[32] = { 0 };
  int response_pid = -1;
  char trailing = '\0';
  if (!domainless_read_line(broker_fd, response, sizeof(response)) ||
      sscanf(response, "RELEASED %31s %d %c", response_service, &response_pid, &trailing) != 2 ||
      strcmp(response_service, service) != 0 || response_pid != pid) {
    LOGE("APatch rejected rendezvous release for %s/%d: %s", service, pid, response);
    kill(pid, SIGCONT);
    return false;
  }
  return true;
}

static bool domainless_target_seen(pid_t pid) {
  for (size_t i = 0; i < DOMAINLESS_MAX_TARGETS; i++) {
    if (domainless_targets[i] == pid) return true;
  }

  return false;
}

static bool domainless_remember_target(pid_t pid, bool is_64bit) {
  for (size_t i = 0; i < DOMAINLESS_MAX_TARGETS; i++) {
    if (domainless_targets[i] != 0) continue;

    domainless_targets[i] = pid;
    domainless_target_is64[i] = is_64bit;
    return true;
  }

  LOGE("domainless target table is full");
  return false;
}

static bool domainless_target_is_current_and_live(pid_t pid, bool is_64bit) {
  char stat_path[64];
  snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
  FILE *stat_file = fopen(stat_path, "re");
  if (stat_file == NULL) return false;

  char stat_line[1024];
  bool live = false;
  if (fgets(stat_line, sizeof(stat_line), stat_file) != NULL) {
    /* comm is parenthesized and may contain spaces; state is the byte after
       the final ') '. kill(pid, 0) still succeeds for a zombie, which caused
       i13 to report an injected process after init had already replaced it. */
    char *comm_end = strrchr(stat_line, ')');
    if (comm_end != NULL && comm_end[1] == ' ') {
      char state = comm_end[2];
      live = state != 'Z' && state != 'X' && state != 'x';
    }
  }
  fclose(stat_file);
  if (!live) return false;

  /* The init debug PID property is the authoritative service generation. A
     live but superseded PID must not keep the UI green after Zygote restart. */
  for (size_t i = 0; i < domainless_service_count; i++) {
    if (domainless_services[i].is_64bit != is_64bit) continue;
    char value[PROP_VALUE_MAX] = { 0 };
    if (__system_property_get(domainless_services[i].debug_pid_prop, value) <= 0)
      continue;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno == 0 && end != value && *end == '\0' && parsed == pid) return true;
  }
  return false;
}

static void domainless_forget_dead_targets() {
  bool lost_injected_target = false;
  for (size_t i = 0; i < DOMAINLESS_MAX_TARGETS; i++) {
    if (domainless_targets[i] == 0) continue;
    if (!domainless_target_is_current_and_live(domainless_targets[i],
                                                domainless_target_is64[i])) {
      struct rezygiskd_status *status = domainless_target_is64[i] ? &status64 : &status32;
      if (status->zygote_injected) lost_injected_target = true;
      status->zygote_injected = false;
      domainless_targets[i] = 0;
      domainless_target_is64[i] = false;
    }
  }
  if (lost_injected_target)
    update_status("Injected Zygote restarted after the one-shot rendezvous; reboot required");
}

static bool domainless_run_tracer(int broker_fd, pid_t pid, bool is_64bit, uint32_t ticket) {
  pid_t child = fork();

  if (child == 0) {
    close(broker_fd);

    /* Every pre-exec service child still has init's native ABI. The native
       monitor therefore performs the self-claim and crosses PTRACE_EVENT_EXEC;
       trace_zygote_preexec performs an exact-boundary ABI handoff when the new
       app_process image has the other bitness. */
    _exit(trace_zygote_preexec(pid, false, ticket, is_64bit) ? 0 : 1);
  } else if (child == -1) {
    LOGE("failed to fork pre-exec tracer for %d", pid);
    return false;
  }

  struct timespec started = { 0 };
  clock_gettime(CLOCK_MONOTONIC, &started);
  int status = 0;
  while (1) {
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (waited == -1 && errno != EINTR) {
      PLOGE("wait for pre-exec tracer");
      return false;
    }

    struct timespec now = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - started.tv_sec) * 1000L +
                      (now.tv_nsec - started.tv_nsec) / 1000000L;
    if (elapsed_ms >= DOMAINLESS_TRACE_TIMEOUT_MS) {
      LOGE("pre-exec tracer watchdog expired for %d", pid);
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      kill(pid, SIGCONT);
      return false;
    }
    usleep(1000);
  }
}

static void domainless_consider_target(int broker_fd,
                                       struct domainless_zygote_service *service,
                                       pid_t pid) {
  bool is_64bit = service->is_64bit;

  if (domainless_target_seen(pid)) return;

  /* A forked daemon is not a ready daemon.  In particular, never issue the
     delegated KernelPatch grant while the daemon is still in exec/setns/root
     discovery.  Leave the target unrecorded so the next nonblocking scan can
     reconsider it after DAEMON*_SET_INFO has completed. */
  if (!ensure_daemon_created(is_64bit)) return;

  /* Record before any blocking IPC so the same live process cannot be raced by
     two scan iterations. A restarted Zygote gets a new PID and is considered. */
  if (!domainless_remember_target(pid, is_64bit)) return;
  /* init.svc_debug_pid can retain a dead/released PID. Remember completion per
     service even after the generic live-target table drops the dead process,
     while still allowing a genuinely restarted service with a new PID. */
  service->completed_pid = pid;
  service->rendezvous_consumed = true;

  if ((is_64bit && should_stop_inject64()) || (!is_64bit && should_stop_inject32())) {
    LOGE("Zygote%s restarted too often; domainless injection is suspended", is_64bit ? "64" : "32");
    monitor_stop_reason = "Zygote restarted too often";
    tracing_state = STOPPED;
    update_status(NULL);
    (void)domainless_release_target(broker_fd, service->name, pid, false);

    return;
  }

  uint32_t ticket = 0;
  if (!domainless_stage_target(broker_fd, service->name, pid, is_64bit, &ticket)) {
    struct rezygiskd_status *status = is_64bit ? &status64 : &status32;
    status->zygote_injected = false;
    update_status("APatch rejected the pre-exec Zygote target; released safely");
    (void)domainless_release_target(broker_fd, service->name, pid, false);
    return;
  }

  LOGI("APatch staged pre-exec %s/Zygote%s target %d for self-claim",
       service->name, is_64bit ? "64" : "32", pid);
  bool injected = domainless_run_tracer(broker_fd, pid, is_64bit, ticket);
  (void)domainless_release_target(broker_fd, service->name, pid, injected);
  if (!injected) {
    struct rezygiskd_status *status = is_64bit ? &status64 : &status32;
    status->zygote_injected = false;
    update_status("Pre-exec Zygote injection failed safely");
  }
}

static void domainless_discover_preexec_targets(int broker_fd) {
  for (size_t i = 0; i < domainless_service_count; i++) {
    if (domainless_services[i].rendezvous_consumed) continue;
    char value[PROP_VALUE_MAX] = { 0 };
    if (__system_property_get(domainless_services[i].debug_pid_prop, value) <= 0) continue;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 1 || parsed > INT_MAX) continue;
    pid_t pid = (pid_t)parsed;
    if (domainless_services[i].completed_pid == pid) continue;
    if (domainless_target_seen(pid)) continue;
    domainless_consider_target(broker_fd, &domainless_services[i], pid);
  }
}

static bool domainless_prepare_runtime() {
  const char *path = getenv("PATH");
  if (path == NULL || strstr(path, "/data/adb/ap/bin") == NULL) {
    static const char apatch_path[] = "/data/adb/ap/bin";
    static const char android_path[] =
      "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
      "/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin";

    size_t path_length = sizeof(apatch_path) + (path && *path ? strlen(path) : strlen(android_path)) + 1;
    char *domainless_path = malloc(path_length);
    if (domainless_path == NULL) {
      PLOGE("allocate APatch domainless PATH");
      return false;
    }

    snprintf(domainless_path, path_length, "%s:%s", apatch_path,
             path && *path ? path : android_path);
    if (setenv("PATH", domainless_path, 1) == -1) {
      PLOGE("set APatch domainless PATH");
      free(domainless_path);
      return false;
    }
    free(domainless_path);
  }

  const char *runtime = "/data/adb/rezygisk";
  if (mkdir(runtime, 0555) == -1 && errno != EEXIST) {
    PLOGE("create domainless runtime");

    return false;
  }
  chmod(runtime, 0555);

  /* These are transient sockets/state from the previous boot. Module data and
     user configuration are deliberately not removed here. */
  unlink("/data/adb/rezygisk/init_monitor");
  unlink("/data/adb/rezygisk/cp32.sock");
  unlink("/data/adb/rezygisk/cp64.sock");
  unlink("/data/adb/rezygisk/state.json");

  return true;
}

void init_domainless_monitor() {
  LOGI("IRezygisk %s (APatch domainless-v1)", ZKSU_VERSION);
  domainless_monitor_active = true;
  memset(domainless_targets, 0, sizeof(domainless_targets));
  memset(domainless_target_is64, 0, sizeof(domainless_target_is64));
  memset(domainless_services, 0, sizeof(domainless_services));

  char zygote_mode[PROP_VALUE_MAX] = { 0 };
  __system_property_get("ro.zygote", zygote_mode);
  if (strcmp(zygote_mode, "zygote64") == 0) {
    domainless_services[0] = (struct domainless_zygote_service) {
      .name = "zygote", .debug_pid_prop = "init.svc_debug_pid.zygote", .is_64bit = true
    };
    domainless_service_count = 1;
  } else if (strcmp(zygote_mode, "zygote32") == 0) {
    domainless_services[0] = (struct domainless_zygote_service) {
      .name = "zygote", .debug_pid_prop = "init.svc_debug_pid.zygote", .is_64bit = false
    };
    domainless_service_count = 1;
  } else if (strcmp(zygote_mode, "zygote64_32") == 0 ||
             strcmp(zygote_mode, "zygote32_64") == 0) {
    bool primary64 = strcmp(zygote_mode, "zygote64_32") == 0;
    domainless_services[0] = (struct domainless_zygote_service) {
      .name = "zygote", .debug_pid_prop = "init.svc_debug_pid.zygote", .is_64bit = primary64
    };
    domainless_services[1] = (struct domainless_zygote_service) {
      .name = "zygote_secondary",
      .debug_pid_prop = "init.svc_debug_pid.zygote_secondary",
      .is_64bit = !primary64
    };
    domainless_service_count = 2;
  } else {
    LOGE("Unsupported ro.zygote mode for APatch rendezvous: %s", zygote_mode);
    exit(1);
  }
  domainless_expect64 = false;
  domainless_expect32 = false;
  for (size_t i = 0; i < domainless_service_count; i++) {
    if (domainless_services[i].is_64bit) domainless_expect64 = true;
    else domainless_expect32 = true;
  }

  /* Report every ABI advertised by ro.zygote from the first status update.
     Daemon startup remains lazy for the non-native ABI. */
  status64.supported = domainless_expect64;
  status32.supported = domainless_expect32;

  if (!domainless_prepare_runtime() || !prepare_environment()) exit(1);
  if (!rezygiskd_listener_init()) exit(1);
  if (!sigchld_listener_init()) {
    rezygiskd_listener_stop();
    exit(1);
  }

  /* Start the native-ABI daemon while init is still held by APatch. Waiting
     until app_process appears would spend the most valuable part of the
     injection window on a daemon fork/exec. */
  bool native_is_64bit = sizeof(void *) == 8;
  (void)ensure_daemon_created(native_is_64bit);
  struct rezygiskd_status *native_status = native_is_64bit ? &status64 : &status32;
  if (native_status->daemon_pid == -1) {
    sigchld_listener_stop();
    rezygiskd_listener_stop();
    exit(1);
  }

  int broker_fd = domainless_open_broker();
  if (broker_fd == -1) {
    sigchld_listener_stop();
    rezygiskd_listener_stop();
    exit(1);
  }

  update_status(NULL);
  LOGI("domainless pre-exec rendezvous armed; PID 1 is not traced; services=%zu; poll=%u/%u/%u us",
       domainless_service_count,
       (unsigned)DOMAINLESS_DISCOVERY_BURST_US, (unsigned)DOMAINLESS_DISCOVERY_WARM_US,
       (unsigned)DOMAINLESS_DISCOVERY_IDLE_US);

  struct timespec discovery_started = { 0 };
  clock_gettime(CLOCK_MONOTONIC, &discovery_started);

  while (monitor_events_running) {
    /* The listener is nonblocking, so this handles status/control datagrams
       without a second thread while /proc discovery owns the main loop. */
    rezygiskd_listener_callback();
    sigchld_listener_callback();

    if (tracing_state == TRACING) domainless_discover_preexec_targets(broker_fd);
    domainless_forget_dead_targets();

    bool injected_all_supported =
      (!domainless_expect64 || status64.zygote_injected) &&
      (!domainless_expect32 || status32.zygote_injected) &&
      (domainless_expect64 || domainless_expect32);
    if (injected_all_supported) {
      usleep(100000);
      continue;
    }

    /* Only two init debug PID properties are polled.  The old full-/proc scan
       is intentionally gone; the stopped pre-exec rendezvous means this loop
       no longer races a one-shot linker window. */
    struct timespec now = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &now);
    time_t elapsed = now.tv_sec - discovery_started.tv_sec;
    if (elapsed < 1) usleep(DOMAINLESS_DISCOVERY_BURST_US);
    else if (elapsed < 5) usleep(DOMAINLESS_DISCOVERY_WARM_US);
    else usleep(DOMAINLESS_DISCOVERY_IDLE_US);
  }

  close(broker_fd);
  sigchld_listener_stop();
  rezygiskd_listener_stop();
  LOGI("Terminating APatch domainless monitor");
}

void init_monitor() {
  LOGI("ReZygisk %s", ZKSU_VERSION);

  if (!prepare_environment()) exit(1);

  if (!claim_init_tracer()) exit(1);

  monitor_events_init();

  if (!rezygiskd_listener_init()) {
    LOGE("failed to create socket");

    close(monitor_epoll_fd);

    exit(1);
  }

  monitor_events_register_event(rezygiskd_listener_callback, monitor_sock_fd, EPOLLIN | EPOLLET);

  if (sigchld_listener_init() == false) {
    LOGE("failed to create signalfd");

    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  monitor_events_register_event(sigchld_listener_callback, sigchld_signal_fd, EPOLLIN | EPOLLET);

  monitor_events_loop();

  /* INFO: Once it stops the loop, we cannot access the epool data, so we
             either manually call the stops or save to a structure. */
  rezygiskd_listener_stop();
  sigchld_listener_stop();

  if (status64.daemon_info) free(status64.daemon_info);
  if (status64.daemon_error_info) free(status64.daemon_error_info);
  if (status32.daemon_info) free(status32.daemon_info);
  if (status32.daemon_error_info) free(status32.daemon_error_info);

  if (environment_information64.root_impl) free((void *)environment_information64.root_impl);
  if (environment_information64.modules) {
    for (uint32_t i = 0; i < environment_information64.modules_len; i++) {
      free((void *)environment_information64.modules[i]);
    }
    free((void *)environment_information64.modules);
  }

  if (environment_information32.root_impl) free((void *)environment_information32.root_impl);
  if (environment_information32.modules) {
    for (uint32_t i = 0; i < environment_information32.modules_len; i++) {
      free((void *)environment_information32.modules[i]);
    }
    free((void *)environment_information32.modules);
  }

  LOGI("Terminating ReZygisk monitor");
}

int send_control_command(enum rezygiskd_command cmd) {
  int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1) return -1;

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };

  size_t sun_path_len = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", rezygiskd_get_path(), SOCKET_NAME);

  socklen_t socklen = sizeof(sa_family_t) + sun_path_len;

  uint8_t cmd_op = cmd;
  ssize_t nsend = sendto(sockfd, (void *)&cmd_op, sizeof(cmd_op), 0, (struct sockaddr *)&addr, socklen);

  close(sockfd);

  return nsend != sizeof(cmd_op) ? -1 : 0;
}
