#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <link.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <elf.h>
#include <unistd.h>

#define LOG_TAG "zygisk-injector" LP_SELECT("32", "64")

#include "misc.h"
#include "utils.h"
#include "daemon.h"

#include "remote_csoloader.h"

#define APATCH_SUPERCALL_NR 45
#define APATCH_SELF_CLAIM_VER_CMD (((long)0x1158 << 16) | 0x1125)

#if defined(__arm__)
  /* 32-bit ARM exposes the six-argument page-offset syscall as mmap2. */
  #define REMOTE_SYS_MMAP SYS_mmap2
#else
  #define REMOTE_SYS_MMAP SYS_mmap
#endif

static void remote_close_fd(int pid, struct user_regs_struct *regs,
                            uintptr_t syscall_gadget, int fd) {
  if (fd < 0 || syscall_gadget == 0) return;
  long close_args[1] = { fd };
  long result = remote_syscall(pid, regs, syscall_gadget, SYS_close, close_args, 1);
  if (result != 0 && result != -EBADF)
    LOGW("remote close of inherited domainless fd %d returned %ld", fd, result);
}

static void remote_close_fd_current(int pid, struct user_regs_struct *regs, int fd) {
  if (fd < 0) return;
  char pid_str[16];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);
  struct maps_info *maps = parse_maps(pid_str);
  if (maps == NULL) {
    LOGE("cannot parse maps to close inherited domainless fd %d", fd);
    return;
  }
  uintptr_t syscall_gadget = find_syscall_gadget(pid, maps);
  free_maps(maps);
  if (syscall_gadget == 0) {
    LOGE("cannot find syscall gadget to close inherited domainless fd %d", fd);
    return;
  }
  remote_close_fd(pid, regs, syscall_gadget, fd);
}

static uintptr_t align_remote(uintptr_t value, size_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

/* Receive one descriptor from the pre-exec daemon connection.  The tracee is
   still the native-ABI init service child here, so these libc socket layouts
   match the remote syscall ABI. */
static int remote_recv_fd(int pid, struct user_regs_struct *regs,
                          uintptr_t syscall_gadget, int transport_fd,
                          uintptr_t scratch) {
  uintptr_t byte_remote = scratch;
  uintptr_t iov_remote = align_remote(byte_remote + sizeof(uint8_t), _Alignof(struct iovec));
  uintptr_t msg_remote = align_remote(iov_remote + sizeof(struct iovec), _Alignof(struct msghdr));
  uintptr_t control_remote = align_remote(msg_remote + sizeof(struct msghdr), _Alignof(struct cmsghdr));
  char control[CMSG_SPACE(sizeof(int))];
  memset(control, 0, sizeof(control));

  struct iovec iov = {
    .iov_base = (void *)byte_remote,
    .iov_len = sizeof(uint8_t)
  };
  struct msghdr msg = {
    .msg_iov = (struct iovec *)iov_remote,
    .msg_iovlen = 1,
    .msg_control = (void *)control_remote,
    .msg_controllen = sizeof(control)
  };
  uint8_t payload = 0;
  if (write_proc(pid, byte_remote, &payload, sizeof(payload)) != sizeof(payload) ||
      write_proc(pid, iov_remote, &iov, sizeof(iov)) != sizeof(iov) ||
      write_proc(pid, control_remote, control, sizeof(control)) != sizeof(control) ||
      write_proc(pid, msg_remote, &msg, sizeof(msg)) != sizeof(msg)) {
    LOGE("failed to stage pre-exec SCM_RIGHTS receive");
    return -1;
  }

  long recvmsg_args[3] = { transport_fd, (long)msg_remote, MSG_WAITALL };
  long recvmsg_result = remote_syscall(pid, regs, syscall_gadget, SYS_recvmsg,
                                       recvmsg_args, 3);
  if (recvmsg_result != (long)sizeof(payload)) {
    LOGE("pre-exec daemon session fd receive failed: %ld", recvmsg_result);
    return -1;
  }

  if (read_proc(pid, msg_remote, &msg, sizeof(msg)) != sizeof(msg) ||
      msg.msg_controllen > sizeof(control) ||
      read_proc(pid, control_remote, control, msg.msg_controllen) !=
          (ssize_t)msg.msg_controllen) {
    LOGE("failed to read pre-exec SCM_RIGHTS response");
    return -1;
  }
  msg.msg_control = control;

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
      continue;

    int received_fd = -1;
    memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
    return received_fd;
  }

  LOGE("pre-exec daemon response did not contain a session fd");
  return -1;
}

/* Establish and authenticate the daemon channel before exec, while Android's
   init service child can still traverse /data/adb. The explicitly-bound
   abstract client name also keeps old Zygote FD inspection safe on releases
   that do not expose fds_to_ignore. */
static int remote_open_domainless_session_preexec(int pid,
                                                   struct user_regs_struct *regs,
                                                   uintptr_t syscall_gadget,
                                                   bool target_is_64bit) {
  long map_args[6] = {
    0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
  };
  long map_result = remote_syscall(pid, regs, syscall_gadget,
                                   REMOTE_SYS_MMAP, map_args, 6);
  if (map_result <= 0 && map_result >= -4095) {
    LOGE("pre-exec channel scratch mmap failed: %ld", map_result);
    return -1;
  }
  uintptr_t scratch = (uintptr_t)map_result;

  struct sockaddr_un local_addr = { .sun_family = AF_UNIX };
  local_addr.sun_path[0] = '\0';
  snprintf(local_addr.sun_path + 1, sizeof(local_addr.sun_path) - 1,
           "irezygisk-preexec-%d-%s", pid, target_is_64bit ? "64" : "32");
  socklen_t local_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                    1 + strlen(local_addr.sun_path + 1));

  struct sockaddr_un server_addr = { .sun_family = AF_UNIX };
  snprintf(server_addr.sun_path, sizeof(server_addr.sun_path),
           "/data/adb/rezygisk/cp%s.sock", target_is_64bit ? "64" : "32");
  socklen_t server_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                     strlen(server_addr.sun_path) + 1);

  uintptr_t local_remote = scratch;
  uintptr_t server_remote = scratch + sizeof(local_addr);
  uintptr_t io_remote = server_remote + sizeof(server_addr);
  int fd = -1;

  if (write_proc(pid, local_remote, &local_addr, sizeof(local_addr)) !=
          (ssize_t)sizeof(local_addr) ||
      write_proc(pid, server_remote, &server_addr, sizeof(server_addr)) !=
          (ssize_t)sizeof(server_addr)) {
    LOGE("failed to stage pre-exec daemon socket addresses");
    goto cleanup;
  }

  long socket_args[3] = { AF_UNIX, SOCK_STREAM, 0 };
  long socket_result = remote_syscall(pid, regs, syscall_gadget, SYS_socket,
                                      socket_args, 3);
  if (socket_result < 0) {
    LOGE("pre-exec daemon socket failed: %ld", socket_result);
    goto cleanup;
  }
  fd = (int)socket_result;

  long bind_args[3] = { fd, (long)local_remote, local_len };
  long bind_result = remote_syscall(pid, regs, syscall_gadget, SYS_bind, bind_args, 3);
  if (bind_result != 0) {
    LOGE("pre-exec abstract client bind failed: %ld", bind_result);
    goto cleanup;
  }

  long connect_args[3] = { fd, (long)server_remote, server_len };
  long connect_result = remote_syscall(pid, regs, syscall_gadget, SYS_connect,
                                       connect_args, 3);
  if (connect_result != 0) {
    LOGE("pre-exec daemon connect failed: %ld", connect_result);
    goto cleanup;
  }

  uint8_t action = (uint8_t)DomainlessSession;
  if (write_proc(pid, io_remote, &action, sizeof(action)) != sizeof(action)) {
    LOGE("failed to stage domainless session action");
    goto cleanup;
  }
  long write_args[3] = { fd, (long)io_remote, sizeof(action) };
  if (remote_syscall(pid, regs, syscall_gadget, SYS_write, write_args, 3) !=
      (long)sizeof(action)) {
    LOGE("pre-exec domainless session request failed");
    goto cleanup;
  }

  /* The pathname-connected client socket was created while the task was in
     init's domain.  Keeping that file across exec makes native SELinux deny
     zygote -> init:unix_stream_socket read/write.  The daemon already creates
     sockets with the Zygote sockcreate context, so replace this transport with
     a daemon-created socketpair endpoint before crossing exec. */
  int session_fd = remote_recv_fd(pid, regs, syscall_gadget, fd, io_remote);
  if (session_fd < 0) goto cleanup;
  remote_close_fd(pid, regs, syscall_gadget, fd);
  fd = session_fd;

  uint8_t accepted = 0;
  if (write_proc(pid, io_remote, &accepted, sizeof(accepted)) != sizeof(accepted)) {
    LOGE("failed to clear domainless session response byte");
    goto cleanup;
  }
  long read_args[3] = { fd, (long)io_remote, sizeof(accepted) };
  if (remote_syscall(pid, regs, syscall_gadget, SYS_read, read_args, 3) !=
          (long)sizeof(accepted) ||
      read_proc(pid, io_remote, &accepted, sizeof(accepted)) != sizeof(accepted) ||
      accepted != 1) {
    LOGE("pre-exec domainless session was not accepted");
    goto cleanup;
  }

  {
    long unmap_args[2] = { (long)scratch, 4096 };
    remote_syscall(pid, regs, syscall_gadget, SYS_munmap, unmap_args, 2);
  }
  LOGI("pre-exec APatch domainless session ready on inherited fd %d", fd);
  return fd;

cleanup:
  remote_close_fd(pid, regs, syscall_gadget, fd);
  {
    long unmap_args[2] = { (long)scratch, 4096 };
    remote_syscall(pid, regs, syscall_gadget, SYS_munmap, unmap_args, 2);
  }
  return -1;
}

bool inject_on_main(int pid, const char *lib_path, uintptr_t libc_init_target,
                    uintptr_t libc_init_got_slot, bool is_tango, uint32_t auth_ticket,
                    int inherited_domainless_fd) {
  LOGI("injecting %s to zygote %d via GOT hook", lib_path, pid);

  uintptr_t break_addr = (uintptr_t)((intptr_t)(-0x0F & ~1) | (intptr_t)(libc_init_target & 1));
  if (!ptrace_poke_uintptr(pid, libc_init_got_slot, break_addr)) {
    LOGE("Failed to patch GOT slot with break_addr");

    return false;
  }

  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
    PLOGE("Failed to continue to GOT break");

    return false;
  }

  int status = 0;
  wait_for_trace(pid, &status, __WALL);

  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSEGV) {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("expected SIGSEGV on __libc_init GOT call, got: %s", status_str);

    return false;
  }

  struct user_regs_struct regs = { 0 };
  if (!get_regs(pid, &regs)) {
    LOGE("Failed to get regs after GOT break");

    return false;
  }

  /* Restore valid __libc_init pointer to RELRO GOT slot via PTRACE_POKEDATA fallback */
  if (!ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_target)) {
    LOGE("Failed to restore __libc_init GOT slot");

    return false;
  }

  struct user_regs_struct backup;
  memcpy(&backup, &regs, sizeof(regs));
  /* The tracee stopped with its PC at the deliberate invalid GOT target.
     Every failure after this point must restore the complete pre-call register
     frame, not only the GOT word, or detach resumes at the trap address and
     turns a recoverable loader error into a Zygote SIGSEGV. */
  backup.REG_IP = (long)libc_init_target;

  char pid_str[11];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *map = parse_maps(pid_str);
  if (!map) {
    LOGE("Failed to parse remote maps after GOT break");
    set_regs(pid, &backup);

    return false;
  }

  struct maps_info *local_map = parse_maps("self");
  if (!local_map) {
    LOGE("Failed to parse local maps");

    free_maps(map);
    set_regs(pid, &backup);

    return false;
  }

  uintptr_t syscall_gadget = 0;
  if (auth_ticket != 0 || inherited_domainless_fd >= 0)
    syscall_gadget = find_syscall_gadget(pid, map);
  if ((auth_ticket != 0 || inherited_domainless_fd >= 0) && syscall_gadget == 0) {
    LOGE("Could not find syscall gadget for APatch injection cleanup");
    free_maps(local_map);
    free_maps(map);
    set_regs(pid, &backup);
    return false;
  }

  /* APD only stages an opaque ticket. Execute the claim as a remote syscall
     while Zygote itself is current, before Zygote opens/maps anything under
     /data/adb. KernelPatch therefore writes current's own task_ext only. */
  if (auth_ticket != 0) {
    long claim_args[3] = { 0, APATCH_SELF_CLAIM_VER_CMD, (long)auth_ticket };
    long claim_result = remote_syscall(pid, &regs, syscall_gadget, APATCH_SUPERCALL_NR,
                                       claim_args, 3);
    if (claim_result != 0) {
      LOGE("APatch self-claim rejected for Zygote %d: %ld", pid, claim_result);
      remote_close_fd(pid, &regs, syscall_gadget, inherited_domainless_fd);
      free_maps(local_map);
      free_maps(map);
      set_regs(pid, &backup);
      return false;
    }
    LOGI("APatch self-claim completed inside Zygote %d", pid);
  }

  void *libc_return_addr = find_module_return_addr(map, "libc.so");
  uintptr_t remote_base = 0, injector_entry = 0;
  size_t remote_size = 0;

  if (!remote_csoloader_load_and_resolve_entry(pid, &regs, map, local_map, lib_path, &remote_base, &remote_size, &injector_entry)) {
    LOGE("Remote CSOLoader mapping failed");

    remote_close_fd(pid, &regs, syscall_gadget, inherited_domainless_fd);
    free_maps(local_map);
    free_maps(map);
    set_regs(pid, &backup);

    return false;
  }

  long args[4] = {
    (long)remote_base,
    (long)remote_size,
    is_tango ? 1 : 0,
    inherited_domainless_fd
  };
  uintptr_t injector_result = remote_call(pid, &regs, injector_entry,
                                          (uintptr_t)libc_return_addr, args, 4);

  bool injector_ok = false;
  #if defined(__arm__)
    injector_ok = (((uintptr_t)regs.REG_IP & ~1u) == ((uintptr_t)libc_return_addr & ~1u));
  #else
    injector_ok = ((uintptr_t)regs.REG_IP == (uintptr_t)libc_return_addr);
  #endif

  if (!injector_ok || injector_result != 1) {
    if (!injector_ok) LOGE("injector entry faulted at %p", (void *)regs.REG_IP);
    else LOGE("injector entry rejected daemon session");

    remote_close_fd(pid, &regs, syscall_gadget, inherited_domainless_fd);
    if (syscall_gadget != 0 && remote_base != 0 && remote_size != 0) {
      long unmap_args[2] = { (long)remote_base, (long)remote_size };
      remote_syscall(pid, &regs, syscall_gadget, SYS_munmap, unmap_args, 2);
    }
    free_maps(local_map);
    free_maps(map);

    set_regs(pid, &backup);

    return false;
  }

  free_maps(local_map);
  free_maps(map);

  if (!set_regs(pid, &backup)) return false;

  LOGD("injection complete, instruction pointer reset to __libc_init (%p)", (void *)libc_init_target);

  return true;
}

#define STOPPED_WITH(sig, event) (WIFSTOPPED(status) && WSTOPSIG(status) == (sig) && (status >> 16) == (event))
#define WAIT_OR_DIE wait_for_trace(pid, &status, __WALL);
#define CONT_OR_DIE                           \
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) { \
    PLOGE("cont");                            \
                                              \
    return false;                             \
  }

bool trace_zygote(int pid, bool tango_flag) {
  LOGI("start tracing %d (tracer %d)", pid, getpid());

  /* INFO: Set value 0 to make compiler happy. */
  int status = 0;

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP) == -1) {
      PLOGE("seize for tango");

      return false;
    }

    WAIT_OR_DIE;
  } else {
    if (ptrace(PTRACE_SEIZE, pid, 0, 0) == -1) {
      PLOGE("seize");

      return false;
    }

    WAIT_OR_DIE;
  }

  kill(pid, SIGCONT);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);

  int dummy;
  wait_for_ptrace_syscall_stop(pid, &dummy);

  uintptr_t libc_init_got_slot = 0, libc_init_resolved = 0;
  if (!wait_linker_ready(pid, &libc_init_resolved, &libc_init_got_slot)) {
    LOGE("Failed to wait for linker ready for injection");

    ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

    return false;
  }

  LOGD("Resolved __libc_init at %p (GOT slot %p)", (void *)libc_init_resolved, (void *)libc_init_got_slot);

  if (STOPPED_WITH(SIGSTOP, PTRACE_EVENT_STOP)) {
    char *lib_path = "/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so";
    if (!inject_on_main(pid, lib_path, libc_init_resolved, libc_init_got_slot,
                        tango_flag, 0, -1)) {
      LOGE("failed to inject");

      return false;
    }

    LOGD("inject done, continue process");
    if (kill(pid, SIGCONT)) {
      PLOGE("kill");

      return false;
    }

    CONT_OR_DIE
    WAIT_OR_DIE

    if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
      CONT_OR_DIE
      WAIT_OR_DIE

      if (STOPPED_WITH(SIGCONT, 0)) {
        LOGD("received SIGCONT");

        /* INFO: Due to kernel bugs, fixed in 5.16+, ptrace_message (msg of
             PTRACE_GETEVENTMSG) may not represent the current state of
             the process. Because we set some options, which alters the
             ptrace_message, we need to call PTRACE_SYSCALL to reset the
             ptrace_message to 0, the default/normal state.
        */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);

        WAIT_OR_DIE

        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
      }
    } else {
      char status_str[64];
      parse_status(status, status_str, sizeof(status_str));

      LOGE("Expected SIGTRAP (event: EVENT_STOP), found: %s", status_str);

      ptrace(PTRACE_DETACH, pid, 0, 0);

      return false;
    }
  } else {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("Expected SIGSTOP (event: EVENT_STOP), found: %s", status_str);

    ptrace(PTRACE_DETACH, pid, 0, 0);

    return false;
  }

  return true;
}

bool trace_zygote_direct(int pid, bool tango_flag, uint32_t auth_ticket) {
  LOGI("start direct tracing %d (tracer %d)", pid, getpid());

  if (auth_ticket == 0 || auth_ticket > INT32_MAX) {
    LOGE("direct trace refused without a valid APatch self-claim ticket");
    return false;
  }

  int status = 0;
  bool attached = false;
  bool injected = false;
  uintptr_t libc_init_got_slot = 0;
  uintptr_t libc_init_resolved = 0;

  /* One absolute deadline covers attach, linker stepping, remote mapping and
     the injector call. No inner wait is allowed to pin a booting Zygote. */
  ptrace_wait_set_deadline_ms(4000);

  /* Do not use PTRACE_O_EXITKILL here. Domainless mode must leave the booting
     Zygote alive even if the tracer itself crashes or APatch rejects it. */
  if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESECCOMP) == -1) {
    PLOGE("direct seize");
    ptrace_wait_clear_deadline();

    return false;
  }

  attached = true;

  if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
    PLOGE("direct interrupt");

    goto cleanup;
  }

  wait_for_trace(pid, &status, __WALL);
  if (!STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));
    LOGE("direct attach expected ptrace event-stop, got: %s", status_str);

    goto cleanup;
  }

  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
    PLOGE("direct initial syscall step");

    goto cleanup;
  }

  if (!wait_for_ptrace_syscall_stop(pid, &status)) goto cleanup;

  if (!wait_linker_ready(pid, &libc_init_resolved, &libc_init_got_slot)) {
    LOGE("direct mode missed or failed the linker injection window");

    goto cleanup;
  }

  LOGD("direct mode resolved __libc_init at %p (GOT slot %p)",
       (void *)libc_init_resolved, (void *)libc_init_got_slot);

  {
    char *lib_path = "/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so";
    if (!inject_on_main(pid, lib_path, libc_init_resolved, libc_init_got_slot, tango_flag,
                        auth_ticket, -1)) {
      LOGE("direct mode failed to inject");

      /* inject_on_main normally restores this slot. Repeat the restoration on
         every failure path so an aborted experiment cannot poison Zygote. */
      if (libc_init_got_slot != 0 && libc_init_resolved != 0) {
        ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_resolved);
      }

      goto cleanup;
    }
  }

  injected = true;

cleanup:
  ptrace_wait_clear_deadline();
  if (attached) {
    /* If a timed wait expired while the tracee was running, force one bounded
       recovery stop before restoring the GOT slot and detaching. */
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == 0) {
      int recovery_status = 0;
      ptrace_wait_set_deadline_ms(300);
      wait_for_trace(pid, &recovery_status, __WALL);
      ptrace_wait_clear_deadline();
    } else if (errno != EIO && errno != ESRCH) {
      PLOGE("direct recovery interrupt");
    }

    if (!injected && libc_init_got_slot != 0 && libc_init_resolved != 0) {
      ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_resolved);
    }
    if (ptrace(PTRACE_DETACH, pid, 0, SIGCONT) == -1 && errno != ESRCH) {
      PLOGE("direct detach");
    }
    kill(pid, SIGCONT);
  }

  if (injected) LOGI("direct injection completed for %d", pid);
  else LOGW("direct injection safely abandoned for %d", pid);

  return injected;
}

bool trace_zygote_postexec(int pid, bool tango_flag, int inherited_domainless_fd) {
  LOGI("start post-exec tracing %d (tracer %d)", pid, getpid());

  int status = 0;
  bool attached = false;
  bool injected = false;
  uintptr_t libc_init_got_slot = 0;
  uintptr_t libc_init_resolved = 0;
  ptrace_wait_set_deadline_ms(4000);

  /* The native-ABI tracer detached at PTRACE_EVENT_EXEC and deliberately left
     the new image in SIGSTOP. The ABI-matched tracer resumes from that exact
     post-exec boundary; the APatch ticket was already consumed before exec. */
  if (ptrace(PTRACE_SEIZE, pid, 0, 0) == -1) {
    PLOGE("post-exec seize");
    goto cleanup;
  }
  attached = true;

  if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1 && errno != EIO) {
    PLOGE("post-exec interrupt");
    goto cleanup;
  }
  wait_for_trace(pid, &status, __WALL);
  if (!WIFSTOPPED(status) ||
      (WSTOPSIG(status) != SIGSTOP && WSTOPSIG(status) != SIGTRAP)) {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));
    LOGE("post-exec handoff target is not stopped: %s", status_str);
    goto cleanup;
  }

  if (kill(pid, SIGCONT) == -1) {
    PLOGE("resume post-exec Zygote group-stop");
    goto cleanup;
  }
  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
    PLOGE("post-exec initial syscall step");
    goto cleanup;
  }
  if (!wait_for_ptrace_syscall_stop(pid, &status)) goto cleanup;
  if (!wait_linker_ready(pid, &libc_init_resolved, &libc_init_got_slot)) {
    LOGE("post-exec handoff failed while waiting for linker readiness");
    goto cleanup;
  }

  {
    char *lib_path = "/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so";
    bool inject_result = inject_on_main(pid, lib_path, libc_init_resolved,
                                        libc_init_got_slot, tango_flag, 0,
                                        inherited_domainless_fd);
    /* inject_on_main either transferred the fd to libzygisk or closed it on
       failure; the outer cleanup must not act on a recycled descriptor. */
    inherited_domainless_fd = -1;
    if (!inject_result) {
      LOGE("post-exec handoff failed to inject");
      if (libc_init_got_slot != 0 && libc_init_resolved != 0)
        ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_resolved);
      goto cleanup;
    }
  }
  injected = true;

cleanup:
  ptrace_wait_clear_deadline();
  if (attached) {
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == 0) {
      int recovery_status = 0;
      ptrace_wait_set_deadline_ms(300);
      wait_for_trace(pid, &recovery_status, __WALL);
      ptrace_wait_clear_deadline();
    } else if (errno != EIO && errno != ESRCH) {
      PLOGE("post-exec recovery interrupt");
    }
    if (!injected && inherited_domainless_fd >= 0) {
      struct user_regs_struct close_regs = { 0 };
      if (get_regs(pid, &close_regs))
        remote_close_fd_current(pid, &close_regs, inherited_domainless_fd);
      inherited_domainless_fd = -1;
    }
    if (!injected && libc_init_got_slot != 0 && libc_init_resolved != 0)
      ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_resolved);
    if (ptrace(PTRACE_DETACH, pid, 0, SIGCONT) == -1 && errno != ESRCH)
      PLOGE("post-exec detach");
    kill(pid, SIGCONT);
  }

  if (injected) LOGI("post-exec injection completed for %d", pid);
  else LOGW("post-exec injection safely abandoned for %d", pid);
  return injected;
}

bool trace_zygote_preexec(int pid, bool tango_flag, uint32_t auth_ticket,
                          bool target_is_64bit) {
  LOGI("start pre-exec tracing %d (tracer %d)", pid, getpid());

  if (auth_ticket == 0 || auth_ticket > INT32_MAX) {
    LOGE("pre-exec trace refused without a valid APatch self-claim ticket");
    return false;
  }

  int status = 0;
  bool attached = false;
  bool injected = false;
  int inherited_domainless_fd = -1;
  uintptr_t libc_init_got_slot = 0;
  uintptr_t libc_init_resolved = 0;
  ptrace_wait_set_deadline_ms(4000);

  /* Android init has already placed this service child in a SIGSTOP group-stop
     immediately before exec.  TRACEEXEC is installed at seize time, so the
     exact exec boundary cannot be lost after the target is resumed. */
  if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
    PLOGE("pre-exec seize");
    goto cleanup;
  }
  attached = true;

  if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1 && errno != EIO) {
    PLOGE("pre-exec interrupt");
    goto cleanup;
  }
  wait_for_trace(pid, &status, __WALL);
  if (!WIFSTOPPED(status) || (status >> 16) != PTRACE_EVENT_STOP ||
      (WSTOPSIG(status) != SIGSTOP && WSTOPSIG(status) != SIGTRAP)) {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));
    LOGE("pre-exec target is not at the init SIGSTOP rendezvous: %s", status_str);
    goto cleanup;
  }

  struct user_regs_struct regs = { 0 };
  if (!get_regs(pid, &regs)) goto cleanup;
  char pid_str[16];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);
  struct maps_info *preexec_maps = parse_maps(pid_str);
  if (preexec_maps == NULL) {
    LOGE("failed to parse pre-exec init maps");
    goto cleanup;
  }
  uintptr_t syscall_gadget = find_syscall_gadget(pid, preexec_maps);
  free_maps(preexec_maps);
  if (syscall_gadget == 0) {
    LOGE("could not find a pre-exec syscall gadget");
    goto cleanup;
  }

  /* SIGCONT's group-stop wakeup happens before signal-delivery-stop and cannot
     be suppressed by ptrace.  Send it explicitly rather than trying to inject
     it from PTRACE_EVENT_STOP, where Linux is allowed to ignore the ptrace
     signal argument.  The tracee remains controlled by this tracer. */
  if (kill(pid, SIGCONT) == -1) {
    PLOGE("resume init Zygote group-stop");
    goto cleanup;
  }
  long claim_args[3] = { 0, APATCH_SELF_CLAIM_VER_CMD, (long)auth_ticket };
  long claim_result = remote_syscall(
      pid, &regs, syscall_gadget, APATCH_SUPERCALL_NR, claim_args, 3);
  if (claim_result != 0) {
    LOGE("APatch pre-exec self-claim rejected for Zygote %d: %ld", pid, claim_result);
    goto cleanup;
  }
  LOGI("APatch self-claim completed inside pre-exec Zygote task %d", pid);

  inherited_domainless_fd = remote_open_domainless_session_preexec(
      pid, &regs, syscall_gadget, target_is_64bit);
  if (inherited_domainless_fd < 0) {
    LOGE("failed to establish the mandatory pre-exec daemon channel for Zygote %d", pid);
    goto cleanup;
  }

  if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
    PLOGE("set pre-exec TRACEEXEC");
    goto cleanup;
  }
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
    PLOGE("continue to Zygote exec");
    goto cleanup;
  }

  while (1) {
    wait_for_trace(pid, &status, __WALL);
    if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_EXEC)) break;
    if (WIFSTOPPED(status) &&
        ((WSTOPSIG(status) == SIGCONT && (status >> 16) == 0) ||
         (WSTOPSIG(status) == SIGTRAP && (status >> 16) == PTRACE_EVENT_STOP))) {
      if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) goto cleanup;
      continue;
    }
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));
    LOGE("expected PTRACE_EVENT_EXEC for Zygote %d, got %s", pid, status_str);
    goto cleanup;
  }
  LOGI("captured deterministic PTRACE_EVENT_EXEC for Zygote %d", pid);

  /* A pre-exec Android service child still has init's native ABI. On a mixed
     zygote64_32/zygote32_64 device, selecting the tracer from the *future*
     app_process ABI before exec makes register and remote-syscall access
     invalid. Cross the exec boundary with the native tracer, then hand the
     stopped image to the ABI-matched tracer before the linker can run. */
  if (((sizeof(void *) == 8) != target_is_64bit)) {
    const char *postexec_tracer = target_is_64bit
        ? "./bin/zygisk-ptrace64" : "./bin/zygisk-ptrace32";
    char pid_str[32];
    char domainless_fd_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    snprintf(domainless_fd_str, sizeof(domainless_fd_str), "%d", inherited_domainless_fd);

    if (kill(pid, SIGSTOP) == -1) {
      PLOGE("queue post-exec handoff stop");
      goto cleanup;
    }
    if (ptrace(PTRACE_DETACH, pid, 0, SIGSTOP) == -1) {
      PLOGE("detach for post-exec ABI handoff");
      goto cleanup;
    }
    attached = false;
    ptrace_wait_clear_deadline();
    LOGI("handoff post-exec Zygote %d to %s", pid, postexec_tracer);
    execl(postexec_tracer, basename(postexec_tracer), "trace-postexec", pid_str,
          "--domainless-fd", domainless_fd_str, NULL);
    PLOGE("exec post-exec ABI tracer");
    kill(pid, SIGCONT);
    return false;
  }

  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
    PLOGE("initial post-exec syscall step");
    goto cleanup;
  }
  if (!wait_for_ptrace_syscall_stop(pid, &status)) goto cleanup;
  if (!wait_linker_ready(pid, &libc_init_resolved, &libc_init_got_slot)) {
    LOGE("pre-exec path failed while waiting for linker readiness");
    goto cleanup;
  }

  {
    char *lib_path = "/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so";
    /* The ticket was consumed before exec; do not attempt a second claim at
       the later GOT break. */
    bool inject_result = inject_on_main(pid, lib_path, libc_init_resolved,
                                        libc_init_got_slot, tango_flag, 0,
                                        inherited_domainless_fd);
    inherited_domainless_fd = -1;
    if (!inject_result) {
      LOGE("pre-exec path failed to inject");
      if (libc_init_got_slot != 0 && libc_init_resolved != 0)
        ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_resolved);
      goto cleanup;
    }
  }
  injected = true;

cleanup:
  ptrace_wait_clear_deadline();
  if (attached) {
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == 0) {
      int recovery_status = 0;
      ptrace_wait_set_deadline_ms(300);
      wait_for_trace(pid, &recovery_status, __WALL);
      ptrace_wait_clear_deadline();
    } else if (errno != EIO && errno != ESRCH) {
      PLOGE("pre-exec recovery interrupt");
    }
    if (!injected && inherited_domainless_fd >= 0) {
      struct user_regs_struct close_regs = { 0 };
      if (get_regs(pid, &close_regs))
        remote_close_fd_current(pid, &close_regs, inherited_domainless_fd);
      inherited_domainless_fd = -1;
    }
    if (!injected && libc_init_got_slot != 0 && libc_init_resolved != 0)
      ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_resolved);
    if (ptrace(PTRACE_DETACH, pid, 0, SIGCONT) == -1 && errno != ESRCH)
      PLOGE("pre-exec detach");
    kill(pid, SIGCONT);
  }

  if (injected) LOGI("pre-exec injection completed for %d", pid);
  else LOGW("pre-exec injection safely abandoned for %d", pid);
  return injected;
}
