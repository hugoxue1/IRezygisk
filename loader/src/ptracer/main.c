#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon.h"
#include "monitor.h"

int main(int argc, char **argv) {
  printf("The ReZygisk Tracer %s\n\n", ZKSU_VERSION);

  if (argc >= 2 && strcmp(argv[1], "monitor") == 0) {
    init_monitor();

    return 0;
  } else if (argc >= 2 && strcmp(argv[1], "monitor-domainless") == 0) {
    init_domainless_monitor();

    return 0;
  } else if (argc >= 3 &&
             (strcmp(argv[1], "trace-direct") == 0 ||
              strcmp(argv[1], "trace-preexec") == 0 ||
              strcmp(argv[1], "trace-postexec") == 0)) {
    bool is_tango = false;
    uint32_t auth_ticket = 0;
    int inherited_domainless_fd = -1;
    bool target_is_64bit = sizeof(void *) == 8;
    for (int i = 3; i < argc; i++) {
      if (strcmp(argv[i], "--tango") == 0) is_tango = true;
      else if (strcmp(argv[i], "--ticket") == 0 && i + 1 < argc) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[++i], &end, 10);
        if (end == argv[i] || *end != '\0' || parsed == 0 || parsed > INT32_MAX) return 2;
        auth_ticket = (uint32_t)parsed;
      } else if (strcmp(argv[i], "--target-abi") == 0 && i + 1 < argc) {
        const char *abi = argv[++i];
        if (strcmp(abi, "64") == 0) target_is_64bit = true;
        else if (strcmp(abi, "32") == 0) target_is_64bit = false;
        else return 2;
      } else if (strcmp(argv[i], "--domainless-fd") == 0 && i + 1 < argc) {
        char *end = NULL;
        long parsed = strtol(argv[++i], &end, 10);
        if (end == argv[i] || *end != '\0' || parsed < 0 || parsed > INT_MAX) return 2;
        inherited_domainless_fd = (int)parsed;
      }
    }

    long pid = strtol(argv[2], 0, 0);
    /* Domainless mode is deliberately fail-open for boot safety: a missed
       injection window must never kill or restart the real Zygote. */
    if (strcmp(argv[1], "trace-preexec") == 0)
      return trace_zygote_preexec(pid, is_tango, auth_ticket, target_is_64bit) ? 0 : 1;
    if (strcmp(argv[1], "trace-postexec") == 0)
      return trace_zygote_postexec(pid, is_tango, inherited_domainless_fd) ? 0 : 1;
    return trace_zygote_direct(pid, is_tango, auth_ticket) ? 0 : 1;
  } else if (argc >= 3 && strcmp(argv[1], "trace") == 0) {
      bool is_tango = false;
      bool do_restart = false;

      for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--restart") == 0) do_restart = true;
        else if (strcmp(argv[i], "--tango") == 0) is_tango = true;
      }

      /* INFO: We need to be fast enough to not miss Tango's injection point,
                 so we just delay for Tango Zygote. */
      if (do_restart && !is_tango) rezygiskd_zygote_restart();

      long pid = strtol(argv[2], 0, 0);
      if (!trace_zygote(pid, is_tango)) {
        kill(pid, SIGKILL);

        return 1;
      }

      if (do_restart && is_tango) rezygiskd_zygote_restart();

      return 0;
  } else if (argc >= 2 && strcmp(argv[1], "ctl") == 0) {
    enum rezygiskd_command command;

    if (strcmp(argv[2], "start") == 0) command = START;
    else if (strcmp(argv[2], "stop") == 0) command = STOP;
    else if (strcmp(argv[2], "exit") == 0) command = EXIT;
    else {
      printf("[ReZygisk]: Usage: %s ctl <start|stop|exit>\n", argv[0]);

      return 1;
    }

    if (send_control_command(command) == -1) {
      printf("[ReZygisk]: Failed to send the command, is the daemon running?\n");

      return 1;
    }

    printf("[ReZygisk]: command sent\n");

    return 0;
  } else if (argc >= 2 && strcmp(argv[1], "version") == 0) {
    /* INFO: Noop*/

    return 0;
  } else if (argc >= 2 && strcmp(argv[1], "info") == 0) {
    struct rezygisk_info info;
    rezygiskd_get_info(&info);

    printf("Daemon process PID: %d\n", info.pid);

    switch (info.root_impl) {
      case ROOT_IMPL_NONE: {
        printf("Root implementation: none\n");

        break;
      }
      case ROOT_IMPL_APATCH: {
        printf("Root implementation: APatch\n");

        break;
      }
      case ROOT_IMPL_KERNELSU: {
        printf("Root implementation: KernelSU\n");

        break;
      }
      case ROOT_IMPL_MAGISK: {
        printf("Root implementation: Magisk\n");

        break;
      }
    }

    if (info.modules.modules_count != 0) {
      printf("Modules: %zu\n", info.modules.modules_count);

      for (size_t i = 0; i < info.modules.modules_count; i++) {
        printf(" - %s\n", info.modules.modules[i]);
      }
    } else {
      printf("Modules: N/A\n");
    }

    free_rezygisk_info(&info);

    return 0;
  } else {
    printf(
      "Available commands:\n"
      " - monitor\n"
      " - monitor-domainless\n"
      " - trace <pid> [--restart]\n"
      " - trace-direct <pid>\n"
      " - trace-preexec <pid> --ticket <ticket>\n"
      " - ctl <start|stop|exit>\n"
      " - version: Shows the version of ReZygisk.\n"
      " - info: Shows information about the created daemon/injection.\n"
      "\n"
      "<...>: Obligatory\n"
      "[...]: Optional\n");

    return 1;
  }
}
