#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

void init_monitor();
void init_domainless_monitor();

bool trace_zygote(int pid, bool is_tango);
bool trace_zygote_direct(int pid, bool is_tango, uint32_t auth_ticket);
bool trace_zygote_preexec(int pid, bool is_tango, uint32_t auth_ticket,
                          bool target_is_64bit);
bool trace_zygote_postexec(int pid, bool is_tango, int inherited_domainless_fd);

enum rezygiskd_command {
  START = 1,
  STOP = 2,
  EXIT = 3,

  /* sent from daemon */
  ZYGOTE64_INJECTED = 4,
  ZYGOTE32_INJECTED = 5,
  DAEMON64_SET_INFO = 6,
  DAEMON32_SET_INFO = 7,
  DAEMON64_SET_ERROR_INFO = 8,
  DAEMON32_SET_ERROR_INFO = 9
};

int send_control_command(enum rezygiskd_command cmd);

#endif /* MONITOR_H */
