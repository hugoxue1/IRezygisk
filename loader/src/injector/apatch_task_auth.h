#ifndef APATCH_TASK_AUTH_H
#define APATCH_TASK_AUTH_H

#include <stdbool.h>

bool apatch_task_auth_activate_zygote_carrier(void);
bool apatch_task_auth_begin_callback(void);
bool apatch_task_auth_end_callback(bool keep_carrier);
bool apatch_task_auth_enabled(void);

#endif /* APATCH_TASK_AUTH_H */
