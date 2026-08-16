#ifndef ZYGISK_H
#define ZYGISK_H

#include <stdbool.h>
#include <stddef.h>

extern void *start_addr;
extern size_t block_size;

bool hook_functions(bool require_domainless_fd_hook);

#endif /* ZYGISK_H */
