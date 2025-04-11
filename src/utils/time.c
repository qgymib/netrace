#include <time.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "time.h"

uint64_t nt_clock_gettime_ms(void)
{    struct timespec t;
    NT_ASSERT(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "(%d) %s.", errno, strerror(errno));
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
        }
