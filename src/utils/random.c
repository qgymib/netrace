#include <sys/random.h>
#include "utils/log.h"
#include "random.h"

uint16_t nt_random_u16(void)
{
    uint16_t data = 0;
    NT_ASSERT(getrandom(&data, sizeof(data), 0) == 0, "getrandom() failed.");
    return data;
}
