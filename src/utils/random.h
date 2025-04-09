#ifndef NT_UTILS_RANDOM_H
#define NT_UTILS_RANDOM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Random.
 * @return  2 bytes random data.
 */
uint16_t nt_random_u16(void);

#ifdef __cplusplus
}
#endif
#endif
