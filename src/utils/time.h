#ifndef NT_UTILS_TIME_H
#define NT_UTILS_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get high resolution clock time.
 * @return Timestamp.
 */
uint64_t nt_clock_gettime_ms(void);

/**
 * @brief Sleep timeout.
 * @param[in] ms  Timeout in millisecond.
 */
void nt_sleep(uint32_t ms);

#ifdef __cplusplus
}
#endif
#endif
