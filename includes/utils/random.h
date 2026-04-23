#ifndef HACRYPT_RANDOM_H
# define HACRYPT_RANDOM_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Generate secure random bytes and fill the provided buffer.
 * @param buf The buffer to fill with random bytes. Must be allocated by the caller and have at least `len` bytes of space.
 * @param len The number of random bytes to generate and write into `buf`.
 * @return 0 on success, -1 on failure (e.g., if `buf` is NULL, `len` is 0, or if there was an error reading random bytes).
 */
int	hajSecRandBytes(uint8_t *buf, size_t len);

/**
 * Generate a cryptographically secure random 64-bit unsigned integer.
 *
 * @return A random 64-bit value, or 0 on error.
 */
uint64_t hajRandomUint64(void);

/**
 * Generate a random 64-bit integer within [min, max] (inclusive).
 * Uses rejection sampling to avoid modulo bias.
 *
 * @param min Minimum value (inclusive)
 * @param max Maximum value (inclusive)
 * @return Random value in [min, max]
 */
uint64_t hajRandomRange(uint64_t min, uint64_t max);

#endif /* HACRYPT_RANDOM_H */
