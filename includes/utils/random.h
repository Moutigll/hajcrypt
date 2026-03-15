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

#endif /* HACRYPT_RANDOM_H */
