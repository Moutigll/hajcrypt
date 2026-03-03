#ifndef HAJCRYPT_PBKDF_H
#define HAJCRYPT_PBKDF_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * This function parses the input hexadecimal string `hex` and writes the corresponding
 * byte values into the `bytes` array. The conversion stops when either the end of the
 * string is reached or `maxBytes` bytes have been written.
 *
 * @param hex       Pointer to a null-terminated hexadecimal string.
 * @param bytes     Pointer to the output byte array.
 * @param maxBytes  Maximum number of bytes to write to the output array.
 * @return The number of bytes written to `bytes`, or -1 if the input is invalid.
 */
int	pbkdfHexToBytes(const char *hex, uint8_t *bytes, size_t maxBytes);

#endif /* HAJCRYPT_PBKDF_H */
