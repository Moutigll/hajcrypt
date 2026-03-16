#ifndef HAJCRYPT_PBKDF_H
#define HAJCRYPT_PBKDF_H

#include <stddef.h>
#include <stdint.h>

#include "../cli/parser.h"

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * This function parses the input hexadecimal string `hex` and writes the corresponding
 * byte values into the `bytes` array. The function requires that the input not represent
 * more than `maxBytes` bytes; if it does, the conversion fails without truncation.
 *
 * @param hex       Pointer to a null-terminated hexadecimal string.
 * @param bytes     Pointer to the output byte array.
 * @param maxBytes  Maximum number of bytes that the output array can hold.
 * @return The number of bytes written to `bytes`, or -1 if the input is invalid (for
 *         example, if it contains non-hex characters or encodes more than `maxBytes` bytes).
 */
int	pbkdfHexToBytes(const char *hex, uint8_t *bytes, size_t maxBytes);


/**
 * @brief Derives a cryptographic key and initialization vector from SSL options.
 * 
 * @param opts Pointer to SSL options structure containing parameters for key derivation.
 * @param key Pointer to buffer where the derived key will be stored.
 * @param keyLen Length of the key buffer in bytes.
 * @param iv Pointer to buffer where the initialization vector will be stored.
 * 
 * @return Returns 0 on success, non-zero error code on failure.
 */
int deriveKeyFromParams(t_sslOptions *opts, uint8_t *key, size_t keyLen, uint8_t *iv);

#endif /* HAJCRYPT_PBKDF_H */
