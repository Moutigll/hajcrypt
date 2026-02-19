#ifndef HAJCRYPT_CONSTS_H
#define HAJCRYPT_CONSTS_H

#include <stdint.h>
#define GET_FRACTIONAL(x) ((uint32_t)((x - (uint32_t)(x)) * 4294967296.0))

/* Header generator function type */
typedef int (*headerGenerator)(int fd);

/**
 * @brief Struct to represent a header file to generate, with its name and generator function.
 * The 'name' field is the base name of the header (e.g. "md5"),
 * and the 'generate' field is a function pointer to the function that generates the header content
 */
typedef struct s_header {
	const char		*name;
	headerGenerator	generate;
} t_header;

/**
 * @brief Convert a uint32_t value to a hexadecimal string representation in a buffer.
 * The buffer must be at least 11 characters long (including null terminator).
 * @param buf - buffer to write the hex string to
 * @param n - the uint32_t value to convert
 */
void writeUint32Hex(char buf[11], uint32_t n);

/**
 * @brief Generate the MD5 header file with initial state constants and sine-based constants.
 * @param fd - file descriptor to write the generated header content to
 * @return 0 on success, 1 on failure (e.g. write error)
 */
int generateMd5Header(int fd);

/**
 * @brief Generate the SHA-256 header file with initial state constants and prime-based constants.
 * @param fd - file descriptor to write the generated header content to
 * @return 0 on success, 1 on failure (e.g. write error)
 */
int generateSha256Header(int fd);

#endif /* HAJCRYPT_CONSTS_H */
