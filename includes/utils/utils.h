#ifndef HACRYPT_UTILS_H
# define HACRYPT_UTILS_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Secure memory wipe that won't be optimized away by compiler
 * 
 * This function uses volatile pointer to prevent compiler optimizations
 * that might remove the memory clearing operation.
 * 
 * @param ptr Pointer to memory to wipe
 * @param len Number of bytes to wipe
 */
void secureZeroMemory(void *ptr, size_t len);

/**
 * @brief Secure free that wipes memory before freeing
 * 
 * @param ptr Pointer to memory to wipe and free
 * @param len Number of bytes that were allocated
 */
void secureFree(void *ptr, size_t len);

/**
 * @brief Reads the contents of a binary file into a dynamically allocated buffer.
 * 
 * @param file The path to the binary file to be read.
 * @param data A pointer to a uint8_t* variable where the address of the allocated buffer will be stored.
 * @param len A pointer to a size_t variable where the length of the read data will be stored.
 * 
 * @return An integer status code indicating success or failure:
 *         - 1 on success (data and len are set)
 *         - 0 on error (data and len are not modified)
 * 
 * @note The caller is responsible for freeing the allocated buffer pointed to by data after use.
 */
int readBinaryFile(const char *file, uint8_t **data, size_t *len);

#endif /* HACRYPT_UTILS_H */
