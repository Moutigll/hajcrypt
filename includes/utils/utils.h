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

#endif /* HACRYPT_UTILS_H */
