#include <stdlib.h>
#include <string.h>

#include "../includes/utils/utils.h"

/**
 * @brief Secure memory wipe that won't be optimized away by compiler
 * 
 * This function uses volatile pointer to prevent compiler optimizations
 * that might remove the memory clearing operation.
 * 
 * @param ptr Pointer to memory to wipe
 * @param len Number of bytes to wipe
 */
void secureZeroMemory(void *ptr, size_t len)
{
	if (ptr == NULL || len == 0)
		return;

#ifdef __linux__
	explicit_bzero(ptr, len);
#else
	volatile uint8_t *p = (volatile uint8_t *)ptr;
	while (len--) {
		*p++ = 0;
	}
	__asm__ volatile("" : : "r"(ptr) : "memory");
#endif
}

/**
 * @brief Secure free that wipes memory before freeing
 * 
 * @param ptr Pointer to memory to wipe and free
 * @param len Number of bytes that were allocated
 */
void secureFree(void *ptr, size_t len)
{
	if (ptr == NULL)
		return;
	
	/* Wipe the memory */
	secureZeroMemory(ptr, len);
	
	/* Free the memory */
	free(ptr);
}

