#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../hajlib/include/hmemory.h"
#include "../includes/utils/utils.h"
#include "../includes/x509/oid.h"
#include "../includes/hajcrypt.h"

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

#if defined(__GLIBC__) && (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25)
	/* glibc 2.25+ has explicit_bzero */
	explicit_bzero(ptr, len);
#elif defined(__has_builtin) && __has_builtin(__builtin_memset)
	/* Clang/GCC builtin that won't be optimized away */
	__builtin_memset(ptr, 0, len);
#else
	/* Fallback implementation */
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


int readBinaryFile(const char *file, uint8_t **data, size_t *len)
{
	int		fd;
	uint8_t	tmp[4096];
	uint8_t	*buf;
	size_t	capacity;
	size_t	total;
	ssize_t	r;

	fd = file ? open(file, O_RDONLY) : STDIN_FILENO;
	if (fd < 0)
	{
		HAJCRYPT_DPRINT("cannot open '%s'\n", file ? file : "stdin");
		return (1);
	}

	capacity = 4096;
	buf = malloc(capacity);
	if (!buf)
	{
		HAJCRYPT_DPRINT("memory allocation failed\n");
		if (file)
			close(fd);
		return (1);
	}

	total = 0;
	while ((r = read(fd, tmp, sizeof(tmp))) > 0)
	{
		if (total + (size_t)r >= capacity)
		{
			while (total + (size_t)r >= capacity)
				capacity *= 2;
			buf = realloc(buf, capacity);
			if (!buf)
			{
				HAJCRYPT_DPRINT("memory allocation failed\n");
				if (file)
					close(fd);
				return (1);
			}
		}
		ft_memcpy(buf + total, tmp, r);
		total += r;
	}

	if (file)
		close(fd);

	*data = buf;
	if (len)
		*len = total;
	return (0);
}

int	oidEqual(const t_algoId *a, const t_algoId *b)
{
	if (!a || !b)
		return (0);
	if (a->len != b->len)
		return (0);
	return (ft_memcmp(a->data, b->data, a->len) == 0);
}
