#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__linux__)
# include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
# include <stdlib.h> // arc4random_buf
#elif defined(_WIN32)
# include <windows.h>
# include <bcrypt.h>
# pragma comment(lib, "bcrypt.lib")
#else
# error "Unsupported OS"
#endif

#include "../includes/utils/random.h"

int	hajSecRandBytes(uint8_t *buf, size_t len)
{
	if (!buf || len == 0)
		return (-1);

	ssize_t	readBytes = 0;
	size_t	total = 0;

#ifdef __linux__
	while (total < len)
	{
		readBytes = getrandom(buf + total, len - total, 0);
		if (readBytes < 0)
		{
			if (errno == EINTR)
				continue; /* Retry on interruption */
			return (-1); /* Other errors */
		}
		total += readBytes;
	}
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	arc4random_buf(buf, len);
#elif defined(_WIN32)
	if (BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		return (-1);
#else
	/* Try Fallback: read from /dev/urandom */
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return (-1);

	while (total < len)
	{
		readBytes = read(fd, buf + total, len - total);
		if (readBytes < 0)
		{
			if (errno == EINTR)
				continue;
			close(fd);
			return (-1);
		}
		total += readBytes;
	}
	close(fd);
#endif

	return (0);
}
