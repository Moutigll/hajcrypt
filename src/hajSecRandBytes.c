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
#else
# error "Unsupported OS"
#endif

#include "../includes/utils/random.h"

int	hajSecRandBytes(uint8_t *buf, size_t len)
{
	if (!buf || len == 0)
		return (-1);

	
#ifdef __linux__
	ssize_t	readBytes = 0;
	size_t	total = 0;
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

uint64_t hajRandomUint64(void)
{
	uint64_t value = 0;
	
	if (hajSecRandBytes((uint8_t *)&value, sizeof(value)) != 0)
		return (0);   /* On error, return 0 (caller may retry) */
	
	return (value);
}

uint64_t hajRandomRange(uint64_t min, uint64_t max)
{
	uint64_t	range;
	uint64_t	limit;
	uint64_t	value;
	
	if (min >= max)
		return (min);

	if (max == UINT64_MAX && min == 0) /* Avoid modulo by zero */
		return (hajRandomUint64());

	range = max - min + 1;
	limit = UINT64_MAX - (UINT64_MAX % range);
	
	do {
		value = hajRandomUint64();
		if (value == 0 && hajRandomUint64() == 0 && hajRandomUint64() == 0)
		{
			/* Multiple consecutive errors - fallback to modulo (biased but better than hang) */
			return (min + (hajRandomUint64() % range));
		}
	} while (value >= limit);
	
	return (min + (value % range));
}
