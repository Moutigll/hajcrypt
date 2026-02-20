#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/consts/consts.h"

static int isPrime(int n)
{
	if (n < 2)
		return (0);
	if (n == 2 || n == 3)
		return (1);
	if (n % 2 == 0)
		return (0);
	for (int i = 3; i*i <= n; i += 2)
		if (n % i == 0)
			return (0);
	return (1);
}

int generateSha256Header(int fd)
{

	ft_dprintf(fd, "#include <stdint.h>\n\n");

	/* H0..H7 : square root of the first 8 primes */
	ft_dprintf(fd, "/* SHA-256 initial hash H0..H7 */\n");
	int found = 0;
	for (int n = 2; found < 8; n++)
	{
		if (!isPrime(n)) continue;
		uint32_t val = GET_FRACTIONAL(ft_sqrtNewton((double)n));
		ft_dprintf(fd, "#define H%d 0x%08X\n", found, val);
		found++;
	}

	/* K[64] : cube root of the first 64 primes */
	ft_dprintf(fd, "\n/* SHA-256 round constants K[64] */\n");
	ft_dprintf(fd, "static const uint32_t g_sha256_K[64] = {\n");
	found = 0;
	for (int n = 2; found < 64; n++)
	{
		if (!isPrime(n)) continue;
		uint32_t val = GET_FRACTIONAL(ft_cbrt((double)n));
		ft_dprintf(fd, "\t0x%08X%s\n", val, (found == 63) ? "" : ",");
		found++;
	}
	ft_dprintf(fd, "};\n");

	return (0);
}
