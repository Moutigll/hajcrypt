#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/consts/consts.h"

/* Fast integer prime check */
static int isPrime(int n)
{
	if (n < 2)
		return 0;
	if (n == 2 || n == 3)
		return 1;
	if (n % 2 == 0)
		return 0;
	for (int i = 3; i*i <= n; i += 2)
		if (n % i == 0)
			return 0;
	return 1;
}

/* Fast cube root approximation using Newton-Raphson */
static double fastCbrt(double x)
{
	if (x == 0.0) return 0.0;
	double y = x;
	for (int i = 0; i < 5; i++)
		y = (2.0 * y + x / (y * y)) / 3.0;
	return y;
}

/* Get fractional part scaled to 32-bit uint */
#define FRACTIONAL32(x) ((uint32_t)((x - (uint32_t)(x)) * 4294967296.0))

/* Generate SHA-256 constants: H0..H7 and K[64] */
int generateSha256Header(int fd)
{
	ft_dprintf(fd, "#include <stdint.h>\n\n");

	/* --- SHA-256 initial hash H0..H7 --- */
	ft_dprintf(fd, "/* SHA-256 initial hash H0..H7 (first 32 bits of sqrt(primes)) */\n");
	int found = 0;
	for (int n = 2; found < 8; n++)
	{
		if (!isPrime(n))
			continue;
		uint32_t val = FRACTIONAL32(ft_sqrtNewton((double)n));
		char buf[11];
		writeUint32Hex(buf, val);
		ft_dprintf(fd, "#define H%d %s\n", found, buf);
		found++;
	}

	/* --- SHA-256 round constants K[64] --- */
	ft_dprintf(fd, "\n/* SHA-256 round constants K[64] (first 32 bits of cbrt(primes)) */\n");
	ft_dprintf(fd, "static const uint32_t K[64] = {\n");
	found = 0;
	for (int n = 2; found < 64; n++)
	{
		if (!isPrime(n))
			continue;
		uint32_t val = FRACTIONAL32(fastCbrt((double)n));
		char buf[11];
		writeUint32Hex(buf, val);
		ft_dprintf(fd, "\t%s%s\n", buf, (found == 63) ? "" : ",");
		found++;
	}
	ft_dprintf(fd, "};\n");

	return 0;
}
