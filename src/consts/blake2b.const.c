#include "../../hajlib/include/hprintf.h"
#include "../../includes/consts/consts.h"

static void writeUint64Hex(int fd, uint64_t val)
{
	int		i;
	uint8_t	byte;

	for (i = 0; i < 8; i++)
	{
		byte = (val >> (56 - i * 8)) & 0xFF;
		ft_dprintf(fd, "%02X", byte);
	}
}

static long double ft_fabsl(long double x)
{
	return (x < 0.0L) ? -x : x;
}

static long double ft_sqrtl(long double x)
{
	long double guess;
	long double prev_guess;

	if (x == 0.0L)
		return (0.0L);
	guess = x / 2.0L;
	do {
		prev_guess = guess;
		guess = (guess + x / guess) / 2.0L;
	} while (ft_fabsl(guess - prev_guess) > 1e-18L);
	return (guess);
}

static uint64_t sqrtFractional64(uint64_t n)
{
	unsigned __int128	low;
	unsigned __int128	high;
	unsigned __int128	mid;
	unsigned __int128	rhs;
	unsigned __int128	mask64;
	unsigned __int128	midSq;
	unsigned __int128	lhsHi;
	uint64_t			k;
	uint64_t			r;

	k = (uint64_t)ft_sqrtl((long double)n);
	while ((k + 1) * (k + 1) <= n)
		k++;
	while (k * k > n)
		k--;

	r      = n - k * k;
	rhs    = (unsigned __int128)r << 64;
	mask64 = ((unsigned __int128)1 << 64) - 1;
	low    = 0;
	high   = mask64;

	while (low < high)
	{
		mid    = low + (high - low + 1) / 2;
		midSq = mid * mid;
		lhsHi = (unsigned __int128)(2 * k) * mid + (midSq >> 64);

		if (lhsHi < rhs || (lhsHi == rhs && (midSq & mask64) == 0))
			low = mid;
		else
			high = mid - 1;
	}
	return (uint64_t)low;
}


static void generateIv(int fd)
{
	int		primes[8] = {2, 3, 5, 7, 11, 13, 17, 19};
	uint64_t	iv[8];
	int		i;

	ft_dprintf(fd, "/* Blake2b initialization vector (IV) */\n");
	ft_dprintf(fd, "/* From fractional parts of square roots of first 8 primes */\n");
	ft_dprintf(fd, "static const uint64_t g_blake2b_IV[8] = {\n");

	for (i = 0; i < 8; i++)
	{
		iv[i] = sqrtFractional64((uint64_t)primes[i]);
		ft_dprintf(fd, "\t0x");
		writeUint64Hex(fd, iv[i]);
		ft_dprintf(fd, "ULL");
		if (i < 7)
			ft_dprintf(fd, ",");
		ft_dprintf(fd, "\n");
	}
	ft_dprintf(fd, "};\n\n");
}

static void generateSigma(int fd)
{
	const uint8_t	basePerm[10][16] = {
		{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
		{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
		{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
		{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
		{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
		{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
		{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
		{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
		{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
	};
	uint8_t	sigma[12][16];
	int		round;
	int		i;

	for (i = 0; i < 16; i++)
	{
		sigma[0][i]  = (uint8_t)i;
		sigma[10][i] = (uint8_t)i;
	}
	for (round = 1; round < 10; round++)
		for (i = 0; i < 16; i++)
			sigma[round][i] = basePerm[round][i];
	for (i = 0; i < 16; i++)
		sigma[11][i] = basePerm[1][i];

	ft_dprintf(fd, "/* Blake2b sigma permutations (12 rounds x 16 indices) */\n");
	ft_dprintf(fd, "static const uint8_t g_blake2b_sigma[12][16] = {\n");

	for (round = 0; round < 12; round++)
	{
		ft_dprintf(fd, "\t{");
		for (i = 0; i < 16; i++)
		{
			ft_dprintf(fd, "%2d", sigma[round][i]);
			if (i < 15)
				ft_dprintf(fd, ",");
		}
		ft_dprintf(fd, "}");
		if (round < 11)
			ft_dprintf(fd, ",");
		ft_dprintf(fd, "\n");
	}
	ft_dprintf(fd, "};\n\n");
}

int generateBlake2bHeader(int fd)
{
	if (fd < 0)
		return (-1);

	ft_dprintf(fd, "#include <stdint.h>\n\n");

	generateIv(fd);
	generateSigma(fd);

	return (0);
}
