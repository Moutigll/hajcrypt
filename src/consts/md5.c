#include <stdlib.h>
#include <stdint.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmath.h"

#include "../../includes/consts/consts.h"

#define MD5_FRACTIONAL(x) ((uint32_t)((x - (uint32_t)(x)) * 4294967296.0))
#define SIN_CONSTS_COUNT 64

/* Convert uint32_t -> hex string (0xXXXXXXXX) */
static char *uint32ToHex(uint32_t n)
{
	static const char hex[] = "0123456789ABCDEF";
	char *buf = malloc(11);
	if (!buf)
		return (NULL);
	buf[0] = '0';
	buf[1] = 'x';
	for (int i = 0; i < 8; i++)
		buf[2 + i] = hex[(n >> ((7 - i) * 4)) & 0xF];
	buf[10] = '\0';
	return (buf);
}

/* Generate 64 constants based on sine function as an example */
int generateMd5SinConsts(int fd)
{
	ft_dprintf(fd, "\n/* MD5 sine-based constants (K) */\n");
	ft_dprintf(fd, "static const uint32_t g_MD5_K[64] = {\n");
	for (int i = 0; i < 64; i++)
	{
		uint32_t val = MD5_FRACTIONAL(ft_fabs(ft_sin(i + 1)));
		char *hex = uint32ToHex(val);

		ft_dprintf(fd, "\t%s,%s\n", hex, (i == 63) ? "" : "");
		free(hex);
	}
	ft_dprintf(fd, "};\n");

	return (0);
}

int generateMd5Shifts(int fd)
{
	ft_dprintf(fd, "\n/* MD5 shift amounts (S) */\n");
	ft_dprintf(fd, "static const uint32_t g_MD5_S[64] = {\n");

	ft_dprintf(fd,
		"\t7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,\n"
		"\t5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,\n"
		"\t4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,\n"
		"\t6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21\n"
	);

	ft_dprintf(fd, "};\n");

	return (0);
}

/* Generate MD5 initial state constants */
int generateMd5Header(int fd)
{
	ft_dprintf(fd, "#include <stdint.h>\n\n\n");

	ft_dprintf(fd, "/* MD5 initial state (A, B, C, D) */\n");
	ft_dprintf(fd, "#define MD5_INIT_A 0x%08X\n", 0x67452301);
	ft_dprintf(fd, "#define MD5_INIT_B 0x%08X\n", 0xEFCDAB89);
	ft_dprintf(fd, "#define MD5_INIT_C 0x%08X\n", 0x98BADCFE);
	ft_dprintf(fd, "#define MD5_INIT_D 0x%08X\n", 0x10325476);

	if (generateMd5Shifts(fd) != 0)
		return (1);

	if (generateMd5SinConsts(fd) != 0)
		return (1);

	return (0);
}
