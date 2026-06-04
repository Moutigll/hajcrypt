#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hprintf.h"
#include "../../includes/consts/consts.h"

static uint32_t getFractional32(double x)
{
	double fractional = x - (double)((uint64_t)x);
	return (uint32_t)(fractional * 4294967296.0);  /* 2^32 */
}

static int generateSha1Consts(int fd)
{
	ft_dprintf(fd, "#include <stdint.h>\n\n");
	ft_dprintf(fd, "/* --------------- SHA-1 Constants --------------- */\n\n");

	ft_dprintf(fd, "/* SHA-1 initial hash values (standard) */\n");
	ft_dprintf(fd, "#define SHA1_H0 0x67452301\n");
	ft_dprintf(fd, "#define SHA1_H1 0xEFCDAB89\n");
	ft_dprintf(fd, "#define SHA1_H2 0x98BADCFE\n");
	ft_dprintf(fd, "#define SHA1_H3 0x10325476\n");
	ft_dprintf(fd, "#define SHA1_H4 0xC3D2E1F0\n");

	/* SHA-1 round constants K[0..79] = floor(2^30 * sqrt(2,3,5,10)) */
	ft_dprintf(fd, "\n/* SHA-1 round constants K[0..79] (floor(2^30 * sqrt(n))) */\n");
	ft_dprintf(fd, "static const uint32_t g_sha1_K[80] = {\n");
	
	/* Rounds 0-19 : floor(2^30 * sqrt(2)) = 0x5A827999 */
	uint32_t k0_19 = (uint32_t)(1073741824.0 * ft_sqrtNewton(2.0));  /* 2^30 */
	for (int i = 0; i < 20; i++)
		ft_dprintf(fd, "\t0x%08X,%s\n", k0_19, (i == 19) ? "" : "");
	
	/* Rounds 20-39 : floor(2^30 * sqrt(3)) = 0x6ED9EBA1 */
	uint32_t k20_39 = (uint32_t)(1073741824.0 * ft_sqrtNewton(3.0));
	for (int i = 20; i < 40; i++)
		ft_dprintf(fd, "\t0x%08X,%s\n", k20_39, (i == 39) ? "" : "");
	
	/* Rounds 40-59 : floor(2^30 * sqrt(5)) = 0x8F1BBCDC */
	uint32_t k40_59 = (uint32_t)(1073741824.0 * ft_sqrtNewton(5.0));
	for (int i = 40; i < 60; i++)
		ft_dprintf(fd, "\t0x%08X,%s\n", k40_59, (i == 59) ? "" : "");
	
	/* Rounds 60-79 : floor(2^30 * sqrt(10)) = 0xCA62C1D6 */
	uint32_t k60_79 = (uint32_t)(1073741824.0 * ft_sqrtNewton(10.0));
	for (int i = 60; i < 80; i++)
		ft_dprintf(fd, "\t0x%08X%s\n", k60_79, (i == 79) ? "" : ",");
	
	ft_dprintf(fd, "};\n\n");
	return (0);
}

/* --------------------------------------------------------------------------
 * SHA-224 : valeurs initiales fixes, K identiques à SHA-256
 * -------------------------------------------------------------------------- */
static int generateSha224Consts(int fd)
{
	ft_dprintf(fd, "\n\n/* --------------- SHA-224 Constants --------------- */\n\n");

	/* SHA-224 initial hash values (standard) */
	ft_dprintf(fd, "/* SHA-224 initial hash values (standard) */\n");
	ft_dprintf(fd, "#define SHA224_H0 0xC1059ED8\n");
	ft_dprintf(fd, "#define SHA224_H1 0x367CD507\n");
	ft_dprintf(fd, "#define SHA224_H2 0x3070DD17\n");
	ft_dprintf(fd, "#define SHA224_H3 0xF70E5939\n");
	ft_dprintf(fd, "#define SHA224_H4 0xFFC00B31\n");
	ft_dprintf(fd, "#define SHA224_H5 0x68581511\n");
	ft_dprintf(fd, "#define SHA224_H6 0x64F98FA7\n");
	ft_dprintf(fd, "#define SHA224_H7 0xBEFA4FA4\n");

	ft_dprintf(fd, "\n/* SHA-224 uses the same round constants as SHA-256 */\n");
	ft_dprintf(fd, "#define g_sha224_K g_sha256_K\n\n");
	return (0);
}

static int generateSha256Consts(int fd)
{
	ft_dprintf(fd, "\n\n/* --------------- SHA-256 Constants --------------- */\n\n");

	/* SHA-256 initial hash H0..H7 (fractional parts of square roots of first 8 primes) */
	ft_dprintf(fd, "/* SHA-256 initial hash values */\n");
	int found = 0;
	for (int n = 2; found < 8; n++)
	{
		if (!isPrime(n))
			continue;
		uint32_t val = getFractional32(ft_sqrtNewton((double)n));
		ft_dprintf(fd, "#define SHA256_H%d 0x%08X\n", found, val);
		found++;
	}

	/* SHA-256 round constants K[64] (fractional parts of cube roots of first 64 primes) */
	ft_dprintf(fd, "\n/* SHA-256 round constants K[0..63] */\n");
	ft_dprintf(fd, "static const uint32_t g_sha256_K[64] = {\n");
	found = 0;
	for (int n = 2; found < 64; n++)
	{
		if (!isPrime(n))
			continue;
		uint32_t val = getFractional32(ft_cbrt((double)n));
		ft_dprintf(fd, "\t0x%08X%s\n", val, (found == 63) ? "" : ",");
		found++;
	}
	ft_dprintf(fd, "};\n\n");
	return (0);
}

static int generateSha384Consts(int fd)
{
	ft_dprintf(fd, "\n\n/* --------------- SHA-384 Constants --------------- */\n\n");

	/* SHA-384 initial hash values (standard) */
	ft_dprintf(fd, "/* SHA-384 initial hash values (standard) */\n");
	ft_dprintf(fd, "#define SHA384_H0 0xCBBB9D5DC1059ED8ULL\n");
	ft_dprintf(fd, "#define SHA384_H1 0x629A292A367CD507ULL\n");
	ft_dprintf(fd, "#define SHA384_H2 0x9159015A3070DD17ULL\n");
	ft_dprintf(fd, "#define SHA384_H3 0x152FECD8F70E5939ULL\n");
	ft_dprintf(fd, "#define SHA384_H4 0x67332667FFC00B31ULL\n");
	ft_dprintf(fd, "#define SHA384_H5 0x8EB44A8768581511ULL\n");
	ft_dprintf(fd, "#define SHA384_H6 0xDB0C2E0D64F98FA7ULL\n");
	ft_dprintf(fd, "#define SHA384_H7 0x47B5481DBEFA4FA4ULL\n");

	ft_dprintf(fd, "\n/* SHA-384 uses the same round constants as SHA-512 */\n");
	ft_dprintf(fd, "#define g_sha384_K g_sha512_K\n\n");
	return (0);
}

static int generateSha512Consts(int fd)
{
	ft_dprintf(fd, "\n\n/* --------------- SHA-512 Constants --------------- */\n\n");

	/* SHA-512 initial hash values (standard) */
	ft_dprintf(fd, "/* SHA-512 initial hash values */\n");
	ft_dprintf(fd, "#define SHA512_H0 0x6A09E667F3BCC908ULL\n");
	ft_dprintf(fd, "#define SHA512_H1 0xBB67AE8584CAA73BULL\n");
	ft_dprintf(fd, "#define SHA512_H2 0x3C6EF372FE94F82BULL\n");
	ft_dprintf(fd, "#define SHA512_H3 0xA54FF53A5F1D36F1ULL\n");
	ft_dprintf(fd, "#define SHA512_H4 0x510E527FADE682D1ULL\n");
	ft_dprintf(fd, "#define SHA512_H5 0x9B05688C2B3E6C1FULL\n");
	ft_dprintf(fd, "#define SHA512_H6 0x1F83D9ABFB41BD6BULL\n");
	ft_dprintf(fd, "#define SHA512_H7 0x5BE0CD19137E2179ULL\n");

	/* SHA-512 round constants K[80] */
	ft_dprintf(fd, "\n/* SHA-512 round constants K[0..79] */\n");
	ft_dprintf(fd, "static const uint64_t g_sha512_K[80] = {\n"); /* We need 64 bits of floating-point precision and i'm too lazy to implement 80bit double-precision for all platforms, so dumb copy paste it is */
	ft_dprintf(fd, "	0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL,\n");
	ft_dprintf(fd, "	0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,\n");
	ft_dprintf(fd, "	0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,\n");
	ft_dprintf(fd, "	0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,\n");
	ft_dprintf(fd, "	0xD807AA98A3030242ULL, 0x12835B0145706FBEULL,\n");
	ft_dprintf(fd, "	0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,\n");
	ft_dprintf(fd, "	0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL,\n");
	ft_dprintf(fd, "	0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,\n");
	ft_dprintf(fd, "	0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,\n");
	ft_dprintf(fd, "	0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,\n");
	ft_dprintf(fd, "	0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL,\n");
	ft_dprintf(fd, "	0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,\n");
	ft_dprintf(fd, "	0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL,\n");
	ft_dprintf(fd, "	0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,\n");
	ft_dprintf(fd, "	0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,\n");
	ft_dprintf(fd, "	0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,\n");
	ft_dprintf(fd, "	0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL,\n");
	ft_dprintf(fd, "	0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,\n");
	ft_dprintf(fd, "	0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL,\n");
	ft_dprintf(fd, "	0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,\n");
	ft_dprintf(fd, "	0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,\n");
	ft_dprintf(fd, "	0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,\n");
	ft_dprintf(fd, "	0xD192E819D6EF5218ULL, 0xD69906245565A910ULL,\n");
	ft_dprintf(fd, "	0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,\n");
	ft_dprintf(fd, "	0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL,\n");
	ft_dprintf(fd, "	0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,\n");
	ft_dprintf(fd, "	0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,\n");
	ft_dprintf(fd, "	0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,\n");
	ft_dprintf(fd, "	0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL,\n");
	ft_dprintf(fd, "	0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,\n");
	ft_dprintf(fd, "	0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL,\n");
	ft_dprintf(fd, "	0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,\n");
	ft_dprintf(fd, "	0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,\n");
	ft_dprintf(fd, "	0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,\n");
	ft_dprintf(fd, "	0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL,\n");
	ft_dprintf(fd, "	0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,\n");
	ft_dprintf(fd, "	0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL,\n");
	ft_dprintf(fd, "	0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,\n");
	ft_dprintf(fd, "	0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,\n");
	ft_dprintf(fd, "	0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL\n");
	ft_dprintf(fd, "};\n\n");
	return (0);
}

static int generateSha512_224Consts(int fd)
{
	ft_dprintf(fd, "\n\n/* --------------- SHA-512/224 Constants --------------- */\n\n");

	/* SHA-512/224 initial hash values (standard) */
	ft_dprintf(fd, "/* SHA-512/224 initial hash values (standard) */\n");
	ft_dprintf(fd, "#define SHA512_224_H0 0x8C3D37C819544DA2ULL\n");
	ft_dprintf(fd, "#define SHA512_224_H1 0x73E1996689DCD4D6ULL\n");
	ft_dprintf(fd, "#define SHA512_224_H2 0x1DFAB7AE32FF9C82ULL\n");
	ft_dprintf(fd, "#define SHA512_224_H3 0x679DD514582F9FCFULL\n");
	ft_dprintf(fd, "#define SHA512_224_H4 0x0F6D2B697BD44DA8ULL\n");
	ft_dprintf(fd, "#define SHA512_224_H5 0x77E36F7304C48942ULL\n");
	ft_dprintf(fd, "#define SHA512_224_H6 0x3F9D85A86A1D36C8ULL\n");
	ft_dprintf(fd, "#define SHA512_224_H7 0x1112E6AD91D692A1ULL\n");

	ft_dprintf(fd, "\n/* SHA-512/224 uses the same round constants as SHA-512 */\n");
	ft_dprintf(fd, "#define g_sha512_224_K g_sha512_K\n\n");
	return (0);
}

static int generateSha512_256Consts(int fd)
{
	ft_dprintf(fd, "\n\n/* --------------- SHA-512/256 Constants --------------- */\n\n");

	/* SHA-512/256 initial hash values (standard) */
	ft_dprintf(fd, "/* SHA-512/256 initial hash values (standard) */\n");
	ft_dprintf(fd, "#define SHA512_256_H0 0x22312194FC2BF72CULL\n");
	ft_dprintf(fd, "#define SHA512_256_H1 0x9F555FA3C84C64C2ULL\n");
	ft_dprintf(fd, "#define SHA512_256_H2 0x2393B86B6F53B151ULL\n");
	ft_dprintf(fd, "#define SHA512_256_H3 0x963877195940EABDULL\n");
	ft_dprintf(fd, "#define SHA512_256_H4 0x96283EE2A88EFFE3ULL\n");
	ft_dprintf(fd, "#define SHA512_256_H5 0xBE5E1E2553863992ULL\n");
	ft_dprintf(fd, "#define SHA512_256_H6 0x2B0199FC2C85B8AAULL\n");
	ft_dprintf(fd, "#define SHA512_256_H7 0x0EB72DDC81C52CA2ULL\n");

	ft_dprintf(fd, "\n/* SHA-512/256 uses the same round constants as SHA-512 */\n");
	ft_dprintf(fd, "#define g_sha512_256_K g_sha512_K\n\n");
	return (0);
}

int generateShaHeader(int fd)
{
	generateSha1Consts(fd);
	generateSha224Consts(fd);
	generateSha256Consts(fd);
	generateSha384Consts(fd);
	generateSha512Consts(fd);
	generateSha512_224Consts(fd);
	generateSha512_256Consts(fd);
	return (0);
}
