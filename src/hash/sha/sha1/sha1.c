#include "../../../../includes/hash/sha/sha1.h"
#include "../../../../includes/consts/sha.h"

#if defined(__aarch64__) && (defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_SHA1))
	#define SHA_USE_ARM64 1
#else
	#define SHA_USE_ARM64 0

#include "../../../../includes/utils/bitopts.h"

static void sha1Transform(uint32_t state[5], const uint8_t block[64])
{
	uint32_t	w[80];
	uint32_t	a = state[0];
	uint32_t	b = state[1];
	uint32_t	c = state[2];
	uint32_t	d = state[3];
	uint32_t	e = state[4];
	int			i;

	for (i = 0; i < 16; i++)
		w[i] = load32Be(block + i * 4);

	for (i = 16; i < 80; i++)
		w[i] = rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

	for (i = 0; i < 80; i++)
	{
		uint32_t f, k;
		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}

		uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = temp;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

#endif

#define SHA_NAME				sha1
#define SHA_CTX					t_sha1Ctx
#define SHA_OID					SHA1_OID
#define SHA_DEPRECATED			1
#define SHA_DIGEST_SIZE			SHA1_DIGEST_SIZE
#define SHA_BLOCK_SIZE			SHA1_BLOCK_SIZE
#define SHA_STATE_WORDS			5
#define SHA_WORD				uint32_t
#define SHA_H0					SHA1_H0
#define SHA_H1					SHA1_H1
#define SHA_H2					SHA1_H2
#define SHA_H3					SHA1_H3
#define SHA_H4					SHA1_H4

#define SHA_TRANSFORM			sha1Transform
#define SHA_TRANSFORM_ARM64		sha1TransformArm64
#define SHA_LOAD_BE(ptr)		load32Be(ptr)
#define SHA_STORE_BE(ptr, val)	store32Be(ptr, val)
#define SHA_PAD_PARAMS			{ .blockSize = SHA1_BLOCK_SIZE, .isLittleEndian = 0, .lengthFieldSize = 8 }

#include "../shaImplTemplate.h"
