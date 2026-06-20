#include "../../../includes/utils/bitopts.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/chacha20Poly1305.h"

#ifndef CHACHA_USE_NEON

/**
 * @brief Performs one ChaCha20 quarter round operation.
 * 
 * Executes a quarter round on four 32-bit state words as specified in RFC 7539.
 * A quarter round consists of four operations performed in sequence:
 * 1. a += b, d ^= a, d <<<= 16
 * 2. c += d, b ^= c, b <<<= 12
 * 3. a += b, d ^= a, d <<<= 8
 * 4. c += d, b ^= c, b <<<= 7
 * 
 * This function is called multiple times per ChaCha20 block to mix the state.
 * 
 * @param a Pointer to first state word (modified in-place)
 * @param b Pointer to second state word (modified in-place)
 * @param c Pointer to third state word (modified in-place)
 * @param d Pointer to fourth state word (modified in-place)
 */
static void	chacha20QuarterRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a += *b; *d ^= *a; *d = rotateLeft(*d, 16);
	*c += *d; *b ^= *c; *b = rotateLeft(*b, 12);
	*a += *b; *d ^= *a; *d = rotateLeft(*d, 8);
	*c += *d; *b ^= *c; *b = rotateLeft(*b, 7);
}

/**
 * @brief Generates one block of ChaCha20 keystream (scalar implementation).
 * 
 * Performs the ChaCha20 block function as specified in RFC 7539:
 * - Copies the state to a working buffer
 * - Applies 10 iterations of quarter-round operations (20 rounds total):
 *   - 4 column rounds
 *   - 4 diagonal rounds
 * - Adds the original state to the working buffer
 * - Serializes the result as little-endian 32-bit words into the keystream
 * - Increments the block counter in the state
 * 
 * @param state Pointer to the 16-word ChaCha20 state matrix (modified by incrementing counter)
 * @param keystream Output buffer for 64-byte keystream block
 */
static void	chacha20Block(uint32_t state[16], uint8_t keystream[CHACHA20_BLOCK_SIZE])
{
	uint32_t	working[16];
	int			i;

	ft_memcpy(working, state, sizeof(working));
	for (i = 0; i < 10; i++)
	{
		/* Columns */
		chacha20QuarterRound(&working[0], &working[4], &working[8], &working[12]);
		chacha20QuarterRound(&working[1], &working[5], &working[9], &working[13]);
		chacha20QuarterRound(&working[2], &working[6], &working[10], &working[14]);
		chacha20QuarterRound(&working[3], &working[7], &working[11], &working[15]);
		/* Diagonals */
		chacha20QuarterRound(&working[0], &working[5], &working[10], &working[15]);
		chacha20QuarterRound(&working[1], &working[6], &working[11], &working[12]);
		chacha20QuarterRound(&working[2], &working[7], &working[8], &working[13]);
		chacha20QuarterRound(&working[3], &working[4], &working[9], &working[14]);
	}
	for (i = 0; i < 16; i++)
		working[i] += state[i];
	/* Always store as little-endian as specified by RFC 7539 */
	for (i = 0; i < 16; i++)
		store32(keystream + i * 4, working[i]);
	state[12]++;
}

#else /* CHACHA_USE_NEON */

#include <arm_neon.h>

/**
 * @brief Generates one block of ChaCha20 keystream (NEON accelerated implementation).
 * 
 * NEON-optimized version that processes four quarter-round operations in parallel.
 * Uses column and diagonal rounds with proper vector element permutation.
 * Handles endianness correctly for both little-endian and big-endian architectures.
 * 
 * @param state Pointer to the 16-word ChaCha20 state matrix (modified by incrementing counter)
 * @param keystream Output buffer for 64-byte keystream block
 */
static void	chacha20BlockNeon(uint32_t state[16], uint8_t keystream[CHACHA20_BLOCK_SIZE])
{
	uint32x4_t	v0, v1, v2, v3;
	uint32x4_t	orig0, orig1, orig2, orig3;
	int			i;

	/* Load state vectors */
	v0 = vld1q_u32(state + 0);
	v1 = vld1q_u32(state + 4);
	v2 = vld1q_u32(state + 8);
	v3 = vld1q_u32(state + 12);

	/* Save original state for final addition */
	orig0 = v0;
	orig1 = v1;
	orig2 = v2;
	orig3 = v3;

	/* 10 double rounds = 20 rounds total */
	for (i = 0; i < 10; i++)
	{
		/* Column 0: a=v0, b=v1, c=v2, d=v3 */
		/* 1: a += b; d ^= a; d <<<= 16 */
		v0 = vaddq_u32(v0, v1);
		v3 = veorq_u32(v3, v0);
		v3 = neonRol(v3, 16);

		/* 2: c += d; b ^= c; b <<<= 12 */
		v2 = vaddq_u32(v2, v3);
		v1 = veorq_u32(v1, v2);
		v1 = neonRol(v1, 12);

		/* 3: a += b; d ^= a; d <<<= 8 */
		v0 = vaddq_u32(v0, v1);
		v3 = veorq_u32(v3, v0);
		v3 = neonRol(v3, 8);

		/* 4: c += d; b ^= c; b <<<= 7 */
		v2 = vaddq_u32(v2, v3);
		v1 = veorq_u32(v1, v2);
		v1 = neonRol(v1, 7);

		v1 = vextq_u32(v1, v1, 1);  /* Rotate left by 1 element */
		v2 = vextq_u32(v2, v2, 2);  /* Rotate left by 2 elements */
		v3 = vextq_u32(v3, v3, 3);  /* Rotate left by 3 elements */

		/* Diagonal 0: a=v0, b=v1, c=v2, d=v3 */
		/* 1: a += b; d ^= a; d <<<= 16 */
		v0 = vaddq_u32(v0, v1);
		v3 = veorq_u32(v3, v0);
		v3 = neonRol(v3, 16);

		/* 2: c += d; b ^= c; b <<<= 12 */
		v2 = vaddq_u32(v2, v3);
		v1 = veorq_u32(v1, v2);
		v1 = neonRol(v1, 12);

		/* 3: a += b; d ^= a; d <<<= 8 */
		v0 = vaddq_u32(v0, v1);
		v3 = veorq_u32(v3, v0);
		v3 = neonRol(v3, 8);

		/* 4: c += d; b ^= c; b <<<= 7 */
		v2 = vaddq_u32(v2, v3);
		v1 = veorq_u32(v1, v2);
		v1 = neonRol(v1, 7);

		v1 = vextq_u32(v1, v1, 3);  /* Rotate left by 3 (= right by 1) to undo */
		v2 = vextq_u32(v2, v2, 2);  /* Rotate left by 2 to undo (same as rotation) */
		v3 = vextq_u32(v3, v3, 1);  /* Rotate left by 1 (= right by 3) to undo */
	}

	/* Add original state */
	v0 = vaddq_u32(v0, orig0);
	v1 = vaddq_u32(v1, orig1);
	v2 = vaddq_u32(v2, orig2);
	v3 = vaddq_u32(v3, orig3);

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/* Big-endian: swap bytes within each 32-bit word to get little-endian output */
	v0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v0)));
	v1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v1)));
	v2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v2)));
	v3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v3)));
#endif

	/* Store directly as 32-bit words (little-endian format) */
	vst1q_u8(keystream + 0,  vreinterpretq_u8_u32(v0));
	vst1q_u8(keystream + 16, vreinterpretq_u8_u32(v1));
	vst1q_u8(keystream + 32, vreinterpretq_u8_u32(v2));
	vst1q_u8(keystream + 48, vreinterpretq_u8_u32(v3));

	/* Increment block counter */
	state[12]++;
}

#endif /* CHACHA_USE_NEON */

void	chacha20Init(t_chacha20Ctx	*ctx,
					 const uint8_t	key[CHACHA20_KEY_SIZE],
					 const uint8_t	nonce[CHACHA20_NONCE_SIZE],
					 uint32_t		counter)
{
	int	i;

	ctx->state[0] = CHACHA20_CONSTANT_0;
	ctx->state[1] = CHACHA20_CONSTANT_1;
	ctx->state[2] = CHACHA20_CONSTANT_2;
	ctx->state[3] = CHACHA20_CONSTANT_3;

	for (i = 0; i < 8; i++)
		ctx->state[4 + i] = load32(key + i * 4);

	ctx->state[12] = counter;

	for (i = 0; i < 3; i++)
		ctx->state[13 + i] = load32(nonce + i * 4);

	ctx->keystreamPos = CHACHA20_BLOCK_SIZE;
}

void	chacha20NextBlock(t_chacha20Ctx *ctx, uint8_t keystream[CHACHA20_BLOCK_SIZE])
{
#ifdef CHACHA_USE_NEON
	chacha20BlockNeon(ctx->state, keystream);
#else
	chacha20Block(ctx->state, keystream);
#endif
}

void	chacha20GenerateKeystream(t_chacha20Ctx *ctx, uint8_t *keystream, size_t len)
{
	size_t	offset = 0;
	uint8_t	block[CHACHA20_BLOCK_SIZE];

	while (len >= CHACHA20_BLOCK_SIZE)
	{
		chacha20NextBlock(ctx, keystream + offset);
		offset += CHACHA20_BLOCK_SIZE;
		len -= CHACHA20_BLOCK_SIZE;
	}

	if (len > 0)
	{
		chacha20NextBlock(ctx, block);
		ft_memcpy(keystream + offset, block, len);
	}
}

void	chacha20Crypt(t_chacha20Ctx *ctx, const uint8_t *input, uint8_t *output, size_t len)
{
	size_t	i;

	for (i = 0; i < len; i++)
	{
		if (ctx->keystreamPos == CHACHA20_BLOCK_SIZE)
		{
			chacha20NextBlock(ctx, ctx->keystream);
			ctx->keystreamPos = 0;
		}
		output[i] = input[i] ^ ctx->keystream[ctx->keystreamPos++];
	}
}

/* ---------- Generic cipher API implementation ---------- */

int	chacha20InitGen(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	t_chacha20Ctx	*ctx = vctx;

	(void)dir;

	if (!ctx || !key || keyLen != CHACHA20_KEY_SIZE || !iv)
		return (-1);

	chacha20Init(ctx, key, iv, 0);
	return (0);
}

void	chacha20UpdateGen(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_chacha20Ctx	*ctx = vctx;

	*outLen = 0;

	if (!inLen)
		return;

	chacha20Crypt(ctx, in, out, inLen);
	*outLen = inLen;
}

void	chacha20FinalGen(void *vctx, uint8_t *out, size_t *outLen)
{
	(void)vctx;
	(void)out;
	*outLen = 0;
}

void	chacha20Free(void *vctx)
{
	if (vctx)
		secureZeroMemory(vctx, sizeof(t_chacha20Ctx));
}

const t_cipher	g_chacha20Cipher = {
	.name			= "chacha20",
	.deprecated		= 0,
	.mode			= CIPHER_MODE_STREAM,
	.oid			= OID_NONE,
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= 1,
	.keySize		= CHACHA20_KEY_SIZE,
	.ivSize			= CHACHA20_NONCE_SIZE,
	.ctxSize		= sizeof(t_chacha20Ctx),
	.init			= chacha20InitGen,
	.update			= chacha20UpdateGen,
	.final			= chacha20FinalGen,
	.free			= chacha20Free,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
