#include "../../../includes/cipher/blowfish.h"
#include "../../../includes/consts/blowfish.h"

void	blowfishInitKey(t_blowfishEcbCtx *ctx, const uint8_t *key, size_t keyLen)
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	data;
	uint32_t	l;
	uint32_t	r;
	uint64_t	block;

	/* Copy initial P-array from constants */
	for (i = 0; i < 18; i++)
		ctx->P[i] = g_blowfish_P_init[i];

	/* Copy initial S-boxes from constants */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j++)
			ctx->S[i][j] = g_blowfish_S_init[i][j];
	}

	/* XOR P-array with key (cycling through key bytes) */
	j = 0;
	for (i = 0; i < 18; i++)
	{
		data = ((uint32_t)key[j % keyLen] << 24) |
			   ((uint32_t)key[(j + 1) % keyLen] << 16) |
			   ((uint32_t)key[(j + 2) % keyLen] << 8) |
			   (uint32_t)key[(j + 3) % keyLen];
		ctx->P[i] ^= data;
		j = (j + 4) % keyLen;
	}

	/* Expand key by encrypting zero block to initialize P-array */
	l = 0;
	r = 0;
	for (i = 0; i < 18; i += 2)
	{
		block = ((uint64_t)l << 32) | r;
		block = blowfishEncryptBlock(ctx, block);
		l = block >> 32;
		r = block & 0xFFFFFFFF;
		ctx->P[i] = l;
		ctx->P[i + 1] = r;
	}

	/* Continue expanding to initialize S-boxes */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			block = ((uint64_t)l << 32) | r;
			block = blowfishEncryptBlock(ctx, block);
			l = block >> 32;
			r = block & 0xFFFFFFFF;
			ctx->S[i][j] = l;
			ctx->S[i][j + 1] = r;
		}
	}
}

/*
 * Encrypt a single 64-bit block using Blowfish
 * Standard 16-round Feistel network
 */
uint64_t	blowfishEncryptBlock(const t_blowfishEcbCtx *ctx, uint64_t block)
{
	uint32_t	l;
	uint32_t	r;
	uint32_t	temp;
	int			i;

	/* Split 64-bit block into two 32-bit halves */
	l = block >> 32;
	r = block & 0xFFFFFFFF;

	/* XOR left half with first P-array entry */
	l ^= ctx->P[0];

	/* 16 rounds of Feistel network */
	for (i = 1; i < 16; i += 2)
	{
		/* Round i */
		r ^= blowfishFFast(l, ctx->S) ^ ctx->P[i];
		
		/* Round i+1 */
		l ^= blowfishFFast(r, ctx->S) ^ ctx->P[i + 1];
	}

	/* XOR right half with last P-array entry */
	r ^= ctx->P[17];

	/* Final swap (undo last swap) */
	temp = l;
	l = r;
	r = temp;

	/* Recombine into 64-bit block */
	return (((uint64_t)l << 32) | r);
}

/*
 * Decrypt a single 64-bit block using Blowfish
 * Uses same P-array but in reverse order
 */
uint64_t	blowfishDecryptBlock(const t_blowfishEcbCtx *ctx, uint64_t block)
{
	uint32_t	l;
	uint32_t	r;
	uint32_t	temp;
	int			i;

	/* Split 64-bit block into two 32-bit halves */
	l = block >> 32;
	r = block & 0xFFFFFFFF;

	/* XOR left half with last P-array entry (reversed order) */
	l ^= ctx->P[17];

	/* 16 rounds in reverse order */
	for (i = 15; i > 0; i -= 2)
	{
		/* Round i */
		r ^= blowfishFFast(l, ctx->S) ^ ctx->P[i];
		
		/* Round i-1 */
		l ^= blowfishFFast(r, ctx->S) ^ ctx->P[i - 1];
	}

	/* XOR right half with first P-array entry */
	r ^= ctx->P[0];

	/* Final swap */
	temp = l;
	l = r;
	r = temp;

	/* Recombine into 64-bit block */
	return (((uint64_t)l << 32) | r);
}
