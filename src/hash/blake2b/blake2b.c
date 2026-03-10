#include "../../../includes/hash/blake2b.h"
#include "../../../includes/consts/blake2b.h"
#include "../../../hajlib/include/hmemory.h"

void blake2bInit(void *ctx)
{
	t_blake2bCtx	*b2 = (t_blake2bCtx *)ctx;
	int i;


	/* Copy IV */
	for (i = 0; i < 8; i++)
		b2->h[i] = g_blake2b_IV[i];

	/* XOR with outlen parameter */
	b2->h[0] ^= 0x01010000 ^ 64;  /* outlen default = 64 bytes */

	b2->t[0] = 0;
	b2->t[1] = 0;
	b2->f = 0;
	b2->buflen = 0;
	b2->outlen = 64;  /* Default output length */
}

void blake2bSetOutlen(void *ctx, size_t outlen)
{
	t_blake2bCtx	*b2 = (t_blake2bCtx *)ctx;

	if (outlen == 0 || outlen > 64)
		outlen = 64;  /* Clamp to valid range */

	b2->outlen = outlen;
	/* Recompute the parameter block properly */
	b2->h[0] = g_blake2b_IV[0] ^ 0x01010000 ^ (uint64_t)outlen;
}

void blake2bInitKeyed(void *ctx, const uint8_t *key, size_t keyLen, size_t outlen)
{
	t_blake2bCtx	*b2 = (t_blake2bCtx *)ctx;
	uint8_t 		keyblock[BLAKE2B_BLOCK_SIZE] = {0};
	size_t			i;

	if (keyLen > 64)
		keyLen = 64;

	/* Initialize normally */
	blake2bInit(ctx);
	blake2bSetOutlen(ctx, outlen);

	/* XOR with keyed hash parameter */
	b2->h[0] ^= (uint64_t)keyLen << 8;

	/* Pad key to block size and hash it as first block */
	ft_memcpy(keyblock, key, keyLen);
	for (i = keyLen; i < BLAKE2B_BLOCK_SIZE; i++)
		keyblock[i] = 0;

	b2->buflen = BLAKE2B_BLOCK_SIZE;
	ft_memcpy(b2->buffer, keyblock, BLAKE2B_BLOCK_SIZE);
}

void blake2bUpdate(void *ctx, const uint8_t *data, size_t len)
{
	t_blake2bCtx	*b2 = (t_blake2bCtx *)ctx;
	size_t			index;
	size_t			partLen;
	size_t			i;

	if (!ctx || (!data && len > 0))
		return;
	if (len == 0)
		return;

	index = b2->buflen;
	partLen = BLAKE2B_BLOCK_SIZE - index;
	i = 0;

	if (len > partLen)
	{
		/* Fill and compress the buffered partial block */
		ft_memcpy(&b2->buffer[index], data, partLen);
		b2->t[0] += BLAKE2B_BLOCK_SIZE;
		if (b2->t[0] < BLAKE2B_BLOCK_SIZE)
			b2->t[1]++;
		blake2bCompress(b2, b2->buffer);
		i = partLen;
		b2->buflen = 0;
		index = 0;

		/* Compress full blocks, but NOT the last one */
		while (i + BLAKE2B_BLOCK_SIZE < len)
		{
			b2->t[0] += BLAKE2B_BLOCK_SIZE;
			if (b2->t[0] < BLAKE2B_BLOCK_SIZE)
				b2->t[1]++;
			blake2bCompress(b2, &data[i]);
			i += BLAKE2B_BLOCK_SIZE;
		}
	}

	/* Buffer the remaining (possibly the entire input if len <= partLen) */
	ft_memcpy(&b2->buffer[index], &data[i], len - i);
	b2->buflen = index + (len - i);
}

void blake2bFinal(uint8_t *digest, void *ctx)
{
	t_blake2bCtx	*b2 = (t_blake2bCtx *)ctx;
	size_t			i;

	b2->t[0] += b2->buflen;
	if (b2->t[0] < b2->buflen)
		b2->t[1]++;

	/* Set last block flag */
	b2->f = 1;

	/* Zero-pad buffer */
	for (i = b2->buflen; i < BLAKE2B_BLOCK_SIZE; i++)
		b2->buffer[i] = 0;

	/* Compress last block */
	blake2bCompress(b2, b2->buffer);

	/* Output digest (little-endian) */
	for (i = 0; i < b2->outlen / 8; i++)
	{
		digest[i*8]   = (uint8_t)(b2->h[i]);
		digest[i*8+1] = (uint8_t)(b2->h[i] >> 8);
		digest[i*8+2] = (uint8_t)(b2->h[i] >> 16);
		digest[i*8+3] = (uint8_t)(b2->h[i] >> 24);
		digest[i*8+4] = (uint8_t)(b2->h[i] >> 32);
		digest[i*8+5] = (uint8_t)(b2->h[i] >> 40);
		digest[i*8+6] = (uint8_t)(b2->h[i] >> 48);
		digest[i*8+7] = (uint8_t)(b2->h[i] >> 56);
	}
	for (i = (b2->outlen / 8) * 8; i < b2->outlen; i++)
	{
		int word = i / 8;
		int shift = (i % 8) * 8;
		digest[i] = (uint8_t)(b2->h[word] >> shift);
	}
}

void blake2b(const uint8_t	*data,		size_t	datalen,
			 uint8_t		*digest,	size_t	digestlen)
{
	t_blake2bCtx ctx;

	blake2bInit(&ctx);
	blake2bSetOutlen(&ctx, digestlen);
	blake2bUpdate(&ctx, data, datalen);
	blake2bFinal(digest, &ctx);
}

void blake2bMac(const uint8_t	*key,		size_t	keyLen,
				const uint8_t	*data,		size_t	datalen,
				uint8_t			*digest,	size_t	digestlen)
{
	t_blake2bCtx ctx;

	blake2bInitKeyed(&ctx, key, keyLen, digestlen);
	blake2bUpdate(&ctx, data, datalen);
	blake2bFinal(digest, &ctx);
}

void blake2bLong(uint8_t *out, size_t outLen, const uint8_t *in, size_t inLen)
{
	t_blake2bCtx b2;
	uint8_t buffer[64];
	uint32_t outLenLe = (uint32_t)outLen;

	if (outLen <= 64) {
		blake2bInit(&b2);
		blake2bSetOutlen(&b2, outLen);
		blake2bUpdate(&b2, (uint8_t*)&outLenLe, 4);
		blake2bUpdate(&b2, in, inLen);
		blake2bFinal(out, &b2);
		return;
	}

	/* First 64-byte hash */
	blake2bInit(&b2);
	blake2bSetOutlen(&b2, 64);
	blake2bUpdate(&b2, (uint8_t*)&outLenLe, 4);
	blake2bUpdate(&b2, in, inLen);
	blake2bFinal(buffer, &b2);
	ft_memcpy(out, buffer, 32);
	out += 32;
	uint32_t toProduce = (uint32_t)outLen - 32;

	/* Intermediate steps */
	while (toProduce > 64) {
		ft_memcpy(buffer, buffer, 64);   /* use previous hash as input */
		blake2bInit(&b2);
		blake2bSetOutlen(&b2, 64);
		blake2bUpdate(&b2, buffer, 64);
		blake2bFinal(buffer, &b2);
		ft_memcpy(out, buffer, 32);
		out += 32;
		toProduce -= 32;
	}

	/* Final step */
	blake2bInit(&b2);
	blake2bSetOutlen(&b2, toProduce);
	blake2bUpdate(&b2, buffer, 64);
	blake2bFinal(out, &b2);
}


const t_hash g_blake2bHash = {
	.name = "blake2b",
	.init = blake2bInit,
	.update = blake2bUpdate,
	.final = blake2bFinal,
	.hmacInit = NULL,  /* Blake2b has built-in keyed mode */
	.ctxSize = sizeof(t_blake2bCtx),
	.digestSize = 64   /* Default 512-bit output */
};
