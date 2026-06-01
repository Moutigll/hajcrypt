#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/bitopts.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/chacha20Poly1305.h"

/**
 * @brief Derives the Poly1305 key from the ChaCha20 keystream block 0
 * @param ctx Pointer to the ChaCha20-Poly1305 context
 * @param key Pointer to the 32-byte ChaCha20 key
 * @param nonce Pointer to the 12-byte nonce
 * @return 0 on success, -1 on error
 */
static int  chacha20Poly1305DeriveKey(t_chacha20Poly1305Ctx *ctx, const uint8_t *key, const uint8_t *nonce)
{
	t_chacha20Ctx	chachaCtx;
	uint8_t			block[CHACHA20_BLOCK_SIZE];

	ft_memset(block, 0, sizeof(block));

	chacha20Init(&chachaCtx, key, nonce, 0);
	chacha20Crypt(&chachaCtx, block, block, CHACHA20_BLOCK_SIZE);
	ft_memcpy(ctx->polyKey, block, POLY1305_KEY_SIZE);
	chacha20Free(&chachaCtx);
	return (0);
}

/* ---------- Initialisation ---------- */

int chacha20Poly1305Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *nonce, t_cipherDirection dir)
{
	t_chacha20Poly1305Ctx	*ctx = vctx;

	if (!ctx || !key || keyLen != CHACHA20_KEY_SIZE || !nonce)
		return (-1);
	ctx->dir = dir;
	chacha20Init(&ctx->chachaCtx, key, nonce, 1);
	ctx->chachaCtx.keystreamPos = CHACHA20_BLOCK_SIZE;
	if (chacha20Poly1305DeriveKey(ctx, key, nonce) != 0)
		return (-1);
	poly1305Init(&ctx->polyCtx, ctx->polyKey);
	ctx->aadBufferLen = 0;
	ctx->dataBufferLen = 0;
	ctx->aadTotalLen = 0;
	ctx->dataTotalLen = 0;
	ctx->tagValid = 0;
	ft_memset(ctx->tag, 0, CHACHA20_POLY1305_TAG_SIZE);
	return (0);
}

/* ---------- AAD ---------- */

void	chacha20Poly1305UpdateAAD(void *vctx, const uint8_t *aad, size_t aadLen)
{
	t_chacha20Poly1305Ctx	*ctx = vctx;
	size_t					avail;

	if (!ctx || !aad || !aadLen)
		return;
	ctx->aadTotalLen += aadLen;
	if (ctx->aadBufferLen)
	{
		avail = CHACHA20_POLY1305_BLOCK_SIZE - ctx->aadBufferLen;
		if (aadLen < avail)
		{
			ft_memcpy(ctx->aadBuffer + ctx->aadBufferLen, aad, aadLen);
			ctx->aadBufferLen += aadLen;
			return ;
		}
		ft_memcpy(ctx->aadBuffer + ctx->aadBufferLen, aad, avail);
		poly1305Update(&ctx->polyCtx, ctx->aadBuffer,
			CHACHA20_POLY1305_BLOCK_SIZE);
		aad += avail;
		aadLen -= avail;
		ctx->aadBufferLen = 0;
	}
	while (aadLen >= CHACHA20_POLY1305_BLOCK_SIZE)
	{
		poly1305Update(&ctx->polyCtx, aad, CHACHA20_POLY1305_BLOCK_SIZE);
		aad += CHACHA20_POLY1305_BLOCK_SIZE;
		aadLen -= CHACHA20_POLY1305_BLOCK_SIZE;
	}
	if (aadLen)
	{
		ft_memcpy(ctx->aadBuffer, aad, aadLen);
		ctx->aadBufferLen = aadLen;
	}
}

/* ---------- Data processing ---------- */

/**
 * @brief Processes a single block of data (encrypt/decrypt + authenticate)
 * @param ctx Pointer to the ChaCha20-Poly1305 context
 * @param in Pointer to input data
 * @param inLen Length of input data (must be <= 16 bytes)
 * @param out Pointer to output buffer
 */
static void chacha20Poly1305ProcessData(t_chacha20Poly1305Ctx *ctx, const uint8_t *in, size_t inLen, uint8_t *out)
{
	if (ctx->dir == CIPHER_ENCRYPT)
	{
		chacha20Crypt(&ctx->chachaCtx, in, out, inLen);
		poly1305Update(&ctx->polyCtx, out, inLen);
	}
	else
	{
		poly1305Update(&ctx->polyCtx, in, inLen);
		chacha20Crypt(&ctx->chachaCtx, in, out, inLen);
	}
	ctx->dataTotalLen += inLen;
}

void	chacha20Poly1305Update(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_chacha20Poly1305Ctx	*ctx = vctx;
	size_t					avail;

	*outLen = 0;
	if (!ctx || !in || !inLen || !out)
		return ;
	if (ctx->aadBufferLen > 0)
	{
		ft_bzero(ctx->aadBuffer + ctx->aadBufferLen,
			CHACHA20_POLY1305_BLOCK_SIZE - ctx->aadBufferLen);
		poly1305Update(&ctx->polyCtx, ctx->aadBuffer,
			CHACHA20_POLY1305_BLOCK_SIZE);
		ctx->aadBufferLen = 0;
	}
	if (ctx->dataBufferLen)
	{
		avail = CHACHA20_POLY1305_BLOCK_SIZE - ctx->dataBufferLen;
		if (inLen < avail)
		{
			ft_memcpy(ctx->dataBuffer + ctx->dataBufferLen, in, inLen);
			ctx->dataBufferLen += inLen;
			return ;
		}
		ft_memcpy(ctx->dataBuffer + ctx->dataBufferLen, in, avail);
		chacha20Poly1305ProcessData(ctx, ctx->dataBuffer,
			CHACHA20_POLY1305_BLOCK_SIZE, out);
		*outLen = CHACHA20_POLY1305_BLOCK_SIZE;
		in += avail;
		inLen -= avail;
		ctx->dataBufferLen = 0;
	}
	while (inLen >= CHACHA20_POLY1305_BLOCK_SIZE)
	{
		chacha20Poly1305ProcessData(ctx, in,
			CHACHA20_POLY1305_BLOCK_SIZE, out + *outLen);
		*outLen += CHACHA20_POLY1305_BLOCK_SIZE;
		in += CHACHA20_POLY1305_BLOCK_SIZE;
		inLen -= CHACHA20_POLY1305_BLOCK_SIZE;
	}
	if (inLen)
	{
		ft_memcpy(ctx->dataBuffer, in, inLen);
		ctx->dataBufferLen = inLen;
	}
}

/* ---------- Finalisation ---------- */

void	chacha20Poly1305Final(void *vctx, uint8_t *out, size_t *outLen)
{
	t_chacha20Poly1305Ctx   *ctx = vctx;
	uint8_t				 lenBlock[CHACHA20_POLY1305_BLOCK_SIZE];
	size_t				  localOutLen = 0;

	if (!ctx || !out || !outLen)
	{
		if (outLen) *outLen = 0;
		return ;
	}

	/* 1. Flush remaining AAD if Update was never called (e.g. empty plaintext) */
	if (ctx->aadBufferLen > 0)
	{
		ft_bzero(ctx->aadBuffer + ctx->aadBufferLen,
			CHACHA20_POLY1305_BLOCK_SIZE - ctx->aadBufferLen);
		poly1305Update(&ctx->polyCtx, ctx->aadBuffer,
			CHACHA20_POLY1305_BLOCK_SIZE);
		ctx->aadBufferLen = 0;
	}

	/* 2. Process remaining partial data block */
	if (ctx->dataBufferLen > 0)
	{
		uint8_t tmpOut[CHACHA20_POLY1305_BLOCK_SIZE];
		uint8_t polyBlock[CHACHA20_POLY1305_BLOCK_SIZE];

		ft_bzero(tmpOut, sizeof(tmpOut));
		ft_bzero(polyBlock, sizeof(polyBlock));

		chacha20Crypt(&ctx->chachaCtx, ctx->dataBuffer, tmpOut, ctx->dataBufferLen);
		ft_memcpy(out, tmpOut, ctx->dataBufferLen);
		localOutLen += ctx->dataBufferLen;

		if (ctx->dir == CIPHER_ENCRYPT)
			ft_memcpy(polyBlock, tmpOut, ctx->dataBufferLen);
		else
			ft_memcpy(polyBlock, ctx->dataBuffer, ctx->dataBufferLen);
		
		poly1305Update(&ctx->polyCtx, polyBlock, CHACHA20_POLY1305_BLOCK_SIZE);
		ctx->dataTotalLen += ctx->dataBufferLen;
		ctx->dataBufferLen = 0;
	}

	/* 3. Construct and update the final lengths block (in octets!) */
	ft_bzero(lenBlock, CHACHA20_POLY1305_BLOCK_SIZE);
	store32(lenBlock + 0, (uint32_t)(ctx->aadTotalLen & 0xFFFFFFFF));
	store32(lenBlock + 4, (uint32_t)(ctx->aadTotalLen >> 32));
	store32(lenBlock + 8, (uint32_t)(ctx->dataTotalLen & 0xFFFFFFFF));
	store32(lenBlock + 12, (uint32_t)(ctx->dataTotalLen >> 32));
	
	poly1305Update(&ctx->polyCtx, lenBlock, CHACHA20_POLY1305_BLOCK_SIZE);
	poly1305Final(&ctx->polyCtx, ctx->tag);

	if (ctx->dir == CIPHER_DECRYPT)
		ctx->tagValid = 1;

	*outLen = localOutLen;
}

/* ---------- Tag verification ---------- */

int chacha20Poly1305VerifyTag(void *vctx, const uint8_t *tag, size_t tagLen)
{
	t_chacha20Poly1305Ctx	*ctx = vctx;
	uint8_t					diff;
	size_t					i;

	if (!ctx || !tag || tagLen != CHACHA20_POLY1305_TAG_SIZE || !ctx->tagValid)
		return (-1);
	diff = 0;
	i = 0;
	while (i < CHACHA20_POLY1305_TAG_SIZE)
	{
		diff |= ctx->tag[i] ^ tag[i];
		i++;
	}
	return ((diff == 0) ? 0 : -1);
}



void	chacha20Poly1305Free(void *vctx)
{
	if (vctx)
		secureZeroMemory(vctx, sizeof(t_chacha20Poly1305Ctx));
}

/* ---------- one‑shot Functions ---------- */

int chacha20Poly1305Seal(const uint8_t	key[CHACHA20_KEY_SIZE],
						 const uint8_t	nonce[CHACHA20_NONCE_SIZE],
						 const uint8_t	*aad,			size_t	aadLen,
						 const uint8_t	*plaintext,		size_t	plaintextLen,
						 uint8_t		*ciphertext,	uint8_t	tag[CHACHA20_POLY1305_TAG_SIZE])
{
	t_chacha20Poly1305Ctx	ctx;
	size_t					outLen;
	size_t					totalLen;
	int						ret;

	ret = chacha20Poly1305Init(&ctx, key, CHACHA20_KEY_SIZE, nonce,
		CIPHER_ENCRYPT);
	if (ret != 0)
		return (-1);
	chacha20Poly1305UpdateAAD(&ctx, aad, aadLen);
	totalLen = 0;
	chacha20Poly1305Update(&ctx, plaintext, plaintextLen, ciphertext, &outLen);
	totalLen += outLen;
	chacha20Poly1305Final(&ctx, ciphertext + totalLen, &outLen);
	totalLen += outLen;
	if (tag)
		ft_memcpy(tag, ctx.tag, CHACHA20_POLY1305_TAG_SIZE);
	chacha20Poly1305Free(&ctx);
	return (0);
}

int chacha20Poly1305Open(const uint8_t	key[CHACHA20_KEY_SIZE],
						 const uint8_t	nonce[CHACHA20_NONCE_SIZE],
						 const uint8_t	*aad,			size_t			aadLen,
						 const uint8_t	*ciphertext,	size_t			ciphertextLen,
						 uint8_t		*plaintext,		const uint8_t	tag[CHACHA20_POLY1305_TAG_SIZE])
{
	t_chacha20Poly1305Ctx	ctx;
	size_t					outLen;
	size_t					totalLen;
	int						ret;

	ret = chacha20Poly1305Init(&ctx, key, CHACHA20_KEY_SIZE, nonce,
		CIPHER_DECRYPT);
	if (ret != 0)
		return (-1);
	chacha20Poly1305UpdateAAD(&ctx, aad, aadLen);
	totalLen = 0;
	chacha20Poly1305Update(&ctx, ciphertext, ciphertextLen,
						   plaintext, &outLen);
	totalLen += outLen;
	chacha20Poly1305Final(&ctx, plaintext + totalLen, &outLen);
	totalLen += outLen;

	if (chacha20Poly1305VerifyTag(&ctx, tag, CHACHA20_POLY1305_TAG_SIZE) != 0)
	{
		if (plaintext && ciphertextLen)
			secureZeroMemory(plaintext, ciphertextLen);
		chacha20Poly1305Free(&ctx);
		return (-1);
	}
	chacha20Poly1305Free(&ctx);
	return (0);
}
