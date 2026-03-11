#include "../../../hajlib/include/hmemory.h"

#include "../../../includes/cipher/des.h"


void desCbcInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_desCbcCtx	*ctx = vctx;
	uint64_t	k = 0;
	int			i;

	/* Convert the key (max 8 bytes) */
	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, ctx->subkeys);
	
	/* Initialize IV: use provided IV or default to zeros */
	if (iv) {
		ctx->iv = 0;
		for (i = 0; i < 8; i++)
			ctx->iv = (ctx->iv << 8) | iv[i];
	} else
		ctx->iv = 0;
	
	ctx->bufferLen = 0;
	ctx->dir = dir;
}

void desCbcUpdate(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	t_desCbcCtx	*ctx = vctx;
	size_t		processed = 0;
	uint64_t	blockVal;
	int			i;

	*outLen = 0;

	while (processed < inLen) {
		size_t	toCopy = 8 - ctx->bufferLen;
		if (toCopy > inLen - processed)
			toCopy = inLen - processed;

		ft_memcpy(ctx->buffer + ctx->bufferLen, in + processed, toCopy);

		ctx->bufferLen += toCopy;
		processed += toCopy;

		if (ctx->bufferLen == 8) {
			blockVal = 0;
			for (i = 0; i < 8; i++)
				blockVal = (blockVal << 8) | ctx->buffer[i];
			
			if (ctx->dir == CIPHER_ENCRYPT) {
				/* CBC Encryption: C_i = E_k(P_i ⊕ C_{i-1}) */
				/* XOR with IV (or previous ciphertext) */
				blockVal ^= ctx->iv;
				blockVal = desEncryptBlock(blockVal, ctx->subkeys);
				ctx->iv = blockVal; /* Update IV to current ciphertext for next block */
			} else {
				/* CBC Decryption: P_i = D_k(C_i) ⊕ C_{i-1} */
				uint64_t cipherBlock = blockVal;
				blockVal = desDecryptBlock(blockVal, ctx->subkeys);
				blockVal ^= ctx->iv;
				ctx->iv = cipherBlock;
			}

			for (i = 0; i < 8; i++)
				out[(*outLen)++] = (blockVal >> (56 - i * 8)) & 0xFF;

			ctx->bufferLen = 0;
		}
	}
}

void desCbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desCbcCtx	*ctx = vctx;
	uint64_t	blockVal;
	size_t		unpaddedLen;
	int			i;

	*outLen = 0;

	if (ctx->dir == CIPHER_ENCRYPT) {
		uint8_t block[8];
		ft_memcpy(block, ctx->buffer, ctx->bufferLen);
		pkcs7Pad(block, ctx->bufferLen, 8);

		blockVal = 0;
		for (i = 0; i < 8; i++)
			blockVal = (blockVal << 8) | block[i];

		blockVal ^= ctx->iv;
		blockVal = desEncryptBlock(blockVal, ctx->subkeys);

		for (i = 0; i < 8; i++)
			out[(*outLen)++] = (blockVal >> (56 - i * 8)) & 0xFF;

	} else {
		if (ctx->bufferLen != 8) {
			*outLen = 0;
			return;
		}

		blockVal = 0;
		for (i = 0; i < 8; i++)
			blockVal = (blockVal << 8) | ctx->buffer[i];

		blockVal = desDecryptBlock(blockVal, ctx->subkeys);
		blockVal ^= ctx->iv;

		uint8_t block[8];
		for (i = 0; i < 8; i++)
			block[i] = (blockVal >> (56 - i * 8)) & 0xFF;

		if (pkcs7Unpad(block, &unpaddedLen, 8) != 0) {
			*outLen = 0;
			return;
		}

		ft_memcpy(out, block, unpaddedLen);
		*outLen = unpaddedLen;
	}
}

void desCbcFree(void *vctx)
{
	(void)vctx;
}

/* ---------- Global cipher structures ---------- */

const t_cipher g_desCbcCipher = {
	.name = "des-cbc",
	.mode = CIPHER_MODE_CBC,
	.isEncoder = 1,

	.blockSize = 8,
	.keySize = 8,
	.ivSize = 8,
	.ctxSize = sizeof(t_desCbcCtx),

	.init = desCbcInit,
	.update = desCbcUpdate,
	.final = desCbcFinal,
	.free = desCbcFree,

	.pad = pkcs7Pad,
	.unpad = pkcs7Unpad,

	.supportsWrap = 0
};

const t_cipher g_desCipher = {
	.name = "des",
	.mode = CIPHER_MODE_CBC,
	.isEncoder = 1,

	.blockSize = 8,
	.keySize = 8,
	.ivSize = 8,
	.ctxSize = sizeof(t_desCbcCtx),

	.init = desCbcInit,
	.update = desCbcUpdate,
	.final = desCbcFinal,
	.free = desCbcFree,

	.pad = pkcs7Pad,
	.unpad = pkcs7Unpad,

	.supportsWrap = 0
};
