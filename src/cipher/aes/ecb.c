#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/aes.h"
#include "../../../includes/cipher/cipher.h"

int	aesEcbInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_aesEcbCtx	*ctx;

	ctx = vctx;
	(void)iv;
	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return (-1);
	/**
	 * aesExpandDecryptKeys pre-applies InvMixColumns to the middle round keys.
	 * Required only by the T-table path (equivalent inverse cipher).
	 * Reference: handles InvMixColumns itself during decryption.
	 * NEON:      handles key transformation inside prepareKeys().
	 */
#if !defined(AES_USE_NEON) && !defined(AES_USE_AESNI) && !defined(AES_USE_REFERENCE)
	if (dir == CIPHER_DECRYPT)
		aesExpandDecryptKeys(ctx->roundKeys, ctx->nbRounds, ctx->roundKeys);
#endif
	ctx->bufferLen = 0;
	ctx->dir = dir;
	return (0);
}

void	aesEcbFree(void *vctx)
{
	t_aesEcbCtx	*ctx;

	ctx = vctx;
	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->buffer, AES_BLOCK_SIZE);
}

/* ---------- Update ---------- */

/**
 * Handles any buffered data from the previous update and processes full blocks.
 * Returns the number of bytes written to the output buffer.
 */
static size_t	flushBuffer(t_aesEcbCtx		*ctx,
							const uint8_t	**in,
							size_t			*inLen,
							uint8_t			**out)
{
	uint8_t	temp[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	size_t	need;

	need = AES_BLOCK_SIZE - ctx->bufferLen;
	if (*inLen < need)
	{
		ft_memcpy(ctx->buffer + ctx->bufferLen, *in, *inLen);
		ctx->bufferLen += *inLen;
		*inLen = 0;
		return (0);
	}
	ft_memcpy(temp, ctx->buffer, ctx->bufferLen);
	ft_memcpy(temp + ctx->bufferLen, *in, need);
	*in += need;
	*inLen -= need;
	ctx->bufferLen = 0;

#if defined(AES_USE_NEON)
	aesProcessBlocksNeon(temp, temp, ctx->roundKeys, 1, ctx->nbRounds,
						 ctx->dir == CIPHER_ENCRYPT);
#elif defined(AES_USE_AESNI)
	aesProcessBlocksX86(temp, temp, ctx->roundKeys, 1, ctx->nbRounds,
						ctx->dir == CIPHER_ENCRYPT);
#else
	if (ctx->dir == CIPHER_ENCRYPT)
		aesEncryptBlock(temp, temp, ctx->roundKeys, ctx->nbRounds);
	else
		aesDecryptBlock(temp, temp, ctx->roundKeys, ctx->nbRounds);
#endif

	ft_memcpy(*out, temp, AES_BLOCK_SIZE);
	*out += AES_BLOCK_SIZE;
	return (AES_BLOCK_SIZE);
}

void	aesEcbUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen)
{
	t_aesEcbCtx	*ctx;
	uint8_t		*outStart;
	size_t		blocks;

	ctx = vctx;
	outStart = out;
	*outLen = 0;
	if (ctx->bufferLen > 0 && flushBuffer(ctx, &in, &inLen, &out) == 0)
		return ;
	if (inLen >= AES_BLOCK_SIZE)
	{
		blocks = inLen / AES_BLOCK_SIZE;

#if defined(AES_USE_NEON)
	aesProcessBlocksNeon(in, out, ctx->roundKeys, blocks, ctx->nbRounds,
						 ctx->dir == CIPHER_ENCRYPT);
#elif defined(AES_USE_AESNI)
	aesProcessBlocksX86(in, out, ctx->roundKeys, blocks, ctx->nbRounds,
						ctx->dir == CIPHER_ENCRYPT);
#else
	void	(*cryptFunc)(const uint8_t *, uint8_t *, const uint32_t *, uint32_t);
	size_t	i;

	cryptFunc = (ctx->dir == CIPHER_ENCRYPT) ? aesEncryptBlock : aesDecryptBlock;
	i = 0;
	while (i < blocks)
	{
		ft_memcpy(out + i * AES_BLOCK_SIZE, in + i * AES_BLOCK_SIZE,
				  AES_BLOCK_SIZE);
		cryptFunc(out + i * AES_BLOCK_SIZE, out + i * AES_BLOCK_SIZE, ctx->roundKeys, ctx->nbRounds);
		i++;
	}
#endif

		out += blocks * AES_BLOCK_SIZE;
		in += blocks * AES_BLOCK_SIZE;
		inLen -= blocks * AES_BLOCK_SIZE;
	}
	if (inLen > 0)
	{
		ft_memcpy(ctx->buffer, in, inLen);
		ctx->bufferLen = inLen;
	}
	*outLen = out - outStart;
}

void	aesEcbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	(void)vctx;
	(void)out;
	*outLen = 0;
}


/* ---------- Cipher descriptors ---------- */

#define AES_ECB_CIPHER(name_str, key_size) { \
	.name			= name_str,				\
	.mode			= CIPHER_MODE_ECB,		\
	.isEncoder		= 1,					\
	.blockSize		= AES_BLOCK_SIZE,		\
	.keySize		= key_size,				\
	.ivSize			= 0,					\
	.ctxSize		= sizeof(t_aesEcbCtx),	\
	.init			= aesEcbInit,			\
	.update			= aesEcbUpdate,			\
	.final			= aesEcbFinal,			\
	.free			= aesEcbFree,			\
	.pad			= pkcs7Pad,				\
	.unpad			= pkcs7Unpad,			\
	.supportsWrap	= 0						\
}

const t_cipher	g_aes128EcbCipher = AES_ECB_CIPHER("aes-128-ecb", AES_KEY_SIZE_128);
const t_cipher	g_aes192EcbCipher = AES_ECB_CIPHER("aes-192-ecb", AES_KEY_SIZE_192);
const t_cipher	g_aes256EcbCipher = AES_ECB_CIPHER("aes-256-ecb", AES_KEY_SIZE_256);
