#include "../../../hajlib/include/hmemory.h"

#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"

#include "../../../includes/cipher/aes.h"

static void aesProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const t_aesCbcCtx *ctx = key;

#if defined(AES_USE_NEON)
	if (encrypt)
		aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
	else
		aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 0);
#elif defined(AES_USE_AESNI)
	if (encrypt)
		aesProcessBlocksX86(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
	else
		aesProcessBlocksX86(in, out, ctx->roundKeys, 1, ctx->nbRounds, 0);
#else
	if (encrypt)
		aesEncryptBlock(in, out, ctx->roundKeys, ctx->nbRounds);
	else
		aesDecryptBlock(in, out, ctx->roundKeys, ctx->nbRounds);

	(void)out;
#endif
}


int aesCbcInit(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	t_aesCbcCtx *ctx = vctx;

	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return (-1);

	ft_memcpy(ctx->cbcCtx.iv, iv ? iv : (uint8_t[AES_BLOCK_SIZE]){0}, AES_BLOCK_SIZE);
	ctx->cbcCtx.bufferLen = 0;
	ctx->cbcCtx.dir = dir;
	ctx->cbcCtx.blockSize = AES_BLOCK_SIZE;
	ctx->cbcCtx.cipherCtx = ctx;
	ctx->cbcCtx.processBlock = aesProcessBlock;

#if !defined(AES_USE_NEON) && !defined(AES_USE_AESNI) && !defined(AES_USE_REFERENCE)
	if (dir == CIPHER_DECRYPT)
		aesExpandDecryptKeys(ctx->roundKeys, ctx->nbRounds, ctx->roundKeys);
#endif

	return (0);
}


void	aesCbcFree(void *vctx)
{
	t_aesCbcCtx	*ctx;

	ctx = vctx;
	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->cbcCtx.iv, sizeof(ctx->cbcCtx.iv));
	secureZeroMemory(ctx->cbcCtx.buffer, sizeof(ctx->cbcCtx.buffer));
}

void aesCbcUpdate(void *vctx, const uint8_t *in, size_t inLen,
				  uint8_t *out, size_t *outLen)
{
	t_aesCbcCtx *ctx = vctx;
	cbcGenUpdate(&ctx->cbcCtx, in, inLen, out, outLen);
}

void aesCbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesCbcCtx *ctx = vctx;
	cbcGenFinal(&ctx->cbcCtx, out, outLen);
}

#define AES_CBC_CIPHER(nameStr, size, oidDef) {	\
	.name			= nameStr,				\
	.mode			= CIPHER_MODE_CBC,		\
	.oid			= oidDef,				\
	.oiwOid			= OID_NONE,				\
	.isEncoder		= 1,					\
	.blockSize		= AES_BLOCK_SIZE,		\
	.keySize		= size,					\
	.ivSize			= AES_BLOCK_SIZE,		\
	.ctxSize		= sizeof(t_aesCbcCtx),	\
	.init			= aesCbcInit,			\
	.update			= aesCbcUpdate,			\
	.final			= aesCbcFinal,			\
	.free			= aesCbcFree,			\
	.pad			= pkcs7Pad,				\
	.unpad			= pkcs7Unpad,			\
	.supportsWrap	= 0						\
}

const t_cipher g_aes128CbcCipher = AES_CBC_CIPHER("aes-128-cbc", AES_KEY_SIZE_128, OID_DEF("AES-128-CBC", AES128_CBC_OID));
const t_cipher g_aes192CbcCipher = AES_CBC_CIPHER("aes-192-cbc", AES_KEY_SIZE_192, OID_DEF("AES-192-CBC", AES192_CBC_OID));
const t_cipher g_aes256CbcCipher = AES_CBC_CIPHER("aes-256-cbc", AES_KEY_SIZE_256, OID_DEF("AES-256-CBC", AES256_CBC_OID));
const t_cipher g_aes128Cipher	 = AES_CBC_CIPHER("aes128",	 	 AES_KEY_SIZE_128, OID_DEF("AES-128-CBC", AES128_CBC_OID));
const t_cipher g_aes192Cipher	 = AES_CBC_CIPHER("aes192",	 	 AES_KEY_SIZE_192, OID_DEF("AES-192-CBC", AES192_CBC_OID));
const t_cipher g_aes256Cipher	 = AES_CBC_CIPHER("aes256",	 	 AES_KEY_SIZE_256, OID_DEF("AES-256-CBC", AES256_CBC_OID));
