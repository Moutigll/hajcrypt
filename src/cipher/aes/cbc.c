#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/aes.h"
#include "../../../includes/cipher/cipher.h"

int	aesCbcInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir)
{
	t_aesCbcCtx	*ctx;

	ctx = vctx;
	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return (-1);
	ft_memcpy(ctx->iv, iv ? iv : (uint8_t[AES_BLOCK_SIZE]){0}, AES_BLOCK_SIZE);

#if !defined(__aarch64__) && !defined(AES_USE_REFERENCE)
	if (dir == CIPHER_DECRYPT)
		aesExpandDecryptKeys(ctx->roundKeys, ctx->nbRounds, ctx->roundKeys);
#endif

	ctx->bufferLen = 0;
	ctx->dir = dir;
	return (0);
}

void	aesCbcFree(void *vctx)
{
	t_aesCbcCtx	*ctx;

	ctx = vctx;
	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->iv, sizeof(ctx->iv));
	secureZeroMemory(ctx->buffer, sizeof(ctx->buffer));
}

/*
 * Process one block in place with CBC chaining.
 * Encrypt: XOR(block, iv) → encrypt → iv = ciphertext
 * Decrypt: save ciphertext → decrypt → XOR(block, iv) → iv = saved ciphertext
*/
static void	processCbcBlock(t_aesCbcCtx *ctx, uint8_t *block)
{
	uint8_t	saved[AES_BLOCK_SIZE];
	size_t	i;

	if (ctx->dir == CIPHER_ENCRYPT)
	{
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			block[i] ^= ctx->iv[i];
#if defined(__aarch64__)
		aesProcessBlocksNeon(block, block, ctx->roundKeys, 1, ctx->nbRounds, 1);
#else
		aesEncryptBlock(block, ctx->roundKeys, ctx->nbRounds);
#endif
		ft_memcpy(ctx->iv, block, AES_BLOCK_SIZE);
	}
	else
	{
		ft_memcpy(saved, block, AES_BLOCK_SIZE);
#if defined(__aarch64__)
		aesProcessBlocksNeon(block, block, ctx->roundKeys, 1, ctx->nbRounds, 0);
#else
		aesDecryptBlock(block, ctx->roundKeys, ctx->nbRounds);
#endif
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			block[i] ^= ctx->iv[i];
		ft_memcpy(ctx->iv, saved, AES_BLOCK_SIZE);
	}
}

/*
 * Process N full blocks with CBC chaining.
 *
 * Encrypt: sequential – each plaintext block depends on the previous
 *          ciphertext, so blocks cannot be parallelized.
 *
 * Decrypt: fully parallelizable – all ciphertext blocks are independent
 *          from each other for the AES operation.
 *          1. Decrypt all N blocks at once with NEON.
 *          2. XOR pass: block[0] ^= iv, block[i] ^= in[i-1] for i > 0.
 *          3. Update iv = in[N-1] (last ciphertext block).
 */
static void	processFullBlocks(t_aesCbcCtx	*ctx,
							  const uint8_t	*in,
							  uint8_t		*out,
							  size_t		blocks)
{
	size_t	i;
	size_t	j;

	if (ctx->dir == CIPHER_ENCRYPT)
	{
		i = 0;
		while (i < blocks)
		{
			ft_memcpy(out + i * AES_BLOCK_SIZE, in + i * AES_BLOCK_SIZE,
					  AES_BLOCK_SIZE);
			processCbcBlock(ctx, out + i * AES_BLOCK_SIZE);
			i++;
		}
	}
	else
	{
#if defined(__aarch64__)
		aesProcessBlocksNeon(in, out, ctx->roundKeys, blocks, ctx->nbRounds, 0);
		for (j = 0; j < AES_BLOCK_SIZE; j++)
			out[j] ^= ctx->iv[j];
		i = 1;
		while (i < blocks)
		{
			for (j = 0; j < AES_BLOCK_SIZE; j++)
				out[i * AES_BLOCK_SIZE + j] ^= in[(i - 1) * AES_BLOCK_SIZE + j];
			i++;
		}
		ft_memcpy(ctx->iv, in + (blocks - 1) * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
#else
		i = 0;
		while (i < blocks)
		{
			ft_memcpy(out + i * AES_BLOCK_SIZE, in + i * AES_BLOCK_SIZE,
					  AES_BLOCK_SIZE);
			processCbcBlock(ctx, out + i * AES_BLOCK_SIZE);
			i++;
		}
#endif
	}
}

/*
 * Complete the partial block buffered from the previous call if possible.
 * Returns AES_BLOCK_SIZE if a block was emitted, 0 if more data is needed.
 */
static size_t	flushBuffer(t_aesCbcCtx		*ctx,
							const uint8_t	**in,
							size_t			*inLen,
							uint8_t			**out)
{
	uint8_t	block[AES_BLOCK_SIZE];
	size_t	need;

	need = AES_BLOCK_SIZE - ctx->bufferLen;
	if (*inLen < need)
	{
		ft_memcpy(ctx->buffer + ctx->bufferLen, *in, *inLen);
		ctx->bufferLen += *inLen;
		*inLen = 0;
		return (0);
	}
	ft_memcpy(block, ctx->buffer, ctx->bufferLen);
	ft_memcpy(block + ctx->bufferLen, *in, need);
	*in += need;
	*inLen -= need;
	ctx->bufferLen = 0;
	processCbcBlock(ctx, block);
	ft_memcpy(*out, block, AES_BLOCK_SIZE);
	*out += AES_BLOCK_SIZE;
	return (AES_BLOCK_SIZE);
}

void	aesCbcUpdate(void			*vctx,
					 const uint8_t	*in,	size_t	inLen,
					 uint8_t		*out,	size_t	*outLen)
{
	t_aesCbcCtx	*ctx;
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
		processFullBlocks(ctx, in, out, blocks);
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

void	aesCbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesCbcCtx	*ctx;
	uint8_t		block[AES_BLOCK_SIZE];
	size_t		unpaddedLen;

	ctx = vctx;
	*outLen = 0;
	if (ctx->dir == CIPHER_ENCRYPT)
	{
		ft_memcpy(block, ctx->buffer, ctx->bufferLen);
		pkcs7Pad(block, ctx->bufferLen, AES_BLOCK_SIZE);
		processCbcBlock(ctx, block);
		ft_memcpy(out, block, AES_BLOCK_SIZE);
		*outLen = AES_BLOCK_SIZE;
	}
	else
	{
		if (ctx->bufferLen != AES_BLOCK_SIZE)
			return ;
		ft_memcpy(block, ctx->buffer, AES_BLOCK_SIZE);
		processCbcBlock(ctx, block);
		if (pkcs7Unpad(block, &unpaddedLen, AES_BLOCK_SIZE) != 0)
			return ;
		ft_memcpy(out, block, unpaddedLen);
		*outLen = unpaddedLen;
	}
}


#define AES_CBC_CIPHER(name_str, key_size) {  \
	.name         = name_str,                  \
	.mode         = CIPHER_MODE_CBC,           \
	.isEncoder    = 1,                         \
	.blockSize    = AES_BLOCK_SIZE,            \
	.keySize      = key_size,                  \
	.ivSize       = AES_BLOCK_SIZE,            \
	.ctxSize      = sizeof(t_aesCbcCtx),       \
	.init         = aesCbcInit,                \
	.update       = aesCbcUpdate,              \
	.final        = aesCbcFinal,               \
	.free         = aesCbcFree,                \
	.pad          = pkcs7Pad,                  \
	.unpad        = pkcs7Unpad,                \
	.supportsWrap = 0                          \
}

const t_cipher	g_aes128CbcCipher = AES_CBC_CIPHER("aes128-cbc", AES_KEY_SIZE_128);
const t_cipher	g_aes192CbcCipher = AES_CBC_CIPHER("aes192-cbc", AES_KEY_SIZE_192);
const t_cipher	g_aes256CbcCipher = AES_CBC_CIPHER("aes256-cbc", AES_KEY_SIZE_256);
const t_cipher	g_aes128Cipher    = AES_CBC_CIPHER("aes128",      AES_KEY_SIZE_128);
const t_cipher	g_aes192Cipher    = AES_CBC_CIPHER("aes192",      AES_KEY_SIZE_192);
const t_cipher	g_aes256Cipher    = AES_CBC_CIPHER("aes256",      AES_KEY_SIZE_256);
