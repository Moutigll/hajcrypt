#include "../../hajlib/include/hmemory.h"
#include "../../includes/utils/utils.h"

#include "../includes/aeadCipher.h"

int	tlsAeadGetParams(t_tlsCipherType	type,
					 size_t				*keyLen,
					 size_t				*ivLen,
					 size_t				*tagLen)
{
	switch (type)
	{
	case TLS_CIPHER_AES_128_GCM:
		if (keyLen) *keyLen = 16;
		if (ivLen) *ivLen = 12;
		if (tagLen) *tagLen = 16;
		break;
	case TLS_CIPHER_AES_256_GCM:
		if (keyLen) *keyLen = 32;
		if (ivLen) *ivLen = 12;
		if (tagLen) *tagLen = 16;
		break;
	case TLS_CIPHER_CHACHA20_POLY1305:
		if (keyLen) *keyLen = 32;
		if (ivLen) *ivLen = 12;
		if (tagLen) *tagLen = 16;
		break;
	default:
		return (0);
	}
	return (1);
}

int	tlsAeadCipherInit(t_tlsAeadCipher	*ctx,
					  t_tlsCipherType	type,
					  const uint8_t		*key,
					  size_t			keyLen,
					  const uint8_t		*iv,
					  size_t			ivLen,
					  t_cipherDirection	dir)
{
	size_t	expectedKeyLen;
	size_t	expectedIvLen;
	int		ret;

	if (!ctx || !key || !iv)
		return (0);

	if (!tlsAeadGetParams(type, &expectedKeyLen, &expectedIvLen, NULL))
		return (0);
	if (keyLen != expectedKeyLen || ivLen != expectedIvLen)
		return (0);

	ft_memset(ctx, 0, sizeof(t_tlsAeadCipher));

	ctx->type = type;
	ctx->dir = dir;
	ctx->keyLen = keyLen;
	ctx->ivLen = ivLen;
	ctx->tagLen = 16;

	ft_memcpy(ctx->key, key, keyLen);
	ft_memcpy(ctx->iv, iv, ivLen);
	ctx->keyLenCache = keyLen;
	ctx->ivLenCache = ivLen;

	switch (type)
	{
	case TLS_CIPHER_AES_128_GCM:
	case TLS_CIPHER_AES_256_GCM:
		ret = aesGcmInit(&ctx->ctx.gcm, key, keyLen, iv, ivLen, dir);
		break;

	case TLS_CIPHER_CHACHA20_POLY1305:
		ret = chacha20Poly1305Init(&ctx->ctx.chacha, key, keyLen, iv, dir);
		break;

	default:
		return (0);
	}

	return (ret == 0 ? 1 : 0);
}

void	tlsAeadCipherUpdateAAD(t_tlsAeadCipher	*ctx,
							  const uint8_t		*aad,
							  size_t			aadLen)
{
	if (!ctx || !aad || aadLen == 0)
		return ;

	switch (ctx->type)
	{
	case TLS_CIPHER_AES_128_GCM:
	case TLS_CIPHER_AES_256_GCM:
		aesGcmUpdateAAD(&ctx->ctx.gcm, aad, aadLen);
		break;

	case TLS_CIPHER_CHACHA20_POLY1305:
		chacha20Poly1305UpdateAAD(&ctx->ctx.chacha, aad, aadLen);
		break;
	}
}

void	tlsAeadCipherUpdate(t_tlsAeadCipher	*ctx,
						   const uint8_t	*in,
						   size_t			inLen,
						   uint8_t			*out,
						   size_t			*outLen)
{
	if (!ctx || !in || !out || !outLen)
		return ;

	switch (ctx->type)
	{
	case TLS_CIPHER_AES_128_GCM:
	case TLS_CIPHER_AES_256_GCM:
		aesGcmUpdate(&ctx->ctx.gcm, in, inLen, out, outLen);
		break;

	case TLS_CIPHER_CHACHA20_POLY1305:
		chacha20Poly1305Update(&ctx->ctx.chacha, in, inLen, out, outLen);
		break;
	}
}

int	tlsAeadCipherFinal(t_tlsAeadCipher	*ctx,
					   uint8_t			*tag,
					   size_t			tagLen)
{
	if (!ctx || !tag || tagLen != 16)
		return (0);

	switch (ctx->type)
	{
	case TLS_CIPHER_AES_128_GCM:
	case TLS_CIPHER_AES_256_GCM:
		if (ctx->dir == CIPHER_ENCRYPT)
		{
			aesGcmFinal(&ctx->ctx.gcm, tag, &tagLen);
			return (1);
		}
		else
		{
			return (aesGcmVerifyTag(&ctx->ctx.gcm, tag, tagLen) == 0 ? 1 : 0);
		}

	case TLS_CIPHER_CHACHA20_POLY1305:
		if (ctx->dir == CIPHER_ENCRYPT)
		{
			chacha20Poly1305Final(&ctx->ctx.chacha, NULL, NULL);
			ft_memcpy(tag, ctx->ctx.chacha.tag, 16);
			return (1);
		}
		else
		{
			return (chacha20Poly1305VerifyTag(&ctx->ctx.chacha, tag, tagLen) == 0 ? 1 : 0);
		}

	default:
		return (0);
	}
}

int	tlsAeadSeal(t_tlsCipherType	type,
				const uint8_t	*key,		size_t	keyLen,
				const uint8_t	*iv,		size_t	ivLen,
				const uint8_t	*aad,		size_t	aadLen,
				const uint8_t	*plaintext,	size_t	plaintextLen,
				uint8_t			*ciphertext,
				uint8_t			*tag)
{
	t_tlsAeadCipher	ctx;
	size_t			outLen;
	size_t			processedLen;
	int				ret;

	if (!key || !iv || !ciphertext || !tag)
		return (0);

	if (!tlsAeadCipherInit(&ctx, type, key, keyLen, iv, ivLen, CIPHER_ENCRYPT))
		return (0);

	if (aad && aadLen > 0)
		tlsAeadCipherUpdateAAD(&ctx, aad, aadLen);

	processedLen = 0;
	outLen = 0;

	if (plaintext && plaintextLen > 0)
	{
		tlsAeadCipherUpdate(&ctx, plaintext, plaintextLen,
							ciphertext, &outLen);
		processedLen = outLen;
	}

	ret = tlsAeadCipherFinal(&ctx, tag, 16);

	tlsAeadCipherFree(&ctx);

	return (ret);
}

int	tlsAeadOpen(t_tlsCipherType	type,
				const uint8_t	*key,			size_t keyLen,
				const uint8_t	*iv,			size_t ivLen,
				const uint8_t	*aad,			size_t aadLen,
				const uint8_t	*ciphertext,	size_t ciphertextLen,
				uint8_t			*plaintext,
				const uint8_t	*tag)
{
	t_tlsAeadCipher	ctx;
	size_t			outLen;
	size_t			processedLen;
	int				ret;
	uint8_t			computedTag[16];

	if (!key || !iv || !ciphertext || !plaintext || !tag)
		return (0);

	if (!tlsAeadCipherInit(&ctx, type, key, keyLen, iv, ivLen, CIPHER_DECRYPT))
		return (0);

	if (aad && aadLen > 0)
		tlsAeadCipherUpdateAAD(&ctx, aad, aadLen);

	processedLen = 0;
	outLen = 0;

	if (ciphertext && ciphertextLen > 0)
	{
		tlsAeadCipherUpdate(&ctx, ciphertext, ciphertextLen,
							plaintext, &outLen);
		processedLen = outLen;
	}

	ft_memcpy(computedTag, tag, 16);
	ret = tlsAeadCipherFinal(&ctx, computedTag, 16);

	tlsAeadCipherFree(&ctx);

	return (ret);
}

void	tlsAeadCipherFree(t_tlsAeadCipher *ctx)
{
	if (!ctx)
		return ;

	switch (ctx->type)
	{
	case TLS_CIPHER_AES_128_GCM:
	case TLS_CIPHER_AES_256_GCM:
		aesGcmFree(&ctx->ctx.gcm);
		break;

	case TLS_CIPHER_CHACHA20_POLY1305:
		chacha20Poly1305Free(&ctx->ctx.chacha);
		break;
	}

	secureZeroMemory(ctx->key, sizeof(ctx->key));
	secureZeroMemory(ctx->iv, sizeof(ctx->iv));
	ft_memset(ctx, 0, sizeof(t_tlsAeadCipher));
}
