#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/utils/random.h"
#include "../../includes/utils/utils.h"

#include "../includes/tlsCipher.h"


/**
 * @brief (Re)initialise the underlying AEAD context with the per-record
 *        nonce, just before sealing/opening.
 *
 * The traffic key never changes for the lifetime of ctx, but the nonce
 * (RFC 8446 5.3: write_iv XOR seq_num) DOES change on every single
 * record. The previous implementation initialised aesGcm/chacha once
 * in tlsCipherInit() with the static traffic IV and never touched it
 * again, which only happened to work for seqnum == 0 (nonce ==
 * traffic_iv) and silently produced a wrong keystream/tag for every
 * record afterwards (-> bad_record_mac on the peer side).
 *
 * @param ctx		TLS cipher context (must be AEAD type)
 * @param nonce		Per-record nonce (traffic_iv XOR seqnum)
 * @param nonceLen	Length of nonce, must match suite->cipher->ivSize
 * @return			1 on success, 0 on error
 */
static int aeadReinitNonce(t_tlsCipher *ctx, const uint8_t *nonce, size_t nonceLen)
{
	const t_aeadCipher	*aead = ctx->suite->cipher;
	int					ret;

	if (!aead || !nonce || nonceLen != aead->ivSize)
		return (0);

	switch (ctx->suite->cipherType) {
	case BTLS_CIPHER_AES_128_GCM:
	case BTLS_CIPHER_AES_256_GCM:
		ret = aesGcmInit(&ctx->ctx.gcm, ctx->key, aead->keySize, nonce, nonceLen, ctx->dir);
		break;
	case BTLS_CIPHER_CHACHA20_POLY1305:
		ret = chacha20Poly1305Init(&ctx->ctx.chacha, ctx->key, aead->keySize, nonce, ctx->dir);
		break;
	default:
		return (0);
	}

	return (ret == 0 ? 1 : 0);
}

/**
 * @brief Perform AEAD seal (encrypt + tag generation) using the given context.
 *
 * @param ctx		TLS cipher context (must be AEAD type)
 * @param nonce		Per-record nonce (traffic_iv XOR seqnum)
 * @param nonceLen	Length of nonce
 * @param aad		Additional authenticated data
 * @param aadLen	Length of AAD
 * @param plaintext	Plaintext to encrypt
 * @param plaintextLen	Length of plaintext
 * @param ciphertext	Output buffer for ciphertext
 * @param tag		Output buffer for authentication tag (16 bytes)
 * @return			1 on success, 0 on error
 */
static int aeadSealInternal(t_tlsCipher		*ctx,
							const uint8_t	*nonce,			size_t	nonceLen,
							const uint8_t	*aad,			size_t	aadLen,
							const uint8_t	*plaintext,		size_t	plaintextLen,
							uint8_t			*ciphertext,	uint8_t	*tag)
{
	size_t outLen;

	/* Re-key the AEAD context with this record's nonce before anything else */
	if (!aeadReinitNonce(ctx, nonce, nonceLen))
		return (0);

	/* Update AAD if provided */
	if (aad && aadLen > 0) {
		switch (ctx->suite->cipherType) {
		case BTLS_CIPHER_AES_128_GCM:
		case BTLS_CIPHER_AES_256_GCM:
			aesGcmUpdateAAD(&ctx->ctx.gcm, aad, aadLen);
			break;
		case BTLS_CIPHER_CHACHA20_POLY1305:
			chacha20Poly1305UpdateAAD(&ctx->ctx.chacha, aad, aadLen);
			break;
		default:
			return (0);
		}
	}

	/* Encrypt */
	outLen = 0;
	if (plaintext && plaintextLen > 0) {
		switch (ctx->suite->cipherType) {
		case BTLS_CIPHER_AES_128_GCM:
		case BTLS_CIPHER_AES_256_GCM:
			aesGcmUpdate(&ctx->ctx.gcm, plaintext, plaintextLen,
						 ciphertext, &outLen);
			break;
		case BTLS_CIPHER_CHACHA20_POLY1305:
			chacha20Poly1305Update(&ctx->ctx.chacha, plaintext, plaintextLen,
								   ciphertext, &outLen);
			break;
		default:
			return (0);
		}
	}

	/* Finalise and get tag */
	switch (ctx->suite->cipherType) {
	case BTLS_CIPHER_AES_128_GCM:
	case BTLS_CIPHER_AES_256_GCM:
		aesGcmFinal(&ctx->ctx.gcm, tag, &outLen);
		break;
	case BTLS_CIPHER_CHACHA20_POLY1305:
		chacha20Poly1305Final(&ctx->ctx.chacha, NULL, NULL);
		ft_memcpy(tag, ctx->ctx.chacha.tag, 16);
		break;
	default:
		return (0);
	}
	return (1);
}

/**
 * @brief Perform AEAD open (decrypt + tag verification).
 *
 * @param ctx		TLS cipher context (must be AEAD type)
 * @param nonce		Per-record nonce (traffic_iv XOR seqnum)
 * @param nonceLen	Length of nonce
 * @param aad		Additional authenticated data
 * @param aadLen	Length of AAD
 * @param ciphertext	Ciphertext to decrypt
 * @param ciphertextLen	Length of ciphertext
 * @param tag		Authentication tag to verify (16 bytes)
 * @param plaintext	Output buffer for plaintext
 * @return			1 on success (tag valid), 0 on error
 */
static int aeadOpenInternal(t_tlsCipher		*ctx,
							const uint8_t	*nonce,			size_t	nonceLen,
							const uint8_t	*aad,			size_t	aadLen,
							const uint8_t	*ciphertext,	size_t	ciphertextLen,
							const uint8_t	*tag,			uint8_t	*plaintext)
{
	size_t	outLen;
	uint8_t	computedTag[16];

	/* Re-key the AEAD context with this record's nonce before anything else */
	if (!aeadReinitNonce(ctx, nonce, nonceLen))
		return (0);

	/* Update AAD if provided */
	if (aad && aadLen > 0) {
		switch (ctx->suite->cipherType) {
		case BTLS_CIPHER_AES_128_GCM:
		case BTLS_CIPHER_AES_256_GCM:
			aesGcmUpdateAAD(&ctx->ctx.gcm, aad, aadLen);
			break;
		case BTLS_CIPHER_CHACHA20_POLY1305:
			chacha20Poly1305UpdateAAD(&ctx->ctx.chacha, aad, aadLen);
			break;
		default:
			return (0);
		}
	}

	/* Decrypt */
	outLen = 0;
	if (ciphertext && ciphertextLen > 0) {
		switch (ctx->suite->cipherType) {
		case BTLS_CIPHER_AES_128_GCM:
		case BTLS_CIPHER_AES_256_GCM:
			aesGcmUpdate(&ctx->ctx.gcm, ciphertext, ciphertextLen,
						 plaintext, &outLen);
			break;
		case BTLS_CIPHER_CHACHA20_POLY1305:
			chacha20Poly1305Update(&ctx->ctx.chacha, ciphertext, ciphertextLen,
								   plaintext, &outLen);
			break;
		default:
			return (0);
		}
	}

	/* Verify tag */
	ft_memcpy(computedTag, tag, 16);
	switch (ctx->suite->cipherType) {
	case BTLS_CIPHER_AES_128_GCM:
	case BTLS_CIPHER_AES_256_GCM:
		if (aesGcmVerifyTag(&ctx->ctx.gcm, computedTag, 16) != 0)
			return (0);
		break;
	case BTLS_CIPHER_CHACHA20_POLY1305:
		if (chacha20Poly1305VerifyTag(&ctx->ctx.chacha, computedTag, 16) != 0)
			return (0);
		break;
	default:
		return (0);
	}
	return (1);
}

/**
 * @brief Perform CBC+HMAC seal (encrypt + MAC generation)
 *
 * @param ctx		TLS cipher context (must be CBC+HMAC type)
 * @param aad		Additional authenticated data (used for MAC)
 * @param aadLen	Length of AAD
 * @param plaintext	Plaintext to encrypt
 * @param plaintextLen	Length of plaintext
 * @param ciphertext	Output buffer for ciphertext
 * @param tag		Output buffer for MAC (will be truncated/padded to 16 bytes)
 * @return			1 on success, 0 on error
 */
static int cbcHmacSealInternal(t_tlsCipher		*ctx,
							   const uint8_t	*aad,			size_t	aadLen,
							   const uint8_t	*plaintext,		size_t	plaintextLen,
							   uint8_t			*ciphertext,	uint8_t	*tag)
{
	const	t_cipher	*cipher = ctx->suite->cipher;
	uint8_t				mac[64];
	size_t				macLen;
	uint8_t				*ptr = ciphertext;
	size_t				blockSize = cipher->blockSize;
	size_t				ivLen = cipher->ivSize;
	size_t				macKeyLen = ctx->macKeyLen;
	size_t				plainLen = plaintextLen;
	size_t				paddedLen, paddingLen, totalPlain;
	size_t				hmacDataLen;
	uint8_t				*explicitIV;
	int					ret;

	/* 1. Generate explicit IV (random) directly into the output buffer */
	explicitIV = ptr;
	if (hajSecRandBytes(ptr, ivLen) != 0)
		return (0);
	ptr += ivLen;

	/* 2. Re-key the CBC context with this record's explicit IV. */
	ret = cipher->init(ctx->ctx.cbcHmac.cbcCtx, ctx->key, cipher->keySize,
						explicitIV, ctx->dir);
	if (ret != 1)
		return (0);

	/* 3. Compute HMAC over AAD + plaintext */
	uint8_t	*hmacData = malloc(aadLen + plaintextLen);
	if (!hmacData)
		return (0);
	hmacDataLen = 0;
	ft_memcpy(hmacData + hmacDataLen, aad, aadLen);
	hmacDataLen += aadLen;
	ft_memcpy(hmacData + hmacDataLen, plaintext, plaintextLen);
	hmacDataLen += plaintextLen;

	hmac(ctx->suite->hash, ctx->macKey, macKeyLen,
		 hmacData, hmacDataLen, mac);
	free(hmacData);
	macLen = ctx->suite->hash->digestSize;

	/* 4. Build plaintext block: plaintext + MAC + padding */
	paddedLen = plainLen + macLen;
	paddingLen = blockSize - (paddedLen % blockSize);
	if (paddingLen == 0)
		paddingLen = blockSize;
	totalPlain = paddedLen + paddingLen;

	/* Copy plaintext */
	ft_memcpy(ptr, plaintext, plainLen);
	ptr += plainLen;
	/* Copy MAC */
	ft_memcpy(ptr, mac, macLen);
	ptr += macLen;
	/* Apply padding (PKCS#7) */
	ft_memset(ptr, paddingLen - 1, paddingLen);
	ptr += paddingLen;

	/* 5. CBC encrypt in-place (starting from ciphertext+ivLen) */
	cipher->update(&ctx->ctx.cbcHmac.cbcCtx,
				   ciphertext + ivLen, totalPlain,
				   ciphertext + ivLen, &totalPlain);

	/* 6. Fill tag with MAC (truncate/pad to 16 bytes) */
	ft_bzero(tag, 16);
	if (macLen <= 16)
		ft_memcpy(tag, mac, macLen);
	else
		ft_memcpy(tag, mac, 16);

	return (1);
}

/**
 * @brief Perform CBC+HMAC open (decrypt + MAC verification)
 *
 * @param ctx		TLS cipher context (must be CBC+HMAC type)
 * @param aad		Additional authenticated data (used for MAC)
 * @param aadLen	Length of AAD
 * @param ciphertext	Ciphertext to decrypt (including explicit IV)
 * @param ciphertextLen	Length of ciphertext
 * @param tag		Expected MAC (tag) to verify
 * @param tagLen	Length of tag (should be at least 16)
 * @param plaintext	Output buffer for plaintext
 * @return			1 on success (MAC valid), 0 on error
 */
static int cbcHmacOpenInternal(t_tlsCipher 		*ctx,
							   const uint8_t	*aad,			size_t	aadLen,
							   const uint8_t	*ciphertext,	size_t	ciphertextLen,
							   const uint8_t	*tag,			size_t	tagLen,
							   uint8_t			*plaintext)
{
	const t_cipher	*cipher = ctx->suite->cipher;
	size_t			ivLen = cipher->ivSize;
	size_t			blockSize = cipher->blockSize;
	size_t			macKeyLen = ctx->macKeyLen;
	size_t			macLen = ctx->suite->hash->digestSize;
	uint8_t			*decrypted = plaintext;
	size_t			decryptedLen;
	uint8_t			computedMac[64];
	uint8_t			padValue;
	size_t			plainLen;
	const uint8_t	*receivedMac;
	const uint8_t	*explicitIV;
	const uint8_t	*encrypted;
	size_t			encryptedLen;
	size_t			i;
	size_t			hmacDataLen;
	int				ret;

	/* Check minimum length: at least IV + 1 byte + MAC + padding */
	if (ciphertextLen < ivLen + 1 + macLen)
		return (0);

	/* 1. Extract the explicit IV sent by the peer, and the ciphertext that follows it */
	explicitIV = ciphertext;
	encrypted = ciphertext + ivLen;
	encryptedLen = ciphertextLen - ivLen;

	/* 2. Re-key the CBC context with this record's explicit IV. */
	ret = cipher->init(ctx->ctx.cbcHmac.cbcCtx, ctx->key, cipher->keySize,
						explicitIV, ctx->dir);
	if (ret != 1)
		return (0);

	/* 3. CBC decrypt in-place */
	cipher->update(&ctx->ctx.cbcHmac.cbcCtx,
				   encrypted, encryptedLen,
				   decrypted, &decryptedLen);

	/* 4. Remove padding (PKCS#7) */
	if (decryptedLen == 0)
		return 0;
	padValue = decrypted[decryptedLen - 1];
	if (padValue == 0 || padValue > blockSize || padValue > decryptedLen)
		return 0;
	for (i = 0; i < padValue; i++) {
		if (decrypted[decryptedLen - 1 - i] != padValue)
			return (0);
	}
	plainLen = decryptedLen - padValue;

	/* 5. Extract MAC (last macLen bytes before padding) */
	if (plainLen < macLen)
		return (0);
	plainLen -= macLen;
	receivedMac = decrypted + plainLen;

	/* 6. Compute HMAC over AAD + plaintext */
	uint8_t *hmacData = malloc(aadLen + plainLen);
	if (!hmacData)
		return (0);
	hmacDataLen = 0;
	ft_memcpy(hmacData + hmacDataLen, aad, aadLen);
	hmacDataLen += aadLen;
	ft_memcpy(hmacData + hmacDataLen, decrypted, plainLen);
	hmacDataLen += plainLen;

	hmac(ctx->suite->hash, ctx->macKey, macKeyLen,
		 hmacData, hmacDataLen, computedMac);
	free(hmacData);

	/* 7. Compare HMAC with received MAC (constant-time) */
	if (ft_cmemcmp(computedMac, receivedMac, macLen) != 0)
		return (0);

	/* 8. If tag is provided, compare with computed MAC (truncated if needed) */
	if (tag && tagLen > 0) {
		size_t cmpLen = (tagLen < macLen) ? tagLen : macLen;
		if (ft_cmemcmp(computedMac, tag, cmpLen) != 0)
			return (0);
	}

	/* 9. Zero out the part of the buffer after plaintext (for safety) */
	ft_memset(plaintext + plainLen, 0, decryptedLen - plainLen);

	return (1);
}


int	tlsCipherInit(t_tlsCipher				*ctx,
				  const t_tlsCipherSuite	*suite,
				  const uint8_t				*key,		size_t	keyLen,
				  const uint8_t				*iv,		size_t	ivLen,
				  const uint8_t				*macKey,	size_t	macKeyLen,
				  t_cipherDirection			dir,
				  int						isServer)
{
	int ret;

	if (!ctx || !suite || !key)
		return (0);

	ft_memset(ctx, 0, sizeof(t_tlsCipher));
	ctx->suite = suite;
	ctx->dir = dir;
	ctx->isServer = isServer;

	/* Copy key material */
	if (keyLen > sizeof(ctx->key))
		return (0);
	ft_memcpy(ctx->key, key, keyLen);
	if (iv && ivLen > 0) {
		if (ivLen > sizeof(ctx->iv))
			return (0);
		ft_memcpy(ctx->iv, iv, ivLen);
	}
	if (macKey && macKeyLen > 0) {
		if (macKeyLen > sizeof(ctx->macKey))
			return (0);
		ft_memcpy(ctx->macKey, macKey, macKeyLen);
		ctx->macKeyLen = macKeyLen;
	}

	switch (suite->recordCipherType) {
	case BTLS_RECORD_AEAD:
	{
		const t_aeadCipher *aead = suite->cipher;
		if (!aead)
			return (0);
		if (keyLen != aead->keySize || ivLen != aead->ivSize)
			return (0);
		switch (suite->cipherType) {
		case BTLS_CIPHER_AES_128_GCM:
		case BTLS_CIPHER_AES_256_GCM:
			ret = aesGcmInit(&ctx->ctx.gcm, key, keyLen, iv, ivLen, dir);
			break;
		case BTLS_CIPHER_CHACHA20_POLY1305:
			ret = chacha20Poly1305Init(&ctx->ctx.chacha, key, keyLen, iv, dir);
			break;
		default:
			return (0);
		}
		if (ret != 0)
			return (0);
		ctx->initialized = 1;
		return (1);
	}

	case BTLS_RECORD_CBC_HMAC:
	{
		const t_cipher *cipher = suite->cipher;
		if (!cipher || !macKey || macKeyLen == 0)
			return (0);
		if (keyLen != cipher->keySize)
			return (0);
		if (ivLen != cipher->ivSize)
			return (0);

		/* Allocate CBC context */
		void *cbcCtx = malloc(cipher->ctxSize);
		if (!cbcCtx)
			return (0);
		ctx->ctx.cbcHmac.cbcCtx = cbcCtx;

		/* Initialise CBC cipher */
		ret = cipher->init(cbcCtx, key, keyLen, iv, dir);
		if (ret != 1) {
			free(cbcCtx);
			return (0);
		}

		/* Initialise HMAC context */
		if (suite->hash->hmacInit)
			suite->hash->hmacInit(&ctx->ctx.cbcHmac.hmac, macKey, macKeyLen);
		else
			hmacInit(&ctx->ctx.cbcHmac.hmac, suite->hash, macKey, macKeyLen);

		ctx->initialized = 1;
		return (1);
	}

	default:
		return (0);
	}
}

int	tlsCipherSeal(t_tlsCipher	*ctx,
				  const uint8_t	*nonce,		size_t	nonceLen,
				  const uint8_t	*aad,		size_t	aadLen,
				  const uint8_t	*plaintext,	size_t	plaintextLen,
				  uint8_t		*ciphertext,
				  uint8_t		*tag)
{
	int ret;

	if (!ctx || !ctx->initialized || !ciphertext || !tag)
		return (0);

	switch (ctx->suite->recordCipherType) {
	case BTLS_RECORD_AEAD:
		/* AEAD: the nonce is mandatory and changes on every record */
		ret = aeadSealInternal(ctx, nonce, nonceLen, aad, aadLen,
							   plaintext, plaintextLen,
							   ciphertext, tag);
		break;
	case BTLS_RECORD_CBC_HMAC:
		(void)nonce;
		(void)nonceLen;
		ret = cbcHmacSealInternal(ctx, aad, aadLen,
								  plaintext, plaintextLen,
								  ciphertext, tag);
		break;
	default:
		return (0);
	}

	return (ret);
}

int	tlsCipherOpen(t_tlsCipher	*ctx,
				  const uint8_t	*nonce,			size_t	nonceLen,
				  const uint8_t	*aad,			size_t	aadLen,
				  const uint8_t	*ciphertext,	size_t	ciphertextLen,
				  const uint8_t	*tag,			size_t	tagLen,
				  uint8_t		*plaintext)
{
	int ret;

	if (!ctx || !ctx->initialized || !ciphertext || !plaintext)
		return (0);

	switch (ctx->suite->recordCipherType) {
	case BTLS_RECORD_AEAD:
		ret = aeadOpenInternal(ctx, nonce, nonceLen, aad, aadLen,
							   ciphertext, ciphertextLen,
							   tag, plaintext);
		break;
	case BTLS_RECORD_CBC_HMAC:
		/* explicit IV is read back from ciphertext itself, see above */
		(void)nonce;
		(void)nonceLen;
		ret = cbcHmacOpenInternal(ctx, aad, aadLen,
								  ciphertext, ciphertextLen,
								  tag, tagLen, plaintext);
		break;
	default:
		return (0);
	}

	return (ret);
}

void tlsCipherFree(t_tlsCipher *ctx)
{
	if (!ctx || !ctx->initialized)
		return;

	if (!ctx->suite)
	{
		secureZeroMemory(ctx->key, sizeof(ctx->key));
		secureZeroMemory(ctx->iv, sizeof(ctx->iv));
		secureZeroMemory(ctx->macKey, sizeof(ctx->macKey));
		ctx->macKeyLen = 0;
		ctx->initialized = 0;
		return;
	}

	switch (ctx->suite->recordCipherType) {
	case BTLS_RECORD_AEAD:
		switch (ctx->suite->cipherType) {
		case BTLS_CIPHER_AES_128_GCM:
		case BTLS_CIPHER_AES_256_GCM:
			aesGcmFree(&ctx->ctx.gcm);
			break;
		case BTLS_CIPHER_CHACHA20_POLY1305:
			chacha20Poly1305Free(&ctx->ctx.chacha);
			break;
		default:
			break;
		}
		break;
	case BTLS_RECORD_CBC_HMAC:
		if (ctx->ctx.cbcHmac.cbcCtx) {
			const t_cipher *cipher = ctx->suite->cipher;
			if (cipher && cipher->free)
				cipher->free(ctx->ctx.cbcHmac.cbcCtx);
			free(ctx->ctx.cbcHmac.cbcCtx);
			ctx->ctx.cbcHmac.cbcCtx = NULL;
		}
		ft_memset(&ctx->ctx.cbcHmac.hmac, 0, sizeof(t_hmacCtx));
		break;
	default:
		break;
	}

	/* Securely zero sensitive material */
	secureZeroMemory(ctx->key, sizeof(ctx->key));
	secureZeroMemory(ctx->iv, sizeof(ctx->iv));
	secureZeroMemory(ctx->macKey, sizeof(ctx->macKey));
	ctx->macKeyLen = 0;
	ctx->initialized = 0;
}
