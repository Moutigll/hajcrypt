#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/cipher/base64.h"
#include "../../includes/hash/sha256.h"
#include "../../includes/utils/random.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/kdf/pbkdf2.h"

#include "../../includes/x509/pem.h"

static char *base64WithLines(const uint8_t *der, size_t derLen)
{
	char	*b64;
	size_t	b64Len;
	size_t	lines;
	char	*wrapped;
	char	*ptr;

	b64 = malloc(((derLen + 2) / 3) * 4 + 1);
	if (!b64)
		return (NULL);
	base64Encode(der, derLen, b64, ((derLen + 2) / 3) * 4 + 1);

	b64Len = ft_strlen(b64);
	lines = (b64Len + 63) / 64;
	wrapped = malloc(b64Len + lines + 1);
	if (!wrapped) {
		free(b64);
		return (NULL);
	}

	ptr = wrapped;
	for (size_t i = 0; i < b64Len; i += 64) {
		size_t chunk = (b64Len - i < 64) ? b64Len - i : 64;
		ft_memcpy(ptr, b64 + i, chunk);
		ptr += chunk;
		*ptr++ = '\n';
	}
	*ptr = '\0';

	free(b64);
	return (wrapped);
}

/* --------------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------------- */

char *pemEncode(const uint8_t *der, size_t derLen, const char *type)
{
	char	*b64;
	char	*pem;
	size_t	b64Len;
	size_t	pemLen;
	char	*ptr;
	
	if (!der || derLen == 0 || !type)
		return (NULL);

	b64 = base64WithLines(der, derLen);
	if (!b64)
		return (NULL);

	b64Len = ft_strlen(b64);
	pemLen = (17 + ft_strlen(type)) + b64Len + (15 + ft_strlen(type)) + 1;
	pem = malloc(pemLen);
	if (!pem) {
		free(b64);
		return (NULL);
	}

	ft_bzero(pem, pemLen);
	ptr = pem;
	ptr += ft_snprintf(ptr, pemLen - (ptr - pem), "-----BEGIN %s-----\n", type);
	ft_strlcpy(ptr, b64, pemLen - (ptr - pem));
	ptr += b64Len;
	ft_snprintf(ptr, pemLen - (ptr - pem), "-----END %s-----\n", type);

	free(b64);
	return (pem);
}


char *pkcs1EncryptPem(const char		*keyType,
					  const uint8_t		*der,
					  size_t			derLen,
					  const t_cipher	*cipher,
					  const char		*password)
{
	uint8_t	salt[8];
	uint8_t	key[32];
	uint8_t	iv[8];
	uint8_t	*encDer;
	size_t	encLen;
	char	*b64;
	char	*pem;
	size_t	pemLen;

	if (!der || !cipher || !password || !keyType)
		return (NULL);

	if (cipher->keySize > 24 || cipher->ivSize != 8) {
		HAJCRYPT_DPRINT("Cipher %s not supported for PKCS#1 legacy format\n", cipher->name);
		return (NULL);
	}

	/* Generate random salt of 8 bytes */
	hajSecRandBytes(salt, 8);

	/* Derive key using PKCS#1 key derivation method */
	pkcs1KeyDerivation(password, salt, key, cipher->keySize);

	/* Initialize IV with salt value */
	ft_memcpy(iv, salt, 8);

	/* Encrypt the DER data with derived key and IV */
	encDer = encryptDerWithCipher(cipher, key, iv, der, derLen, &encLen);
	if (!encDer)
		return (NULL);

	/* Encode encrypted data to Base64 with line wrapping */
	b64 = base64WithLines(encDer, encLen);
	free(encDer);
	if (!b64)
		return (NULL);

	/* Calculate required PEM buffer size */
	pemLen = ft_snprintf(NULL, 0,
		"-----BEGIN %s-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: %s,%02X%02X%02X%02X%02X%02X%02X%02X\n"
		"\n"
		"%s"
		"-----END %s-----\n",
		keyType, cipher->oid.name,
		salt[0], salt[1], salt[2], salt[3],
		salt[4], salt[5], salt[6], salt[7],
		b64, keyType) + 1;

	/* Allocate and format PEM output */
	pem = malloc(pemLen);
	if (!pem) {
		free(b64);
		return (NULL);
	}

	ft_snprintf(pem, pemLen,
		"-----BEGIN %s-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: %s,%02X%02X%02X%02X%02X%02X%02X%02X\n"
		"\n"
		"%s"
		"-----END %s-----\n",
		keyType, cipher->oid.name,
		salt[0], salt[1], salt[2], salt[3],
		salt[4], salt[5], salt[6], salt[7],
		b64, keyType);

	free(b64);
	return (pem);
}

char *pkcs8EncryptPem(const uint8_t			*pkcs8Der,
					  size_t				derLen,
					  const t_cipher		*cipher,
					  const char			*password,
					  const t_pkcs8Params	*params)
{
	uint8_t			key[64];
	uint8_t			iv[32];
	uint8_t			*encDer, *algoDer, *encryptedInfo;
	size_t			encLen, algoLen, infoLen;
	t_pkcs8Params	defaultParams;
	t_pkcs8Params	mutableParams;
	t_pbkdf2Ctx		pbkdf2_ctx;
	int				ret;

	if (!pkcs8Der || !cipher || !password)
		return (NULL);

	/* Use default parameters if none provided */
	if (!params) {
		defaultParams.iterations = 10000;
		defaultParams.prf = &g_sha256Hash;
		defaultParams.saltLen = 0;
		params = &defaultParams;
	}
	ft_memcpy(&mutableParams, params, sizeof(t_pkcs8Params));

	/* Generate random salt if not present */
	if (mutableParams.saltLen == 0) {
		mutableParams.saltLen = 16;
		hajSecRandBytes(mutableParams.salt, 16);
	}

	/* Generate random IV with size determined by cipher */
	if (cipher->ivSize > sizeof(iv)) {
		HAJCRYPT_DPRINT("IV size unsupported\n");
		return (NULL);
	}
	hajSecRandBytes(iv, cipher->ivSize);
	/* Save IV to parameters */
	ft_memcpy(mutableParams.iv, iv, cipher->ivSize);
	mutableParams.ivLen = cipher->ivSize;

	/* Derive key using PBKDF2 */
	ret = pbkdf2Init(&pbkdf2_ctx, mutableParams.prf ? mutableParams.prf : &g_sha256Hash,
					 (const uint8_t *)password, ft_strlen(password),
					 mutableParams.salt, mutableParams.saltLen,
					 mutableParams.iterations);
	if (ret != 0) return (NULL);

	ret = pbkdf2Derive(&pbkdf2_ctx, key, cipher->keySize);
	if (ret != 0) return (NULL);

	/* Encrypt the PKCS8 data with derived key and IV */
	encDer = encryptDerWithCipher(cipher, key, iv, pkcs8Der, derLen, &encLen);
	if (!encDer) return (NULL);

	/* Wrap ciphertext in an OCTET STRING */
	uint8_t *encOctetString;
	size_t  encOctetLen;
	encOctetString = asn1EncodeOctetString(encDer, encLen, &encOctetLen);
	if (!encOctetString) {
		free(encDer);
		return (NULL);
	}

	/* Build AlgorithmIdentifier containing salt and IV */
	algoDer = buildPbes2Algo(cipher, &mutableParams, &algoLen);
	if (!algoDer) {
		free(encDer);
		free(encOctetString);
		return (NULL);
	}

	/* Create EncryptedPrivateKeyInfo SEQUENCE with algorithm and encryptedData */
	encryptedInfo = asn1EncodeSequence((uint8_t*[]){algoDer, encOctetString},
									   (size_t[]){algoLen, encOctetLen}, 2, &infoLen);
	
	free(algoDer);
	free(encDer);
	free(encOctetString);
	
	if (!encryptedInfo) return (NULL);

	/* Encode to PEM format */
	char *pem = pemEncode(encryptedInfo, infoLen, "ENCRYPTED PRIVATE KEY");
	free(encryptedInfo);
	
	return (pem);
}
