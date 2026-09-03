#include <stdlib.h>

#include "../../hajlib/include/hchar.h"
#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../hajlib/include/hstring.h"
#include "../../includes/hajcrypt.h"
#include "../../includes/utils/dispatch.h"
#include "../../includes/cipher/base64.h"
#include "../../includes/hash/sha/sha256.h"
#include "../../includes/kdf/pbkdf2.h"
#include "../../includes/x509/asn1.h"

#include "../../includes/x509/pem.h"

/* --------------------------------------------------------------------------
 * Static helpers
 * -------------------------------------------------------------------------- */

static int hexToBytes(const char *hex, uint8_t *bytes, size_t len)
{
	size_t hexLen = ft_strlen(hex);
	if (hexLen != len * 2)
		return (-1);
	for (size_t i = 0; i < len; i++) {
		char byteStr[3] = {hex[i*2], hex[i*2+1], 0};
		bytes[i] = (uint8_t)ft_strtol(byteStr, NULL, 16);
	}
	return (0);
}

/**
 * @brief Extracts and decodes the Base64 content from a PEM-formatted string.
 * 
 * @param pem The PEM-formatted string containing the header, Base64 data, and footer.
 * @param isEncryptedPkcs1 Set to 1 if the PEM is an encrypted PKCS#1 block (which has additional headers).
 * @param outLen Output parameter that will be set to the length of the decoded data.
 * 
 * @return A newly allocated string containing the decoded binary data, or NULL on failure.
 */
static char *extractBase64FromPem(const char *pem, int isEncryptedPkcs1, size_t *outLen)
{
	const char	*begin, *headerEnd, *dataStart, *end;
	char		footer[256];
	char		*b64;
	size_t		rawLen, j;

	if (!pem || !outLen)
		return (NULL);

	begin = ft_strstr(pem, "-----BEGIN ");
	if (!begin) return (NULL);
	begin += 11;

	headerEnd = ft_strstr(begin, "-----");
	if (!headerEnd) return (NULL);

	/* Point after the header line */
	dataStart = headerEnd + 5;
	if (*dataStart == '\n') dataStart++;
	else if (dataStart[0] == '\r' && dataStart[1] == '\n') dataStart += 2;

	if (isEncryptedPkcs1) {
		/* Skip Proc-Type and DEK-Info lines, find empty line */
		const char *empty = ft_strstr(dataStart, "\n\n");
		if (!empty) empty = ft_strstr(dataStart, "\r\n\r\n");
		if (!empty) {
			HAJCRYPT_DPRINT("No empty line found after DEK-Info\n");
			return (NULL);
		}
		dataStart = empty + 2;  /* skip the two newlines */
		if (*dataStart == '\r') dataStart++; /* handle \r\n\r\n case */
	}

	/* Build footer */
	size_t typeLen = headerEnd - begin;
	char *headerType = ft_strndup(begin, typeLen);
	if (!headerType) return (NULL);
	ft_strlcpy(footer, "-----END ", sizeof(footer));
	ft_strlcat(footer, headerType, sizeof(footer));
	ft_strlcat(footer, "-----", sizeof(footer));
	free(headerType);

	end = ft_strstr(dataStart, footer);
	if (!end) return (NULL);

	rawLen = end - dataStart;
	b64 = malloc(rawLen + 1);
	if (!b64) return (NULL);

	j = 0;
	for (size_t i = 0; i < rawLen; i++) {
		if (dataStart[i] != '\n' && dataStart[i] != '\r')
			b64[j++] = dataStart[i];
	}
	b64[j] = '\0';
	*outLen = j;
	return (b64);
}
/* --------------------------------------------------------------------------
 * PEM decode (public)
 * -------------------------------------------------------------------------- */

int pemDecode(const char *pem, t_pemBlock *block)
{
	char	*b64;
	size_t	b64Len;
	size_t	derMax;
	size_t	derLen;

	if (!pem || !block)
		return (0);
	ft_bzero(block, sizeof(t_pemBlock));

	b64 = extractBase64FromPem(pem, 0, &b64Len);
	if (!b64)
		return (0);

	/* Extract header type */
	const char	*begin = ft_strstr(pem, "-----BEGIN ");
	if (!begin) {
		free(b64);
		return (0);
	}
	begin += 11;
	const char	*headerEnd = ft_strstr(begin, "-----");
	if (!headerEnd) {
		free(b64);
		return (0);
	}
	block->header = ft_strndup(begin, headerEnd - begin);
	if (!block->header) {
		free(b64);
		return (0);
	}

	derMax = ((b64Len + 3) / 4) * 3;
	block->der = malloc(derMax);
	if (!block->der) {
		free(b64);
		pemFreeBlock(block);
		return (0);
	}
	derLen = base64Decode(b64, block->der);
	free(b64);
	if (derLen == (size_t)-1) {
		pemFreeBlock(block);
		return (0);
	}
	block->derLen = derLen;
	return (1);
}

void pemFreeBlock(t_pemBlock *block)
{
	if (!block)
		return;
	if (block->header)
		free(block->header);
	if (block->der)
		free(block->der);
	ft_bzero(block, sizeof(t_pemBlock));
}


/* --------------------------------------------------------------------------
 * PKCS#1 legacy decryption
 * -------------------------------------------------------------------------- */

uint8_t *pkcs1DecryptedDer(const char *pem, const char *password, size_t *outLen)
{
	uint8_t			salt[8];
	char			saltHex[17];
	uint8_t			key[32];
	uint8_t			iv[8];
	const t_cipher	*cipher;
	char			cipherName[64];
	uint8_t			*encDer;
	size_t			encLen;
	char			*b64;

	if (!pem || !password || !outLen)
		return (NULL);

	/* Step 1: Extract cipher name and salt from DEK-Info header */
	const char *dek = ft_strstr(pem, "DEK-Info: ");
	if (!dek) {
		HAJCRYPT_DPRINT("PKCS#1: DEK-Info header not found\n");
		return (NULL);
	}
	
	const char *comma = ft_strchr(dek, ',');
	if (!comma) {
		HAJCRYPT_DPRINT("PKCS#1: invalid DEK-Info format\n");
		return (NULL);
	}
	
	/* Parse cipher name (e.g., des3-cbc) */
	size_t cipherNameLen = comma - dek - 10;
	if (cipherNameLen >= sizeof(cipherName))
		cipherNameLen = sizeof(cipherName) - 1;
	ft_strlcpy(cipherName, dek + 10, cipherNameLen + 1);
	for (size_t i = 0; cipherName[i]; i++) 
		cipherName[i] = ft_tolower(cipherName[i]);
	
	cipher = getCipherByName(cipherName);
	if (!cipher) {
		HAJCRYPT_DPRINT("PKCS#1: unknown cipher '%s'\n", cipherName);
		return (NULL);
	}

	/* Parse salt from hex string (16 hex characters = 8 bytes) */
	ft_strlcpy(saltHex, comma + 1, 17);
	if (hexToBytes(saltHex, salt, 8) != 0) {
		HAJCRYPT_DPRINT("PKCS#1: invalid salt hex\n");
		return (NULL);
	}

	/* Step 2: Derive key using PKCS#1 key derivation method */
	pkcs1KeyDerivation(password, salt, key, cipher->keySize);

	/* Step 3: Set IV to the salt value */
	ft_memcpy(iv, salt, 8);

	/* Step 4: Extract Base64 content after headers */
	b64 = extractBase64FromPem(pem, 1, &encLen);
	if (!b64)
		return (NULL);
	
	/* Step 5: Decode Base64 to binary */
	encDer = malloc(((encLen + 3) / 4) * 3);
	if (!encDer) {
		free(b64);
		return (NULL);
	}
	encLen = base64Decode(b64, encDer);
	free(b64);
	
	if (encLen == (size_t)-1) {
		free(encDer);
		return (NULL);
	}

	/* Step 6: Decrypt the data */
	uint8_t *decDer = decryptDerWithCipher(cipher, key, iv, encDer, encLen, outLen);
	free(encDer);
	
	if (!decDer) {
		HAJCRYPT_DPRINT("PKCS#1: decryption failed\n");
		return (NULL);
	}
	
	return (decDer);
}

uint8_t *pkcs8DecryptedDer(const char *pem, const char *password, size_t *outLen, const char *expectedType)
{
	t_pemBlock		block;
	uint8_t			*content, *encDer, *decDer;
	size_t			contentLen, encLen, decLen;
	size_t			consumed = 0;
	const t_cipher	*cipher = NULL;
	t_pkcs8Params	params;
	t_pbkdf2Ctx		pbkdf2_ctx;
	uint8_t			key[64];
	int				ret;

	if (!pem || !password || !outLen)
		return (NULL);

	ft_memset(&params, 0, sizeof(params));

	/* Decode the PEM structure */
	if (!pemDecode(pem, &block))
		return (NULL);

	/* Verify the PEM header is for encrypted private key */
	if (ft_strcmp(block.header, expectedType ? expectedType : "ENCRYPTED PRIVATE KEY") != 0) {
		HAJCRYPT_DPRINT("PKCS#8: unexpected PEM header\n");
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Parse the EncryptedPrivateKeyInfo SEQUENCE */
	if (!asn1ParseSequence(block.der, block.derLen, &content, &contentLen, &consumed)) {
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Extract the AlgorithmIdentifier SEQUENCE */
	uint8_t	*algoDer;
	size_t	algoLen;

	if (!asn1ParseSequence(content, contentLen, &algoDer, &algoLen, &consumed)) {
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Parse PBES2 parameters to extract cipher and key derivation info */
	if (!parsePbes2Params(algoDer, algoLen, &cipher, &params)) {
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Initialize PBKDF2 context for key derivation */
	ret = pbkdf2Init(&pbkdf2_ctx, params.prf ? params.prf : &g_sha256Hash,
					 (const uint8_t *)password, ft_strlen(password),
					 params.salt, params.saltLen, params.iterations);
	if (ret != 0) {
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Derive the encryption key from password */
	ret = pbkdf2Derive(&pbkdf2_ctx, key, cipher->keySize);
	if (ret != 0) {
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Extract the encrypted data as OCTET STRING */
	if (!asn1ParseOctetString(content + consumed, contentLen - consumed,
							  &encDer, &encLen, NULL)) {
		pemFreeBlock(&block);
		return (NULL);
	}

	/* Decrypt the private key data */
	decDer = decryptDerWithCipher(cipher, key, params.iv, encDer, encLen, &decLen);

	pemFreeBlock(&block);

	if (!decDer) {
		HAJCRYPT_DPRINT("PKCS#8: decryption failed\n");
		return (NULL);
	}

	*outLen = decLen;
	return (decDer);
}
