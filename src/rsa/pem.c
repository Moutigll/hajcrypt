#include "../../includes/rsa/rsa.h"
#include "../../includes/cipher/base64.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"
#include <stdlib.h>

/**
 * @brief Encodes a length in DER format (ASN.1)
 * @param buf The buffer to write the length encoding to (can be NULL to just calculate length)
 * @param len The length to encode
 * @return size_t The number of bytes written to buf (or that would be written if buf is NULL)
 */
static size_t encodeDerLength(uint8_t *buf, size_t len)
{
	if (len < 128) {
		if (buf) buf[0] = (uint8_t)len;
		return (1);
	} else if (len < 256) {
		if (buf) {
			buf[0] = 0x81;
			buf[1] = (uint8_t)len;
		}
		return (2);
	} else {
		if (buf) {
			buf[0] = 0x82;
			buf[1] = (uint8_t)((len >> 8) & 0xFF);
			buf[2] = (uint8_t)(len & 0xFF);
		}
		return (3);
	}
}

/**
 * @brief Converts a big integer to DER-encoded ASN.1 INTEGER format
 * A DER is an ASN.1 encoding format used in PEM files. For an INTEGER, it consists of:
 * - 1 byte: Tag (0x02 for INTEGER)
 * - 1+ bytes: Length (encoded using encodeDerLength)
 * - N bytes: Value (big-endian, with a possible leading 0x00 if the high bit is set to indicate a positive integer)
 * @param n The big integer to convert
 * @param outLen Output parameter for the length of the DER data
 * @return uint8_t* Pointer to the DER-encoded data (must be freed by caller), or NULL on error
 */
static uint8_t *bigIntToDer(const t_bigInt *n, size_t *outLen)
{
	uint8_t	*data;
	uint8_t	*der;
	size_t	len;
	size_t	headerLen;
	int		extra = 0;

	if (!n) return (NULL);

	len = (bigIntBitLength(n) + 7) / 8;
	if (len == 0) len = 1;
	
	data = malloc(len);
	if (!data) return (NULL);
	bigIntToBytes(n, data, len);

	/* An ASN.1 integer is signed. If the high bit is 1,
	   prepend 0x00 so it's interpreted as positive. */
	if (len > 0 && (data[0] & 0x80))
		extra = 1;

	headerLen = 1 + encodeDerLength(NULL, len + extra);
	*outLen = headerLen + len + extra;
	der = malloc(*outLen);
	if (!der) {
		free(data);
		return (NULL);
	}

	der[0] = 0x02; /* Tag INTEGER */
	encodeDerLength(der + 1, len + extra);
	
	if (extra)
		der[headerLen] = 0x00;
	
	ft_memcpy(der + headerLen + extra, data, len);
	free(data);
	return (der);
}

/**
 * @brief Builds a DER-encoded PKCS#1 structure for an RSA private key
 * @param key The RSA key to encode
 * @param derLen Output parameter for the length of the DER data
 * @return uint8_t* Pointer to the DER-encoded data (must be freed by caller), or NULL on error
 */
static uint8_t *buildPrivateKeyDer(t_rsaKey *key, size_t *derLen)
{
	uint8_t *comp[9];
	size_t  clens[9];
	size_t  totalPayload = 0;
	t_bigInt *vTmp;

	/* Composants PKCS#1: version(0), n, e, d, p, q, dP, dQ, qInv */
	vTmp = bigIntFromUint64(0);
	comp[0] = bigIntToDer(vTmp, &clens[0]); bigIntFree(vTmp);
	comp[1] = bigIntToDer(key->n, &clens[1]);
	comp[2] = bigIntToDer(key->e, &clens[2]);
	comp[3] = bigIntToDer(key->d, &clens[3]);
	comp[4] = bigIntToDer(key->p, &clens[4]);
	comp[5] = bigIntToDer(key->q, &clens[5]);
	comp[6] = bigIntToDer(key->dp, &clens[6]);
	comp[7] = bigIntToDer(key->dq, &clens[7]);
	comp[8] = bigIntToDer(key->qinv, &clens[8]);

	for (int i = 0; i < 9; i++) {
		if (!comp[i]) goto err;
		totalPayload += clens[i];
	}

	size_t seqHeaderLen = 1 + encodeDerLength(NULL, totalPayload);
	uint8_t *seq = malloc(seqHeaderLen + totalPayload);
	if (!seq) goto err;

	seq[0] = 0x30; /* Tag SEQUENCE */
	encodeDerLength(seq + 1, totalPayload);

	uint8_t *ptr = seq + seqHeaderLen;
	for (int i = 0; i < 9; i++) {
		ft_memcpy(ptr, comp[i], clens[i]);
		ptr += clens[i];
		free(comp[i]);
	}
	*derLen = seqHeaderLen + totalPayload;
	return seq;

err:
	for (int i = 0; i < 9; i++) if (comp[i]) free(comp[i]);
	return (NULL);
}

char *rsaKeyToPem(t_rsaKey *key, int isPrivate)
{
	uint8_t		*der;
	size_t		derLen;
	char		*b64;
	char		*pem;
	const char	*header = "-----BEGIN RSA PRIVATE KEY-----\n";
	const char	*footer = "-----END RSA PRIVATE KEY-----\n";

	if (!isPrivate) return (NULL);

	der = buildPrivateKeyDer(key, &derLen);
	if (!der) return (NULL);

	size_t b64Max = ((derLen + 2) / 3) * 4 + 1;
	b64 = malloc(b64Max);
	if (!b64) {
		free(der);
		return (NULL);
	}

	base64Encode(der, derLen, b64, b64Max);
	free(der);

	size_t b64ActualLen = ft_strlen(b64);
	size_t lines = (b64ActualLen + 63) / 64;
	size_t pemLen = ft_strlen(header) + b64ActualLen + lines + ft_strlen(footer) + 1;
	
	pem = malloc(pemLen);
	if (!pem) {
		free(b64);
		return (NULL);
	}

	ft_bzero(pem, pemLen);
	ft_strlcpy(pem, header, pemLen);
	
	size_t pos = ft_strlen(header);
	for (size_t i = 0; i < b64ActualLen; i += 64) {
		size_t chunk = (b64ActualLen - i < 64) ? (b64ActualLen - i) : 64;
		ft_memcpy(pem + pos, b64 + i, chunk);
		pos += chunk;
		pem[pos++] = '\n';
	}
	
	ft_strlcpy(pem + pos, footer, pemLen - pos);

	free(b64);
	return (pem);
}
