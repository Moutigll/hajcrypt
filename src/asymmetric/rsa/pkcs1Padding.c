#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/random.h"
#include "../../../includes/hash/sha256.h"
#include "../../../includes/hash/md5.h"
#include "../../../includes/x509/oid.h"

#include "../../../includes/asymmetric/rsa.h"

/**
 * @brief Compare two algorithm IDs
 * @param a The first algorithm ID
 * @param b The second algorithm ID
 * @return int 1 if equal, 0 otherwise
 */
static int oidEqual(const t_algoId *a, const t_algoId *b)
{
	if (!a || !b)
		return (0);
	if (a->len != b->len)
		return (0);
	return (ft_memcmp(a->data, b->data, a->len) == 0);
}

/**
 * @brief Get the pre-encoded DigestInfo header for a given algorithm ID
 * @param oid The algorithm ID
 * @param header Pointer to store the header
 * @param headerLen Pointer to store the header length
 * @param digestLen Pointer to store the digest length
 * @return int 1 on success, 0 if OID not recognized
 */
static int getDigestInfoHeader(const t_algoId *oid,
		const uint8_t **header, size_t *headerLen,
		size_t *digestLen)
{
	if (oidEqual(oid, &g_sha256Hash.oid))
	{
		*header = g_sha256DigestInfoHeader;
		*headerLen = SHA256_DIGEST_INFO_HEADER_LEN;
		*digestLen = SHA256_DIGEST_LEN;
		return (1);
	}
	// TODO:
	// if (oidEqual(oid, &g_sha384Hash.oid))
	// {
	// 	*header = g_sha384DigestInfoHeader;
	// 	*headerLen = SHA384_DIGEST_INFO_HEADER_LEN;
	// 	*digestLen = SHA384_DIGEST_LEN;
	// 	return (1);
	// }
	// if (oidEqual(oid, &g_sha512Hash.oid))
	// {
	// 	*header = g_sha512DigestInfoHeader;
	// 	*headerLen = SHA512_DIGEST_INFO_HEADER_LEN;
	// 	*digestLen = SHA512_DIGEST_LEN;
	// 	return (1);
	// }
	if (oidEqual(oid, &g_md5Hash.oid))
	{
		*header = g_md5DigestInfoHeader;
		*headerLen = MD5_DIGEST_INFO_HEADER_LEN;
		*digestLen = MD5_DIGEST_LEN;
		return (1);
	}
	HAJCRYPT_DPRINT("Unsupported digest algorithm OID\n");
	return (0);
}

int rsaPkcs1v15PadEncrypt(const uint8_t		*input,		size_t	inputLen,
						  const t_rsaKey	*key,
						  uint8_t			*padded,	size_t	paddedLen)
{
	size_t	k;
	size_t	ps_len;
	size_t	i;
	uint8_t	rnd[1];

	k = rsaModulusBytes(key);
	if (paddedLen < k || inputLen > k - 11)
		return (HAJCRYPT_DPRINT("Padded length is too small\n"), 0);
	padded[0] = 0x00;
	padded[1] = 0x02;
	ps_len = k - 3 - inputLen;
	i = 0;
	while (i < ps_len)
	{
		hajSecRandBytes(rnd, 1);
		if (rnd[0] != 0x00)
		{
			padded[2 + i] = rnd[0];
			i++;
		}
	}
	padded[2 + ps_len] = 0x00;
	ft_memcpy(padded + 3 + ps_len, input, inputLen);
	return (1);
}

int rsaPkcs1v15UnpadEncrypt(const uint8_t	*padded,	size_t	paddedLen,
							uint8_t			*output,	size_t	*outputLen)
{
	size_t	msg_len;
	size_t	sep;

	if (paddedLen < 11)
		return (HAJCRYPT_DPRINT("Padded length is too small\n"), 0);
	if (padded[0] != 0x00 || padded[1] != 0x02)
		return (HAJCRYPT_DPRINT("Invalid padding\n"), 0);
	sep = 2;
	while (sep < paddedLen && padded[sep] != 0x00)
		sep++;
	if (sep == paddedLen || sep == 2)
		return (HAJCRYPT_DPRINT("Invalid padding\n"), 0);
	msg_len = paddedLen - sep - 1;
	ft_memcpy(output, padded + sep + 1, msg_len);
	*outputLen = msg_len;
	return (1);
}



int	rsaPkcs1v15PadSign(const uint8_t	*digest,		size_t	digestLen,
					   const t_algoId	*digestAlgoOid,
					   const t_rsaKey	*key,
					   uint8_t			*padded,		size_t	paddedLen)
{
	const uint8_t	*header;
	size_t			headerLen;
	size_t			expectedDigestLen;
	size_t			k;
	size_t			t_len;
	size_t			ps_len;

	if (!getDigestInfoHeader(digestAlgoOid, &header, &headerLen,
			&expectedDigestLen))
		return (0);
	if (digestLen != expectedDigestLen)
	{
		HAJCRYPT_DPRINT("Digest length mismatch: expected %zu, got %zu\n",
			expectedDigestLen, digestLen);
		return (0);
	}
	k = rsaModulusBytes(key);
	if (paddedLen < k)
		return (HAJCRYPT_DPRINT("Padded length is too small\n"), 0);
	t_len = headerLen + digestLen;
	if (k < t_len + 11)
		return (HAJCRYPT_DPRINT("Key size is too small for given digest\n"), 0);
	padded[0] = 0x00;
	padded[1] = 0x01;
	ps_len = k - 3 - t_len;
	ft_memset(padded + 2, 0xFF, ps_len);
	padded[2 + ps_len] = 0x00;
	ft_memcpy(padded + 3 + ps_len, header, headerLen);
	ft_memcpy(padded + 3 + ps_len + headerLen, digest, digestLen);
	
	return (1);
}


int	rsaPkcs1v15UnpadSign(const uint8_t			*padded,		size_t	paddedLen,
							  uint8_t			*digestOut,		size_t	*digestLen,
							  const t_algoId	*expectedAlgoOid)
{
	const uint8_t	*header;
	size_t			headerLen;
	size_t			expectedDigestLen;
	const uint8_t	*di;
	size_t			di_len;
	size_t			sep;

	if (!getDigestInfoHeader(expectedAlgoOid, &header, &headerLen,
			&expectedDigestLen))
		return (0);
	if (paddedLen < 11)
		return (HAJCRYPT_DPRINT("Padded length is too small\n"), 0);
	if (padded[0] != 0x00 || padded[1] != 0x01)
		return (HAJCRYPT_DPRINT("Invalid padding\n"), 0);
	sep = 2;
	while (sep < paddedLen && padded[sep] == 0xFF)
		sep++;
	if (sep == paddedLen || padded[sep] != 0x00)
		return (HAJCRYPT_DPRINT("Invalid padding\n"), 0);
	di = padded + sep + 1;
	di_len = paddedLen - sep - 1;
	if (di_len < headerLen + expectedDigestLen
		|| ft_memcmp(di, header, headerLen) != 0)
		return (HAJCRYPT_DPRINT("Digest mismatch\n"), 0);
	ft_memcpy(digestOut, di + headerLen, expectedDigestLen);
	*digestLen = expectedDigestLen;
	return (1);
}
