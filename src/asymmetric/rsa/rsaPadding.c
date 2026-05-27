#include <stdlib.h>

#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/dispatch.h"
#include "../../../includes/utils/random.h"
#include "../../../includes/hash/sha256.h"
#include "../../../includes/hash/md5.h"
#include "../../../includes/hajcrypt.h"

#include "../../../includes/asymmetric/rsa.h"


static int	oidEqual(const t_algoId *a, const t_algoId *b)
{
	if (!a || !b)
		return (0);
	if (a->len != b->len)
		return (0);
	return (ft_memcmp(a->data, b->data, a->len) == 0);
}

static int	getDigestInfoHeader(const t_algoId *oid, const uint8_t **header, size_t *headerLen, size_t *digestLen)
{
	if (oidEqual(oid, &g_sha256Hash.oid))
	{
		*header = g_sha256DigestInfoHeader;
		*headerLen = SHA256_DIGEST_INFO_HEADER_LEN;
		*digestLen = SHA256_DIGEST_LEN;
		return (1);
	}
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

/**
 * @brief MGF1 mask generation function (RFC 8017, Appendix B.2).
 * @param seed         Input seed.
 * @param seedLen      Length of seed.
 * @param output       Output buffer.
 * @param outputLen    Desired output length.
 * @param hashOid      Hash algorithm OID (must be SHA-256 for now).
 * @return 1 on success, 0 on error.
 */
static int	mgf1(const uint8_t	*seed,		size_t	seedLen,
				 uint8_t		*output,	size_t	outputLen,
				 const t_algoId	*hashOid)
{
	const t_hash	*hash;
	uint8_t			digest[64];
	size_t			hashLen;
	uint32_t		counter;
	uint8_t			counterBytes[4];
	size_t			written;
	size_t			toCopy;

	hash = getHashByOid(hashOid->data, hashOid->len);
	if (!hash)
		return (0);
	hashLen = hash->digestSize;
	if (outputLen > (UINT32_MAX) * hashLen)
		return (0);
	counter = 0;
	written = 0;
	void *ctx = malloc(hash->ctxSize);
	if (!ctx)
		return (0);
	while (written < outputLen)
	{
		counterBytes[0] = (uint8_t)(counter >> 24);
		counterBytes[1] = (uint8_t)(counter >> 16);
		counterBytes[2] = (uint8_t)(counter >> 8);
		counterBytes[3] = (uint8_t)(counter);
		hash->init(ctx);
		hash->update(ctx, seed, seedLen);
		hash->update(ctx, counterBytes, 4);
		hash->final(ctx, digest);
		toCopy = hashLen;
		if (toCopy > outputLen - written)
			toCopy = outputLen - written;
		ft_memcpy(output + written, digest, toCopy);
		written += toCopy;
		counter++;
	}
	free(ctx);
	return (1);
}

/* =========================================================================
 *                   PKCS#1 v1.5 Encryption Padding
 * ========================================================================= */

int	rsaPkcs1v15PadEncrypt(const uint8_t		*input,		size_t	inputLen,
						  const t_rsaKey	*key,
						  uint8_t			*padded,	size_t	paddedLen)
{
	size_t	k;
	size_t	ps_len;
	size_t	i;
	uint8_t	rnd[1];

	k = rsaModulusBytes(key);
	if (paddedLen < k )
		return (HAJCRYPT_DPRINT("PKCS#1 v1.5 padding: padded length too short\n"), (0));
	if (inputLen > k - 11)
		return (HAJCRYPT_DPRINT("PKCS#1 v1.5 padding: input too long for key size\n"), (0));
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

int	rsaPkcs1v15UnpadEncrypt(const uint8_t	*padded,	size_t	paddedLen,
							 uint8_t		*output,	size_t	*outputLen)
{
	int		valid;
	int		errType;  /* 0=ok, 1=len too short, 2=invalid format, 3=no separator */
	size_t	sepFound;
	size_t	sepPos;
	size_t	msgLen;
	size_t	i;

	valid = 1;
	errType = 0;

	errType |= (paddedLen < 11) ? 1 : 0;
	valid &= !(paddedLen < 11);

	errType |= ((padded[0] != 0x00) || (padded[1] != 0x02)) ? 2 : 0;
	valid &= (padded[0] == 0x00) && (padded[1] == 0x02);

	sepFound = 0;
	sepPos = 0;
	i = 2;
	while (i < paddedLen)
	{
		int	is_sep;

		is_sep = (padded[i] == 0x00) && !sepFound;
		sepPos = is_sep ? i : sepPos;
		sepFound = is_sep ? 1 : sepFound;
		i++;
	}
	errType |= (!sepFound || sepPos == 2) ? 3 : 0;
	valid &= (sepFound && sepPos > 2);

	msgLen = paddedLen - sepPos - 1;

	i = 0;
	while (i < msgLen)
	{
		uint8_t	byte;

		byte = padded[sepPos + 1 + i];
		output[i] = byte & -(uint8_t)valid;
		i++;
	}
	*outputLen = msgLen;

	if (!valid)
	{
		if (errType == 1)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: padded length too short\n");
		else if (errType == 2)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: invalid padding format\n");
		else if (errType == 3)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: 0x00 separator not found or no padding bytes\n");
	}
	return (valid);
}
/* =========================================================================
 *                   PKCS#1 v1.5 Signature Padding
 * ========================================================================= */

int	rsaPkcs1v15PadSign(const uint8_t	*digest,	size_t	digestLen,
					   const t_algoId	*digestAlgo,
					   const t_rsaKey	*key,
					   uint8_t			*padded,	size_t	paddedLen)
{
	const uint8_t	*header;
	size_t			headerLen;
	size_t			expectedDigestLen;
	size_t			k;
	size_t			t_len;
	size_t			ps_len;

	if (!getDigestInfoHeader(digestAlgo, &header, &headerLen,
			&expectedDigestLen))
		return (HAJCRYPT_DPRINT("PKCS#1 v1.5 padding: unsupported digest algorithm OID\n"), (0));
	if (digestLen != expectedDigestLen)
		return (HAJCRYPT_DPRINT("PKCS#1 v1.5 padding: digest length mismatch, expected %zu, got %zu\n", expectedDigestLen, digestLen), (0));
	k = rsaModulusBytes(key);
	if (paddedLen < k)
		return (HAJCRYPT_DPRINT("PKCS#1 v1.5 padding: padded length too short\n"), (0));
	t_len = headerLen + digestLen;
	if (k < t_len + 11)
		return (HAJCRYPT_DPRINT("Key size too small for PKCS#1 v1.5 signature padding\n"), (0));
	padded[0] = 0x00;
	padded[1] = 0x01;
	ps_len = k - 3 - t_len;
	ft_memset(padded + 2, 0xFF, ps_len);
	padded[2 + ps_len] = 0x00;
	ft_memcpy(padded + 3 + ps_len, header, headerLen);
	ft_memcpy(padded + 3 + ps_len + headerLen, digest, digestLen);
	return (1);
}

int	rsaPkcs1v15UnpadSign(const uint8_t	*padded,	size_t	paddedLen,
						 uint8_t		*digestOut,	size_t	*digestLen,
						 const t_algoId	*expectedAlgo)
{
	const uint8_t	*header;
	size_t			headerLen;
	size_t			expectedDigestLen;
	const uint8_t	*di;
	size_t			diLen;
	size_t			sep;
	int				valid;
	int				errType; /* 0=ok, 1=len too short, 2=invalid format, 3=separator not found, 4=header mismatch */
	size_t			i;

	if (!getDigestInfoHeader(expectedAlgo, &header, &headerLen,
			&expectedDigestLen))
		return (HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: unsupported digest algorithm OID\n"), 0);

	valid = 1;
	errType = 0;

	errType |= (paddedLen < 11) ? 1 : 0;
	valid &= !(paddedLen < 11);

	errType |= ((padded[0] != 0x00) || (padded[1] != 0x01)) ? 2 : 0;
	valid &= (padded[0] == 0x00) && (padded[1] == 0x01);

	sep = 2;
	while (sep < paddedLen && padded[sep] == 0xFF)
		sep++;
	errType |= ((sep >= paddedLen) || (padded[sep] != 0x00)) ? 3 : 0;
	valid &= (sep < paddedLen && padded[sep] == 0x00);

	diLen = (valid) ? (paddedLen - sep - 1) : 0;
	di = padded + sep + 1;

	i = 0;
	while (i < headerLen && i < diLen)
	{
		valid &= (di[i] == header[i]);
		i++;
	}
	valid &= (diLen >= headerLen + expectedDigestLen);
	errType |= (!valid && errType == 0) ? 4 : 0;

	i = 0;
	while (i < expectedDigestLen)
	{
		uint8_t	byte;

		byte = di[headerLen + i];
		digestOut[i] = byte & -(uint8_t)valid;
		i++;
	}
	*digestLen = expectedDigestLen;

	if (!valid)
	{
		if (errType == 1)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: padded length too short\n");
		else if (errType == 2)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: invalid padding format\n");
		else if (errType == 3)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: invalid padding format\n");
		else if (errType == 4)
			HAJCRYPT_DPRINT("PKCS#1 v1.5 unpadding: digest info header mismatch\n");
	}
	return (valid);
}

/* =========================================================================
 *                   OAEP Encryption Padding (SHA-256)
 * ========================================================================= */

int	rsaOaepPadEncrypt(const uint8_t		*input,		size_t	inputLen,
					  const t_rsaKey	*key,
					  uint8_t			*padded,	size_t	paddedLen)
{
	size_t	k;
	size_t	hLen;
	uint8_t	lHash[32];
	uint8_t	*db = NULL;
	uint8_t	*seed = NULL;
	uint8_t	*dbMask = NULL;
	uint8_t	*seedMask = NULL;

	k = rsaModulusBytes(key);
	hLen = SHA256_DIGEST_LEN;
	if (inputLen > k - 2 * hLen - 2 || paddedLen < k)
		return (HAJCRYPT_DPRINT("OAEP padding failed: input too long for key size\n"), (0));

	/* Compute lHash = SHA256("") */
	sha256Hash((const uint8_t *)"", 0, lHash);

	/* DB = lHash || 00 ... 00 || 01 || message */
	{
		size_t	dbLen = k - hLen - 1;
		db = malloc(dbLen);
		if (!db) return (0);
		ft_memcpy(db, lHash, hLen);
		ft_memset(db + hLen, 0, dbLen - hLen - inputLen - 1);
		db[dbLen - inputLen - 1] = 0x01;
		ft_memcpy(db + dbLen - inputLen, input, inputLen);
	}

	/* Generate random seed */
	seed = malloc(hLen);
	if (!seed)
		goto error;
	hajSecRandBytes(seed, hLen);

	/* dbMask = MGF1(seed, hLen, dbLen) */
	dbMask = malloc(k - hLen - 1);
	if (!dbMask)
		goto error;
	if (!mgf1(seed, hLen, dbMask, k - hLen - 1, &g_sha256Hash.oid))
		{ HAJCRYPT_DPRINT("OAEP padding: MGF1 failed\n"); goto error; }
	/* maskedDB = DB ^ dbMask */
	for (size_t i = 0; i < (size_t)(k - hLen - 1); i++)
		db[i] ^= dbMask[i];

	/* seedMask = MGF1(maskedDB, dbLen, hLen) */
	seedMask = malloc(hLen);
	if (!seedMask)
		goto error;
	if (!mgf1(db, k - hLen - 1, seedMask, hLen, &g_sha256Hash.oid))
		{ HAJCRYPT_DPRINT("OAEP padding: MGF1 failed\n"); goto error; }
	/* maskedSeed = seed ^ seedMask */
	for (size_t i = 0; i < hLen; i++)
		seed[i] ^= seedMask[i];

	/* Build EM = 0x00 || maskedSeed || maskedDB */
	padded[0] = 0x00;
	ft_memcpy(padded + 1, seed, hLen);
	ft_memcpy(padded + 1 + hLen, db, k - hLen - 1);

	free(db); free(seed); free(dbMask); free(seedMask);
	return (1);
error:
	free(db);
	free(seed);
	free(dbMask);
	free(seedMask);
	return (0);
}


int	rsaOaepUnpadEncrypt(const uint8_t	*padded,	size_t	paddedLen,
						uint8_t			*output,	size_t	*outputLen)
{
	size_t		k;
	size_t		hLen;
	uint8_t		*seed;
	uint8_t		*db;
	uint8_t		*dbMask;
	uint8_t		*seedMask;
	uint8_t		lHash[32];
	int			valid;
	int			errType; /* 0=ok, 1=lHash mismatch, 2=separator not found */
	size_t		msgLen;
	size_t		i;

	k = paddedLen;
	hLen = SHA256_DIGEST_LEN;
	if (k < 2 * hLen + 2 || padded[0] != 0x00)
		return (0);

	seed = malloc(hLen);
	db = malloc(k - hLen - 1);
	dbMask = malloc(k - hLen - 1);
	seedMask = malloc(hLen);
	if (!seed || !db || !dbMask || !seedMask)
	{
		free(seed); free(db); free(dbMask); free(seedMask);
		return (0);
	}
	ft_memcpy(seed, padded + 1, hLen);
	ft_memcpy(db, padded + 1 + hLen, k - hLen - 1);

	if (!mgf1(db, k - hLen - 1, seedMask, hLen, &g_sha256Hash.oid))
	{
		HAJCRYPT_DPRINT("OAEP unpadding: MGF1 failed\n");
		free(seed); free(db); free(dbMask); free(seedMask);
		return (0);
	}
	for (i = 0; i < hLen; i++)
		seed[i] ^= seedMask[i];

	if (!mgf1(seed, hLen, dbMask, k - hLen - 1, &g_sha256Hash.oid))
	{
		HAJCRYPT_DPRINT("OAEP unpadding: MGF1 failed\n");
		free(seed); free(db); free(dbMask); free(seedMask);
		return (0);
	}
	for (i = 0; i < (size_t)(k - hLen - 1); i++)
		db[i] ^= dbMask[i];

	sha256Hash((const uint8_t *)"", 0, lHash);

	valid = 1;
	errType = 0;

	/* Compare hash in constant time */
	for (i = 0; i < hLen; i++)
		valid &= (db[i] == lHash[i]);
	errType |= (!valid && errType == 0) ? 1 : 0;

	{
		size_t	pos;
		int		found;

		found = 0;
		pos = 0;
		i = hLen;
		while (i < (size_t)(k - hLen - 1))
		{
			int	is_sep;

			is_sep = (db[i] == 0x01) && !found;
			pos = is_sep ? i : pos;
			found = is_sep ? 1 : found;
			i++;
		}
		valid &= found;
		errType |= (!found && errType == 0) ? 2 : 0;
		msgLen = k - hLen - 1 - pos - 1;

		i = 0;
		while (i < msgLen)
		{
			uint8_t	byte;

			byte = db[pos + 1 + i];
			output[i] = byte & -(uint8_t)valid;
			i++;
		}
		*outputLen = msgLen;
	}

	free(seed); free(db); free(dbMask); free(seedMask);

	if (!valid)
	{
		if (errType == 1)
			HAJCRYPT_DPRINT("OAEP unpadding: lHash mismatch\n");
		else if (errType == 2)
			HAJCRYPT_DPRINT("OAEP unpadding: 0x01 separator not found\n");
	}
	return (valid);
}

/* =========================================================================
 *                   PSS Signature Padding (SHA-256)
 * ========================================================================= */

int	rsaPssPadSign(const uint8_t		*digest,	size_t	digestLen,
				  const t_algoId	*digestAlgo,
				  const t_rsaKey	*key,
				  uint8_t			*padded,	size_t	paddedLen)
{
	size_t		k;
	size_t		hLen;
	size_t		sLen;
	uint8_t		salt[32];
	uint8_t		mHash[32];
	uint8_t		hash[32];
	uint8_t		*db;
	uint8_t		*dbMask;

	if (!oidEqual(digestAlgo, &g_sha256Hash.oid))
		return (HAJCRYPT_DPRINT("PSS padding: unsupported hash algorithm OID\n"), (0));
	if (digestLen != SHA256_DIGEST_LEN)
		return (HAJCRYPT_DPRINT("PSS padding: invalid digest length\n"), (0));

	k = rsaModulusBytes(key);
	hLen = SHA256_DIGEST_LEN;
	sLen = hLen; /* recommended salt length */
	if (paddedLen != k || k < hLen + sLen + 2)
		return (HAJCRYPT_DPRINT("PSS padding failed: invalid padded length or key size\n"), (0));

	/* mHash = SHA256(M) = digest (already hashed by caller) */
	ft_memcpy(mHash, digest, hLen);

	/* Generate random salt */
	hajSecRandBytes(salt, sLen);

	/* M' = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 || mHash || salt */
	{
		uint8_t m_prime[8 + 32 + 32]; /* 8 zero bytes + hash + salt */
		ft_memset(m_prime, 0, 8);
		ft_memcpy(m_prime + 8, mHash, hLen);
		ft_memcpy(m_prime + 8 + hLen, salt, sLen);
		sha256Hash(m_prime, 8 + hLen + sLen, hash);
	}

	/* DB = 0x00...0x01 || salt */
	{
		size_t dbLen = k - hLen - 1;
		db = malloc(dbLen);
		if (!db) return (0);
		ft_memset(db, 0, dbLen - sLen - 1);
		db[dbLen - sLen - 1] = 0x01;
		ft_memcpy(db + dbLen - sLen, salt, sLen);
	}

	/* dbMask = MGF1(hash, hLen, dbLen) */
	dbMask = malloc(k - hLen - 1);
	if (!dbMask) { free(db); return (0); }
	if (!mgf1(hash, hLen, dbMask, k - hLen - 1, &g_sha256Hash.oid))
		{ free(db); free(dbMask); return (HAJCRYPT_DPRINT("PSS padding: MGF1 failed\n"), (0)); }

	/* maskedDB = DB ^ dbMask */
	for (size_t i = 0; i < (size_t)(k - hLen - 1); i++)
		db[i] ^= dbMask[i];

	/* Build EM = maskedDB || hash || 0xBC */
	ft_memcpy(padded, db, k - hLen - 1);
	ft_memcpy(padded + k - hLen - 1, hash, hLen);
	padded[k - 1] = 0xBC;

	free(db);
	free(dbMask);
	return (1);
}

int rsaPssUnpadSign(const uint8_t	*padded,			size_t	paddedLen,
					const uint8_t	*expectedDigest,	size_t	expectedDigestLen,
					const t_algoId	*expectedAlgo)
{
	size_t	k,			hLen,		dbLen;
	uint8_t	*db,		*dbMask;
	uint8_t	hash[32],	salt[32],	mHash[32];
	uint8_t	mPrime[8 + 32 + 32],	hash2[32];
	size_t	i;

	/* We currently only support SHA‑256 */
	if (!oidEqual(expectedAlgo, &g_sha256Hash.oid))
		return (HAJCRYPT_DPRINT("PSS verification: unsupported hash algorithm OID\n"), (0));
	if (expectedDigestLen != SHA256_DIGEST_LEN)
		return (HAJCRYPT_DPRINT("PSS verification: invalid expected digest length, expected %zu, got %zu\n", SHA256_DIGEST_LEN, expectedDigestLen), (0));

	k = paddedLen;
	hLen = SHA256_DIGEST_LEN;
	if (k < hLen + hLen + 2 || padded[k - 1] != 0xBC)
		return (HAJCRYPT_DPRINT("PSS verification: invalid encoded message format\n"), (0));

	dbLen = k - hLen - 1;
	db = malloc(dbLen);
	dbMask = malloc(dbLen);
	if (!db || !dbMask) {
		free(db); free(dbMask);
		return (0);
	}

	/* Split EM: maskedDB || H || 0xBC */
	ft_memcpy(db, padded, dbLen);
	ft_memcpy(hash, padded + dbLen, hLen);

	/* dbMask = MGF1(H, dbLen) */
	if (!mgf1(hash, hLen, dbMask, dbLen, &g_sha256Hash.oid)) {
		HAJCRYPT_DPRINT("PSS verification: MGF1 failed\n");
		free(db); free(dbMask);
		return (0);
	}

	/* DB = maskedDB XOR dbMask */
	for (i = 0; i < dbLen; i++)
		db[i] ^= dbMask[i];

	/* Find the 0x01 separator and extract salt (last hLen bytes) */
	{
		size_t pos = 0;
		while (pos < dbLen && db[pos] == 0x00)
			pos++;
		if (pos >= dbLen - 1 || db[pos] != 0x01) {
			HAJCRYPT_DPRINT("PSS verification: invalid DB format\n");
			free(db); free(dbMask);
			return (0);
		}
		if (dbLen - pos - 1 != hLen) {   /* salt length must equal hash length */
			HAJCRYPT_DPRINT("PSS verification: invalid salt length\n");
			free(db); free(dbMask);
			return (0);
		}
		ft_memcpy(salt, db + pos + 1, hLen);
	}

	/* mHash = expectedDigest */
	ft_memcpy(mHash, expectedDigest, hLen);

	/* M' = (0x00*8) || mHash || salt */
	ft_memset(mPrime, 0, 8);
	ft_memcpy(mPrime + 8, mHash, hLen);
	ft_memcpy(mPrime + 8 + hLen, salt, hLen);
	sha256Hash(mPrime, 8 + hLen + hLen, hash2);

	/* Compare H' with H */
	if (ft_memcmp(hash, hash2, hLen) != 0) {
		HAJCRYPT_DPRINT("PSS verification: hash mismatch\n");
		free(db); free(dbMask);
		return (0);
	}

	free(db);
	free(dbMask);
	return (1);
}
