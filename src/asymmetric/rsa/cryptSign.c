#include <stdlib.h>

#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/asymmetric/pkey.h"

#include "../../../includes/asymmetric/rsa.h"


/**
 * @brief Performs RSA public key operation on input data.
 *
 * Executes modular exponentiation using the public exponent and modulus
 * (c = m^e mod n), converting input bytes to a big integer, computing the
 * result, and serializing it back to a fixed-size byte array.
 *
 * @param data   Input buffer containing the message representative.
 * @param dataLen Length of the input buffer in bytes.
 * @param key    Pointer to the RSA public key.
 * @param out    Output buffer for the resulting ciphertext representative.
 * @param outLen Pointer to receive the number of bytes written to out.
 *
 * @return 1 on success, 0 on allocation failure.
 */
static int	rsaPublicOp(const uint8_t	*data,	size_t	dataLen,
						const t_rsaKey	*key,
						uint8_t			*out,	size_t	*outLen)
{
	t_bigInt	*m;
	t_bigInt	*c;
	size_t		k;

	m = bigIntFromBytes(data, dataLen);
	c = bigIntNew(key->n->numWords + 1);
	if (!m || !c)
	{
		bigIntFree(m);
		bigIntFree(c);
		return (0);
	}
	bigIntModExp(c, m, key->e, key->n);
	k = rsaModulusBytes(key);
	*outLen = bigIntToBytes(c, out, k);
	bigIntFree(m);
	bigIntFree(c);
	return (1);
}

/**
 * @brief Performs RSA private key operation on the input data.
 *
 * This function converts the input byte array into a big integer, computes the
 * modular exponentiation using the private exponent and modulus (m = c^d mod n),
 * and writes the result as a fixed-size byte array corresponding to the modulus
 * length.
 *
 * @param data    Input data buffer to be processed.
 * @param dataLen Length of the input data in bytes.
 * @param key     RSA key containing the private exponent and modulus.
 * @param out     Output buffer to receive the operation result.
 * @param outLen  Pointer to receive the length of the output in bytes.
 *
 * @return 1 on success, 0 on failure (e.g., allocation error).
 */
static int	rsaPrivateOp(const uint8_t	*data,	size_t	dataLen,
						 const t_rsaKey	*key,
						 uint8_t		*out,	size_t	*outLen)
{
	t_bigInt	*c;
	t_bigInt	*m;
	size_t		k;

	c = bigIntFromBytes(data, dataLen);
	m = bigIntNew(key->n->numWords + 1);
	if (!c || !m)
	{
		bigIntFree(c);
		bigIntFree(m);
		return (0);
	}
	bigIntModExp(m, c, key->d, key->n);
	k = rsaModulusBytes(key);
	*outLen = bigIntToBytes(m, out, k);
	bigIntFree(c);
	bigIntFree(m);
	return (1);
}



int	rsaEncrypt(const uint8_t	*input,		size_t	inputLen,
			   const void		*key,
			   uint8_t			*output,	size_t	*outputLen,
			   t_pkeyPadding	padding)
{
	const t_rsaKey	*rsa;
	size_t			k;
	uint8_t			*padded;
	int				padOk;
	int				opOk;

	rsa = (const t_rsaKey *)key;
	k = rsaModulusBytes(rsa);
	padded = malloc(k);
	if (!padded)
		return (0);

	/* Select padding function */
	padOk = 0;
	if (padding == PKEY_PADDING_PKCS1V15)
		padOk = rsaPkcs1v15PadEncrypt(input, inputLen, rsa, padded, k);
	else if (padding == PKEY_PADDING_OAEP)
		padOk = rsaOaepPadEncrypt(input, inputLen, rsa, padded, k);
	else
	{
		HAJCRYPT_DPRINT("rsaEncrypt: unsupported padding mode %d\n", padding);
		free(padded);
		return (0);
	}
	if (!padOk)
	{
		free(padded);
		return (0);
	}
	opOk = rsaPublicOp(padded, k, rsa, output, outputLen);
	free(padded);
	return (opOk);
}

int	rsaDecrypt(const uint8_t	*input,		size_t	inputLen,
			   const void		*key,
			   uint8_t			*output,	size_t	*outputLen,
			   t_pkeyPadding	padding)
{
	const t_rsaKey	*rsa;
	size_t			k;
	uint8_t			*padded;
	size_t			paddedLen;
	int				unpadOk;

	rsa = (const t_rsaKey *)key;
	k = rsaModulusBytes(rsa);
	if (inputLen != k)
		return (0);
	padded = malloc(k);
	if (!padded)
		return (0);
	if (!rsaPrivateOp(input, k, rsa, padded, &paddedLen))
	{
		free(padded);
		return (0);
	}

	/* Select unpadding function */
	unpadOk = 0;
	if (padding == PKEY_PADDING_PKCS1V15)
		unpadOk = rsaPkcs1v15UnpadEncrypt(padded, paddedLen, output, outputLen);
	else if (padding == PKEY_PADDING_OAEP)
		unpadOk = rsaOaepUnpadEncrypt(padded, paddedLen, output, outputLen);
	else
		HAJCRYPT_DPRINT("rsaDecrypt: unsupported padding mode %d\n", padding);
	free(padded);
	if (!unpadOk)
		return (0);
	return (1);
}

int	rsaSign(const uint8_t	*digest,	size_t	digestLen,
			const t_algoId *digestAlgo,
			const void		*key,
			uint8_t			*sig,		size_t	*sigLen,
			t_pkeyPadding	padding)
{
	const t_rsaKey	*rsa;
	size_t			k;
	uint8_t			*padded;
	int				padOk;
	int				opOk;

	rsa = (const t_rsaKey *)key;
	k = rsaModulusBytes(rsa);
	padded = malloc(k);
	if (!padded)
		return (0);

	/* Select padding function */
	padOk = 0;
	if (padding == PKEY_PADDING_PKCS1V15)
		padOk = rsaPkcs1v15PadSign(digest, digestLen, digestAlgo,
					rsa, padded, k);
	else if (padding == PKEY_PADDING_PSS)
		padOk = rsaPssPadSign(digest, digestLen, digestAlgo,
					rsa, padded, k);
	else
	{
		HAJCRYPT_DPRINT("rsaSign: unsupported padding mode %d\n", padding);
		free(padded);
		return (0);
	}
	if (!padOk)
	{
		free(padded);
		return (0);
	}
	opOk = rsaPrivateOp(padded, k, rsa, sig, sigLen);
	free(padded);
	return (opOk);
}


int	rsaVerify(const uint8_t		*digest,	size_t	digestLen,
			  const t_algoId	*digestAlgo,
			  const void		*key,
			  const uint8_t		*sig,		size_t	sigLen,
			  t_pkeyPadding		padding)
{
	const t_rsaKey	*rsa;
	size_t			k;
	uint8_t			*padded;
	size_t			paddedLen;
	int				ret;

	rsa = (const t_rsaKey *)key;
	k = rsaModulusBytes(rsa);
	if (sigLen != k)
		return (0);
	padded = malloc(k);
	if (!padded)
		return (0);
	if (!rsaPublicOp(sig, sigLen, rsa, padded, &paddedLen))
	{
		free(padded);
		return (0);
	}

	ret = 0;
	if (padding == PKEY_PADDING_PKCS1V15)
	{
		uint8_t	recoveredDigest[64];
		size_t	recoveredLen;

		if (rsaPkcs1v15UnpadSign(padded, paddedLen,
				recoveredDigest, &recoveredLen, digestAlgo))
		{
			if (recoveredLen == digestLen
				&& ft_memcmp(recoveredDigest, digest, digestLen) == 0)
				ret = 1;
		}
	}
	else if (padding == PKEY_PADDING_PSS)
	{
		if (rsaPssUnpadSign(padded, paddedLen,
				digest, digestLen, digestAlgo))
			ret = 1;
	}
	else
		HAJCRYPT_DPRINT("rsaVerify: unsupported padding mode %d\n", padding);
	free(padded);
	return (ret);
}
