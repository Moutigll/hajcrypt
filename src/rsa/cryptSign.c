#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"

#include "../../includes/rsa/rsa.h"

/**
 * @brief Performs RSA public key operation (encryption).
 *
 * Encrypts data using the RSA public key operation. The plaintext message is
 * converted to a big integer, raised to the power of the public exponent modulo
 * the RSA modulus, and the result is converted back to bytes.
 *
 * @param data	  Pointer to the input data (plaintext message).
 * @param dataLen   Length of the input data in bytes.
 * @param key	   Pointer to the RSA public key structure containing modulus (n)
 *				  and public exponent (e).
 * @param out	   Pointer to the output buffer where encrypted data is stored.
 * @param outLen	Pointer to size_t that receives the length of encrypted output
 *				  in bytes.
 * @return 1 on success, 0 on failure (memory allocation error).
 */
static int rsaPublicOp(const uint8_t	*data,	size_t	dataLen,
					   const t_rsaKey	*key,
					   uint8_t			*out,	size_t	*outLen)
{
	t_bigInt	*m = bigIntFromBytes(data, dataLen);
	t_bigInt	*c = bigIntNew(key->n->numWords + 1);
	if (!m || !c)
		goto fail;

	bigIntModExp(c, m, key->e, key->n);
	size_t k = rsaModulusBytes(key);
	*outLen = bigIntToBytes(c, out, k);
	bigIntFree(m);
	bigIntFree(c);
	return (1);

fail:
	bigIntFree(m);
	bigIntFree(c);
	return (0);
}

/**
 * @brief Performs RSA private key operation (decryption).
 *
 * Decrypts data using the RSA private key operation. The ciphertext message is
 * converted to a big integer, raised to the power of the private exponent modulo
 * the RSA modulus, and the result is converted back to bytes.
 *
 * @param data	  Pointer to the input data (ciphertext message).
 * @param dataLen   Length of the input data in bytes.
 * @param key	   Pointer to the RSA private key structure containing modulus (n),
 *				  private exponent (d), and public exponent (e).
 * @param out	   Pointer to the output buffer where decrypted data is stored.
 * @param outLen	Pointer to size_t that receives the length of decrypted output
 *				  in bytes.
 * @return 1 on success, 0 on failure (memory allocation error).
 */
static int rsaPrivateOp(const uint8_t	*data,		size_t	dataLen,
						const t_rsaKey	*key,
						uint8_t			*out,		size_t	*outLen)
{
	t_bigInt	*c = bigIntFromBytes(data, dataLen);
	t_bigInt	*m = bigIntNew(key->n->numWords + 1);
	if (!c || !m)
		goto fail;

	bigIntModExp(m, c, key->d, key->n);
	size_t k = rsaModulusBytes(key);
	*outLen = bigIntToBytes(m, out, k);
	bigIntFree(c);
	bigIntFree(m);
	return (1);

fail:
	bigIntFree(c);
	bigIntFree(m);
	return (0);
}

/* ---------- Crypt ---------- */

int	rsaEncryptPkcs1v15(const uint8_t	*input,		size_t	inputLen,
					   const t_rsaKey	*key,
					   uint8_t			*output,	size_t	*outputLen)
{
	size_t	k = rsaModulusBytes(key);
	uint8_t	*padded = malloc(k);
	if (!padded) return (0);

	if (!rsaPkcs1v15PadEncrypt(input, inputLen, key, padded, k)) {
		free(padded);
		return (0);
	}

	/* Apply public exponentiation */
	int ret = rsaPublicOp(padded, k, key, output, outputLen);
	free(padded);
	return (ret);
}

int	rsaDecryptPkcs1v15(const uint8_t	*input,		size_t	inputLen,
					   const t_rsaKey	*key,
					   uint8_t			*output,	size_t	*outputLen)
{
	size_t	k = rsaModulusBytes(key);
	if (inputLen != k)
		return (0);

	uint8_t	*padded = malloc(k);
	if (!padded) return (0);

	if (!rsaPrivateOp(input, k, key, padded, &k)) {
		free(padded);
		return (0);
	}

	int	ret = rsaPkcs1v15UnpadEncrypt(padded, k, output, outputLen);
	free(padded);
	return (ret);
}

/* ---------- Sign ---------- */

int rsaSignPkcs1v15(const uint8_t	*digest,	size_t	digestLen,
					const t_algoId	*digestAlgo,
					const t_rsaKey	*key,
					uint8_t			*sig,		size_t	*sigLen)
{
	size_t	k = rsaModulusBytes(key);
	uint8_t	*padded = malloc(k);

	if (!padded)
		return (0);
	if (!rsaPkcs1v15PadSign(digest, digestLen, digestAlgo, key, padded, k)) {
		free(padded);
		return (0);
	}
	int ret = rsaPrivateOp(padded, k, key, sig, sigLen);
	free(padded);
	return (ret);
}

int rsaVerifyPkcs1v15(const uint8_t		*digest,		size_t	digestLen,
					  const t_algoId	*digestAlgo,
					  const t_rsaKey	*key,
					  const uint8_t		*sig,		size_t	*sigLen)
{
	size_t	k = rsaModulusBytes(key);

	if (*sigLen != k)
		return (0);
	uint8_t	*padded = malloc(k);
	if (!padded)
		return (0);
	size_t	paddedLen;
	if (!rsaPublicOp(sig, *sigLen, key, padded, &paddedLen)) {
		free(padded);
		return (0);
	}
	uint8_t	recoveredDigest[64];	/* max 512-bit hash */
	size_t	recoveredLen;
	int		ret = rsaPkcs1v15UnpadSign(padded, k, recoveredDigest, &recoveredLen,
				digestAlgo);
	free(padded);
	if (!ret || recoveredLen != digestLen ||
		ft_memcmp(recoveredDigest, digest, digestLen) != 0)
		return (0);
	return (1);
}
