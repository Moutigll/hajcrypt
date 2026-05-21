#include <stdlib.h>

#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../hajlib/include/hmemory.h"
#include "../../includes/hajcrypt.h"

#include "../../includes/asymmetric/pkey.h"

int	pkeyGenerate(t_pkey *pkey, int bits)
{
	const t_pkeyDef	*def;
	void			*key;

	if (!pkey || !pkey->def)
		return (0);
	def = pkey->def;
	if (!def->generate)
		return (0);
	if (!def->validateBits || !def->validateBits(bits))
		return (HAJCRYPT_DPRINT("pkeyGenerate: invalid key size %d for algorithm\n", bits), 0);
	key = malloc(def->keyLen);
	if (!key)
		return (0);
	ft_bzero(key, def->keyLen);
	if (!def->generate(key, bits))
	{
		free(key);
		return (0);
	}
	pkey->key = key;
	return (1);
}

void	pkeyFree(t_pkey *pkey)
{
	if (!pkey || !pkey->def || !pkey->key)
		return ;
	if (pkey->def->freeKey)
		pkey->def->freeKey(pkey->key);
	free(pkey->key);
	pkey->key = NULL;
	pkey->def = NULL;
}



int	pkeyEncrypt(t_pkey			*pkey,
				const uint8_t	*input,		size_t	inputLen,
				uint8_t			*output,	size_t	*outputLen,
				t_pkeyPadding	padding)
{
	if (!pkey || !pkey->def || !pkey->key)
		return (0);
	if (!(pkey->def->caps & PKEY_CAP_ENCRYPT) || !pkey->def->encrypt)
		return (HAJCRYPT_DPRINT("pkeyEncrypt: key does not support encryption\n"), 0);
	return (pkey->def->encrypt(input, inputLen, pkey->key, output, outputLen, padding));
}

int	pkeyDecrypt(t_pkey			*pkey,
				const uint8_t	*input,		size_t	inputLen,
				uint8_t			*output,	size_t	*outputLen,
				t_pkeyPadding	padding)
{
	if (!pkey || !pkey->def || !pkey->key)
		return (0);
	if (!(pkey->def->caps & PKEY_CAP_ENCRYPT) || !pkey->def->decrypt)
		return (HAJCRYPT_DPRINT("pkeyDecrypt: key does not support decryption\n"), 0);
	return (pkey->def->decrypt(input, inputLen, pkey->key, output, outputLen, padding));
}

int	pkeySign(t_pkey			*pkey,
			 const uint8_t	*digest,	size_t	digestLen,
			 const t_algoId	*digestAlgo,
			 uint8_t		*sig,		size_t	*sigLen,
			 t_pkeyPadding	padding)
{
	if (!pkey || !pkey->def || !pkey->key)
		return (0);
	if (!(pkey->def->caps & PKEY_CAP_SIGN) || !pkey->def->sign)
		return (HAJCRYPT_DPRINT("pkeySign: key does not support signing\n"), 0);
	return (pkey->def->sign(digest, digestLen, digestAlgo, pkey->key, sig, sigLen, padding));
}

int	pkeyVerify(t_pkey			*pkey,
			   const uint8_t	*digest,	size_t	digestLen,
			   const t_algoId	*digestAlgo,
			   const uint8_t	*sig,		size_t	sigLen,
			   t_pkeyPadding	padding)
{
	if (!pkey || !pkey->def || !pkey->key)
		return (0);
	if (!(pkey->def->caps & PKEY_CAP_SIGN) || !pkey->def->verify)
		return (HAJCRYPT_DPRINT("pkeyVerify: key does not support signature verification\n"), 0);
	return (pkey->def->verify(digest, digestLen, digestAlgo, pkey->key, sig, sigLen, padding));
}
