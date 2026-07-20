#include "../hajlib/include/hmemory.h"
#include "../hajlib/include/hstring.h"

#include "../includes/hash/md5.h"
#include "../includes/hash/sha.h" /* IWYU pragma: keep */
#include "../includes/hash/whirlpool.h"
#include "../includes/hash/blake2b.h"

#include "../includes/cipher/base64.h"
#include "../includes/cipher/base32.h"
#include "../includes/cipher/des.h"
#include "../includes/cipher/des3.h"
#include "../includes/cipher/aes.h"
#include "../includes/cipher/blowfish.h"
#include "../includes/cipher/chacha20Poly1305.h"

#include "../includes/asymmetric/rsa.h"
#include "../includes/asymmetric/dsa.h"

#include "../includes/utils/dispatch.h"

/* =========================================================================
 *                           Hash dispatch table
 * ========================================================================= */
const t_hashDispatch g_hashTable[] = {
	{ ALGO_MD5,			&g_md5Hash },
	{ ALGO_SHA1,			&g_sha1Hash },
	{ ALGO_SHA224,		&g_sha224Hash },
	{ ALGO_SHA256,		&g_sha256Hash },
	{ ALGO_SHA384,		&g_sha384Hash },
	{ ALGO_SHA512,		&g_sha512Hash },
	{ ALGO_SHA512_224,	&g_sha512_224Hash },
	{ ALGO_SHA512_256,	&g_sha512_256Hash },
	{ ALGO_BLAKE2B,		&g_blake2bHash },
	{ ALGO_BLAKE2B_160,	&g_blake2b160Hash },
	{ ALGO_BLAKE2B_256,	&g_blake2b256Hash },
	{ ALGO_BLAKE2B_384,	&g_blake2b384Hash },
	{ ALGO_BLAKE2B_512,	&g_blake2b512Hash },
	{ ALGO_WHIRLPOOL,	&g_whirlpoolHash },
	{ ALGO_NONE,			NULL }
};

/* =========================================================================
 *                   Asymmetric key definition dispatch table
 * ========================================================================= */
const t_pkeyDispatch g_pkeyTable[] = {
	{ PKEY_TYPE_RSA,	&g_rsaPkeyDef },
	{ PKEY_TYPE_DSA,	&g_dsaPkeyDef },
	/* Add PKEY_TYPE_EC, PKEY_TYPE_ED25519, … here */
	{ PKEY_TYPE_UNDEFINED, NULL }
};

/* =========================================================================
 *                          Cipher dispatch table
 * ========================================================================= */
const t_cipherDispatch g_cipherTable[] = {
	{ ALGO_BASE64,	&g_base64Cipher },
	{ ALGO_BASE32,	&g_base32Cipher },

	/* DES family */
	{ ALGO_DES,			&g_desCipher },
	{ ALGO_DES_ECB,		&g_desEcbCipher },
	{ ALGO_DES_CBC,		&g_desCbcCipher },
	{ ALGO_DES_CFB,		&g_desCfbCipher },
	{ ALGO_DES_CFB1,		&g_desCfb1Cipher },
	{ ALGO_DES_CFB8,		&g_desCfb8Cipher },
	{ ALGO_DES_OFB,		&g_desOfbCipher },
	{ ALGO_DES_CTR,		&g_desCtrCipher },
	{ ALGO_DES_PCBC,		&g_desPcbcCipher },

	/* Triple DES family */
	{ ALGO_DES3,			&g_des3Cipher },
	{ ALGO_DES3_ECB,		&g_des3EcbCipher },
	{ ALGO_DES3_CBC,		&g_des3CbcCipher },
	{ ALGO_DES3_CFB,		&g_des3CfbCipher },
	{ ALGO_DES3_CFB1,	&g_des3Cfb1Cipher },
	{ ALGO_DES3_CFB8,	&g_des3Cfb8Cipher },
	{ ALGO_DES3_OFB,		&g_des3OfbCipher },
	{ ALGO_DES3_CTR,		&g_des3CtrCipher },
	{ ALGO_DES3_PCBC,	&g_des3PcbcCipher },

	/* AES-128 family */
	{ ALGO_AES_128,		&g_aes128Cipher },
	{ ALGO_AES_128_ECB,	&g_aes128EcbCipher },
	{ ALGO_AES_128_CBC,	&g_aes128CbcCipher },
	{ ALGO_AES_128_CFB,	&g_aes128CfbCipher },
	{ ALGO_AES_128_CFB1,	&g_aes128Cfb1Cipher },
	{ ALGO_AES_128_CFB8,	&g_aes128Cfb8Cipher },
	{ ALGO_AES_128_OFB,	&g_aes128OfbCipher },
	{ ALGO_AES_128_CTR,	&g_aes128CtrCipher },
	{ ALGO_AES_128_PCBC,	&g_aes128PcbcCipher },
	
	/* AES-192 family */
	{ ALGO_AES_192,		&g_aes192Cipher },
	{ ALGO_AES_192_ECB,	&g_aes192EcbCipher },
	{ ALGO_AES_192_CBC,	&g_aes192CbcCipher },
	{ ALGO_AES_192_CFB,	&g_aes192CfbCipher },
	{ ALGO_AES_192_CFB1,	&g_aes192Cfb1Cipher },
	{ ALGO_AES_192_CFB8,	&g_aes192Cfb8Cipher },
	{ ALGO_AES_192_OFB,	&g_aes192OfbCipher },
	{ ALGO_AES_192_CTR,	&g_aes192CtrCipher },
	{ ALGO_AES_192_PCBC,	&g_aes192PcbcCipher },
	
	/* AES-256 family */
	{ ALGO_AES_256,		&g_aes256Cipher },
	{ ALGO_AES_256_ECB,	&g_aes256EcbCipher },
	{ ALGO_AES_256_CBC,	&g_aes256CbcCipher },
	{ ALGO_AES_256_CFB,	&g_aes256CfbCipher },
	{ ALGO_AES_256_CFB1,	&g_aes256Cfb1Cipher },
	{ ALGO_AES_256_CFB8,	&g_aes256Cfb8Cipher },
	{ ALGO_AES_256_OFB,	&g_aes256OfbCipher },
	{ ALGO_AES_256_CTR,	&g_aes256CtrCipher },
	{ ALGO_AES_256_PCBC,	&g_aes256PcbcCipher },

	/* Blowfish family */
	{ ALGO_BLOWFISH,			&g_blowfishCipher },
	{ ALGO_BLOWFISH_ECB,		&g_blowfishEcbCipher },
	{ ALGO_BLOWFISH_CBC,		&g_blowfishCbcCipher },
	{ ALGO_BLOWFISH_CFB,		&g_blowfishCfbCipher },
	{ ALGO_BLOWFISH_CFB1,	&g_blowfishCfb1Cipher },
	{ ALGO_BLOWFISH_CFB8,	&g_blowfishCfb8Cipher },
	{ ALGO_BLOWFISH_OFB,		&g_blowfishOfbCipher },
	{ ALGO_BLOWFISH_CTR,		&g_blowfishCtrCipher },
	{ ALGO_BLOWFISH_PCBC,	&g_blowfishPcbcCipher },

	/* ChaCha20 stream cipher */
	{ ALGO_CHACHA20,			&g_chacha20Cipher },

	{ ALGO_NONE, NULL }
};

const char *getAlgoName(t_algo algo)
{
	const t_hash	*h;
	const t_cipher	*c;

	h = getHashByAlgo(algo);
	if (h)
		return (h->name);
	c = getCipherByAlgo(algo);
	if (c)
		return (c->name);
	return (NULL);
}

/* =========================================================================
 *                          Hash Lookup
 * ========================================================================= */

const t_hash *getHashByAlgo(t_algo algo)
{
	for (int i = 0; g_hashTable[i].hash != NULL; i++)
		if (g_hashTable[i].algo == algo)
			return (g_hashTable[i].hash);
	return (NULL);
}


const t_hash *getHashByName(const char *name)
{
	for (int i = 0; g_hashTable[i].hash != NULL; i++)
		if (ft_strcmp(g_hashTable[i].hash->name, name) == 0)
			return (g_hashTable[i].hash);
	return (NULL);
}

const t_hash *getHashByOid(const uint8_t *oid, size_t oidLen)
{
	for (int i = 0; g_hashTable[i].hash != NULL; i++)
	{
		const t_hash *h = g_hashTable[i].hash;
		if (h->oid.len == oidLen &&
			ft_memcmp(h->oid.data, oid, oidLen) == 0)
			return (h);
	}
	return (NULL);
}

/* =========================================================================
 *                          Cipher Lookup
 * ========================================================================= */

const t_cipher *getCipherByAlgo(t_algo algo)
{
	for (int i = 0; g_cipherTable[i].cipher != NULL; i++)
		if (g_cipherTable[i].algo == algo)
			return (g_cipherTable[i].cipher);
	return (NULL);
}

const t_cipher *getCipherByName(const char *name)
{
	for (int i = 0; g_cipherTable[i].cipher != NULL; i++)
		if (ft_strcmp(g_cipherTable[i].cipher->name, name) == 0)
			return (g_cipherTable[i].cipher);
	return (NULL);
}

const t_cipher *getCipherByOid(const uint8_t *oid, size_t oidLen)
{
	for (int i = 0; g_cipherTable[i].cipher != NULL; i++)
	{
		const t_cipher *c = g_cipherTable[i].cipher;
		if (c->oid.len == oidLen &&
			ft_memcmp(c->oid.data, oid, oidLen) == 0)
			return (c);
		if (c->oiwOid.len == oidLen &&
			ft_memcmp(c->oiwOid.data, oid, oidLen) == 0)
			return (c);
	}
	return (NULL);
}

/* =========================================================================
 *              Asymmetric key definition lookup (new)
 * ========================================================================= */

const t_pkeyDef *getPkeyDefByType(t_pkeyType type)
{
	for (int i = 0; g_pkeyTable[i].def != NULL; i++)
		if (g_pkeyTable[i].type == type)
			return (g_pkeyTable[i].def);
	return (NULL);
}

const t_pkeyDef *getPkeyDefByOid(const uint8_t *oid, size_t oidLen)
{
	for (int i = 0; g_pkeyTable[i].def != NULL; i++)
	{
		const t_pkeyDef *def = g_pkeyTable[i].def;
		if (def->oid.len == oidLen &&
			ft_memcmp(def->oid.data, oid, oidLen) == 0)
			return (def);
	}
	return (NULL);
}

const t_pkeyDef *getPkeyDefByName(const char *name)
{
	for (int i = 0; g_pkeyTable[i].def != NULL; i++)
		if (ft_strcmp(g_pkeyTable[i].def->name, name) == 0)
			return (g_pkeyTable[i].def);
	return (NULL);
}

const t_pkeyDef *getPkeyDefByLabel(const char *label, int isPrivate)
{
	for (int i = 0; g_pkeyTable[i].def != NULL; i++)
	{
		const t_pkeyDef *def = g_pkeyTable[i].def;
		if (isPrivate && def->tradPrivLabel &&
			ft_strcmp(def->tradPrivLabel, label) == 0)
			return (def);
		if (!isPrivate && def->tradPubLabel &&
			ft_strcmp(def->tradPubLabel, label) == 0)
			return (def);
	}
	return (NULL);
}
