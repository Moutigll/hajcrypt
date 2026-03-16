#include "../../includes/cli/client.h"

#include "../../includes/hash/md5.h"
#include "../../includes/hash/sha256.h"
#include "../../includes/hash/whirlpool.h"
#include "../../includes/hash/blake2b.h"

#include "../../includes/cipher/base64.h"
#include "../../includes/cipher/des.h"
#include "../../includes/cipher/aes.h"

const t_hashDispatch g_hashTable[] = {
	{ ALGO_MD5,		&g_md5Hash },
	{ ALGO_SHA256,	&g_sha256Hash },
	{ ALGO_WHIRLPOOL,	&g_whirlpoolHash },
	{ ALGO_BLAKE2B,	&g_blake2bHash },
	{ ALGO_NONE,		NULL }
};

const t_cipherDispatch g_cipherTable[] = {
	/* Base64 */
	{ ALGO_BASE64,	&g_base64Cipher },
	
	/* DES family */
	{ ALGO_DES,		&g_desCipher },
	{ ALGO_DES_ECB,	&g_desEcbCipher },
	{ ALGO_DES_CBC,	&g_desCbcCipher },
	
	/* AES-128 family */
	{ ALGO_AES_128,		&g_aes128Cipher },
	{ ALGO_AES_128_ECB,	&g_aes128EcbCipher },
	{ ALGO_AES_128_CBC,	&g_aes128CbcCipher },
	
	/* AES-192 family */
	{ ALGO_AES_192,		&g_aes192Cipher },
	{ ALGO_AES_192_ECB,	&g_aes192EcbCipher },
	{ ALGO_AES_192_CBC,	&g_aes192CbcCipher },
	
	/* AES-256 family */
	{ ALGO_AES_256,		&g_aes256Cipher },
	{ ALGO_AES_256_ECB,	&g_aes256EcbCipher },
	{ ALGO_AES_256_CBC,	&g_aes256CbcCipher },
	
	{ ALGO_NONE, NULL }
};

const t_hash *getHashByAlgo(t_algo algo)
{
	int i;

	i = 0;
	while (g_hashTable[i].hash)
	{
		if (g_hashTable[i].algo == algo)
			return (g_hashTable[i].hash);
		i++;
	}
	return (NULL);
}

const t_cipher *getCipherByAlgo(t_algo algo)
{
	int i;

	i = 0;
	while (g_cipherTable[i].cipher)
	{
		if (g_cipherTable[i].algo == algo)
			return (g_cipherTable[i].cipher);
		i++;
	}
	return (NULL);
}
