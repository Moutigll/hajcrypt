#include "../../includes/cli/client.h"

#include "../../includes/hash/md5.h"
#include "../../includes/hash/sha256.h"
#include "../../includes/hash/whirlpool.h"
#include "../../includes/hash/blake2b.h"

#include "../../includes/cipher/base64.h"
#include "../../includes/cipher/des.h"

const t_hashDispatch g_hashTable[] = {
	{ ALGO_MD5,		&g_md5Hash },
	{ ALGO_SHA256,	&g_sha256Hash },
	{ ALGO_WHIRLPOOL,	&g_whirlpoolHash },
	{ ALGO_BLAKE2B,	&g_blake2bHash },
	{ ALGO_NONE,		NULL }
};

const t_cipherDispatch g_cipherTable[] = {
	{ ALGO_BASE64,	&g_base64Cipher },
	{ ALGO_DES,		&g_desCipher }, /* Default to CBC for DES */
	{ ALGO_DES_ECB,	&g_desEcbCipher },
	{ ALGO_DES_CBC,	&g_desCbcCipher },
	{ ALGO_NONE,	NULL }
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
