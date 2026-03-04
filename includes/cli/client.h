#ifndef HAJCRYPT_CLI_CLIENT_H
#define HAJCRYPT_CLI_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "../hash/hmac.h"
#include "../hash/hash.h"
#include "../cipher/cipher.h"

typedef enum e_algo
{
	ALGO_NONE,
	ALGO_MD5,
	ALGO_SHA256,
	ALGO_WHIRLPOOL,
	ALGO_BASE64,
	ALGO_DES_ECB,
	ALGO_DES_CBC
}	t_algo;

typedef struct s_hashDispatch
{
	t_algo			algo;
	const t_hash	*hash;
}	t_hashDispatch;

typedef struct s_cipherDispatch
{
	t_algo			algo;
	const t_cipher	*cipher;
}	t_cipherDispatch;
extern const	t_hashDispatch g_hashTable[];
extern const	t_cipherDispatch g_cipherTable[];

const t_hash	*getHashByAlgo(t_algo algo);
const t_cipher	*getCipherByAlgo(t_algo algo);

#endif /* HAJCRYPT_CLI_CLIENT_H */
