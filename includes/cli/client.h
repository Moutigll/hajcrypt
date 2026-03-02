#ifndef HAJCRYPT_CLI_CLIENT_H
#define HAJCRYPT_CLI_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "../hash/hmac.h"

typedef enum e_algo
{
	ALGO_NONE,
	ALGO_MD5,
	ALGO_SHA256,
	ALGO_WHIRLPOOL
}	t_algo;

typedef struct s_hash
{
	char	*name;
	void	(*init)(void *ctx);
	void	(*update)(void *ctx, const uint8_t *data, size_t len);
	void	(*final)(uint8_t *digest, void *ctx);
	void	(*hmacInit)(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);
	size_t	ctxSize;
	size_t	digestSize;
}	t_hash;

typedef struct s_hashDispatch
{
	t_algo			algo;
	const t_hash	*hash;
}	t_hashDispatch;

extern const	t_hashDispatch g_hashTable[];

const t_hash	*getHashByAlgo(t_algo algo);

#endif /* HAJCRYPT_CLI_CLIENT_H */
