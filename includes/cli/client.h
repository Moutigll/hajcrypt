#ifndef HAJCRYPT_CLI_CLIENT_H
#define HAJCRYPT_CLI_CLIENT_H

#include <stddef.h>
#include <stdint.h>

typedef enum e_algo
{
	ALGO_NONE,
	ALGO_MD5,
	ALGO_SHA256
}	t_algo;

typedef struct s_hash
{
	void	(*init)(void *ctx);
	void	(*update)(void *ctx, const uint8_t *data, size_t len);
	void	(*final)(uint8_t *digest, void *ctx);
	size_t	ctxSize;
	size_t	digestSize;
}	t_hash;

typedef struct s_hashDispatch
{
	t_algo			algo;
	const t_hash	*hash;
}	t_hashDispatch;

const t_hash *getHashByAlgo(t_algo algo);

#endif /* HAJCRYPT_CLI_CLIENT_H */
