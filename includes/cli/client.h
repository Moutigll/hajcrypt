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
	ALGO_WHIRLPOOL,
	ALGO_BASE64
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

typedef struct s_encode
{
	char	*name;

	void (*init)(void *ctx, int isDecoding);
	int	 (*update)(void			*ctx,
				   const uint8_t	*in,
				   size_t		inLen,
				   uint8_t		*out,
				   size_t		*outLen);
	void (*final)(void *ctx, uint8_t *out, size_t *outLen);

	size_t	ctxSize;
	int		supportsWrap;
} t_encode;

typedef struct s_hashDispatch
{
	t_algo			algo;
	const t_hash	*hash;
}	t_hashDispatch;

typedef struct s_encodeDispatch
{
	t_algo			algo;
	const t_encode	*encode;
}	t_encodeDispatch;

extern const	t_hashDispatch g_hashTable[];
extern const	t_encodeDispatch g_encodeTable[];

const t_hash	*getHashByAlgo(t_algo algo);
const t_encode	*getEncodeByAlgo(t_algo algo);

#endif /* HAJCRYPT_CLI_CLIENT_H */
