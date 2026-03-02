#include "../../includes/cli/client.h"
#include "../../includes/hash/hmac.h"

#include "../../includes/hash/md5.h"
#include "../../includes/hash/sha256.h"
#include "../../includes/hash/whirlpool.h"

const t_hash g_md5Hash = {
	.name = "md5",
	.init = md5Init,
	.update = md5Update,
	.final = md5Final,
	.hmacInit = md5HmacInit,
	.ctxSize = sizeof(t_md5Ctx),
	.digestSize = 16
};

const t_hash g_sha256Hash = {
	.name = "sha256",
	.init = sha256Init,
	.update = sha256Update,
	.final = sha256Final,
	.hmacInit = sha256HmacInit,
	.ctxSize = sizeof(t_sha256Ctx),
	.digestSize = 32
};

const t_hash g_whirlpoolHash = {
	.name = "whirlpool",
	.init = whirlpoolInit,
	.update = whirlpoolUpdate,
	.final = whirlpoolFinal,
	.hmacInit = whirlpoolHmacInit,
	.ctxSize = sizeof(t_whirlpoolCtx),
	.digestSize = 64
};

const t_hashDispatch g_hashTable[] = {
	{ ALGO_MD5,		&g_md5Hash },
	{ ALGO_SHA256,	&g_sha256Hash },
	{ ALGO_WHIRLPOOL,	&g_whirlpoolHash },
	{ ALGO_NONE,		NULL }
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
