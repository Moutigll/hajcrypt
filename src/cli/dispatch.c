#include "../../includes/cli/client.h"
#include "../../includes/hash/md5.h"

const t_hash g_md5Hash = {
	.init = md5Init,
	.update = md5Update,
	.final = md5Final,
	.ctxSize = sizeof(t_md5Ctx),
	.digestSize = 16
};

static const t_hashDispatch g_hashTable[] = {
	{ ALGO_MD5,    &g_md5Hash },
	{ ALGO_SHA256, NULL }, /* TODO: add SHA-256 implementation */
	{ ALGO_NONE,   NULL }
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
