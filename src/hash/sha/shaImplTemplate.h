#include "../../../includes/hajcrypt.h"
#include "../../../includes/hash/hash.h"
#include "../../../includes/utils/bitopts.h"

#if !defined(SHA_NAME) || !defined(SHA_CTX) || !defined(SHA_OID) || \
	!defined(SHA_DEPRECATED) || !defined(SHA_DIGEST_SIZE) || \
	!defined(SHA_BLOCK_SIZE) || !defined(SHA_STATE_WORDS) || \
	!defined(SHA_WORD) || !defined(SHA_TRANSFORM) || \
	!defined(SHA_USE_ARM64) || !defined(SHA_STORE_BE) || \
	!defined(SHA_PAD_PARAMS)
# error "One or more required SHA macros are not defined"
#endif

#if SHA_STATE_WORDS == 5 && !defined(SHA_H4)
# error "SHA_H4 must be defined for SHA algorithms with 5 state words"
#endif
#if SHA_STATE_WORDS == 6 && !defined(SHA_H5)
# error "SHA_H5 must be defined for SHA algorithms with 6 state words"
#endif
#if SHA_STATE_WORDS == 7 && !defined(SHA_H6)
# error "SHA_H6 must be defined for SHA algorithms with 7 state words"
#endif
#if SHA_STATE_WORDS == 8 && !defined(SHA_H7)
# error "SHA_H7 must be defined for SHA algorithms with 8 state words"
#endif



#if defined(__aarch64__) && SHA_USE_ARM64
	#define SHA_SELECT_TRANSFORM(state, block) \
		SHA_TRANSFORM_ARM64(state, block)
#else
	#define SHA_SELECT_TRANSFORM(state, block) \
		SHA_TRANSFORM(state, block)
#endif



void HC_CONCAT(SHA_NAME, Init)(void *ctx)
{
	SHA_CTX *sctx = (SHA_CTX *)ctx;

	sctx->state[0] = SHA_H0;
	sctx->state[1] = SHA_H1;
	sctx->state[2] = SHA_H2;
	sctx->state[3] = SHA_H3;
#if SHA_STATE_WORDS >= 5
	sctx->state[4] = SHA_H4;
#endif
#if SHA_STATE_WORDS >= 6
	sctx->state[5] = SHA_H5;
#endif
#if SHA_STATE_WORDS >= 7
	sctx->state[6] = SHA_H6;
#endif
#if SHA_STATE_WORDS >= 8
	sctx->state[7] = SHA_H7;
#endif

	sctx->totalLen = 0;
	sctx->bufferLen = 0;
	ft_bzero(sctx->buffer, SHA_BLOCK_SIZE);
}



void HC_CONCAT(SHA_NAME, Update)(void *ctx, const uint8_t *data, size_t len)
{
	SHA_CTX	*sctx;
	size_t	i;
	size_t	index;
	size_t	partLen;

	if (!ctx || (!data && len > 0))
		return;

	sctx = (SHA_CTX *)ctx;

	index = sctx->bufferLen;
	sctx->totalLen += (uint64_t)len;

	partLen = SHA_BLOCK_SIZE - index;
	i = 0;

	if (len >= partLen)
	{
		ft_memcpy(&sctx->buffer[index], data, partLen);
		SHA_SELECT_TRANSFORM(sctx->state, sctx->buffer);
		i = partLen;

		while (i + (SHA_BLOCK_SIZE - 1) < len)
		{
			SHA_SELECT_TRANSFORM(sctx->state, &data[i]);
			i += SHA_BLOCK_SIZE;
		}
		index = 0;
	}

	if (i < len)
	{
		size_t remain = len - i;
		ft_memcpy(&sctx->buffer[index], &data[i], remain);
		index += remain;
	}
	sctx->bufferLen = index;
}



void HC_CONCAT(SHA_NAME, Final)(uint8_t *digest, void *ctx)
{
	SHA_CTX		*sctx = (SHA_CTX *)ctx;
	uint8_t		padded[SHA_BLOCK_SIZE * 2];
	size_t		paddedLen;
	size_t		offset;

	t_paddParams   params = SHA_PAD_PARAMS;

	params.msgLen = sctx->totalLen;
	paddedLen = padMessage(padded, sctx->buffer, sctx->bufferLen, &params);

	for (offset = 0; offset < paddedLen; offset += SHA_BLOCK_SIZE)
	{
		SHA_SELECT_TRANSFORM(sctx->state, padded + offset);
	}

	size_t wordsToWrite = SHA_DIGEST_SIZE / sizeof(SHA_WORD);
	size_t bytesRemain = SHA_DIGEST_SIZE % sizeof(SHA_WORD);
	for (size_t i = 0; i < wordsToWrite; i++)
	{
		SHA_STORE_BE(digest + i * sizeof(SHA_WORD), sctx->state[i]);
	}
	if (bytesRemain > 0)
	{
		uint8_t tmp[sizeof(SHA_WORD)];
		SHA_STORE_BE(tmp, sctx->state[wordsToWrite]);
		ft_memcpy(digest + wordsToWrite * sizeof(SHA_WORD), tmp, bytesRemain);
	}
}



void HC_CONCAT(SHA_NAME, Hash)(const uint8_t *data, size_t len, uint8_t *digest)
{
	SHA_CTX ctx;
	HC_CONCAT(SHA_NAME, Init)(&ctx);
	HC_CONCAT(SHA_NAME, Update)(&ctx, data, len);
	HC_CONCAT(SHA_NAME, Final)(digest, &ctx);
}


const t_hash HC_CONCAT3(g_, SHA_NAME, Hash) = {
	.name = HC_STRINGIFY(SHA_NAME),
	.oid = OID_DEF(HC_STRINGIFY(SHA_NAME), SHA_OID),
	.ctxSize = sizeof(SHA_CTX),
	.digestSize = SHA_DIGEST_SIZE,
	.blockSize = SHA_BLOCK_SIZE,
	.deprecated = SHA_DEPRECATED,
	.init = HC_CONCAT(SHA_NAME, Init),
	.update = HC_CONCAT(SHA_NAME, Update),
	.final = HC_CONCAT(SHA_NAME, Final),
	.hash = HC_CONCAT(SHA_NAME, Hash),
	.hmacInit = HC_CONCAT(SHA_NAME, HmacInit)
};
