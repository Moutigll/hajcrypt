#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/hash/hmac.h"
#include "../../../includes/hash/hash.h"

#include "../../../includes/hash/whirlpool.h"

#define WHIRLPOOL_OPT 1

void whirlpoolInit(void *ctx)
{
	t_whirlpoolCtx *wh = (t_whirlpoolCtx *)ctx;
	ft_bzero(wh->state, 64);
	ft_bzero(wh->buffer, 64);
	wh->bufferLen = 0;
	wh->totalLen = 0;
}

void whirlpoolUpdate(void *ctx, const uint8_t *data, size_t len)
{
	t_whirlpoolCtx *wh = (t_whirlpoolCtx *)ctx;
	size_t i = 0;
	size_t index = wh->bufferLen;

	if (!ctx || (!data && len > 0))
		return;

	wh->totalLen += (uint64_t)len * 8; // bits

	size_t partLen = 64 - index;

	if (len >= partLen)
	{
		ft_memcpy(&wh->buffer[index], data, partLen);
#ifdef WHIRLPOOL_OPT
		whirlpoolTransformOpt(wh->state, wh->buffer);
#else
		whirlpoolTransform(wh->state, wh->buffer);
#endif
		i = partLen;

		while (i + 63 < len)
		{
#ifdef WHIRLPOOL_OPT
			whirlpoolTransformOpt(wh->state, &data[i]);
#else
			whirlpoolTransform(wh->state, &data[i]);
#endif
			i += 64;
		}

		index = 0;
	}

	if (i < len)
	{
		size_t remain = len - i;
		ft_memcpy(&wh->buffer[index], &data[i], remain);
		index += remain;
	}

	wh->bufferLen = index;
}

void whirlpoolFinal(uint8_t *digest, void *ctx)
{
	t_whirlpoolCtx *wh = (t_whirlpoolCtx *)ctx;
	uint8_t padded[128];
	t_paddParams params;
	size_t paddedLen;
	size_t offset;
	size_t i, j;
	
	params.blockSize = 64;
	params.msgLen = wh->totalLen / 8;
	params.isLittleEndian = 0;
	params.lengthFieldSize = 32;
	
	paddedLen = padMessage(padded, wh->buffer, wh->bufferLen, &params);
	
	for (offset = 0; offset < paddedLen; offset += 64)
#ifdef WHIRLPOOL_OPT
		whirlpoolTransformOpt(wh->state, padded + offset);
#else
		whirlpoolTransform(wh->state, padded + offset);
#endif
	
	/* Copy final state to digest in big-endian order */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			digest[i*8 + j] = (wh->state[i] >> (56 - 8*j)) & 0xFF;
		}
	}
}

void whirlpoolHash(const uint8_t *data, size_t len, uint8_t *digest)
{
	t_whirlpoolCtx ctx;

	whirlpoolInit(&ctx);
	whirlpoolUpdate(&ctx, data, len);
	whirlpoolFinal(digest, &ctx);
}

const t_hash g_whirlpoolHash = {
	.name = "whirlpool",
	.oid = OID_DEF("whirlpool", WHIRLPOOL_OID),
	.ctxSize = sizeof(t_whirlpoolCtx),
	.digestSize = 64,
	.blockSize = 64,
	.deprecated = 0,
	.init = whirlpoolInit,
	.update = whirlpoolUpdate,
	.final = whirlpoolFinal,
	.hash = whirlpoolHash,
	.hmacInit = whirlpoolHmacInit
};
