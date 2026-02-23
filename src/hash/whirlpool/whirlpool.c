#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/hash/hash.h"

#include "../../../includes/hash/whirlpool.h"

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
		whirlpoolTransform(wh->state, wh->buffer);
		i = partLen;

		while (i + 63 < len)
		{
			whirlpoolTransform(wh->state, &data[i]);
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
	params.lenghtFieldSize = 32;
	
	paddedLen = padMessage(padded, wh->buffer, wh->bufferLen, &params);
	
	for (offset = 0; offset < paddedLen; offset += 64)
		whirlpoolTransform(wh->state, padded + offset);
	
	/* Copy final state to digest in big-endian order */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			digest[i*8 + j] = (wh->state[i] >> (56 - 8*j)) & 0xFF;
		}
	}
}
