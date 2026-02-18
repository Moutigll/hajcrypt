#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/consts/md5.h"
#include "../../../includes/hash/hash.h"

#include "../../../includes/hash/md5.h"
#include <stdlib.h>

void md5Init(void *ctx)
{
	t_md5Ctx *md5 = (t_md5Ctx *)ctx;

	md5->state[0] = MD5_INIT_A;
	md5->state[1] = MD5_INIT_B;
	md5->state[2] = MD5_INIT_C;
	md5->state[3] = MD5_INIT_D;

	md5->bitlen = 0;
	ft_bzero(md5->buffer, 64);
}

void	md5Update(void *ctx, const uint8_t *data, size_t len)
{
	t_md5Ctx	*md5;
	size_t		i;
	size_t		index;
	size_t		partLen;

	md5 = (t_md5Ctx *)ctx;

	index = (md5->bitlen / 8) % 64;
	md5->bitlen += len * 8;

	partLen = 64 - index;
	i = 0;

	if (len >= partLen) /* Check if we have enough input to fill the current 64-byte buffer */
	{
		ft_memcpy(&md5->buffer[index], data, partLen);

		md5Transform(md5->state, md5->buffer);

		i = partLen;
		// Process as many full 64-byte blocks as possible directly from input data
		while (i + 63 < len)
		{
			md5Transform(md5->state, &data[i]);
			i += 64; // Move to the next 64-byte chunk
		}

		// Reset index since the buffer is now empty for remaining bytes
		index = 0;
	}

	ft_memcpy(&md5->buffer[index], &data[i], len - i);
}



void md5Final(uint8_t *digest, void *ctx)
{
	t_md5Ctx	*md5 = (t_md5Ctx *)ctx;
	size_t		paddedLen;
	uint8_t		*padded;
	size_t		offset;
	t_paddParams	params;

	/* Setup padding parameters */
	params.blockSize		= 64;
	params.msgLen			= md5->bitlen / 8;
	params.isLittleEndian	= 1;

	/* Pad remaining message */
	padded = padMessage(md5->buffer, (md5->bitlen / 8) % 64, &params, &paddedLen);
	if (!padded)
		return;	// malloc failed

	/* Process each padded block */
	for (offset = 0; offset < paddedLen; offset += 64)
		md5Transform(md5->state, padded + offset);

	free(padded);

	/* Output digest in little-endian */
	for (size_t i = 0; i < 4; i++)
	{
		digest[i * 4 + 0] = (md5->state[i] >> 0) & 0xFF;
		digest[i * 4 + 1] = (md5->state[i] >> 8) & 0xFF;
		digest[i * 4 + 2] = (md5->state[i] >> 16) & 0xFF;
		digest[i * 4 + 3] = (md5->state[i] >> 24) & 0xFF;
	}
}
