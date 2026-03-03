#include "../../../includes/consts/sha256.h"
#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/hash/hash.h"

#include "../../../includes/hash/sha256.h"

void sha256Init(void *ctx)
{
	t_sha256Ctx *sha256 = (t_sha256Ctx *)ctx;

	sha256->state[0] = H0;
	sha256->state[1] = H1;
	sha256->state[2] = H2;
	sha256->state[3] = H3;
	sha256->state[4] = H4;
	sha256->state[5] = H5;
	sha256->state[6] = H6;
	sha256->state[7] = H7;

	sha256->totalLen = 0;
	sha256->bufferLen = 0;
	ft_bzero(sha256->buffer, 64);
}

void sha256Update(void *ctx, const uint8_t *data, size_t len)
{
	t_sha256Ctx *sha256;
	size_t i;
	size_t index;
	size_t partLen;

	if (!ctx || (!data && len > 0))
		return;

	sha256 = (t_sha256Ctx *)ctx;

	index = sha256->bufferLen; /* number of bytes already in buffer */


	sha256->totalLen += (uint64_t)len; /* total in bytes */

	partLen = 64 - index;
	i = 0;

	if (len >= partLen)
	{
		/* fill current buffer and transform it */
		ft_memcpy(&sha256->buffer[index], data, partLen);
#if defined(__aarch64__)
		sha256Transform_arm64(sha256->state, sha256->buffer);
#else
		sha256Transform(sha256->state, sha256->buffer);
#endif
		i = partLen;

		/* process complete blocks directly from data */
		while (i + 63 < len)
		{
#if defined(__aarch64__)
			sha256Transform_arm64(sha256->state, &data[i]);
#else
			sha256Transform(sha256->state, &data[i]);
#endif
			i += 64;
		}

		/* buffer is now empty */
		index = 0;
	}

	/* copy the remaining data (less than 64 bytes) into buffer */
	if (i < len)
	{
		size_t remain = len - i;
		ft_memcpy(&sha256->buffer[index], &data[i], remain);
		index += remain;
	}

	sha256->bufferLen = index;
}

void sha256Final(uint8_t *digest, void *ctx)
{
	t_sha256Ctx		*sha256 = (t_sha256Ctx *)ctx;
	uint8_t			padded[128];
	t_paddParams	params;
	size_t			paddedLen;
	size_t			offset;

	params.blockSize = 64;
	params.msgLen = sha256->totalLen;
	params.isLittleEndian = 0;
	params.lengthFieldSize = 8;

	paddedLen = padMessage(padded, sha256->buffer, 
					sha256->bufferLen, &params);

	for (offset = 0; offset < paddedLen; offset += 64)
	{
#if defined(__aarch64__)
		sha256Transform_arm64(sha256->state, padded + offset);
#else
		sha256Transform(sha256->state, padded + offset);
#endif
	}

	/* Output the final hash in big‑endian format */
	for (size_t i = 0; i < 8; i++)
	{
		digest[i * 4]	 = (sha256->state[i] >> 24) & 0xFF;
		digest[i * 4 + 1] = (sha256->state[i] >> 16) & 0xFF;
		digest[i * 4 + 2] = (sha256->state[i] >> 8) & 0xFF;
		digest[i * 4 + 3] = sha256->state[i] & 0xFF;
	}
}

const t_hash g_sha256Hash = {
	.name = "sha256",
	.init = sha256Init,
	.update = sha256Update,
	.final = sha256Final,
	.hmacInit = sha256HmacInit,
	.ctxSize = sizeof(t_sha256Ctx),
	.digestSize = 32
};
