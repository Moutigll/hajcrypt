#include "../../hajlib/include/hchar.h"

#include "../../includes/cipher/cipher.h"
#include "../../includes/cipher/base64.h"
#include "../../includes/consts/base64.h"

void base64Init(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_base64Ctx *ctx = vctx;
	
	/* Base64 doesn't use any key or IV */
	(void)key;
	(void)keyLen;
	(void)iv;
	
	ctx->buffer = 0;
	ctx->bits = 0;
	ctx->dir = dir;
	ctx->outCount = 0;
	ctx->error = 0;
}

void base64Update(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	t_base64Ctx	*ctx = vctx;
	size_t		i = 0;
	size_t		j = 0;
	
	if (ctx->error) {
		*outLen = 0;
		return;
	}
	
	if (ctx->dir == CIPHER_DECRYPT) {
		for (i = 0; i < inLen; i++) {
			uint8_t val;
			uint8_t c = in[i];

			if (ft_isspace(c))
				continue;

			if (c == '=')
				break;

			val = g_base64_dec[c];
			if (val == 0xFF) {
				ctx->error = 1;
				*outLen = 0;
				return;
			}

			/* Construct the buffer by shifting left and adding the new 6 bits */
			ctx->buffer = (ctx->buffer << 6) | val;
			ctx->bits += 6;

			/* Whenever we have 8 or more bits in the buffer, we can output a byte */
			while (ctx->bits >= 8) {
				ctx->bits -= 8;
				out[j++] = (ctx->buffer >> ctx->bits) & 0xFF;
			}
		}
	} else {
		for (i = 0; i < inLen; i++) {
			/* Shift the buffer left by 8 bits and add the new byte */
			ctx->buffer = (ctx->buffer << 8) | in[i];
			ctx->bits += 8;

			/* Whenever we have 6 or more bits in the buffer, we can output a Base64 character */
			while (ctx->bits >= 6) {
				ctx->bits -= 6;
				uint8_t index = (ctx->buffer >> ctx->bits) & 0x3F;
				out[j++] = g_base64_enc[index];
			}
		}
		ctx->outCount += j;
	}
	
	*outLen = j;
}

void base64Final(void *vctx, uint8_t *out, size_t *outLen)
{
	t_base64Ctx	*ctx = vctx;
	size_t		j = 0;

	if (ctx->error) {
		*outLen = 0;
		return;
	}
	
	if (ctx->dir == CIPHER_DECRYPT) {
		if (ctx->bits > 0 && (ctx->buffer & ((1 << ctx->bits) - 1)) != 0) {
			*outLen = 0;
			return;
		}
		*outLen = 0;
	} else {
		if (ctx->bits > 0) {
			ctx->buffer <<= (6 - ctx->bits);
			out[j++] = g_base64_enc[ctx->buffer & 0x3F];
			ctx->outCount++;
		}
		int pad = (4 - (ctx->outCount % 4)) % 4;
		for (int i = 0; i < pad; i++)
			out[j++] = '=';
		
		*outLen = j;
	}
}

void base64Free(void *vctx)
{
	(void)vctx;
}

void base64Pad(uint8_t *block, size_t len, size_t blockSize)
{
	(void)block;
	(void)len;
	(void)blockSize;
}

int base64Unpad(uint8_t *block, size_t *len, size_t blockSize)
{
	(void)block;
	(void)len;
	(void)blockSize;
	return 0;
}

const t_cipher g_base64Cipher = {
	.name = "base64",
	.mode = CIPHER_MODE_NONE,
	.isEncoder = 1,
	
	.blockSize = 1,
	.keySize = 0,
	.ivSize = 0,
	.ctxSize = sizeof(t_base64Ctx),
	
	.init = base64Init,
	.update = base64Update,
	.final = base64Final,
	.free = base64Free,
	
	.pad = base64Pad,
	.unpad = base64Unpad,
	
	.supportsWrap = 1
};
