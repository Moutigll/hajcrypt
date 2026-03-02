#include "../../hajlib/include/hchar.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/encoding/base64.h"
#include "../../includes/consts/base64.h"

void base64Init(void *vctx, int isDecoding)
{
	t_base64Ctx *ctx = vctx;
	ctx->buffer = 0;
	ctx->bits = 0;
	ctx->isDecoding = isDecoding;
	ctx->outCount = 0;
	ctx->error = 0;
}

int	base64Update(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	t_base64Ctx *ctx = vctx;
	size_t i = 0;
	size_t j = 0;
	
	if (ctx->error) {
		*outLen = 0;
		return (-1);
	}
	
	if (ctx->isDecoding) {
		for (i = 0; i < inLen; i++) {
			uint8_t c = in[i];
			
			/* Skip whitespace */
			if (ft_isspace(c))
				continue;
			
			/* Handle padding */
			if (c == '=') {
				/* On a vu du padding, on s'arrête */
				break;
			}
			
			uint8_t val = g_base64_dec[c];
			if (val == 0xFF) {
				ctx->error = 1;
				*outLen = 0;
				return (-1); /* Invalid character */
			}
			
			ctx->buffer = (ctx->buffer << 6) | val;
			ctx->bits += 6;
			
			while (ctx->bits >= 8) {
				ctx->bits -= 8;
				out[j++] = (ctx->buffer >> ctx->bits) & 0xFF;
			}
		}
	} else {
		/* Encoding mode (inchangé) */
		for (i = 0; i < inLen; i++) {
			ctx->buffer = (ctx->buffer << 8) | in[i];
			ctx->bits += 8;
			
			while (ctx->bits >= 6) {
				ctx->bits -= 6;
				uint8_t index = (ctx->buffer >> ctx->bits) & 0x3F;
				out[j++] = g_base64_enc[index];
			}
		}
		ctx->outCount += j;
	}
	
	*outLen = j;
	return (0);
}

void base64Final(void *vctx, uint8_t *out, size_t *outLen)
{
	t_base64Ctx *ctx = vctx;
	size_t j = 0;
	
	if (ctx->isDecoding) {
		/* Check that any remaining bits are zero (valid padding) */
		if (ctx->bits > 0 && (ctx->buffer & ((1 << ctx->bits) - 1)) != 0) {
			*outLen = 0;			   /* Invalid padding */
			return;
		}
		*outLen = 0;				   /* No more output bytes */
	} else {
		/* Flush remaining bits */
		if (ctx->bits > 0) {
			/* Pad with zeros to make a full 6-bit chunk */
			ctx->buffer <<= (6 - ctx->bits);
			out[j++] = g_base64_enc[ctx->buffer & 0x3F];
			ctx->outCount++;			/* Count this last character */
		}
		
		/* Add padding characters to reach a multiple of 4 */
		int pad = (4 - (ctx->outCount % 4)) % 4;
		for (int i = 0; i < pad; i++)
			out[j++] = '=';
		
		*outLen = j;
	}
}



size_t base64Encode(const uint8_t *in, size_t inLen, char *out)
{
	t_base64Ctx	ctx;
	uint8_t		temp[8192];
	size_t		total = 0;
	size_t		chunk;
	size_t		processed = 0;
	
	base64Init(&ctx, 0);
	
	while (processed < inLen) {
		chunk = (inLen - processed > 3072) ? 3072 : inLen - processed;
		base64Update(&ctx, in + processed, chunk, temp, &chunk);
		
		ft_memcpy(out + total, temp, chunk);
		total += chunk;
		processed += (inLen - processed > 3072) ? 3072 : inLen - processed;
	}
	
	base64Final(&ctx, temp, &chunk);
	ft_memcpy(out + total, temp, chunk);
	total += chunk;
	out[total] = '\0';
	
	return (total);
}

size_t	base64Decode(const char *in, size_t inLen, uint8_t *out)
{
	t_base64Ctx	ctx;
	uint8_t		temp[8192];
	size_t		total = 0;
	size_t		chunk;
	size_t		processed = 0;
	
	base64Init(&ctx, 1);
	
	while (processed < inLen) {
		chunk = (inLen - processed > 4096) ? 4096 : inLen - processed;
		base64Update(&ctx, (const uint8_t*)in + processed, chunk, temp, &chunk);
		
		ft_memcpy(out + total, temp, chunk);
		total += chunk;
		processed += (inLen - processed > 4096) ? 4096 : inLen - processed;
	}
	
	base64Final(&ctx, temp, &chunk);
	ft_memcpy(out + total, temp, chunk);
	total += chunk;
	
	return (total);
}
