#include "../../hajlib/include/hchar.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/encode/base64.h"
#include "../../includes/consts/base64.h"

void base64Init(void *vctx, int isDecoding)
{
	t_base64Ctx *ctx = vctx;
	ctx->buffer = 0;
	ctx->bits = 0;
	ctx->isDecoding = isDecoding;
	ctx->lineLen = 0;
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
	
	if (ctx->isDecoding) {
		for (i = 0; i < inLen; i++) {
			uint8_t c = in[i];
			
			/* Skip whitespace */
			if (ft_isspace(c))
				continue;
			
			/* Handle padding */
			if (c == '=')
				/* Padding means we're done */
				break;
			
			uint8_t val = g_base64_dec[c];
			if (val == 0xFF)
				/* Invalid character */
				continue;
			
			/* Build 24-bit buffer from 6-bit chunks */
			ctx->buffer = (ctx->buffer << 6) | val;
			ctx->bits += 6;
			
			/* Extract 8-bit bytes */
			while (ctx->bits >= 8) {
				ctx->bits -= 8;
				out[j++] = (ctx->buffer >> ctx->bits) & 0xFF;
			}
		}
	} else {
		/* ENCODE MODE */
		for (i = 0; i < inLen; i++) {
			/* Build 24-bit buffer from 8-bit bytes */
			ctx->buffer = (ctx->buffer << 8) | in[i];
			ctx->bits += 8;
			
			/* Extract 6-bit chunks */
			while (ctx->bits >= 6) {
				ctx->bits -= 6;
				uint8_t index = (ctx->buffer >> ctx->bits) & 0x3F;
				out[j++] = g_base64_enc[index];
			}
		}
	}
	
	*outLen = j;
}

void base64Final(void *vctx, uint8_t *out, size_t *outLen)
{
	t_base64Ctx *ctx = vctx;
	size_t j = 0;
	
	if (ctx->isDecoding) {
		/* DECODE: Check for remaining bits (should be 0) */
		if (ctx->bits > 0 && (ctx->buffer & ((1 << ctx->bits) - 1)) != 0) {
			/* Invalid padding */
			*outLen = 0;
			return;
		}
		*outLen = 0;
	} else {
		/* ENCODE: Flush remaining bits with padding */
		if (ctx->bits > 0) {
			/* Pad with zeros to make a full 6-bit chunk */
			ctx->buffer <<= (6 - ctx->bits);
			out[j++] = g_base64_enc[ctx->buffer & 0x3F];
			
			/* Add padding characters to reach multiple of 4 */
			while ((ctx->bits + j * 6) % 24 != 0) {
				out[j++] = '=';
			}
		}
		*outLen = j;
	}
}

/* -------------------------------------------------------------------------- */
/*						   Single-shot functions							*/
/* -------------------------------------------------------------------------- */

size_t base64Encode(const uint8_t *in, size_t inLen, char *out)
{
	t_base64Ctx ctx;
	uint8_t temp[8192];
	size_t total = 0;
	size_t chunk;
	size_t processed = 0;
	
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

size_t base64Decode(const char *in, size_t inLen, uint8_t *out)
{
	t_base64Ctx ctx;
	uint8_t temp[8192];
	size_t total = 0;
	size_t chunk;
	size_t processed = 0;
	
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
