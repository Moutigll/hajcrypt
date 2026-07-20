#include "../../hajlib/include/hstring.h"

#include "../../includes/cipher/base32.h"


/* Base32 alphabet as per RFC 4648 */
static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* Helper functions */
static int is_base32_char(char c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

static int get_base32_value(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a';
	if (c >= '2' && c <= '7') return c - '2' + 26;
	return -1;
}

/* Base32 context functions */
int base32Init(void *vctx, const uint8_t *key, size_t keyLen,
			   const uint8_t *iv, t_cipherDirection dir) {
	t_base32Ctx *ctx = (t_base32Ctx *)vctx;
	(void)key;
	(void)keyLen;
	(void)iv;
	
	if (!ctx) return -1;
	
	ctx->buffer = 0;
	ctx->bits = 0;
	ctx->dir = dir;
	ctx->outCount = 0;
	ctx->error = 0;
	
	return 0;
}

void base32Update(void *vctx, const uint8_t *in, size_t inLen,
				  uint8_t *out, size_t *outLen) {
	t_base32Ctx *ctx = (t_base32Ctx *)vctx;
	size_t outPos = 0;
	
	if (!ctx || !in || !out || !outLen) {
		if (outLen) *outLen = 0;
		return;
	}
	
	if (ctx->dir == CIPHER_ENCRYPT) {
		/* Encoding */
		for (size_t i = 0; i < inLen; i++) {
			ctx->buffer = (ctx->buffer << 8) | in[i];
			ctx->bits += 8;
			
			while (ctx->bits >= 5) {
				ctx->bits -= 5;
				uint8_t index = (ctx->buffer >> ctx->bits) & 0x1F;
				out[outPos++] = (uint8_t)BASE32_ALPHABET[index];
			}
		}
	} else {
		/* Decoding */
		for (size_t i = 0; i < inLen; i++) {
			char c = (char)in[i];
			if (c == '=') break;
			if (!is_base32_char(c)) {
				ctx->error = -1;
				break;
			}
			
			int val = get_base32_value(c);
			if (val < 0) {
				ctx->error = -1;
				break;
			}
			
			ctx->buffer = (ctx->buffer << 5) | val;
			ctx->bits += 5;
			
			if (ctx->bits >= 8) {
				ctx->bits -= 8;
				out[outPos++] = (ctx->buffer >> ctx->bits) & 0xFF;
			}
		}
	}
	
	*outLen = outPos;
	ctx->outCount += outPos;
}

void base32Final(void *vctx, uint8_t *out, size_t *outLen) {
	t_base32Ctx *ctx = (t_base32Ctx *)vctx;
	size_t outPos = 0;
	
	if (!ctx || !out || !outLen) {
		if (outLen) *outLen = 0;
		return;
	}
	
	if (ctx->dir == CIPHER_ENCRYPT) {
		/* Handle remaining bits for encoding */
		if (ctx->bits > 0) {
			uint8_t index = (ctx->buffer << (5 - ctx->bits)) & 0x1F;
			out[outPos++] = (uint8_t)BASE32_ALPHABET[index];
			ctx->bits = 0;
		}
		
		/* Add padding to make length multiple of 8 */
		while (outPos % 8 != 0) {
			out[outPos++] = '=';
		}
	} else {
		/* No final bits for decoding, they were already processed */
		/* Check for padding */
		if (ctx->bits > 0) {
			/* If there are leftover bits, they should be 0 */
			if ((ctx->buffer << (5 - ctx->bits)) & 0x1F) {
				ctx->error = -1;
			}
		}
	}
	
	*outLen = outPos;
	ctx->outCount += outPos;
}

void base32Free(void *vctx) {
	(void)vctx;
	/* Nothing to free for Base32 */
}

/* One-shot functions */
size_t base32EncodedLength(size_t inputLen) {
	return ((inputLen + 4) / 5) * 8;
}

size_t base32DecodedLength(const char *input) {
	size_t len = ft_strlen(input);
	
	/* Count padding characters */
	while (len > 0 && input[len - 1] == '=') {
		len--;
	}
	
	/* Each 8 characters encode 5 bytes */
	return (len * 5) / 8;
}

size_t base32Encode(const uint8_t *input, size_t inputLen, char *output, size_t outputSize) {
	t_base32Ctx ctx;
	size_t outLen1 = 0, outLen2 = 0;
	uint8_t *outBuffer = (uint8_t *)output;
	
	if (!input || !output || outputSize == 0) {
		return (size_t)-1;
	}
	
	/* Calculate required output size */
	size_t required = base32EncodedLength(inputLen) + 1; /* +1 for null terminator */
	if (outputSize < required) {
		return (size_t)-1;
	}
	
	/* Initialize context */
	if (base32Init(&ctx, NULL, 0, NULL, CIPHER_ENCRYPT) != 0) {
		return (size_t)-1;
	}
	
	/* Process input */
	base32Update(&ctx, input, inputLen, outBuffer, &outLen1);
	base32Final(&ctx, outBuffer + outLen1, &outLen2);
	
	size_t totalLen = outLen1 + outLen2;
	output[totalLen] = '\0';
	
	return totalLen;
}

size_t base32Decode(const char *input, uint8_t *output, size_t outputSize) {
	t_base32Ctx ctx;
	size_t outLen1 = 0, outLen2 = 0;
	
	if (!input || !output || outputSize == 0) {
		return (size_t)-1;
	}
	
	/* Calculate required output size */
	size_t required = base32DecodedLength(input);
	if (outputSize < required) {
		return (size_t)-1;
	}
	
	/* Initialize context */
	if (base32Init(&ctx, NULL, 0, NULL, CIPHER_DECRYPT) != 0) {
		return (size_t)-1;
	}
	
	/* Process input */
	base32Update(&ctx, (const uint8_t *)input, ft_strlen(input), output, &outLen1);
	base32Final(&ctx, output + outLen1, &outLen2);
	
	if (ctx.error != 0) {
		return (size_t)-1;
	}
	
	return outLen1 + outLen2;
}

const t_cipher g_base32Cipher = {
	.name		= "base32",
	.deprecated	= 0,
	.mode		= CIPHER_MODE_NONE,
	.isEncoder	= 1,
	
	.blockSize	= 1,
	.keySize	= 0,
	.ivSize		= 0,
	.ctxSize	= sizeof(t_base32Ctx),

	.init	= base32Init,
	.update	= base32Update,
	.final	= base32Final,
	.free	= base32Free,
	
	.pad	= NULL,
	.unpad	= NULL,
	
	.supportsWrap	= 1
};
