#include "../../../includes/cipher/des.h"

void desEcbInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_desEcbCtx	*ctx = vctx;
	uint64_t	k = 0;
	int			i;

	(void)iv;	/* ECB does not use an IV */

	/* Convert the key (max 8 bytes) */
	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, ctx->subkeys);
	ctx->bufferLen = 0;
	ctx->dir = dir;
}

void desEcbUpdate(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	t_desEcbCtx	*ctx = vctx;
	*outLen = 0;

	for (size_t i = 0; i < inLen; i += 8) {
        uint64_t block = 0;
        for (int j = 0; j < 8; j++)
            block = (block << 8) | in[i + j];
        
        if (ctx->dir == CIPHER_ENCRYPT)
            block = desEncryptBlock(block, ctx->subkeys);
        else
            block = desDecryptBlock(block, ctx->subkeys);
        
        for (int j = 0; j < 8; j++)
            out[(*outLen)++] = (block >> (56 - j * 8)) & 0xFF;
    }
}

void desEcbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
    (void)vctx;
	(void)out;
    *outLen = 0;
}

void desEcbFree(void *vctx)
{
	(void)vctx;
}

const t_cipher g_desEcbCipher = {
	.name = "des-ecb",
	.mode = CIPHER_MODE_ECB,
	.isEncoder = 1,

	.blockSize = 8,
	.keySize = 8,
	.ivSize = 0,
	.ctxSize = sizeof(t_desEcbCtx),

	.init = desEcbInit,
	.update = desEcbUpdate,
	.final = desEcbFinal,
	.free = desEcbFree,

	.pad = desPad,
	.unpad = desUnpad,

	.supportsWrap = 0
};
