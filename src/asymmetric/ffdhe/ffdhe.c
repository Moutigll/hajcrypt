
#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hstring.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/asymmetric/bigint.h"

#include "../../../includes/asymmetric/ffdhe.h"

int	ffdheInit(t_ffdheCtx *ctx, int groupId)
{
	const char	*pHex;
	const char	*gHex;
	size_t		hexLen;

	if (!ctx)
		return (0);
	ft_bzero(ctx, sizeof(t_ffdheCtx));

	if (!getGroupParams(groupId, &pHex, &gHex))
		return (0);

	hexLen = ft_strlen(pHex);
	ctx->p = bigIntFromHex(pHex, hexLen);
	ctx->g = bigIntFromHex(gHex, ft_strlen(gHex));
	if (!ctx->p || !ctx->g)
	{
		ffdheFree(ctx);
		return (0);
	}
	ctx->groupId = groupId;
	return (1);
}

int	ffdheGenerateKeypair(t_ffdheCtx *ctx)
{
	size_t	bits;

	if (!ctx || !ctx->p || !ctx->g)
		return (0);

	/* Private key size =  modulus size in bits, rounded up to bytes */
	bits = bigIntBitLength(ctx->p);

	ctx->priv = bigIntNew((bits + 63) / 64);
	if (!ctx->priv)
		return (0);
	bigIntRandom(ctx->priv, bits);

	bigIntSetBit(ctx->priv, bits - 1);

	/* pub = g^priv mod p */
	ctx->pub = bigIntNew(ctx->p->numWords);
	if (!ctx->pub || !bigIntModExp(ctx->pub, ctx->g, ctx->priv, ctx->p))
	{
		ffdheFree(ctx);
		return (0);
	}
	return (1);
}

int	ffdheGetPublicBytes(const t_ffdheCtx *ctx, uint8_t *out, size_t *outLen)
{
	size_t	need;
	size_t	written;

	if (!ctx || !ctx->pub || !outLen)
		return (0);

	need = (bigIntBitLength(ctx->pub) + 7) / 8;

	if (out == NULL)
	{
		*outLen = need;
		return (1);
	}

	if (*outLen < need)
		return (0);

	written = bigIntToBytes(ctx->pub, out, *outLen);
	if (written == 0)
		return (0);
	
	*outLen = written;
	return (1);
}

int	ffdheComputeShared(t_ffdheCtx		*ctx,
					   const uint8_t	*peerPub,	size_t	peerPubLen,
					   uint8_t			*shared,	size_t	*sharedLen)
{
	t_bigInt	*peer;
	size_t		need;

	if (!ctx || !ctx->priv || !ctx->p || !peerPub || !shared || !sharedLen)
		return (0);

	peer = bigIntFromBytes(peerPub, peerPubLen);
	if (!peer)
		return (0);

	if (!ctx->shared)
		ctx->shared = bigIntNew(ctx->p->numWords);
	if (!ctx->shared || !bigIntModExp(ctx->shared, peer, ctx->priv, ctx->p))
	{
		bigIntFree(peer);
		return (0);
	}
	bigIntFree(peer);

	need = (bigIntBitLength(ctx->shared) + 7) / 8;
	if (*sharedLen < need)
		return (0);
	*sharedLen = bigIntToBytes(ctx->shared, shared, *sharedLen);
	return (1);
}

void	ffdheFree(t_ffdheCtx *ctx)
{
	if (!ctx)
		return;
	bigIntFree(ctx->p);
	bigIntFree(ctx->g);
	bigIntFree(ctx->priv);
	bigIntFree(ctx->pub);
	bigIntFree(ctx->shared);
	secureZeroMemory(ctx, sizeof(t_ffdheCtx));
}
