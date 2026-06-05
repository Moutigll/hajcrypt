#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/asymmetric/ffdhe.h"
#include "../../includes/asymmetric/ecdh.h"

#include "../../includes/asymmetric/kex.h"

int	kexInit(t_kexCtx *ctx, t_kexType type, int group_id)
{
	if (!ctx) return (0);
	ft_bzero(ctx, sizeof(t_kexCtx));
	ctx->type = type;
	switch (type) {
	case KEX_TYPE_FFDHE:
		ctx->internal = ft_calloc(1, sizeof(t_ffdheCtx));
		if (!ctx->internal) return (0);
		return ffdheInit((t_ffdheCtx*)ctx->internal, group_id);
	case KEX_TYPE_ECDH:
		ctx->internal = ft_calloc(1, sizeof(t_ecdhCtx));
		if (!ctx->internal) return (0);
		return ecdhInit((t_ecdhCtx*)ctx->internal, group_id);
	default:
		return (0);
	}
}

int	kexGenerateKeypair(t_kexCtx *ctx)
{
	if (!ctx || !ctx->internal) return (0);
	switch (ctx->type) {
	case KEX_TYPE_FFDHE:
		return ffdheGenerateKeypair((t_ffdheCtx*)ctx->internal);
	case KEX_TYPE_ECDH:
		return ecdhGenerateKeypair((t_ecdhCtx*)ctx->internal);
	default:
		return (0);
	}
}

int	kexGetPublicBytes(const t_kexCtx *ctx, uint8_t *out, size_t *out_len)
{
	if (!ctx || !ctx->internal) return (0);
	switch (ctx->type) {
	case KEX_TYPE_FFDHE:
		return ffdheGetPublicBytes((t_ffdheCtx*)ctx->internal, out, out_len);
	case KEX_TYPE_ECDH:
		return ecdhGetPublicBytes((t_ecdhCtx*)ctx->internal, out, out_len);
	default:
		return (0);
	}
}

int	kexComputeShared(t_kexCtx		*ctx,
					 const uint8_t	*peer_pub,		size_t	peer_pub_len,
					 uint8_t		*shared_secret,	size_t	*shared_len)
{
	if (!ctx || !ctx->internal) return (0);
	switch (ctx->type) {
	case KEX_TYPE_FFDHE:
		return ffdheComputeShared((t_ffdheCtx*)ctx->internal,
								  peer_pub, peer_pub_len,
								  shared_secret, shared_len);
	case KEX_TYPE_ECDH:
		return ecdhComputeShared((t_ecdhCtx*)ctx->internal,
								 peer_pub, peer_pub_len,
								 shared_secret, shared_len);
	default:
		return (0);
	}
}

void	kexFree(t_kexCtx *ctx)
{
	if (!ctx || !ctx->internal) return;
	switch (ctx->type) {
	case KEX_TYPE_FFDHE:
		ffdheFree((t_ffdheCtx*)ctx->internal);
		break;
	case KEX_TYPE_ECDH:
		ecdhFree((t_ecdhCtx*)ctx->internal);
		break;
	default:
		break;
	}
	free(ctx->internal);
	ft_memset(ctx, 0, sizeof(t_kexCtx));
}
