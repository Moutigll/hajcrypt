#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hstring.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/utils/random.h"

#include "../../../includes/asymmetric/ecdh.h"

static const char *SECP256R1_P_HEX =
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
static const char *SECP256R1_A_HEX =
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
static const char *SECP256R1_B_HEX =
	"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
static const char *SECP256R1_N_HEX =
	"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
static const char *SECP256R1_GX_HEX =
	"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
static const char *SECP256R1_GY_HEX =
	"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

static const char *SECP384R1_P_HEX =
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF";
static const char *SECP384R1_A_HEX =
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC";
static const char *SECP384R1_B_HEX =
	"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF";
static const char *SECP384R1_N_HEX =
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973";
static const char *SECP384R1_GX_HEX =
	"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7";
static const char *SECP384R1_GY_HEX =
	"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F";

static const char *SECP521R1_P_HEX =
	"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
static const char *SECP521R1_A_HEX =
	"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC";
static const char *SECP521R1_B_HEX =
	"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
static const char *SECP521R1_N_HEX =
	"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";
static const char *SECP521R1_GX_HEX =
	"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66";
static const char *SECP521R1_GY_HEX =
	"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";

static const char *FRP256V1_P_HEX =
	"F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03";
static const char *FRP256V1_A_HEX =
	"F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00";
static const char *FRP256V1_B_HEX =
	"EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F";
static const char *FRP256V1_N_HEX =
	"F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1";
static const char *FRP256V1_GX_HEX =
	"B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF";
static const char *FRP256V1_GY_HEX =
	"6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB";

static t_weierstrassParams	g_weier[32];
static int					g_weierInitialized = 0;



static void reverseBytes(uint8_t *dest, const uint8_t *src, size_t len) {
	for (size_t i = 0; i < len; i++)
		dest[i] = src[len - 1 - i];
}

static int initWeierstrassCurve(int			curveId,
								const char	*pHex,		const char	*aHex,	const char	*bHex,
								const char	*nHex,		const char	*gxHex,	const char	*gyHex,
								size_t		keySize,	size_t		pubSize)
{
	t_weierstrassParams *c = &g_weier[curveId];
	c->p	= bigIntFromHex(pHex,	ft_strlen(pHex));
	c->a	= bigIntFromHex(aHex,	ft_strlen(aHex));
	c->b	= bigIntFromHex(bHex,	ft_strlen(bHex));
	c->n	= bigIntFromHex(nHex,	ft_strlen(nHex));
	c->G.x	= bigIntFromHex(gxHex,	ft_strlen(gxHex));
	c->G.y	= bigIntFromHex(gyHex,	ft_strlen(gyHex));
	c->keySize = keySize;
	c->pubSize = pubSize;
	return (c->p && c->a && c->b && c->n && c->G.x && c->G.y);
}

static void initAllWeierstrass(void)
{
	if (g_weierInitialized) return;
	initWeierstrassCurve(ECDH_GROUP_SECP256R1,
		SECP256R1_P_HEX, SECP256R1_A_HEX, SECP256R1_B_HEX,
		SECP256R1_N_HEX, SECP256R1_GX_HEX, SECP256R1_GY_HEX,
		SECP256R1_KEY_SIZE, SECP256R1_PUB_SIZE);
	initWeierstrassCurve(ECDH_GROUP_SECP384R1,
		SECP384R1_P_HEX, SECP384R1_A_HEX, SECP384R1_B_HEX,
		SECP384R1_N_HEX, SECP384R1_GX_HEX, SECP384R1_GY_HEX,
		SECP384R1_KEY_SIZE, SECP384R1_PUB_SIZE);
	initWeierstrassCurve(ECDH_GROUP_SECP521R1,
		SECP521R1_P_HEX, SECP521R1_A_HEX, SECP521R1_B_HEX,
		SECP521R1_N_HEX, SECP521R1_GX_HEX, SECP521R1_GY_HEX,
		SECP521R1_KEY_SIZE, SECP521R1_PUB_SIZE);
	initWeierstrassCurve(ECDH_GROUP_FRP256V1,
		FRP256V1_P_HEX, FRP256V1_A_HEX, FRP256V1_B_HEX,
		FRP256V1_N_HEX, FRP256V1_GX_HEX, FRP256V1_GY_HEX,
		FRP256V1_KEY_SIZE, FRP256V1_PUB_SIZE);
	g_weierInitialized = 1;
}



/* ---------- Public API ---------- */

int ecdhInit(t_ecdhCtx *ctx, int curveId)
{
	t_weierstrassParams *c;
	if (!ctx) return (0);
	ft_bzero(ctx, sizeof(t_ecdhCtx));

	if (curveId == ECDH_GROUP_X25519 || curveId == ECDH_GROUP_X448) {
		ctx->curveId = curveId;
		size_t keySize = (curveId == ECDH_GROUP_X25519) ? X25519_KEY_SIZE : X448_KEY_SIZE;
		ctx->priv = bigIntNew((keySize + 7) / 8);
		ctx->pubX = bigIntNew((keySize + 7) / 8);
		ctx->pubY = NULL;
		ctx->shared = bigIntNew((keySize + 7) / 8);
		return (ctx->priv && ctx->pubX && ctx->shared);
	}

	/* Weierstrass curves (SECP256r1, SECP384r1, SECP521r1) */
	initAllWeierstrass();
	c = &g_weier[curveId];
	if (!c->p) return (0);

	ctx->curveId = curveId;
	ctx->priv = bigIntNew(c->n->numWords);
	ctx->pubX = bigIntNew(c->p->numWords);
	ctx->pubY = bigIntNew(c->p->numWords);
	ctx->shared = bigIntNew(c->p->numWords);

	if (!ctx->priv || !ctx->pubX || !ctx->pubY || !ctx->shared) {
		ecdhFree(ctx);
		return (0);
	}
	return (1);
}

int ecdhGenerateKeypair(t_ecdhCtx *ctx)
{
	if (!ctx) return (0);

	/* ----- Montgomery curves (X25519, X448) ----- */
	if (ctx->curveId == ECDH_GROUP_X25519 || ctx->curveId == ECDH_GROUP_X448) {
		size_t keySize = (ctx->curveId == ECDH_GROUP_X25519) ? X25519_KEY_SIZE : X448_KEY_SIZE;
		uint8_t privBytes[56] = {0};
		uint8_t pubBytes[56]  = {0};

		/* 1. Get or generate the private key in little‑endian format */
		if (ctx->priv == NULL || bigIntIsZero(ctx->priv)) {
			/* No private key set (normal case) -> random generation + clamping */
			hajSecRandBytes(privBytes, keySize);
			if (ctx->curveId == ECDH_GROUP_X25519)
				x25519Clamp(privBytes);
			else
				x448Clamp(privBytes);
		} else {
			/* Private key already present -> convert big‑endian -> little‑endian */
			uint8_t bePriv[56];
			if (!bigIntToBytes(ctx->priv, bePriv, keySize))
				return (0);
			reverseBytes(privBytes, bePriv, keySize);
		}

		/* 2. Compute the public key (little‑endian) */
		if (ctx->curveId == ECDH_GROUP_X25519)
			x25519ScalarMult(pubBytes, privBytes, x25519BasePoint);
		else
			x448ScalarMult(pubBytes, privBytes, x448BasePoint);

		/* 3. Store the private key in big‑endian format in ctx->priv */
		if (ctx->priv == NULL || bigIntIsZero(ctx->priv)) {
			uint8_t bePriv[56];
			reverseBytes(bePriv, privBytes, keySize);
			bigIntFree(ctx->priv);
			ctx->priv = bigIntFromBytes(bePriv, keySize);
			if (!ctx->priv) return (0);
		}

		/* 4. Store the public key in big‑endian format in ctx->pubX */
		{
			uint8_t be_pub[56];
			reverseBytes(be_pub, pubBytes, keySize);
			bigIntFree(ctx->pubX);
			ctx->pubX = bigIntFromBytes(be_pub, keySize);
			if (!ctx->pubX) return (0);
		}

		bigIntSetUint64(ctx->pubY, 0);
		return (1);
	}

	/* ----- Weierstrass ----- */
	t_weierstrassParams *c = &g_weier[ctx->curveId];
	if (!c->p) return (0);

	if (bigIntIsZero(ctx->priv)) {
		size_t bits = bigIntBitLength(c->n);
		do {
			bigIntRandom(ctx->priv, bits);
		} while (bigIntIsZero(ctx->priv) || bigIntCmp(ctx->priv, c->n) >= 0);
	}

	t_ecPoint Q = { ctx->pubX, ctx->pubY };
	return (ecWeierstrassScalarMult(&Q, ctx->priv, &c->G, c->p, c->a));
}

int ecdhGetPublicBytes(const t_ecdhCtx *ctx, uint8_t *out, size_t *outLen)
{
	t_weierstrassParams *c;
	if (!ctx || !outLen) return (0);

	/* ----- Montgomery curves (X25519, X448) ----- */
	if (ctx->curveId == ECDH_GROUP_X25519 || ctx->curveId == ECDH_GROUP_X448) {
		size_t need = (ctx->curveId == ECDH_GROUP_X25519) ? X25519_PUB_SIZE : X448_PUB_SIZE;
		if (out == NULL) {
			*outLen = need;
			return (1);
		}
		if (*outLen < need) return (0);

		/* Convert the public key from big‑endian to little‑endian format */
		uint8_t be_pub[56];
		if (!bigIntToBytes(ctx->pubX, be_pub, need))
			return (0);
		reverseBytes(out, be_pub, need);
		*outLen = need;
		return (1);
	}

	/* ----- Weierstrass ----- */
	c = &g_weier[ctx->curveId];
	if (!c->p) return (0);

	size_t	coordLen = c->keySize;
	size_t	need = 1 + 2 * coordLen;
	if (out == NULL) {
		*outLen = need;
		return (1);
	}
	if (*outLen < need) return (0);

	out[0] = 0x04;
	if (bigIntToBytes(ctx->pubX, out + 1, coordLen) == 0) return (0);
	if (bigIntToBytes(ctx->pubY, out + 1 + coordLen, coordLen) == 0) return (0);
	*outLen = need;
	return (1);
}

int ecdhComputeShared(t_ecdhCtx		*ctx,
					  const uint8_t	*peerPub,		size_t	peerPubLen,
					  uint8_t		*sharedSecret,	size_t	*sharedLen)
{
	t_weierstrassParams *c;
	if (!ctx || !peerPub || !sharedLen) return (0);

	/* ----- X25519 / X448 ----- */
	if (ctx->curveId == ECDH_GROUP_X25519 || ctx->curveId == ECDH_GROUP_X448) {
		size_t need = (ctx->curveId == ECDH_GROUP_X25519) ? X25519_SHARED_SIZE : X448_SHARED_SIZE;
		if (peerPubLen != need) return (0);
		if (sharedSecret == NULL) {
			*sharedLen = need;
			return (1);
		}
		if (*sharedLen < need) return (0);

		/* 1. Convert our private key from big‑endian to little‑endian format */
		uint8_t bePriv[56];
		if (!bigIntToBytes(ctx->priv, bePriv, need))
			return (0);
		uint8_t privBytes[56];
		reverseBytes(privBytes, bePriv, need);

		/* 2. Calculate the shared secret (little‑endian) */
		uint8_t shared[56];
		if (ctx->curveId == ECDH_GROUP_X25519)
			x25519ScalarMult(shared, privBytes, peerPub);
		else
			x448ScalarMult(shared, privBytes, peerPub);

		/* Free old shared before reassigning */
		bigIntFree(ctx->shared);
		ctx->shared = bigIntFromBytes(shared, need);

		ft_memcpy(sharedSecret, shared, need);
		*sharedLen = need;
		return (1);
	}

	/* ----- Weierstrass ----- */
	c = &g_weier[ctx->curveId];
	if (!c->p) return (0);

	size_t	coordLen = c->keySize;
	size_t	need = 1 + 2 * coordLen;
	if (peerPubLen != need || peerPub[0] != 0x04) return (0);

	t_ecPoint peerPoint;
	peerPoint.x = bigIntFromBytes(peerPub + 1, coordLen);
	peerPoint.y = bigIntFromBytes(peerPub + 1 + coordLen, coordLen);
	if (!peerPoint.x || !peerPoint.y) {
		bigIntFree(peerPoint.x);
		bigIntFree(peerPoint.y);
		return (0);
	}

	/* Free old shared before allocating new one */
	bigIntFree(ctx->shared);
	ctx->shared = bigIntNew(c->p->numWords);
	if (!ctx->shared) {
		bigIntFree(peerPoint.x);
		bigIntFree(peerPoint.y);
		return (0);
	}

	t_ecPoint sharedPoint = { ctx->shared, bigIntNew(c->p->numWords) };
	if (!sharedPoint.y) {
		bigIntFree(peerPoint.x);
		bigIntFree(peerPoint.y);
		return (0);
	}

	int ok = ecWeierstrassScalarMult(&sharedPoint, ctx->priv, &peerPoint, c->p, c->a);
	if (ok) {
		if (bigIntToBytes(sharedPoint.x, sharedSecret, coordLen) == 0)
			ok = 0;
		else
			*sharedLen = coordLen;
	}

	bigIntFree(peerPoint.x);
	bigIntFree(peerPoint.y);
	bigIntFree(sharedPoint.y);
	return (ok);
}

void ecdhFree(t_ecdhCtx *ctx)
{
	if (!ctx) return;
	bigIntFree(ctx->priv);
	bigIntFree(ctx->pubX);
	bigIntFree(ctx->pubY);
	bigIntFree(ctx->shared);
	secureZeroMemory(ctx, sizeof(t_ecdhCtx));
}

const t_weierstrassParams *ecdhGetCurveParams(int curveId)
{
    initAllWeierstrass();
    
    if (curveId == ECDH_GROUP_SECP256R1 ||
        curveId == ECDH_GROUP_SECP384R1 ||
        curveId == ECDH_GROUP_SECP521R1 ||
		curveId == ECDH_GROUP_FRP256V1) {
        if (g_weier[curveId].p)
            return (&g_weier[curveId]);
    }
    return (NULL);
}
