#include "../../../includes/asymmetric/ecdh.h"


static int modSub(t_bigInt *res, const t_bigInt *a, const t_bigInt *b, const t_bigInt *mod)
{
	t_bigInt *tmp = bigIntNew(mod->numWords);
	if (!tmp) return (0);
	if (bigIntCmp(a, b) < 0) {
		bigIntAdd(tmp, a, mod);
		bigIntSub(res, tmp, b);
	} else
		bigIntSub(res, a, b);
	bigIntFree(tmp);
	return (1);
}

static int modAdd(t_bigInt *res, const t_bigInt *a, const t_bigInt *b, const t_bigInt *mod)
{
	t_bigInt *tmp = bigIntNew(mod->numWords);
	if (!tmp) return (0);
	bigIntAdd(tmp, a, b);
	while (bigIntCmp(tmp, mod) >= 0)
		bigIntSub(tmp, tmp, mod);
	bigIntCopy(res, tmp);
	bigIntFree(tmp);
	return (1);
}

static int modMul(t_bigInt *res, const t_bigInt *a, const t_bigInt *b, const t_bigInt *mod)
{
	return (bigIntMulMod(res, a, b, mod) != NULL);
}

static int modInv(t_bigInt *res, const t_bigInt *a, const t_bigInt *mod)
{
	return (bigIntModInverse(res, a, mod) != NULL);
}





int ecWeierstrassPointDouble(t_ecPoint *R, const t_ecPoint *P, const t_bigInt *p, const t_bigInt *a)
{
	t_bigInt	*lambda, *tmp1, *tmp2;
	int			ret = 0;

	if (bigIntIsZero(P->y)) {
		bigIntSetUint64(R->x, 0);
		bigIntSetUint64(R->y, 0);
		return (1);
	}

	lambda	= bigIntNew(p->numWords);
	tmp1	= bigIntNew(p->numWords);
	tmp2	= bigIntNew(p->numWords);
	if (!lambda || !tmp1 || !tmp2) goto err;

	/* lambda = (3*x^2 + a) / (2*y) */
	if (!modMul(tmp1, P->x, P->x, p)) goto err;
	modAdd(tmp2, tmp1, tmp1, p);
	modAdd(tmp1, tmp1, tmp2, p);
	modAdd(lambda, tmp1, a, p);

	modAdd(tmp2, P->y, P->y, p);
	if (!modInv(tmp2, tmp2, p)) goto err;
	if (!modMul(lambda, lambda, tmp2, p)) goto err;

	/* x3 = lambda^2 - 2*x */
	if (!modMul(tmp1, lambda, lambda, p)) goto err;
	modAdd(tmp2, P->x, P->x, p);
	modSub(tmp2, tmp1, tmp2, p);   /* tmp2 = x3 temporaire */

	/* y3 = lambda*(x - x3) - y */
	modSub(tmp1, P->x, tmp2, p);
	if (!modMul(tmp1, lambda, tmp1, p)) goto err;
	modSub(R->y, tmp1, P->y, p);

	/* recopie finale de x3 */
	bigIntCopy(R->x, tmp2);

	ret = 1;
err:
	bigIntFree(lambda);
	bigIntFree(tmp1);
	bigIntFree(tmp2);
	return (ret);
}

/* ---------- Addition de points ---------- */
int ecWeierstrassPointAdd(t_ecPoint *R, const t_ecPoint *P, const t_ecPoint *Q, const t_bigInt *p, const t_bigInt *a)
{
	t_bigInt	*lambda, *dx, *dy, *tmp;
	int			ret = 0;

	if (bigIntIsZero(P->x) && bigIntIsZero(P->y)) {
		bigIntCopy(R->x, Q->x);
		bigIntCopy(R->y, Q->y);
		return (1);
	}
	if (bigIntIsZero(Q->x) && bigIntIsZero(Q->y)) {
		bigIntCopy(R->x, P->x);
		bigIntCopy(R->y, P->y);
		return (1);
	}
	if (bigIntCmp(P->x, Q->x) == 0) {
		if (bigIntCmp(P->y, Q->y) == 0)
			return ecWeierstrassPointDouble(R, P, p, a);
		bigIntSetUint64(R->x, 0);
		bigIntSetUint64(R->y, 0);
		return (1);
	}

	lambda = bigIntNew(p->numWords);
	dx	 = bigIntNew(p->numWords);
	dy	 = bigIntNew(p->numWords);
	tmp	= bigIntNew(p->numWords);
	if (!lambda || !dx || !dy || !tmp) goto err;

	modSub(dx, Q->x, P->x, p);
	modSub(dy, Q->y, P->y, p);
	if (!modInv(dx, dx, p)) goto err;
	if (!modMul(lambda, dy, dx, p)) goto err;

	/* x3 = lambda^2 - Px - Qx */
	if (!modMul(tmp, lambda, lambda, p)) goto err;
	modSub(tmp, tmp, P->x, p);
	modSub(tmp, tmp, Q->x, p);   /* tmp = x3 temporaire */

	/* y3 = lambda*(Px - x3) - Py */
	modSub(dx, P->x, tmp, p);
	if (!modMul(dx, lambda, dx, p)) goto err;
	modSub(R->y, dx, P->y, p);

	bigIntCopy(R->x, tmp);
	ret = 1;
err:
	bigIntFree(lambda);
	bigIntFree(dx);
	bigIntFree(dy);
	bigIntFree(tmp);
	return (ret);
}

/* ---------- Multiplication scalaire (algorithme binaire L→R) ---------- */
int ecWeierstrassScalarMult(t_ecPoint *Q, const t_bigInt *k, const t_ecPoint *P, const t_bigInt *p, const t_bigInt *a)
{
	t_ecPoint	R;
	int			bitlen = bigIntBitLength(k);
	int			i, ret = 0;

	R.x = bigIntNew(p->numWords);
	R.y = bigIntNew(p->numWords);
	if (!R.x || !R.y) return (0);

	bigIntSetUint64(R.x, 0);
	bigIntSetUint64(R.y, 0);

	for (i = bitlen - 1; i >= 0; i--) {
		if (!ecWeierstrassPointDouble(&R, &R, p, a)) goto err;
		if (bigIntGetBit(k, i)) {
			if (!ecWeierstrassPointAdd(&R, &R, P, p, a)) goto err;
		}
	}

	bigIntCopy(Q->x, R.x);
	bigIntCopy(Q->y, R.y);
	ret = 1;
err:
	bigIntFree(R.x);
	bigIntFree(R.y);
	return (ret);
}
