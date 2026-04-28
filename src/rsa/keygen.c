#include "../../includes/rsa/rsa.h"

void rsaGenerateKey(t_rsaKey *key, size_t bits, uint64_t e_val)
{
	t_bigInt *pm1 = NULL, *qm1 = NULL, *phi = NULL, *one = bigIntFromUint64(1);
	key->e = bigIntFromUint64(e_val);

	while (1) {
		key->p = rsaGeneratePrime(bits / 2, 0.999999);
		key->q = rsaGeneratePrime(bits - (bits / 2), 0.999999);

		if (bigIntCmp(key->p, key->q) == 0) {
			rsaFreeKey(key);
			continue;
		}

		key->n = bigIntNew(key->p->numWords + key->q->numWords);
		bigIntMul(key->n, key->p, key->q);

		/* Phi(n) = (p-1)(q-1) */
		pm1 = bigIntDup(key->p); bigIntSub(pm1, pm1, one);
		qm1 = bigIntDup(key->q); bigIntSub(qm1, qm1, one);
		phi = bigIntNew(pm1->numWords + qm1->numWords);
		bigIntMul(phi, pm1, qm1);

		/* d = e^-1 mod phi(n) */
		key->d = bigIntNew(phi->numWords);
		if (bigIntModInverse(key->d, key->e, phi) && !bigIntIsZero(key->d)) {
			key->dp = bigIntNew(key->p->numWords);
			key->dq = bigIntNew(key->q->numWords);
			key->qinv = bigIntNew(key->p->numWords);
			bigIntMod(key->dp, key->d, pm1);
			bigIntMod(key->dq, key->d, qm1);
			/* qInv = q^-1 mod p */
			bigIntModInverse(key->qinv, key->q, key->p);

			bigIntFree(pm1); bigIntFree(qm1); bigIntFree(phi); bigIntFree(one);
			key->bits = bits;
			return;
		}

		rsaFreeKey(key); 
		bigIntFree(pm1); bigIntFree(qm1); bigIntFree(phi);
	}
}

void rsaFreeKey(t_rsaKey *key)
{
	if (!key) return;
	bigIntFree(key->n);
	bigIntFree(key->e);
	bigIntFree(key->d);
	bigIntFree(key->p);
	bigIntFree(key->q);
	bigIntFree(key->dp);
	bigIntFree(key->dq);
	bigIntFree(key->qinv);
}
