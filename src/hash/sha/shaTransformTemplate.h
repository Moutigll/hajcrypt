#include "../../../includes/utils/bitopts.h"

#if !defined(SHA_WORD) || !defined(SHA_ROUNDS) || !defined(SHA_BLOCK_SIZE) || \
	!defined(SHA_K) || !defined(SHA_CH) || !defined(SHA_MAJ) || \
	!defined(SHA_SIGMA0) || !defined(SHA_SIGMA1) || !defined(SHA_sigma0) || \
	!defined(SHA_sigma1) || !defined(SHA_LOAD_BE) || !defined(SHA_TRANSFORM)
# error "One or more required SHA transform macros are not defined"
#endif

void SHA_TRANSFORM(SHA_WORD state[8], const uint8_t block[SHA_BLOCK_SIZE])
{
	SHA_WORD	w[SHA_ROUNDS];
	SHA_WORD	a, b, c, d, e, f, g, h, t1, t2;
	int			i;

	/* Message schedule */
	for (i = 0; i < 16; i++)
		w[i] = SHA_LOAD_BE(block + i * sizeof(SHA_WORD));

	for (i = 16; i < SHA_ROUNDS; i++)
		w[i] = SHA_sigma1(w[i-2]) + w[i-7] + SHA_sigma0(w[i-15]) + w[i-16];

	/* Initialise working variables */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	/* Main loop - compiler will unroll at -O3 */
	for (i = 0; i < SHA_ROUNDS; i++)
	{
		t1 = h + SHA_SIGMA1(e) + SHA_CH(e, f, g) + SHA_K[i] + w[i];
		t2 = SHA_SIGMA0(a) + SHA_MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	/* Feed forward */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
