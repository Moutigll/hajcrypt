#include "../../../includes/asymmetric/ecdh.h"
#include "../../../hajlib/include/hmemory.h"

typedef unsigned __int128 uint128_t;



static void fe25519Reduce(uint64_t out[4]) {
	uint64_t c = out[3] >> 63;
	out[3] &= 0x7FFFFFFFFFFFFFFF;
	uint64_t carry = c * 19;
	for(int i = 0; i < 4; i++) {
		uint128_t sum = (uint128_t)out[i] + carry;
		out[i] = (uint64_t)sum;
		carry = (uint64_t)(sum >> 64);
	}

	c = out[3] >> 63;
	out[3] &= 0x7FFFFFFFFFFFFFFF;
	carry = c * 19;
	for(int i = 0; i < 4; i++) {
		uint128_t sum = (uint128_t)out[i] + carry;
		out[i] = (uint64_t)sum;
		carry = (uint64_t)(sum >> 64);
	}
}

static void fe25519Add(uint64_t out[4], const uint64_t a[4], const uint64_t b[4]) {
	uint64_t carry = 0;
	for (int i = 0; i < 4; i++) {
		uint128_t sum = (uint128_t)a[i] + b[i] + carry;
		out[i] = (uint64_t)sum;
		carry = (uint64_t)(sum >> 64);
	}
	fe25519Reduce(out);
}

static void fe25519Sub(uint64_t out[4], const uint64_t a[4], const uint64_t b[4]) {
	uint64_t borrow = 0;
	for (int i = 0; i < 4; i++) {
		uint128_t diff = (uint128_t)a[i] - b[i] - borrow;
		out[i] = (uint64_t)diff;
		borrow = (uint64_t)(diff >> 64) & 1;
	}
	
	/* If negative, add 2*p = 2^256 - 38. The 256-bit underflow already provides 
	 * the +2^256 implicitly, so we just need to subtract 38. */
	uint64_t	mask = -(uint64_t)borrow;
	uint64_t	subtract_target = 38 & mask;
	for (int i = 0; i < 4; i++) {
		uint128_t diff = (uint128_t)out[i] - subtract_target;
		out[i] = (uint64_t)diff;
		subtract_target = (uint64_t)(diff >> 64) & 1;
	}
	fe25519Reduce(out);
}

static void fe25519Mul(uint64_t out[4], const uint64_t a[4], const uint64_t b[4]) {
	uint64_t r[8] = {0};
	for (int i = 0; i < 4; i++) {
		uint64_t carry = 0;
		for (int j = 0; j < 4; j++) {
			uint128_t m = (uint128_t)a[i] * b[j] + r[i+j] + carry;
			r[i+j] = (uint64_t)m;
			carry = (uint64_t)(m >> 64);
		}
		r[i+4] = carry;
	}
	uint64_t carry = 0;
	for (int i = 0; i < 4; i++) {
		uint128_t m = (uint128_t)r[i+4] * 38 + r[i] + carry;
		out[i] = (uint64_t)m;
		carry = (uint64_t)(m >> 64);
	}
	uint128_t sum = (uint128_t)out[0] + carry * 38;
	out[0] = (uint64_t)sum;
	uint64_t c2 = (uint64_t)(sum >> 64);
	for (int i = 1; i < 4; i++) {
		sum = (uint128_t)out[i] + c2;
		out[i] = (uint64_t)sum;
		c2 = (uint64_t)(sum >> 64);
	}
	/* Safely fold the final spilled carry bit (bit 256) back into the field */
	if (c2 > 0) {
		sum = (uint128_t)out[0] + c2 * 38;
		out[0] = (uint64_t)sum;
		c2 = (uint64_t)(sum >> 64);
		for (int i = 1; i < 4; i++) {
			sum = (uint128_t)out[i] + c2;
			out[i] = (uint64_t)sum;
			c2 = (uint64_t)(sum >> 64);
		}
	}
	fe25519Reduce(out);
}

static void fe25519Sqr(uint64_t out[4], const uint64_t a[4]) {
	fe25519Mul(out, a, a);
}

static void fe25519Mul121665(uint64_t out[4], const uint64_t a[4]) {
	uint64_t b[4] = {121665, 0, 0, 0};
	fe25519Mul(out, a, b);
}

static void fe25519Invert(uint64_t out[4], const uint64_t a[4]) {
	uint64_t	res[4] = {1, 0, 0, 0};
	uint64_t	base[4];
	ft_memcpy(base, a, sizeof(base));
	/* p-2 = 0x7FFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFEB */
	uint64_t p_minus_2[4] = { 0xffffffffffffffeb, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff };
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 64; j++) {
			if ((p_minus_2[i] >> j) & 1) fe25519Mul(res, res, base);
			fe25519Sqr(base, base);
		}
	}
	ft_memcpy(out, res, sizeof(base));
}

static void fe25519Cswap(uint64_t a[4], uint64_t b[4], int swap) {
	uint64_t mask = -(uint64_t)swap;
	for(int i = 0; i < 4; i++) {
		uint64_t dummy = mask & (a[i] ^ b[i]);
		a[i] ^= dummy;
		b[i] ^= dummy;
	}
}





void x25519ScalarMult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
	uint64_t	x1[4],	x2[4],	z2[4],	x3[4],	z3[4];
	uint64_t	A[4],	AA[4],	B[4],	BB[4],	E[4],	C[4],	D[4],	DA[4],	CB[4],	tmp1[4],	tmp2[4];
	int			swap = 0;

	for (int i = 0; i < 4; i++) {
		x1[i] = (uint64_t)point[8*i+0]	  | ((uint64_t)point[8*i+1] << 8) |
				((uint64_t)point[8*i+2] << 16) | ((uint64_t)point[8*i+3] << 24) |
				((uint64_t)point[8*i+4] << 32) | ((uint64_t)point[8*i+5] << 40) |
				((uint64_t)point[8*i+6] << 48) | ((uint64_t)point[8*i+7] << 56);
	}

	x2[0] = 1; x2[1] = 0; x2[2] = 0; x2[3] = 0; 
	z2[0] = 0; z2[1] = 0; z2[2] = 0; z2[3] = 0;
	for (int i = 0; i < 4; i++) { x3[i] = x1[i]; z3[i] = 0; } z3[0] = 1;

	for (int i = 254; i >= 0; i--) {
		uint64_t bit = (scalar[i/8] >> (i%8)) & 1;
		swap ^= bit;
		fe25519Cswap(x2, x3, swap);
		fe25519Cswap(z2, z3, swap);
		swap = bit;

		fe25519Add(A, x2, z2);
		fe25519Sqr(AA, A);
		fe25519Sub(B, x2, z2);
		fe25519Sqr(BB, B);
		fe25519Sub(E, AA, BB);

		fe25519Add(C, x3, z3);
		fe25519Sub(D, x3, z3);
		fe25519Mul(DA, D, A);
		fe25519Mul(CB, C, B);

		fe25519Add(tmp1, DA, CB);
		fe25519Sqr(x3, tmp1);

		fe25519Sub(tmp1, DA, CB);
		fe25519Sqr(tmp2, tmp1);
		fe25519Mul(z3, x1, tmp2);

		fe25519Mul(x2, AA, BB);
		fe25519Mul121665(tmp1, E);
		fe25519Add(tmp2, AA, tmp1);
		fe25519Mul(z2, E, tmp2);
	}

	fe25519Cswap(x2, x3, swap);
	fe25519Cswap(z2, z3, swap);

	fe25519Invert(z2, z2);
	fe25519Mul(x2, x2, z2);

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 8; j++) {
			out[8*i + j] = (x2[i] >> (8*j)) & 0xff;
		}
	}
}

void x25519Clamp(uint8_t scalar[32])
{
	scalar[0] &= 248;
	scalar[31] &= 127;
	scalar[31] |= 64;
}




/* ----- Field arithmetic for Curve448 ----- */

static void fe448Add(uint64_t out[8], const uint64_t a[8], const uint64_t b[8]) {
	uint64_t carry = 0;
	for(int i = 0; i < 8; i++) {
		uint64_t sum = a[i] + b[i] + carry;
		out[i] = sum & 0xFFFFFFFFFFFFFFULL;
		carry = sum >> 56;
	}
	uint64_t sum0 = out[0] + carry;
	out[0] = sum0 & 0xFFFFFFFFFFFFFFULL;
	uint64_t c = sum0 >> 56;
	for(int i = 1; i < 4; i++) {
		uint64_t s = out[i] + c;
		out[i] = s & 0xFFFFFFFFFFFFFFULL;
		c = s >> 56;
	}
	uint64_t sum4 = out[4] + carry + c;
	out[4] = sum4 & 0xFFFFFFFFFFFFFFULL;
	c = sum4 >> 56;
	for(int i = 5; i < 8; i++) {
		uint64_t s = out[i] + c;
		out[i] = s & 0xFFFFFFFFFFFFFFULL;
		c = s >> 56;
	}
}

static void fe448Sub(uint64_t out[8], const uint64_t a[8], const uint64_t b[8]) {
	uint64_t borrow = 0;
	for(int i = 0; i < 8; i++) {
		uint64_t diff = a[i] - b[i] - borrow;
		out[i] = diff & 0xFFFFFFFFFFFFFFULL;
		borrow = (diff >> 56) & 1;
	}
	uint64_t	mask = -(uint64_t)borrow;
	uint64_t	carry = 0;
	uint64_t	sum = out[0] + (0xFFFFFFFFFFFFFFULL & mask);
	out[0] = sum & 0xFFFFFFFFFFFFFFULL; carry = sum >> 56;
	for(int i = 1; i < 4; i++) {
		sum = out[i] + (0xFFFFFFFFFFFFFFULL & mask) + carry;
		out[i] = sum & 0xFFFFFFFFFFFFFFULL; carry = sum >> 56;
	}
	sum = out[4] + (0xFFFFFFFFFFFFFEULL & mask) + carry;
	out[4] = sum & 0xFFFFFFFFFFFFFFULL; carry = sum >> 56;
	for(int i = 5; i < 8; i++) {
		sum = out[i] + (0xFFFFFFFFFFFFFFULL & mask) + carry;
		out[i] = sum & 0xFFFFFFFFFFFFFFULL; carry = sum >> 56;
	}
}

static void fe448Mul(uint64_t out[8], const uint64_t a[8], const uint64_t b[8]) {
	uint128_t r[16] = {0};
	
	/* 1. Standard long multiplication, producing a 896-bit intermediate result in r[0..15] */
	for(int i = 0; i < 8; i++) {
		for(int j = 0; j < 8; j++) {
			r[i+j] += (uint128_t)a[i] * b[j];
		}
	}
	
	/* 2. First pass of reduction */
	for (int i = 12; i < 15; i++) {
		r[i - 4] += r[i]; // + 2^224
		r[i - 8] += r[i]; // + 1
	}
	
	/* 3. Second pass of reduction to ensure all r[i] fit within 56 bits */
	for (int i = 8; i < 12; i++) {
		r[i - 4] += r[i];
		r[i - 8] += r[i];
	}
	
	/* 4. Final carry propagation to ensure all r[i] fit within 56 bits */
	uint64_t carry = 0;
	for(int i = 0; i < 8; i++) {
		uint128_t sum = r[i] + carry;
		out[i] = (uint64_t)(sum & 0xFFFFFFFFFFFFFFULL);
		carry  = (uint64_t)(sum >> 56);
	}
	
	uint64_t carry2 = carry;
	carry = 0;
	for(int i = 0; i < 8; i++) {
		uint64_t append = (i == 0 || i == 4) ? carry2 : 0;
		uint64_t sum = out[i] + append + carry;
		out[i] = sum & 0xFFFFFFFFFFFFFFULL;
		carry = sum >> 56;
	}
	
	if (carry > 0) {
		uint64_t carry3 = carry;
		carry = 0;
		for(int i = 0; i < 8; i++) {
			uint64_t append = (i == 0 || i == 4) ? carry3 : 0;
			uint64_t sum = out[i] + append + carry;
			out[i] = sum & 0xFFFFFFFFFFFFFFULL;
			carry = sum >> 56;
		}
	}
}

static void fe448Sqr(uint64_t out[8], const uint64_t a[8]) {
	fe448Mul(out, a, a);
}

static void fe448Mul39081(uint64_t out[8], const uint64_t a[8]) {
	uint64_t b[8] = {39081, 0, 0, 0, 0, 0, 0, 0};
	fe448Mul(out, a, b);
}

static void fe448Cswap(uint64_t a[8], uint64_t b[8], int swap) {
	uint64_t mask = -(uint64_t)swap;
	for(int i = 0; i < 8; i++) {
		uint64_t dummy = mask & (a[i] ^ b[i]);
		a[i] ^= dummy;
		b[i] ^= dummy;
	}
}

static void fe448Invert(uint64_t out[8], const uint64_t a[8]) {
	uint64_t	res[8] = {1,0,0,0,0,0,0,0};
	uint64_t	base[8];
	ft_memcpy(base, a, sizeof(base));
	/* FLT: a^(p-2) avec p-2 = 2^448 - 2^224 - 3 */
	for(int i = 0; i < 448; i++) {
		int bit = (i == 1 || i == 224) ? 0 : 1;
		if (bit) fe448Mul(res, res, base);
		fe448Sqr(base, base);
	}
	ft_memcpy(out, res, sizeof(res));
}




void x448ScalarMult(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56])
{
	uint64_t	x1[8] = {0},	x2[8],	z2[8],	x3[8],	z3[8];
	uint64_t	A[8],			AA[8],	B[8],	BB[8],	E[8],	C[8],	D[8],	DA[8],	CB[8],	tmp1[8],	tmp2[8];
	int			swap = 0;

	for(int i = 0; i < 8; i++) {
		x1[i] = 0;
		for(int j = 0; j < 7; j++) {
			x1[i] |= ((uint64_t)point[i*7 + j]) << (8*j);
		}
	}

	x2[0] = 1; for(int i=1; i<8; i++) x2[i] = 0;
	for(int i=0; i<8; i++) z2[i] = 0;
	for(int i=0; i<8; i++) x3[i] = x1[i];
	z3[0] = 1; for(int i=1; i<8; i++) z3[i] = 0;

	for(int i = 447; i >= 0; i--) {
		uint64_t bit = (scalar[i/8] >> (i%8)) & 1;
		swap ^= bit;
		fe448Cswap(x2, x3, swap);
		fe448Cswap(z2, z3, swap);
		swap = bit;

		fe448Add(A, x2, z2);
		fe448Sqr(AA, A);
		fe448Sub(B, x2, z2);
		fe448Sqr(BB, B);
		fe448Sub(E, AA, BB);

		fe448Add(C, x3, z3);
		fe448Sub(D, x3, z3);
		fe448Mul(DA, D, A);
		fe448Mul(CB, C, B);

		fe448Add(tmp1, DA, CB);
		fe448Sqr(x3, tmp1);

		fe448Sub(tmp1, DA, CB);
		fe448Sqr(tmp2, tmp1);
		fe448Mul(z3, x1, tmp2);

		fe448Mul(x2, AA, BB);
		fe448Mul39081(tmp1, E);
		fe448Add(tmp2, AA, tmp1);
		fe448Mul(z2, E, tmp2);
	}

	fe448Cswap(x2, x3, swap);
	fe448Cswap(z2, z3, swap);

	fe448Invert(z2, z2);
	fe448Mul(x2, x2, z2);

	uint8_t temp[56];
	for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 7; j++) {
			temp[i * 7 + j] = (uint8_t)(x2[i] >> (8 * j));
		}
	}
	ft_memcpy(out, temp, 56);
}

void x448Clamp(uint8_t scalar[56])
{
	scalar[0] &= 252;
	scalar[55] |= 128;
}


/* ----- Base points ----- */

const uint8_t x25519BasePoint[32] = {
	9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

const uint8_t x448BasePoint[56] = {
	5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0
};
