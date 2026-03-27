#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/aes.h"


#ifndef __aarch64__

/**
 * @brief	Galois Field multiplication in GF(2^128) using the polynomial
 *			x^128 + x^7 + x^2 + x + 1 (GCM specification)
 * @param	x	First operand (16 bytes)
 * @param	y	Second operand (16 bytes)
 * @param	z	Result (16 bytes)
 * @note	Implements standard bit-by-bit multiplication with reduction
 */
static void gfmulStandard(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
	uint8_t	v[16], res[16] = {0};

	ft_memcpy(v, y, 16);
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 8; j++) {
			if (x[i] & (0x80 >> j))
				for (int k = 0; k < 16; k++) res[k] ^= v[k];
			uint8_t carry = v[15] & 1;
			for (int k = 15; k > 0; k--)
				v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
			v[0] >>= 1;
			if (carry) v[0] ^= 0xe1;
		}
	}
	ft_memcpy(z, res, 16);
}

/**
 * @brief	GHASH block operation: updates the GHASH state with one block
 *			by XORing then multiplying by H in GF(2^128)
 * @param	ctx	AES-GCM context containing state and H value
 * @param	block	16-byte block to incorporate
 */
static void ghashBlock(t_aesGcmCtx *ctx, const uint8_t *block)
{
	uint8_t	tmp[16];

	ft_memcpy(tmp, ctx->ghashState, 16);
	for (int k = 0; k < 16; k++) tmp[k] ^= block[k];
	gfmulStandard(tmp, ctx->H, ctx->ghashState);
}

#else /* __aarch64__ */

/* --------------- ARMv8-A Optimized Implementation (NEON + PMULL) --------------- */

#include <arm_neon.h>

/**
 * @brief	GHASH using NEON/PMULL instructions for 16-byte aligned blocks
 * @param	state	Current GHASH state (modified in place)
 * @param	H	Hash key in bit-reflected domain
 * @param	data	Input data blocks
 * @param	len	Length of data (must be multiple of 16)
 * @note	Uses bit-reflected domain for PMULL efficiency
 */
__attribute__((target("aes")))
static void ghashNeon(uint8_t			*state,
					  const uint8_t	*H,
		    		  const uint8_t	*data,
					  size_t			len)
{
	uint8x16_t	acc = vrbitq_u8(vld1q_u8(state));
	uint8x16_t	h   = vrbitq_u8(vld1q_u8(H));
	uint8x16_t	z   = vdupq_n_u8(0);
	uint8x16_t	p   = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087ULL));

	while (len >= 16) {
		acc = veorq_u8(acc, vrbitq_u8(vld1q_u8(data)));
		asm volatile(
			"pmull	v11.1q,	 %0.1d, %1.1d \n\t"			/* Low 64 bits of product */
			"pmull2	v12.1q,	 %0.2d, %1.2d \n\t"			/* High 64 bits of product */
			"ext	v13.16b, %1.16b, %1.16b, #8 \n\t"	/* Shift H right by 64 bits for cross terms */
			"pmull	v14.1q,	 %0.1d, v13.1d \n\t"		/* Cross term 1 */
			"pmull2	v13.1q,	 %0.2d, v13.2d \n\t"		/* Cross term 2 */
			"eor	v13.16b, v13.16b, v14.16b \n\t"		/* Combine cross terms */
			"ext	v14.16b, %2.16b, v13.16b, #8 \n\t"	/* Shift combined cross terms for reduction */
			"eor	v11.16b, v11.16b, v14.16b \n\t"		/* Reduce low part */
			"ext	v14.16b, v13.16b, %2.16b, #8 \n\t"	/* Shift combined cross terms for reduction */
			"eor	v12.16b, v12.16b, v14.16b \n\t"		/* Reduce high part */
			"pmull2	v13.1q,	 v12.2d, %3.2d \n\t"		/* Final reduction step with polynomial */
			"ext	v14.16b, v13.16b, %2.16b, #8 \n\t"	/* Shift for final reduction */
			"eor	v12.16b, v12.16b, v14.16b \n\t"		/* Final reduction part 1 - high */
			"ext	v14.16b, %2.16b, v13.16b, #8 \n\t"	/* Shift for final reduction */
			"eor	v11.16b, v11.16b, v14.16b \n\t"		/* Final reduction part 2 - low */
			"pmull	v13.1q,	 v12.1d, %3.1d \n\t"		/* Final reduction step with polynomial */
			"eor	v11.16b, v11.16b, v13.16b \n\t"		/* Final reduction part 3 - low */
			"mov	%0.16b,	 v11.16b \n\t"				/* Move result back to acc */
			: "+w"(acc)
			: "w"(h), "w"(z), "w"(p)
			: "v11","v12","v13","v14"
		);
		data += 16;
		len  -= 16;
	}
	vst1q_u8(state, vrbitq_u8(acc));
}

static inline void ghashBlock(t_aesGcmCtx *ctx, const uint8_t *block) {
	ghashNeon(ctx->ghashState, ctx->H, block, 16);
}

/**
 * @brief	Galois Field multiplication in bit-reflected domain
 * @param	a	First operand (bit-reflected)
 * @param	h	Second operand (bit-reflected)
 * @return		Product in bit-reflected domain
 * @note	Direct multiplication with reduction using PMULL
 */
static inline uint8x16_t gfmulR(uint8x16_t a, uint8x16_t h)
{
	uint8x16_t	p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087ULL));
	uint8x16_t	z = vdupq_n_u8(0);
	uint8x16_t	r;
	asm volatile(
		"pmull	v11.1q,	 %1.1d, %2.1d \n\t"			/* Low 64 bits of product */
		"pmull2	v12.1q,	 %1.2d, %2.2d \n\t"			/* High 64 bits of product */
		"ext	v13.16b, %2.16b, %2.16b, #8 \n\t"	/* Shift H right by 64 bits for cross terms */
		"pmull	v14.1q,	 %1.1d, v13.1d \n\t"		/* Cross term 1 */
		"pmull2	v13.1q,	 %1.2d, v13.2d \n\t"		/* Cross term 2 */
		"eor	v13.16b, v13.16b, v14.16b \n\t"		/* Combine cross terms */
		"ext	v14.16b, %3.16b, v13.16b, #8 \n\t"	/* Shift combined cross terms for reduction */
		"eor	v11.16b, v11.16b, v14.16b \n\t"		/* Reduce low part */
		"ext	v14.16b, v13.16b, %3.16b, #8 \n\t"	/* Shift for final reduction */
		"eor	v12.16b, v12.16b, v14.16b \n\t"		/* Reduce high part */
		"pmull2	v13.1q,	 v12.2d, %4.2d \n\t"		/* Final reduction step with polynomial */
		"ext	v14.16b, v13.16b, %3.16b, #8 \n\t"	/* Shift for final reduction */
		"eor	v12.16b, v12.16b, v14.16b \n\t"		/* Final reduction part 1 - high */
		"ext	v14.16b, %3.16b, v13.16b, #8 \n\t"	/* Shift for final reduction */
		"eor	v11.16b, v11.16b, v14.16b \n\t"		/* Final reduction part 2 - low */
		"pmull	v13.1q,	 v12.1d, %4.1d \n\t"		/* Final reduction step with polynomial */
		"eor	v11.16b, v11.16b, v13.16b \n\t"		/* Final reduction part 3 - low */
		"mov	%0.16b,	 v11.16b \n\t"				/* Move result back to r */
		: "=w"(r)
		: "w"(a), "w"(h), "w"(z), "w"(p)
		: "v11","v12","v13","v14"
	);
	return (r);
}

/**
 * @brief	Increment GCM counter in big-endian format (bytes 12-15)
 * @param	ctr	Current counter value (modified)
 * @param	inc	Increment value (typically 1)
 * @return		Incremented counter
 * @note	Uses byte-swap to handle ARM little-endian memory ordering
 */
static inline uint8x16_t ctrIncNeon(uint8x16_t ctr, uint32_t inc) 
{
	uint32x4_t c = vreinterpretq_u32_u8(ctr);
	uint32_t lo = vgetq_lane_u32(c, 3);
	lo = __builtin_bswap32(__builtin_bswap32(lo) + inc);
	c = vsetq_lane_u32(lo, c, 3);
	return (vreinterpretq_u8_u32(c));
}

/**
 * @brief	Karatsuba multiplication without reduction
 * @param	a_u8	First operand (bit-reflected)
 * @param	b_u8	Second operand (bit-reflected)
 * @param	lo	Output: low 128 bits of product
 * @param	mid	Output: middle 128 bits of product (bits 64-191)
 * @param	hi	Output: high 128 bits of product (bits 128-255)
 * @note	Product = lo ^ (mid << 64) ^ (hi << 128)
 */
static inline __attribute__((always_inline, target("aes")))
void gcmMulNoreduce(uint8x16_t	a_u8,
					  uint8x16_t	b_u8,
		    		  uint8x16_t	*lo,
					  uint8x16_t	*mid,
					  uint8x16_t	*hi)
{
	/* Interpret inputs as polynomials over GF(2) */
	poly64x2_t	a = vreinterpretq_p64_u8(a_u8);
	poly64x2_t	b = vreinterpretq_p64_u8(b_u8);

	/* Karatsuba decomposition: a = aH*x + aL, b = bH*x + bL */
	poly64x1_t	aL = vget_low_p64(a);
	poly64x1_t	aH = vget_high_p64(a);
	poly64x1_t	bL = vget_low_p64(b);
	poly64x1_t	bH = vget_high_p64(b);

	/* Compute partial products */
	uint8x16_t	p0 = vreinterpretq_u8_p128(vmull_p64(aL, bL));
	uint8x16_t	p1 = vreinterpretq_u8_p128(vmull_p64(aH, bH));

	/* Compute cross terms: (aL ^ aH) * (bL ^ bH) */
	uint64x1_t	aXor = veor_u64(vreinterpret_u64_p64(aL), vreinterpret_u64_p64(aH));
	uint64x1_t	bXor = veor_u64(vreinterpret_u64_p64(bL), vreinterpret_u64_p64(bH));
	
	uint8x16_t p2 = vreinterpretq_u8_p128(vmull_p64(vreinterpret_p64_u64(aXor), 
						       vreinterpret_p64_u64(bXor)));
	/* Combine results: product = p0 + (p1 << 128) + ((p2 ^ p0 ^ p1) << 64) */
	uint8x16_t m = veorq_u8(p2, veorq_u8(p0, p1));

	*lo  = p0;
	*mid = m;
	*hi  = p1;
}

/**
 * @brief	Final reduction modulo x^128 + x^7 + x^2 + x + 1
 * @param	lo	Low 128 bits of unreduced product
 * @param	mid	Middle 128 bits (bits 64-191)
 * @param	hi	High 128 bits (bits 128-255)
 * @return		Reduced 128-bit result in bit-reflected domain
 */
static inline __attribute__((always_inline))
uint8x16_t gcmReduce(uint8x16_t lo, uint8x16_t mid, uint8x16_t hi)
{
	uint8x16_t	p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087ULL));
	uint8x16_t	z = vdupq_n_u8(0);
	uint8x16_t	r;
	asm volatile(
		"mov	v11.16b, %1.16b \n\t"				/* Load low part */
		"mov	v13.16b, %2.16b \n\t"				/* Load middle part */
		"mov	v12.16b, %3.16b \n\t"				/* Load high part */
		"ext	v14.16b, %4.16b, v13.16b, #8 \n\t"	/* Shift middle part for reduction */
		"eor	v11.16b, v11.16b, v14.16b \n\t"		/* Reduce low part with middle */
		"ext	v14.16b, v13.16b, %4.16b, #8 \n\t"	/* Shift middle part for reduction */
		"eor	v12.16b, v12.16b, v14.16b \n\t"		/* Reduce high part with middle */
		"pmull2	v13.1q, v12.2d, %5.2d \n\t"			/* Final reduction step with polynomial */
		"ext	v14.16b, v13.16b, %4.16b, #8 \n\t"	/* Shift for final reduction */
		"eor	v12.16b, v12.16b, v14.16b \n\t"		/* Final reduction part 1 - high */
		"ext	v14.16b, %4.16b, v13.16b, #8 \n\t"	/* Shift for final reduction */
		"eor	v11.16b, v11.16b, v14.16b \n\t"		/* Final reduction part 2 - low */
		"pmull	v13.1q, v12.1d, %5.1d \n\t"			/* Final reduction step with polynomial */
		"eor	v11.16b, v11.16b, v13.16b \n\t"		/* Final reduction part 3 - low */
		"mov	%0.16b, v11.16b \n\t"				/* Move final reduced result to r */
		: "=w"(r)
		: "w"(lo), "w"(mid), "w"(hi), "w"(z), "w"(p)
		: "v11","v12","v13","v14"
	);
	return (r);
}

/**
 * @brief	Single AES block encryption using NEON instructions
 * @param	input	Plaintext block
 * @param	rk	Round keys in NEON format (vrev32q_u8)
 * @param	nr	Number of rounds (10/12/14)
 * @return		Ciphertext block
 */
static inline __attribute__((always_inline, target("aes")))
uint8x16_t aesEncryptOneNeon(uint8x16_t input, const uint8x16_t *rk, int nr)
{
	for (int r = 0; r < nr - 1; ++r) {
		input = vaesmcq_u8(vaeseq_u8(input, rk[r]));
	}
	input = veorq_u8(vaeseq_u8(input, rk[nr - 1]), rk[nr]);
	return (input);
}

/**
 * @brief	Process 8 blocks in parallel with GHASH accumulation
 * @param	acc	Current GHASH accumulator (modified)
 * @param	in	Input plaintext blocks
 * @param	out	Output ciphertext blocks
 * @param	rk	Round keys
 * @param	nr	Number of rounds
 * @param	pctr	Counter value (modified)
 * @param	Hp	Precomputed H^1..H^8 in bit-reflected domain
 * @note	Accumulates using Karatsuba without reduction per block
 */
__attribute__((target("aes")))
static void gcm8Blocks(uint8x16_t		*acc,
					   const uint8_t	*in,
					   uint8_t			*out,
					   const uint8x16_t	*rk,
					   int				nr,
					   uint8x16_t		*pctr,
					   const uint8x16_t	Hp[8])
{
	uint8x16_t	c0 = *pctr;
	uint8x16_t	c1 = ctrIncNeon(c0, 1), c2 = ctrIncNeon(c0, 2);
	uint8x16_t	c3 = ctrIncNeon(c0, 3), c4 = ctrIncNeon(c0, 4);
	uint8x16_t	c5 = ctrIncNeon(c0, 5), c6 = ctrIncNeon(c0, 6);
	uint8x16_t	c7 = ctrIncNeon(c0, 7);
	*pctr = ctrIncNeon(c0, 8);

	/* Encrypt all 8 blocks in parallel */
	for (int r = 0; r < nr - 1; r++) {
		uint8x16_t k = rk[r];
		c0 = vaesmcq_u8(vaeseq_u8(c0, k));
		c1 = vaesmcq_u8(vaeseq_u8(c1, k));
		c2 = vaesmcq_u8(vaeseq_u8(c2, k));
		c3 = vaesmcq_u8(vaeseq_u8(c3, k));
		c4 = vaesmcq_u8(vaeseq_u8(c4, k));
		c5 = vaesmcq_u8(vaeseq_u8(c5, k));
		c6 = vaesmcq_u8(vaeseq_u8(c6, k));
		c7 = vaesmcq_u8(vaeseq_u8(c7, k));
	}

	/* Final round with AddRoundKey */
	uint8x16_t kp = rk[nr - 1], kf = rk[nr];
	c0 = veorq_u8(vaeseq_u8(c0, kp), kf);
	c1 = veorq_u8(vaeseq_u8(c1, kp), kf);
	c2 = veorq_u8(vaeseq_u8(c2, kp), kf);
	c3 = veorq_u8(vaeseq_u8(c3, kp), kf);
	c4 = veorq_u8(vaeseq_u8(c4, kp), kf);
	c5 = veorq_u8(vaeseq_u8(c5, kp), kf);
	c6 = veorq_u8(vaeseq_u8(c6, kp), kf);
	c7 = veorq_u8(vaeseq_u8(c7, kp), kf);

	c0 = veorq_u8(c0, vld1q_u8(in + 0*16));
	c1 = veorq_u8(c1, vld1q_u8(in + 1*16));
	c2 = veorq_u8(c2, vld1q_u8(in + 2*16));
	c3 = veorq_u8(c3, vld1q_u8(in + 3*16));
	c4 = veorq_u8(c4, vld1q_u8(in + 4*16));
	c5 = veorq_u8(c5, vld1q_u8(in + 5*16));
	c6 = veorq_u8(c6, vld1q_u8(in + 6*16));
	c7 = veorq_u8(c7, vld1q_u8(in + 7*16));

	/* Store ciphertext blocks */
	vst1q_u8(out + 0*16, c0); vst1q_u8(out + 1*16, c1);
	vst1q_u8(out + 2*16, c2); vst1q_u8(out + 3*16, c3);
	vst1q_u8(out + 4*16, c4); vst1q_u8(out + 5*16, c5);
	vst1q_u8(out + 6*16, c6); vst1q_u8(out + 7*16, c7);

	/* Convert ciphertext blocks to bit-reflected domain for GHASH */
	c0 = vrbitq_u8(c0); c1 = vrbitq_u8(c1);
	c2 = vrbitq_u8(c2); c3 = vrbitq_u8(c3);
	c4 = vrbitq_u8(c4); c5 = vrbitq_u8(c5);
	c6 = vrbitq_u8(c6); c7 = vrbitq_u8(c7);

	/* Accumulate GHASH using Karatsuba without reduction for each block */
	uint8x16_t sum_lo = vdupq_n_u8(0);
	uint8x16_t sum_mid = vdupq_n_u8(0);
	uint8x16_t sum_hi = vdupq_n_u8(0);
	uint8x16_t lo, mid, hi;

	/* Process blocks in reverse order for better accumulation */
	gcmMulNoreduce(veorq_u8(*acc, c0), Hp[7], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c1, Hp[6], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c2, Hp[5], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c3, Hp[4], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c4, Hp[3], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c5, Hp[2], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c6, Hp[1], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c7, Hp[0], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	/* Final reduction to get new GHASH accumulator */
	*acc = gcmReduce(sum_lo, sum_mid, sum_hi);
}

/**
 * @brief	Process 4 blocks in parallel with GHASH accumulation
 * @param	acc	Current GHASH accumulator (modified)
 * @param	in	Input plaintext blocks
 * @param	out	Output ciphertext blocks
 * @param	rk	Round keys
 * @param	nr	Number of rounds
 * @param	pctr	Counter value (modified)
 * @param	Hp	Precomputed H^1..H^8 in bit-reflected domain
 */
__attribute__((target("aes")))
static void gcm4Blocks(uint8x16_t			*acc,
					    const uint8_t		*in,
					    uint8_t				*out,
					    const uint8x16_t	*rk,
					    int					nr,
					    uint8x16_t			*pctr,
					    const uint8x16_t	Hp[8])
{
	uint8x16_t c0 = *pctr;
	uint8x16_t c1 = ctrIncNeon(c0, 1);
	uint8x16_t c2 = ctrIncNeon(c0, 2);
	uint8x16_t c3 = ctrIncNeon(c0, 3);
	*pctr = ctrIncNeon(c0, 4);

	for (int r = 0; r < nr - 1; r++) {
		uint8x16_t k = rk[r];
		c0 = vaesmcq_u8(vaeseq_u8(c0, k));
		c1 = vaesmcq_u8(vaeseq_u8(c1, k));
		c2 = vaesmcq_u8(vaeseq_u8(c2, k));
		c3 = vaesmcq_u8(vaeseq_u8(c3, k));
	}

	uint8x16_t kp = rk[nr - 1], kf = rk[nr];
	c0 = veorq_u8(vaeseq_u8(c0, kp), kf);
	c1 = veorq_u8(vaeseq_u8(c1, kp), kf);
	c2 = veorq_u8(vaeseq_u8(c2, kp), kf);
	c3 = veorq_u8(vaeseq_u8(c3, kp), kf);

	c0 = veorq_u8(c0, vld1q_u8(in + 0*16));
	c1 = veorq_u8(c1, vld1q_u8(in + 1*16));
	c2 = veorq_u8(c2, vld1q_u8(in + 2*16));
	c3 = veorq_u8(c3, vld1q_u8(in + 3*16));

	vst1q_u8(out + 0*16, c0); vst1q_u8(out + 1*16, c1);
	vst1q_u8(out + 2*16, c2); vst1q_u8(out + 3*16, c3);

	c0 = vrbitq_u8(c0); c1 = vrbitq_u8(c1);
	c2 = vrbitq_u8(c2); c3 = vrbitq_u8(c3);

	uint8x16_t sum_lo = vdupq_n_u8(0);
	uint8x16_t sum_mid = vdupq_n_u8(0);
	uint8x16_t sum_hi = vdupq_n_u8(0);
	uint8x16_t lo, mid, hi;

	gcmMulNoreduce(veorq_u8(*acc, c0), Hp[3], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c1, Hp[2], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c2, Hp[1], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	gcmMulNoreduce(c3, Hp[0], &lo, &mid, &hi);
	sum_lo = veorq_u8(sum_lo, lo);
	sum_mid = veorq_u8(sum_mid, mid);
	sum_hi = veorq_u8(sum_hi, hi);

	*acc = gcmReduce(sum_lo, sum_mid, sum_hi);
}

#endif /* __aarch64__ */

/**
 * @brief	Increment GCM counter in big-endian format (bytes 12-15)
 * @param	ctr	Counter value (modified in place)
 * @note	Standard big-endian increment for GCM
 */
static void ctr_inc(uint8_t *ctr)
{
	uint32_t	c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16)
					| ((uint32_t)ctr[14] <<  8) |  ctr[15];
	c++;
	ctr[12] = (c >> 24) & 0xff; ctr[13] = (c >> 16) & 0xff;
	ctr[14] = (c >>  8) & 0xff; ctr[15] =  c        & 0xff;
}

/**
 * @brief	Finish AAD processing by padding and GHASH-ing final block
 * @param	ctx	AES-GCM context
 */
static void ghash_finish_aad(t_aesGcmCtx *ctx)
{
	if (!ctx->aadBufferLen) return;
	uint8_t	blk[16] = {0};

	ft_memcpy(blk, ctx->aadBuffer, ctx->aadBufferLen);
	ghashBlock(ctx, blk);
	ctx->aadBufferLen = 0;
}



/* ------------------ Public API Functions ------------------ */

int aesGcmInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
	 	       const uint8_t		*iv,
			   size_t				ivLen,
			   t_cipherDirection	dir)
{
	t_aesGcmCtx	*ctx = (t_aesGcmCtx *)vctx;
	ft_memset(ctx, 0, sizeof(*ctx));
	ctx->dir = dir;

	ctx->nr = aesExpandKey(key, keyLen, ctx->roundKeys.rk);
	if (!ctx->nr) return (-1);

	uint8_t zero[16] = {0};
	ft_memcpy(ctx->H, zero, 16);
#ifndef __aarch64__
	aesEncryptBlock(ctx->H, ctx->roundKeys.rk, ctx->nr);
#else
	aesProcessBlocksNeon(zero, ctx->H, ctx->roundKeys.rk, 1, ctx->nr, 1);
#endif

	ft_memcpy(ctx->Hpow[0], ctx->H, 16);
	for (int i = 1; i < 8; i++) {
#ifndef __aarch64__
		gfmulStandard(ctx->Hpow[i-1], ctx->H, ctx->Hpow[i]);
#else
		uint8_t tmp[16] = {0};
		ghashNeon(tmp, ctx->H, ctx->Hpow[i-1], 16);
		ft_memcpy(ctx->Hpow[i], tmp, 16);
#endif
	}

#ifdef __aarch64__
	for (int i = 0; i < 8; i++) {
		uint8x16_t v = vld1q_u8(ctx->Hpow[i]);
		vst1q_u8(ctx->Hpow[i], vrbitq_u8(v));
	}
	for (int i = 0; i < 8; i++)
		ft_memcpy(ctx->Hpow8[i], ctx->Hpow[i], 16);
#endif

	if (ivLen == 12) {
		ft_memcpy(ctx->J0, iv, 12);
		ctx->J0[12] = ctx->J0[13] = ctx->J0[14] = 0;
		ctx->J0[15] = 1;
	} else {
		uint8_t y[16] = {0};
		for (size_t pos = 0; pos < ivLen; pos += 16) {
			uint8_t blk[16] = {0};
			size_t n = (ivLen - pos < 16) ? ivLen - pos : 16;
			ft_memcpy(blk, iv + pos, n);
			for (int k = 0; k < 16; k++) y[k] ^= blk[k];
#ifndef __aarch64__
			gfmulStandard(y, ctx->H, y);
#else
			uint8_t tmp[16] = {0};
			ghashNeon(tmp, ctx->H, y, 16);
			ft_memcpy(y, tmp, 16);
#endif
		}
		uint64_t bits = (uint64_t)ivLen * 8;
		uint8_t  lb[16] = {0};
		for (int i = 0; i < 8; i++) lb[8+i] = (bits >> (56 - i*8)) & 0xff;
		for (int k = 0; k < 16; k++) lb[k] ^= y[k];
#ifndef __aarch64__
		gfmulStandard(lb, ctx->H, y);
#else
		ghashNeon(y, ctx->H, lb, 16);
#endif
		ft_memcpy(ctx->J0, y, 16);
	}

#if defined(__aarch64__)
	for (int i = 0; i <= ctx->nr; i++) {
		uint8x16_t k = vld1q_u8((const uint8_t*)&ctx->roundKeys.rk[i * 4]);
		ctx->rk_neon[i] = vrev32q_u8(k);
	}
#endif

	ft_memcpy(ctx->counter, ctx->J0, 16);
	ctr_inc(ctx->counter);

	ft_memset(ctx->ghashState, 0, 16);
	ctx->aadLen = ctx->dataLen = ctx->aadBufferLen = ctx->dataBufferLen = 0;
	return (0);
}

/**
 * @brief	Process additional authenticated data (AAD)
 * @param	vctx	Context pointer
 * @param	aad	AAD buffer
 * @param	aadLen	AAD length in bytes
 * @note	Buffers partial blocks and GHASH-es when full block available
 */
void aesGcmUpdateAAD(void *vctx, const uint8_t *aad, size_t aadLen) {
	if (!aadLen) return;
	t_aesGcmCtx	*ctx = (t_aesGcmCtx *)vctx;
	ctx->aadLen += aadLen;

	for (size_t pos = 0; pos < aadLen; ) {
		size_t space = 16 - ctx->aadBufferLen;
		if (!space) {
			uint8_t	blk[16] = {0};
			ft_memcpy(blk, ctx->aadBuffer, 16);
			ghashBlock(ctx, blk);
			ctx->aadBufferLen = 0;
			space = 16;
		}
		size_t n = (aadLen - pos < space) ? aadLen - pos : space;
		ft_memcpy(ctx->aadBuffer + ctx->aadBufferLen, aad + pos, n);
		ctx->aadBufferLen += n;
		pos += n;
	}
}

#ifdef __aarch64__
__attribute__((target("aes")))
#endif
void aesGcmUpdate(void			*vctx,
				  const uint8_t	*in,	size_t	inLen,
				  uint8_t		*out,	size_t	*outLen)
{
	t_aesGcmCtx	*ctx = (t_aesGcmCtx *)vctx;
	*outLen = inLen;
	if (!inLen) return;

	if (!ctx->dataLen && ctx->aadBufferLen)
		ghash_finish_aad(ctx);
	ctx->dataLen += inLen;

#ifdef __aarch64__

	uint8x16_t	*rk = ctx->rk_neon;

	uint8x16_t Hp[8];
	for (int i = 0; i < 8; i++)
		Hp[i] = vld1q_u8(ctx->Hpow8[i]);

	uint8x16_t ctr_vec = vld1q_u8(ctx->counter);
	uint8x16_t acc_vec = vrbitq_u8(vld1q_u8(ctx->ghashState));

	size_t offset     = 0;
	size_t fullBlocks = inLen / 16;
	size_t remBytes   = inLen % 16;

	while (fullBlocks >= 8) {
		gcm8Blocks(&acc_vec, in + offset, out + offset,
			    rk, ctx->nr, &ctr_vec, Hp);
		offset     += 8 * 16;
		fullBlocks -= 8;
	}

	if (fullBlocks >= 4) {
		gcm4Blocks(&acc_vec, in + offset, out + offset,
			    rk, ctx->nr, &ctr_vec, Hp);
		offset     += 4 * 16;
		fullBlocks -= 4;
	}

	while (fullBlocks--) {
		uint8x16_t plain = vld1q_u8(in + offset);
		uint8x16_t ks = aesEncryptOneNeon(ctr_vec, rk, ctx->nr);
		uint8x16_t cipher = veorq_u8(plain, ks);
		vst1q_u8(out + offset, cipher);

		uint8x16_t ct = vrbitq_u8(cipher);
		acc_vec = gfmulR(veorq_u8(acc_vec, ct), Hp[0]);

		ctr_vec = ctrIncNeon(ctr_vec, 1);
		offset += 16;
	}

	if (remBytes) {
		uint8x16_t plain = vdupq_n_u8(0);
		ft_memcpy((uint8_t*)&plain, in + offset, remBytes);
		uint8x16_t ks = aesEncryptOneNeon(ctr_vec, rk, ctx->nr);
		uint8x16_t cipher = veorq_u8(plain, ks);
		ft_memcpy(out + offset, (uint8_t*)&cipher, remBytes);

		const uint8_t *ct_data = (ctx->dir == CIPHER_ENCRYPT) ? (uint8_t*)&cipher : in + offset;
		uint8x16_t ct_padded = vdupq_n_u8(0);
		ft_memcpy((uint8_t*)&ct_padded, ct_data, remBytes);
		ct_padded = vrbitq_u8(ct_padded);
		acc_vec = gfmulR(veorq_u8(acc_vec, ct_padded), Hp[0]);

		ctr_vec = ctrIncNeon(ctr_vec, 1);
	}

	vst1q_u8(ctx->counter,    ctr_vec);
	vst1q_u8(ctx->ghashState, vrbitq_u8(acc_vec));

#else

	size_t	offset     = 0;
	size_t	fullBlocks = inLen / 16;
	size_t	remBytes   = inLen % 16;

	for (size_t i = 0; i < fullBlocks; i++) {
		uint8_t ks[16];
		ft_memcpy(ks, ctx->counter, 16);
		aesEncryptBlock(ks, ctx->roundKeys.rk, ctx->nr);
		ctr_inc(ctx->counter);
		for (int j = 0; j < 16; j++)
			out[offset + j] = in[offset + j] ^ ks[j];
		const uint8_t *ct = (ctx->dir == CIPHER_ENCRYPT) ? out : in;
		ghashBlock(ctx, ct + offset);
		offset += 16;
	}

	if (remBytes) {
		uint8_t ks[16];
		ft_memcpy(ks, ctx->counter, 16);
		aesEncryptBlock(ks, ctx->roundKeys.rk, ctx->nr);
		ctr_inc(ctx->counter);
		for (size_t j = 0; j < remBytes; j++)
			out[offset + j] = in[offset + j] ^ ks[j];
		const uint8_t *ct = (ctx->dir == CIPHER_ENCRYPT) ? out : in;
		size_t space = 16 - ctx->dataBufferLen;
		size_t copy  = (remBytes < space) ? remBytes : space;
		ft_memcpy(ctx->dataBuffer + ctx->dataBufferLen, ct + offset, copy);
		ctx->dataBufferLen += copy;
		if (ctx->dataBufferLen == 16) {
			ghashBlock(ctx, ctx->dataBuffer);
			ctx->dataBufferLen = 0;
			if (copy < remBytes) {
				ft_memcpy(ctx->dataBuffer, ct + offset + copy, remBytes - copy);
				ctx->dataBufferLen = remBytes - copy;
			}
		}
	}

#endif
}

/**
 * @brief	Finalize GCM and generate authentication tag
 * @param	vctx	Context pointer
 * @param	out	Tag output buffer (16 bytes)
 * @param	outLen	Output length (always 16)
 * @note	GHASH-es lengths, XOR with AES_K(J0) to produce tag
 */
void aesGcmFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesGcmCtx	*ctx = (t_aesGcmCtx *)vctx;
	*outLen = 16;

	ghash_finish_aad(ctx);

	if (ctx->dataBufferLen) {
		uint8_t	blk[16] = {0};
		ft_memcpy(blk, ctx->dataBuffer, ctx->dataBufferLen);
		ghashBlock(ctx, blk);
		ctx->dataBufferLen = 0;
	}

	uint64_t	aadBits  = ctx->aadLen  * 8ULL;
	uint64_t	dataBits = ctx->dataLen * 8ULL;
	uint8_t		lb[16] = {0};
	for (int i = 0; i < 8; i++) {
		lb[i]   = (aadBits  >> (56 - i*8)) & 0xff;
		lb[8+i] = (dataBits >> (56 - i*8)) & 0xff;
	}
	ghashBlock(ctx, lb);

	uint8_t tagMask[16];
	ft_memcpy(tagMask, ctx->J0, 16);
#ifndef __aarch64__
	aesEncryptBlock(tagMask, ctx->roundKeys.rk, ctx->nr);
#else
	aesProcessBlocksNeon(tagMask, tagMask, ctx->roundKeys.rk, 1, ctx->nr, 1);
#endif
	for (int i = 0; i < 16; i++)
		out[i] = ctx->ghashState[i] ^ tagMask[i];
}

int aesGcmVerifyTag(void *vctx, const uint8_t *tag, size_t tagLen)
{
	if (tagLen != 16) return (-1);
	uint8_t computed[16];
	size_t  dummy;
	aesGcmFinal(vctx, computed, &dummy);
	uint8_t diff = 0;
	for (int i = 0; i < 16; i++)
		diff |= computed[i] ^ tag[i];
	return ((diff == 0) ? 0 : -1);
}

void aesGcmFree(void *vctx)
{
	secureZeroMemory(vctx, sizeof(t_aesGcmCtx));
}
