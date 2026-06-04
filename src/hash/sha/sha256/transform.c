#include "../../../../includes/consts/sha.h"
#include "../../../../includes/hash/sha/shaCommon.h"


#if defined(__aarch64__) || defined(__ARM_NEON)
#include <arm_neon.h>

static inline void sha256LoadMessage(uint32_t w[16], const uint8_t *data) {
	uint8x16_t v0 = vrev32q_u8(vld1q_u8(data));
	uint8x16_t v1 = vrev32q_u8(vld1q_u8(data + 16));
	uint8x16_t v2 = vrev32q_u8(vld1q_u8(data + 32));
	uint8x16_t v3 = vrev32q_u8(vld1q_u8(data + 48));

	vst1q_u32(w,	  vreinterpretq_u32_u8(v0));
	vst1q_u32(w + 4,  vreinterpretq_u32_u8(v1));
	vst1q_u32(w + 8,  vreinterpretq_u32_u8(v2));
	vst1q_u32(w + 12, vreinterpretq_u32_u8(v3));
}

#else
#include "../../../../includes/utils/bitopts.h"

static inline void sha256LoadMessage(uint32_t w[16], const uint8_t *data) {
	for (int i = 0; i < 16; i++)
		w[i] = load32Be(data + (i << 2));
}
#endif

void sha256Transform(uint32_t state[8], const uint8_t block[64]) {
	uint32_t w[16];
	uint32_t a, b, c, d, e, f, g, h;

	sha256LoadMessage(w, block);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	#define R0(r, k_val) do { \
		uint32_t t1 = h + SHA256_SIGMA1(e) + SHA256_CH(e,f,g) + k_val + w[r]; \
		uint32_t t2 = SHA256_SIGMA0(a) + SHA256_MAJ(a,b,c); \
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; \
	} while(0)

	R0(0, 0x428a2f98); R0(1, 0x71374491); R0(2, 0xb5c0fbcf); R0(3, 0xe9b5dba5);
	R0(4, 0x3956c25b); R0(5, 0x59f111f1); R0(6, 0x923f82a4); R0(7, 0xab1c5ed5);
	R0(8, 0xd807aa98); R0(9, 0x12835b01); R0(10, 0x243185be); R0(11, 0x550c7dc3);
	R0(12, 0x72be5d74); R0(13, 0x80deb1fe); R0(14, 0x9bdc06a7); R0(15, 0xc19bf174);

	#undef R0

	#define R(r) do { \
		uint32_t s0 = SHA256_sigma0(w[(r-15) & 15]); \
		uint32_t s1 = SHA256_sigma1(w[(r-2) & 15]); \
		w[r & 15] = s0 + w[(r-16) & 15] + s1 + w[(r-7) & 15]; \
		uint32_t t1 = h + SHA256_SIGMA1(e) + SHA256_CH(e,f,g) + g_sha256_K[r] + w[r & 15]; \
		uint32_t t2 = SHA256_SIGMA0(a) + SHA256_MAJ(a,b,c); \
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; \
	} while(0)

	R(16); R(17); R(18); R(19); R(20); R(21); R(22); R(23);
	R(24); R(25); R(26); R(27); R(28); R(29); R(30); R(31);
	R(32); R(33); R(34); R(35); R(36); R(37); R(38); R(39);
	R(40); R(41); R(42); R(43); R(44); R(45); R(46); R(47);
	R(48); R(49); R(50); R(51); R(52); R(53); R(54); R(55);
	R(56); R(57); R(58); R(59); R(60); R(61); R(62); R(63);

	#undef R

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
