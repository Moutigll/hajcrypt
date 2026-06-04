#include "../../../../includes/consts/sha.h"
#include "../../../../includes/hash/sha/shaCommon.h"


#if defined(__aarch64__) || defined(__ARM_NEON)
#include <arm_neon.h>

static inline void sha512LoadMessage(uint64_t w[16], const uint8_t *data) {
	uint8x16_t v0 = vrev64q_u8(vld1q_u8(data));
	uint8x16_t v1 = vrev64q_u8(vld1q_u8(data + 16));
	uint8x16_t v2 = vrev64q_u8(vld1q_u8(data + 32));
	uint8x16_t v3 = vrev64q_u8(vld1q_u8(data + 48));
	uint8x16_t v4 = vrev64q_u8(vld1q_u8(data + 64));
	uint8x16_t v5 = vrev64q_u8(vld1q_u8(data + 80));
	uint8x16_t v6 = vrev64q_u8(vld1q_u8(data + 96));
	uint8x16_t v7 = vrev64q_u8(vld1q_u8(data + 112));

	vst1q_u64((uint64_t*)(w),		vreinterpretq_u64_u8(v0));
	vst1q_u64((uint64_t*)(w + 2),	vreinterpretq_u64_u8(v1));
	vst1q_u64((uint64_t*)(w + 4),	vreinterpretq_u64_u8(v2));
	vst1q_u64((uint64_t*)(w + 6),	vreinterpretq_u64_u8(v3));
	vst1q_u64((uint64_t*)(w + 8),	vreinterpretq_u64_u8(v4));
	vst1q_u64((uint64_t*)(w + 10),	vreinterpretq_u64_u8(v5));
	vst1q_u64((uint64_t*)(w + 12),	vreinterpretq_u64_u8(v6));
	vst1q_u64((uint64_t*)(w + 14),	vreinterpretq_u64_u8(v7));
}

#else

#include "../../../../includes/utils/bitopts.h"

static inline void sha512LoadMessage(uint64_t w[16], const uint8_t *data) {
	for (int i = 0; i < 16; i++)
		w[i] = load64Be(data + (i << 3));
}

#endif

void sha512Transform(uint64_t state[8], const uint8_t block[128]) {
	uint64_t w[16];
	uint64_t a, b, c, d, e, f, g, h;

	sha512LoadMessage(w, block);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	#define ROUND_EARLY(r, k_val) do { \
		uint64_t t1 = h + SHA512_SIGMA1(e) + SHA512_CH(e,f,g) + k_val + w[r]; \
		uint64_t t2 = SHA512_SIGMA0(a) + SHA512_MAJ(a,b,c); \
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; \
	} while(0)
	
	ROUND_EARLY(0, 0x428a2f98d728ae22ULL);  ROUND_EARLY(1, 0x7137449123ef65cdULL);
	ROUND_EARLY(2, 0xb5c0fbcfec4d3b2fULL);  ROUND_EARLY(3, 0xe9b5dba58189dbbcULL);
	ROUND_EARLY(4, 0x3956c25bf348b538ULL);  ROUND_EARLY(5, 0x59f111f1b605d019ULL);
	ROUND_EARLY(6, 0x923f82a4af194f9bULL);  ROUND_EARLY(7, 0xab1c5ed5da6d8118ULL);
	ROUND_EARLY(8, 0xd807aa98a3030242ULL);  ROUND_EARLY(9, 0x12835b0145706fbeULL);
	ROUND_EARLY(10, 0x243185be4ee4b28cULL); ROUND_EARLY(11, 0x550c7dc3d5ffb4e2ULL);
	ROUND_EARLY(12, 0x72be5d74f27b896fULL); ROUND_EARLY(13, 0x80deb1fe3b1696b1ULL);
	ROUND_EARLY(14, 0x9bdc06a725c71235ULL); ROUND_EARLY(15, 0xc19bf174cf692694ULL);
	
	#undef ROUND_EARLY

	#define ROUND_LATE(r) do { \
		uint64_t s0 = SHA512_sigma0(w[(r-15) & 15]); \
		uint64_t s1 = SHA512_sigma1(w[(r-2) & 15]); \
		w[r & 15] = s0 + w[(r-16) & 15] + s1 + w[(r-7) & 15]; \
\
		uint64_t t1 = h + SHA512_SIGMA1(e) + SHA512_CH(e,f,g) + g_sha512_K[r] + w[r & 15]; \
		uint64_t t2 = SHA512_SIGMA0(a) + SHA512_MAJ(a,b,c); \
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; \
	} while(0)
	
	ROUND_LATE(16); ROUND_LATE(17); ROUND_LATE(18); ROUND_LATE(19);
	ROUND_LATE(20); ROUND_LATE(21); ROUND_LATE(22); ROUND_LATE(23);
	ROUND_LATE(24); ROUND_LATE(25); ROUND_LATE(26); ROUND_LATE(27);
	ROUND_LATE(28); ROUND_LATE(29); ROUND_LATE(30); ROUND_LATE(31);
	ROUND_LATE(32); ROUND_LATE(33); ROUND_LATE(34); ROUND_LATE(35);
	ROUND_LATE(36); ROUND_LATE(37); ROUND_LATE(38); ROUND_LATE(39);
	ROUND_LATE(40); ROUND_LATE(41); ROUND_LATE(42); ROUND_LATE(43);
	ROUND_LATE(44); ROUND_LATE(45); ROUND_LATE(46); ROUND_LATE(47);
	ROUND_LATE(48); ROUND_LATE(49); ROUND_LATE(50); ROUND_LATE(51);
	ROUND_LATE(52); ROUND_LATE(53); ROUND_LATE(54); ROUND_LATE(55);
	ROUND_LATE(56); ROUND_LATE(57); ROUND_LATE(58); ROUND_LATE(59);
	ROUND_LATE(60); ROUND_LATE(61); ROUND_LATE(62); ROUND_LATE(63);
	ROUND_LATE(64); ROUND_LATE(65); ROUND_LATE(66); ROUND_LATE(67);
	ROUND_LATE(68); ROUND_LATE(69); ROUND_LATE(70); ROUND_LATE(71);
	ROUND_LATE(72); ROUND_LATE(73); ROUND_LATE(74); ROUND_LATE(75);
	ROUND_LATE(76); ROUND_LATE(77); ROUND_LATE(78); ROUND_LATE(79);
	
	#undef ROUND_LATE

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
