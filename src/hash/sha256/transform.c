#include "../../../includes/hash/sha256.h"
#include "../../../includes/consts/sha256.h"
#include "../../../includes/utils/bitopts.h"

/**
 * SHA256 logical functions as defined in FIPS PUB 180-4
 * 
 * Ch(x, y, z): Choose function - selects bits from y or z based on x
 *   If a bit in x is 1, the corresponding bit from y is chosen
 *   If a bit in x is 0, the corresponding bit from z is chosen
 * 
 * Maj(x, y, z): Majority function - returns the majority of the three bits
 *   For each bit position, returns 1 if at least two of the three bits are 1
 * 
 * Σ0(x), Σ1(x): Upper-case sigma functions used in compression
 *   These are combinations of rotations used to mix the bits
 * 
 * σ0(x), σ1(x): Lower-case sigma functions used in message schedule expansion
 *   These combine rotations and shifts to generate new message words
 */
#define Ch(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x)	(rotateRight((x), 2) ^ rotateRight((x), 13) ^ rotateRight((x), 22))
#define Sigma1(x)	(rotateRight((x), 6) ^ rotateRight((x), 11) ^ rotateRight((x), 25))
#define sigma0(x)	(rotateRight((x), 7) ^ rotateRight((x), 18) ^ ((x) >> 3))
#define sigma1(x)	(rotateRight((x), 17) ^ rotateRight((x), 19) ^ ((x) >> 10))

/**
 * The sha256Transform function processes a single 64-byte block of the message and updates
 * the current state (A, B, C, D, E, F, G, H). The algorithm consists of 64 rounds divided
 * into two phases:
 *   - Rounds 0-15: Use message words directly from the input block
 *   - Rounds 16-63: Use expanded message words derived from previous words
 * 
 * Each round combines:
 *   - The current state variables
 *   - A message word (either directly from input or expanded)
 *   - A constant from g_sha256_K (derived from the first 32 bits of the fractional parts
 *	 of the cube roots of the first 64 primes)
 * 
 * The round function uses two intermediate values:
 *   T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
 *   T2 = Σ0(a) + Maj(a,b,c)
 * 
 * Then updates the state as:
 *   h = g
 *   g = f
 *   f = e
 *   e = d + T1
 *   d = c
 *   c = b
 *   b = a
 *   a = T1 + T2
 * 
 * This structure ensures that each bit of the input affects many bits of the output
 * (avalanche effect) after multiple rounds.
 * 
 * Step-by-step process:
 * 1. Initialize eight 32-bit working variables (a, b, c, d, e, f, g, h) from current state
 * 2. Prepare message schedule:
 *	- First 16 words come directly from input block (converted to big-endian)
 *	- Next 48 words are derived using: W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
 * 3. Perform 64 rounds of compression using the round function above
 * 4. Add the transformed values back to the state (feed-forward)
 * 
 */
void sha256Transform(uint32_t state[8], const uint8_t block[64])
{
	/* Message schedule array - 64 words (32 bits each) */
	uint32_t w[64];
	
	/* Working variables - hold the current state during compression */
	uint32_t a, b, c, d, e, f, g, h;
	
	/* Temporary values used in each round */
	uint32_t t1, t2;

	/* ------------------------------------------------------------
	 * STEP 1: Prepare message schedule (W[0] through W[63])
	 * ------------------------------------------------------------
	 * First 16 words come directly from the input block
	 * SHA-256 uses big-endian byte order (most significant byte first)
	 */
	for (int i = 0; i < 16; i++)
	{
		w[i] = ((uint32_t)block[i*4 + 0] << 24) |
			   ((uint32_t)block[i*4 + 1] << 16) |
			   ((uint32_t)block[i*4 + 2] <<  8) |
			   ((uint32_t)block[i*4 + 3]);
	}
	
	/* Remaining 48 words are derived from previous words
	 * This expansion creates dependencies between all message bits,
	 * ensuring that changing one bit affects many rounds
	 */
	for (int i = 16; i < 64; i++)
	{
		/* σ1(W[i-2])  + W[i-7] + σ0(W[i-15]) + W[i-16] */
		w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
	}

	/* ------------------------------------------------------------
	 * STEP 2: Initialize working variables with current state
	 * ------------------------------------------------------------
	 */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	/* ------------------------------------------------------------
	 * STEP 3: Perform 64 rounds of compression
	 * ------------------------------------------------------------
	 * Each round updates the working variables using the round function.
	 * The rounds are written inline for maximum performance
	 * (avoids function call overhead and allows compiler optimizations).
	 * 
	 * The constants g_sha256_K[i] provide different bit patterns for each round.
	 */
	
	/* Rounds 0-15: First pass using original message words */
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 0] + w[ 0]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 1] + w[ 1]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 2] + w[ 2]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 3] + w[ 3]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 4] + w[ 4]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 5] + w[ 5]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 6] + w[ 6]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 7] + w[ 7]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 8] + w[ 8]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[ 9] + w[ 9]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[10] + w[10]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[11] + w[11]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[12] + w[12]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[13] + w[13]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[14] + w[14]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[15] + w[15]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[16] + w[16]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[17] + w[17]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[18] + w[18]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[19] + w[19]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[20] + w[20]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[21] + w[21]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[22] + w[22]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[23] + w[23]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[24] + w[24]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[25] + w[25]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[26] + w[26]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[27] + w[27]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[28] + w[28]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[29] + w[29]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[30] + w[30]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[31] + w[31]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[32] + w[32]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[33] + w[33]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[34] + w[34]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[35] + w[35]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[36] + w[36]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[37] + w[37]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[38] + w[38]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[39] + w[39]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[40] + w[40]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[41] + w[41]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[42] + w[42]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[43] + w[43]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[44] + w[44]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[45] + w[45]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[46] + w[46]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[47] + w[47]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[48] + w[48]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[49] + w[49]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[50] + w[50]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[51] + w[51]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[52] + w[52]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[53] + w[53]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[54] + w[54]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[55] + w[55]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[56] + w[56]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[57] + w[57]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[58] + w[58]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[59] + w[59]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[60] + w[60]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[61] + w[61]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[62] + w[62]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	t1 = h + Sigma1(e) + Ch(e, f, g) + g_sha256_K[63] + w[63]; t2 = Sigma0(a) + Maj(a, b, c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

	/* ------------------------------------------------------------
	 * STEP 4: Feed-forward - add the transformed values back to state
	 * ------------------------------------------------------------
	 * This combines the result of this block with the previous state,
	 * ensuring that each block depends on all previous blocks.
	 */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
