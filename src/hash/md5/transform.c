#include "../../../includes/consts/md5.h"
#include "../../../includes/hash/md5.h"
#include "../../../includes/utils/bitopts.h"

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

/*
 * The md5Transform function processes a single 64-byte block of the message and updates
 * the current state (A, B, C, D). The algorithm consists of four main rounds, each
 * using a different nonlinear function (F, G, H, I)
 * (nonlinear meaning you can't express the output as a linear combination of the inputs,
 * 	it involves bitwise operations that create complex dependencies between bits)
 * to mix the data with a series of
 * constants derived from the sine function (g_MD5_K) and with left rotations
 * (g_MD5_S) to ensure diffusion.
 *
 * Step-by-step process:
 * 1. Initialize four 32-bit working variables (a, b, c, d) from the current state.
 * 2. Split the 64-byte input block into sixteen 32-bit words in little-endian format.
 * 3. Perform 64 operations divided into four rounds:
 *	- Round 1 uses F = (B & C) | (~B & D)
 *	- Round 2 uses G = (B & D) | (C & ~D)
 *	- Round 3 uses H = B ^ C ^ D
 *	- Round 4 uses I = C ^ (B | ~D)
 *	Each operation combines one of the 16 message words, a constant, and a rotated sum.
 * 4. After all 64 steps, the working variables are added back to the state (feed-forward),
 *	so the next block continues the accumulation.
 *
 * This structure ensures that small changes in the input propagate quickly through the
 * internal state, providing the avalanche effect characteristic of cryptographic hashes.
 *
 * Note: MD5 is widely used for checksums and non-security-critical applications, but it
 * is considered cryptographically broken for security purposes.
 */
void md5Transform(uint32_t state[4], const uint8_t block[64])
{
	/* Initialize working variables with current state */
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];

	/* Break the 64-byte block into 16 32-bit words (little-endian) */
	uint32_t m[16];
	for (int i = 0; i < 16; i++)
	{
		m[i] = ((uint32_t)block[i*4 + 0]	  ) |
			   ((uint32_t)block[i*4 + 1] <<  8) |
			   ((uint32_t)block[i*4 + 2] << 16) |
			   ((uint32_t)block[i*4 + 3] << 24);
	}

	/* Write everything inline for better performance (avoid function call overhead) */
	a = b + rotateLeft(a + F(b, c, d) + m[ 0] + g_MD5_K[ 0], g_MD5_S[ 0]);
	d = a + rotateLeft(d + F(a, b, c) + m[ 1] + g_MD5_K[ 1], g_MD5_S[ 1]);
	c = d + rotateLeft(c + F(d, a, b) + m[ 2] + g_MD5_K[ 2], g_MD5_S[ 2]);
	b = c + rotateLeft(b + F(c, d, a) + m[ 3] + g_MD5_K[ 3], g_MD5_S[ 3]);
	a = b + rotateLeft(a + F(b, c, d) + m[ 4] + g_MD5_K[ 4], g_MD5_S[ 4]);
	d = a + rotateLeft(d + F(a, b, c) + m[ 5] + g_MD5_K[ 5], g_MD5_S[ 5]);
	c = d + rotateLeft(c + F(d, a, b) + m[ 6] + g_MD5_K[ 6], g_MD5_S[ 6]);
	b = c + rotateLeft(b + F(c, d, a) + m[ 7] + g_MD5_K[ 7], g_MD5_S[ 7]);
	a = b + rotateLeft(a + F(b, c, d) + m[ 8] + g_MD5_K[ 8], g_MD5_S[ 8]);
	d = a + rotateLeft(d + F(a, b, c) + m[ 9] + g_MD5_K[ 9], g_MD5_S[ 9]);
	c = d + rotateLeft(c + F(d, a, b) + m[10] + g_MD5_K[10], g_MD5_S[10]);
	b = c + rotateLeft(b + F(c, d, a) + m[11] + g_MD5_K[11], g_MD5_S[11]);
	a = b + rotateLeft(a + F(b, c, d) + m[12] + g_MD5_K[12], g_MD5_S[12]);
	d = a + rotateLeft(d + F(a, b, c) + m[13] + g_MD5_K[13], g_MD5_S[13]);
	c = d + rotateLeft(c + F(d, a, b) + m[14] + g_MD5_K[14], g_MD5_S[14]);
	b = c + rotateLeft(b + F(c, d, a) + m[15] + g_MD5_K[15], g_MD5_S[15]);

	a = b + rotateLeft(a + G(b, c, d) + m[ 1] + g_MD5_K[16], g_MD5_S[16]);
	d = a + rotateLeft(d + G(a, b, c) + m[ 6] + g_MD5_K[17], g_MD5_S[17]);
	c = d + rotateLeft(c + G(d, a, b) + m[11] + g_MD5_K[18], g_MD5_S[18]);
	b = c + rotateLeft(b + G(c, d, a) + m[ 0] + g_MD5_K[19], g_MD5_S[19]);
	a = b + rotateLeft(a + G(b, c, d) + m[ 5] + g_MD5_K[20], g_MD5_S[20]);
	d = a + rotateLeft(d + G(a, b, c) + m[10] + g_MD5_K[21], g_MD5_S[21]);
	c = d + rotateLeft(c + G(d, a, b) + m[15] + g_MD5_K[22], g_MD5_S[22]);
	b = c + rotateLeft(b + G(c, d, a) + m[ 4] + g_MD5_K[23], g_MD5_S[23]);
	a = b + rotateLeft(a + G(b, c, d) + m[ 9] + g_MD5_K[24], g_MD5_S[24]);
	d = a + rotateLeft(d + G(a, b, c) + m[14] + g_MD5_K[25], g_MD5_S[25]);
	c = d + rotateLeft(c + G(d, a, b) + m[ 3] + g_MD5_K[26], g_MD5_S[26]);
	b = c + rotateLeft(b + G(c, d, a) + m[ 8] + g_MD5_K[27], g_MD5_S[27]);
	a = b + rotateLeft(a + G(b, c, d) + m[13] + g_MD5_K[28], g_MD5_S[28]);
	d = a + rotateLeft(d + G(a, b, c) + m[ 2] + g_MD5_K[29], g_MD5_S[29]);
	c = d + rotateLeft(c + G(d, a, b) + m[ 7] + g_MD5_K[30], g_MD5_S[30]);
	b = c + rotateLeft(b + G(c, d, a) + m[12] + g_MD5_K[31], g_MD5_S[31]);

	a = b + rotateLeft(a + H(b, c, d) + m[ 5] + g_MD5_K[32], g_MD5_S[32]);
	d = a + rotateLeft(d + H(a, b, c) + m[ 8] + g_MD5_K[33], g_MD5_S[33]);
	c = d + rotateLeft(c + H(d, a, b) + m[11] + g_MD5_K[34], g_MD5_S[34]);
	b = c + rotateLeft(b + H(c, d, a) + m[14] + g_MD5_K[35], g_MD5_S[35]);
	a = b + rotateLeft(a + H(b, c, d) + m[ 1] + g_MD5_K[36], g_MD5_S[36]);
	d = a + rotateLeft(d + H(a, b, c) + m[ 4] + g_MD5_K[37], g_MD5_S[37]);
	c = d + rotateLeft(c + H(d, a, b) + m[ 7] + g_MD5_K[38], g_MD5_S[38]);
	b = c + rotateLeft(b + H(c, d, a) + m[10] + g_MD5_K[39], g_MD5_S[39]);
	a = b + rotateLeft(a + H(b, c, d) + m[13] + g_MD5_K[40], g_MD5_S[40]);
	d = a + rotateLeft(d + H(a, b, c) + m[ 0] + g_MD5_K[41], g_MD5_S[41]);
	c = d + rotateLeft(c + H(d, a, b) + m[ 3] + g_MD5_K[42], g_MD5_S[42]);
	b = c + rotateLeft(b + H(c, d, a) + m[ 6] + g_MD5_K[43], g_MD5_S[43]);
	a = b + rotateLeft(a + H(b, c, d) + m[ 9] + g_MD5_K[44], g_MD5_S[44]);
	d = a + rotateLeft(d + H(a, b, c) + m[12] + g_MD5_K[45], g_MD5_S[45]);
	c = d + rotateLeft(c + H(d, a, b) + m[15] + g_MD5_K[46], g_MD5_S[46]);
	b = c + rotateLeft(b + H(c, d, a) + m[ 2] + g_MD5_K[47], g_MD5_S[47]);

	a = b + rotateLeft(a + I(b, c, d) + m[ 0] + g_MD5_K[48], g_MD5_S[48]);
	d = a + rotateLeft(d + I(a, b, c) + m[ 7] + g_MD5_K[49], g_MD5_S[49]);
	c = d + rotateLeft(c + I(d, a, b) + m[14] + g_MD5_K[50], g_MD5_S[50]);
	b = c + rotateLeft(b + I(c, d, a) + m[ 5] + g_MD5_K[51], g_MD5_S[51]);
	a = b + rotateLeft(a + I(b, c, d) + m[12] + g_MD5_K[52], g_MD5_S[52]);
	d = a + rotateLeft(d + I(a, b, c) + m[ 3] + g_MD5_K[53], g_MD5_S[53]);
	c = d + rotateLeft(c + I(d, a, b) + m[10] + g_MD5_K[54], g_MD5_S[54]);
	b = c + rotateLeft(b + I(c, d, a) + m[ 1] + g_MD5_K[55], g_MD5_S[55]);
	a = b + rotateLeft(a + I(b, c, d) + m[ 8] + g_MD5_K[56], g_MD5_S[56]);
	d = a + rotateLeft(d + I(a, b, c) + m[15] + g_MD5_K[57], g_MD5_S[57]);
	c = d + rotateLeft(c + I(d, a, b) + m[ 6] + g_MD5_K[58], g_MD5_S[58]);
	b = c + rotateLeft(b + I(c, d, a) + m[13] + g_MD5_K[59], g_MD5_S[59]);
	a = b + rotateLeft(a + I(b, c, d) + m[ 4] + g_MD5_K[60], g_MD5_S[60]);
	d = a + rotateLeft(d + I(a, b, c) + m[11] + g_MD5_K[61], g_MD5_S[61]);
	c = d + rotateLeft(c + I(d, a, b) + m[ 2] + g_MD5_K[62], g_MD5_S[62]);
	b = c + rotateLeft(b + I(c, d, a) + m[ 9] + g_MD5_K[63], g_MD5_S[63]);

	/* Feed-forward: add the transformed values back to the current state */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
