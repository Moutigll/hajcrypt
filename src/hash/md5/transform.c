#include "../../../includes/consts/md5.h"
#include "../../../includes/hash/md5.h"
#include "../../../includes/utils/bitopts.h"

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
	// Initialize working variables with current state
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];

	// Break the 64-byte block into 16 32-bit words (little-endian)
	uint32_t m[16];
	for (int i = 0; i < 16; i++)
	{
		m[i] = ((uint32_t)block[i*4 + 0]	  ) |
			   ((uint32_t)block[i*4 + 1] <<  8) |
			   ((uint32_t)block[i*4 + 2] << 16) |
			   ((uint32_t)block[i*4 + 3] << 24);
	}

	// --- ROUND 1 ---
	for (int i = 0; i < 16; i++)
	{
		uint32_t tmp = a + ((b & c) | (~b & d)) + g_MD5_K[i] + m[i];
		a = d;
		d = c;
		c = b;
		b = b + rotateLeft(tmp, g_MD5_S[i]);
	}

	// --- ROUND 2 ---
	for (int i = 16; i < 32; i++)
	{
		uint32_t g = (5*i + 1) & 15;
		uint32_t tmp = a + ((b & d) | (c & ~d)) + g_MD5_K[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + rotateLeft(tmp, g_MD5_S[i]);
	}

	// --- ROUND 3 ---
	for (int i = 32; i < 48; i++)
	{
		uint32_t g = (3*i + 5) & 15;
		uint32_t tmp = a + (b ^ c ^ d) + g_MD5_K[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + rotateLeft(tmp, g_MD5_S[i]);
	}

	// --- ROUND 4 ---
	for (int i = 48; i < 64; i++)
	{
		uint32_t g = (7*i) & 15;
		uint32_t tmp = a + (c ^ (b | ~d)) + g_MD5_K[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + rotateLeft(tmp, g_MD5_S[i]);
	}

	// Feed-forward: add the transformed values back to the current state
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
