#include "../../../hajlib/include/galloisField.h"
#include "../../../includes/consts/whirlpool.h"
#include "../../../includes/hash/whirlpool.h"

static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
	return ft_gf2nMul(a, b, WHIRLPOOL_POLY, 8);
}

/* ------------------------------------------------------------------------- */
/*						   Whirlpool Round Function							 */
/* ------------------------------------------------------------------------- */

/**
 * Performs one round of the Whirlpool block cipher.
 * The round consists of four transformations applied in sequence:
 * 
 * 1. γ (Gamma) - Nonlinear substitution layer
 *	- Each byte of the state is replaced by its image in the S-box
 *	- Provides confusion (nonlinear mixing)
 * 
 * 2. π (Pi) - Cyclical permutation of columns
 *	- Column j is shifted down by j positions (mod 8)
 *	- Provides diffusion between rows
 * 
 * 3. θ (Theta) - Linear diffusion layer
 *	- Each byte is replaced by a linear combination of bytes in the same row
 *	- Uses the MDS matrix multiplication in GF(2^8)
 *	- Provides optimal diffusion (branch number 9)
 * 
 * 4. σ (Sigma) - Key addition
 *	- XOR the state with the round key
 * 
 * @param state	 Current 8×8 state (8 uint64_t, each representing a row)
 * @param roundKey  Round key (8 uint64_t, also in row-major order)
 */
static void whirlpoolRound(uint64_t state[8], const uint64_t roundKey[8])
{
	uint64_t	temp[8];
	int i, j, k;

	/* Step 1: γ - SubBytes (nonlinear substitution) */
	/* Replace each byte of the state by its S-box value.
	 * This is the only nonlinear operation in Whirlpool.
	 * The S-box is designed to have good cryptographic properties:
	 * - High nonlinearity
	 * - Low differential uniformity
	 * - No fixed points (S[x] ≠ x for all x)
	 */
	for (i = 0; i < 8; i++) {
		uint64_t line = state[i];
		uint64_t newLine = 0;
		for (j = 0; j < 8; j++) {
			/* Extract byte j from row i (big-endian: byte 0 = most significant) */
			uint8_t byte = (line >> (56 - 8 * j)) & 0xFF;
			/* Apply S-box */
			byte = g_whirlpool_S[byte];
			/* Place back in same position */
			newLine |= (uint64_t)byte << (56 - 8 * j);
		}
		state[i] = newLine;
	}

	/* Step 2: π - ShiftColumns (cyclical column permutation) */
	/* Each column j is rotated downward by j positions.
	 * This is analogous to AES's ShiftRows but applied to columns.
	 * The permutation ensures that bytes from the same column
	 * are spread to different rows in the next round.
	 */
	for (j = 0; j < 8; j++) {
		/* Extract column j from all rows */
		uint8_t col[8];
		for (i = 0; i < 8; i++)
			col[i] = (state[i] >> (56 - 8 * j)) & 0xFF;

		/* Rotate column j by j positions and place back */
		for (i = 0; i < 8; i++) {
			uint8_t newVal = col[(i - j + 8) % 8];
			temp[i] = (temp[i] & ~((uint64_t)0xFF << (56 - 8 * j))) |
					  ((uint64_t)newVal << (56 - 8 * j));
		}
	}

	/* Copy back to state */
	for (i = 0; i < 8; i++)
		state[i] = temp[i];

	/* Step 3: θ - MixRows (linear diffusion via MDS matrix) */
	/* Each byte in row i is replaced by a linear combination of all
	 * bytes in that row, using the MDS matrix multiplication in GF(2^8).
	 * 
	 * The MDS matrix is circulant: each row is the previous row shifted right:
	 *   C = [ 1 1 4 1 8 5 2 9 ]
	 *		 [ 9 1 1 4 1 8 5 2 ]
	 *		 [ 2 9 1 1 4 1 8 5 ]
	 *		 [ 5 2 9 1 1 4 1 8 ]
	 *		 [ 8 5 2 9 1 1 4 1 ]
	 *		 [ 1 8 5 2 9 1 1 4 ]
	 *		 [ 4 1 8 5 2 9 1 1 ]
	 *		 [ 1 4 1 8 5 2 9 1 ]
	 * 
	 * The multiplication is performed in GF(2^8) using the polynomial 0x11D.
	 * This operation provides optimal diffusion (branch number 9),
	 * meaning that a 1-byte change affects at least 9 bytes after one round.
	 */
	for (i = 0; i < 8; i++) {
		uint64_t newLine = 0;
		for (j = 0; j < 8; j++) {
			uint8_t sum = 0;
			/* Linear combination: sum over k of (state[i][k] * MDS[k][j]) */
			for (k = 0; k < 8; k++) {
				uint8_t val = (state[i] >> (56 - 8 * k)) & 0xFF;
				uint8_t coeff = g_whirlpool_MDS[k][j];
				sum ^= gf256_mul(val, coeff);
			}
			newLine |= (uint64_t)sum << (56 - 8 * j);
		}
		temp[i] = newLine;
	}

	/* Copy back to state */
	for (i = 0; i < 8; i++)
		state[i] = temp[i];

	/* Step 4: σ - AddRoundKey (XOR with round key) */
	/* XOR the entire state with the round key.
	 * This incorporates the round-specific constant into the state.
	 */
	for (i = 0; i < 8; i++)
		state[i] ^= roundKey[i];
}

/* ------------------------------------------------------------------------- */
/*					  Whirlpool Block Transformation						 */
/* ------------------------------------------------------------------------- */

/**
 * Processes a single 512-bit (64-byte) block of the message.
 * Implements the Miyaguchi-Preneel compression function:
 *   H[i] = E(H[i-1], M[i]) ⊕ H[i-1] ⊕ M[i]
 * 
 * Where:
 *   - H[i] is the new hash state
 *   - H[i-1] is the previous hash state (or IV for first block)
 *   - M[i] is the current message block
 *   - E(K, P) is the Whirlpool block cipher (10 rounds)
 * 
 * The algorithm proceeds as follows:
 * 
 * 1. Copy H to K (will become the cipher key)
 * 2. Compute W = M[i] ⊕ H[i-1] (initial cipher input)
 * 3. For rounds 0 to 9:
 *	a. K = whirlpoolRound(K, RC[r])   (update key with round constant)
 *	b. W = whirlpoolRound(W, K)		(update state with current key)
 * 4. H[i] = H[i-1] ⊕ W ⊕ M[i]		   (feed-forward)
 * 
 * This structure ensures that the compression function is
 * collision-resistant and preimage-resistant.
 * 
 * @param H	  Current hash state (8 uint64_t) - will be updated
 * @param block  64-byte message block to process
 */
void whirlpoolTransform(uint64_t H[8], const uint8_t block[64])
{
	uint64_t	K[8];	  /* Key schedule state (evolves through rounds) */
	uint64_t	W[8];	  /* Cipher state (evolves through rounds) */
	uint64_t	roundConst[8];
	int r, i, j;

	/* Step 1: Initialize key and cipher state */

	/* K starts as the previous hash value (will be used as cipher key) */
	for (i = 0; i < 8; i++)
		K[i] = H[i];

	/* W starts as message block XOR previous hash (cipher input) */
	for (i = 0; i < 8; i++) {
		uint64_t w = 0;
		/* Convert 8 bytes of block into a uint64_t (big-endian) */
		for (j = 0; j < 8; j++)
			w |= ((uint64_t)block[i * 8 + j]) << (56 - 8 * j);
		W[i] = w ^ H[i];
	}

	/* Step 2: Perform 10 rounds of the Whirlpool block cipher */
	/* Each round updates both the key (K) and the cipher state (W).
	 * The key is updated using the round constant, then the cipher state
	 * is updated using the new key.
	 */
	for (r = 0; r < 10; r++) {
		/* Prepare round constant - only first row is non-zero */
		roundConst[0] = g_whirlpool_RC[r];
		for (i = 1; i < 8; i++)
			roundConst[i] = 0;

		/* Update key with round constant */
		whirlpoolRound(K, roundConst);

		/* Update cipher state with current key */
		whirlpoolRound(W, K);
	}

	/* Step 3: Feed-forward (Miyaguchi-Preneel) */
	/* Combine previous hash, cipher output, and message block:
	 * H_new = H_old ⊕ W ⊕ M
	 * This ensures that the compression function is reversible and
	 * provides good security properties.
	 */
	for (i = 0; i < 8; i++) {
		uint64_t w = 0;
		/* Recompute message block word (needed for XOR) */
		for (j = 0; j < 8; j++)
			w |= ((uint64_t)block[i * 8 + j]) << (56 - 8 * j);
		H[i] ^= W[i] ^ w;
	}
}
