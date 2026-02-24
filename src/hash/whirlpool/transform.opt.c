#include "../../../includes/hash/whirlpool.h"
#include "../../../includes/consts/whirlpool.h"


static void whirlpoolRoundOptimized(uint64_t state[8], const uint64_t roundKey[8])
{
	uint64_t temp[8] = {0};
	
	for (int src_col = 0; src_col < 8; src_col++) { /* For each column of the state, we will compute its contribution to the new state using the T-tables */
		for (int row = 0; row < 8; row++) {
			int src_row = (row - src_col + 8) % 8;
			uint8_t byte = (state[src_row] >> (56 - 8 * src_col)) & 0xFF; /* Extract the relevant byte from the state */
			temp[row] ^= g_whirlpool_T[src_col][byte]; /* XOR the contribution from this column using the precomputed T-table */
		}
	}
	
	for (int i = 0; i < 8; i++) /* AddRoundKey: XOR with round key */
		temp[i] ^= roundKey[i];
	
	for (int i = 0; i < 8; i++)
		state[i] = temp[i];
}

void whirlpoolTransformOpt(uint64_t H[8], const uint8_t block[64])
{
	uint64_t K[8], W[8], roundConst[8] = {0};
	int r, i, j;

	/* Initialisation (same as non-optimized) */
	for (i = 0; i < 8; i++) {
		K[i] = H[i];
		
		uint64_t w = 0;
		for (j = 0; j < 8; j++)
			w |= (uint64_t)block[i * 8 + j] << (56 - 8 * j);
		W[i] = w ^ H[i];
	}

	for (r = 0; r < 10; r++) {
		roundConst[0] = g_whirlpool_RC[r];
		whirlpoolRoundOptimized(K, roundConst);
		whirlpoolRoundOptimized(W, K);
	}

	/* Feed-forward (identique) */
	for (i = 0; i < 8; i++) {
		uint64_t w = 0;
		for (j = 0; j < 8; j++)
			w |= (uint64_t)block[i * 8 + j] << (56 - 8 * j);
		H[i] ^= W[i] ^ w;
	}
}
