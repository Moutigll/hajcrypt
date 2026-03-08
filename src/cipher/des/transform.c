/* src/cipher/des/common.c */

#include "../../../includes/cipher/des.h"
#include "../../../includes/consts/des.h"

#define DES_OPTIMIZED

void desGenerateSubkeys(uint64_t key, uint64_t subkeys[16])
{
	uint64_t	permKey = 0;
	uint64_t	C = 0, D = 0;
	int			i, j;

	/* PC1: 64 bits -> 56 bits */
	for (i = 0; i < 56; i++) {
		int bitPos = g_des_PC1[i] - 1;
		permKey <<= 1;
		permKey |= (key >> (63 - bitPos)) & 1;
	}

	C = (permKey >> 28) & 0xFFFFFFF;
	D = permKey & 0xFFFFFFF;

	for (i = 0; i < 16; i++) {
		C = ((C << g_des_shifts[i]) | (C >> (28 - g_des_shifts[i]))) & 0xFFFFFFF;
		D = ((D << g_des_shifts[i]) | (D >> (28 - g_des_shifts[i]))) & 0xFFFFFFF;

		uint64_t CD = (C << 28) | D;

		subkeys[i] = 0;
		for (j = 0; j < 48; j++) {
			int bitPos = g_des_PC2[j] - 1;
			subkeys[i] <<= 1;
			subkeys[i] |= (CD >> (55 - bitPos)) & 1;
		}
	}
}


#if defined(DES_OPTIMIZED)

uint32_t desFeistel(uint32_t R, uint64_t subkey)
{
	uint8_t bytes[4];
	bytes[0] = R & 0xFF;
	bytes[1] = (R >> 8) & 0xFF;
	bytes[2] = (R >> 16) & 0xFF;
	bytes[3] = (R >> 24) & 0xFF;

	uint64_t expanded = 0;
	expanded |= g_des_E_tab[0][bytes[0]];
	expanded |= g_des_E_tab[1][bytes[1]];
	expanded |= g_des_E_tab[2][bytes[2]];
	expanded |= g_des_E_tab[3][bytes[3]];

	expanded ^= subkey;

	uint32_t result = 0;
	result |= g_des_SP[0][(expanded >> 42) & 0x3F];
	result |= g_des_SP[1][(expanded >> 36) & 0x3F];
	result |= g_des_SP[2][(expanded >> 30) & 0x3F];
	result |= g_des_SP[3][(expanded >> 24) & 0x3F];
	result |= g_des_SP[4][(expanded >> 18) & 0x3F];
	result |= g_des_SP[5][(expanded >> 12) & 0x3F];
	result |= g_des_SP[6][(expanded >> 6) & 0x3F];
	result |= g_des_SP[7][expanded & 0x3F];

	return result;
}


uint64_t desEncryptBlock(uint64_t block, uint64_t subkeys[16])
{
	uint32_t	L, R;
	int			i;

	uint8_t bytes[8];
	for (i = 0; i < 8; i++)
		bytes[i] = (block >> (56 - i * 8)) & 0xFF;
	
	uint64_t permuted = 0;
	permuted |= g_des_ip_lookup[0][bytes[0]];
	permuted |= g_des_ip_lookup[1][bytes[1]];
	permuted |= g_des_ip_lookup[2][bytes[2]];
	permuted |= g_des_ip_lookup[3][bytes[3]];
	permuted |= g_des_ip_lookup[4][bytes[4]];
	permuted |= g_des_ip_lookup[5][bytes[5]];
	permuted |= g_des_ip_lookup[6][bytes[6]];
	permuted |= g_des_ip_lookup[7][bytes[7]];

	L = (permuted >> 32) & 0xFFFFFFFF;
	R = permuted & 0xFFFFFFFF;

	for (i = 0; i < 16; i++) {
		uint32_t temp = R;
		R = L ^ desFeistel(R, subkeys[i]);
		L = temp;
	}

	uint64_t combined = ((uint64_t)R << 32) | L;

	for (i = 0; i < 8; i++)
		bytes[i] = (combined >> (56 - i * 8)) & 0xFF;
	
	uint64_t result = 0;
	result |= g_des_fp_lookup[0][bytes[0]];
	result |= g_des_fp_lookup[1][bytes[1]];
	result |= g_des_fp_lookup[2][bytes[2]];
	result |= g_des_fp_lookup[3][bytes[3]];
	result |= g_des_fp_lookup[4][bytes[4]];
	result |= g_des_fp_lookup[5][bytes[5]];
	result |= g_des_fp_lookup[6][bytes[6]];
	result |= g_des_fp_lookup[7][bytes[7]];

	return (result);
}

#else

uint32_t desFeistel(uint32_t R, uint64_t subkey)
{
	uint64_t	expanded = 0;
	uint32_t	result = 0;
	int			i;

	/* Step 1: Expansion E - 32 bits -> 48 bits
	 * 
	 * The expansion table E takes the 32-bit input and expands it to 48 bits
	 * by duplicating 16 of the bits. The pattern is designed so that each
	 * S-box input depends on bits from multiple S-box outputs in the previous
	 * round, accelerating diffusion through the cipher.
	 * 
	 * The expansion is defined by the g_des_E table where each entry specifies
	 * which bit of R (1-indexed) goes to each position in the 48-bit output.
	 * We build the expanded value bit by bit, shifting left each time.
	 */
	for (i = 0; i < 48; i++) {
		/* Get the source bit position from the expansion table */
		int bitPos = g_des_E[i] - 1;  /* Convert to 0-indexed */
		
		/* Shift the expanded value left to make room for the new bit,
		 * then OR in the bit from R at the specified position.
		 * We extract bits from R using a right shift: (R >> (31 - bitPos))
		 * because bit 31 is the most significant (leftmost) in the 32-bit word.
		 */
		expanded <<= 1;
		expanded |= (R >> (31 - bitPos)) & 1;
	}

	/* Step 2: Key mixing - XOR with the round subkey
	 * 
	 * The expanded value is combined with the 48-bit round subkey.
	 * This is the only place where the key material directly affects
	 * the data in each round. The XOR operation is simple but effective
	 * when combined with the nonlinear S-boxes.
	 */
	expanded ^= subkey;

	/* Step 3: S-box substitution - 48 bits -> 32 bits
	 * 
	 * The 48-bit value after key mixing is split into eight 6-bit chunks.
	 * Each chunk is processed by a different S-box (S1 through S8).
	 * 
	 * The S-boxes are the only nonlinear elements in DES and are crucial
	 * for its security. Each S-box maps 6 input bits to 4 output bits:
	 * 
	 *   - The first and last bits (bits 0 and 5 of the 6-bit chunk)
	 *     form a 2-bit row index (0-3)
	 *   - The middle four bits (bits 1-4) form a 4-bit column index (0-15)
	 *   - The S-box contains a 4×16 matrix of 4-bit values
	 * 
	 * The S-boxes were designed to be resistant to differential
	 * and linear cryptanalysis.
	 */
	for (i = 0; i < 8; i++) {
		/* Extract the 6-bit chunk for this S-box.
		 * The chunks are positioned in the 48-bit expanded value as:
		 *   - Chunk 0: bits 42-47 (most significant 6 bits)
		 *   - Chunk 1: bits 36-41
		 *   - ...
		 *   - Chunk 7: bits 0-5 (least significant 6 bits)
		 * 
		 * We shift right by (42 - i*6) to align the desired 6 bits
		 * with the least significant bits, then mask with 0x3F.
		 */
		uint8_t sextet = (expanded >> (42 - i * 6)) & 0x3F;
		
		/* Compute row (2 bits) and column (4 bits) from the 6-bit input */
		uint8_t row = ((sextet & 0x20) >> 4) | (sextet & 1);  /* bits 5 and 0 */
		uint8_t col = (sextet >> 1) & 0xF;                     /* bits 4-1 */
		
		/* Look up the 4-bit output value in the appropriate S-box */
		uint8_t sbox_out = g_des_S[i][row][col];
		
		/* Concatenate the 4-bit outputs:
		 * Each S-box produces 4 bits; we shift the result left by 4 bits
		 * and OR in the new 4-bit value. This builds the 32-bit result
		 * with S-box 0 occupying the most significant 4 bits and S-box 7
		 * the least significant 4 bits.
		 */
		result = (result << 4) | sbox_out;
	}

	/* Step 4: Permutation P - 32 bits -> 32 bits
	 * 
	 * The 32-bit result from the S-boxes is permuted according to the
	 * P permutation table. This permutation ensures that the output of
	 * each S-box in one round is spread to multiple S-boxes in the next round.
	 * 
	 * The P permutation is a simple bit-level permutation with no expansion
	 * or compression. It is defined by the g_des_P table where each entry
	 * specifies the original position (1-indexed) of each bit in the output.
	 */
	uint32_t permuted = 0;
	for (i = 0; i < 32; i++) {
		/* Get the source bit position from the permutation table */
		int bitPos = g_des_P[i] - 1;  /* Convert to 0-indexed */
		
		/* Build the permuted result bit by bit, shifting left each time.
		 * The source bit comes from the S-box result at position (31 - bitPos),
		 * where bit 31 is the most significant.
		 */
		permuted <<= 1;
		permuted |= (result >> (31 - bitPos)) & 1;
	}

	return permuted;
}

uint64_t desEncryptBlock(uint64_t block, uint64_t subkeys[16])
{
	uint64_t	permuted = 0;
	uint32_t	L, R;
	int			i;

	/* Step 1: Initial Permutation (IP)
	 * 
	 * The IP table rearranges the 64 input bits into a new 64-bit value.
	 * This permutation is fixed and is the same for all DES operations.
	 * While it doesn't add cryptographic strength, it was designed to
	 * facilitate hardware implementation in the 1970s.
	 * 
	 * We build the permuted value bit by bit, shifting left each time.
	 * For each output bit position i, we find which input bit (1-indexed)
	 * should go there from the g_des_IP table, then extract that bit
	 * from the original block.
	 */
	for (i = 0; i < 64; i++) {
		/* Get the source bit position from the IP table */
		int bitPos = g_des_IP[i] - 1;  /* Convert to 0-indexed */
		
		/* Build the permuted result bit by bit.
		 * The source bit is extracted from block at position (63 - bitPos),
		 * where bit 63 is the most significant (leftmost) in the 64-bit block.
		 */
		permuted <<= 1;
		permuted |= (block >> (63 - bitPos)) & 1;
	}

	/* Split the permuted block into left and right halves (each 32 bits) */
	L = (permuted >> 32) & 0xFFFFFFFF;  /* Most significant 32 bits */
	R = permuted & 0xFFFFFFFF;           /* Least significant 32 bits */

	/* Step 2: 16 rounds of Feistel network
	 * 
	 * Each round follows the same pattern:
	 *   newR = L ⊕ F(R, subkey[i])
	 *   newL = R
	 * 
	 * The Feistel structure ensures that the round function F does not
	 * need to be invertible, simplifying the design. The same structure
	 * is used for encryption and decryption, with the subkeys applied
	 * in reverse order for decryption.
	 */
	for (i = 0; i < 16; i++) {
		uint32_t temp = R;                     /* Save current R */
		R = L ^ desFeistel(R, subkeys[i]);     /* New R = L ⊕ F(R, K) */
		L = temp;                               /* New L = old R */
	}

	/* Combine the final halves (note: R comes first, then L)
	 * This is the "swap" after the last round - in a Feistel network,
	 * the final output is (R16 || L16) without swapping.
	 */
	uint64_t combined = ((uint64_t)R << 32) | L;

	/* Step 3: Final Permutation (FP) - inverse of IP
	 * 
	 * The FP table is the inverse of the IP table: applying FP after IP
	 * recovers the original ordering. Like IP, this permutation is fixed
	 * and doesn't affect cryptographic strength.
	 * 
	 * We build the final result bit by bit, using the FP table to determine
	 * which bit of the combined (R16 || L16) block goes to each output position.
	 */
	uint64_t result = 0;
	for (i = 0; i < 64; i++) {
		/* Get the source bit position from the FP table */
		int bitPos = g_des_FP[i] - 1;  /* Convert to 0-indexed */
		
		/* Build the final result bit by bit */
		result <<= 1;
		result |= (combined >> (63 - bitPos)) & 1;
	}

	return result;
}

#endif

uint64_t desDecryptBlock(uint64_t block, uint64_t subkeys[16])
{
	uint64_t reversedKeys[16];
	for (int i = 0; i < 16; i++)
		reversedKeys[i] = subkeys[15 - i];
	return (desEncryptBlock(block, reversedKeys));
}
