/* src/cipher/des/common.c */

#include "../../../includes/cipher/des.h"
#include "../../../includes/consts/des.h"

void desGenerateSubkeys(uint64_t key, uint64_t subkeys[16])
{
	uint64_t	permKey = 0;
	uint64_t	C = 0, D = 0;
	int			i, j;

	/* PC1: 64 bits -> 56 bits
	 * Permute the key and drop parity bits (8 bits, 1 every 8 bits) */
	for (i = 0; i < 56; i++) {
		int bitPos = g_des_PC1[i] - 1;
		permKey <<= 1;
		permKey |= (key >> (63 - bitPos)) & 1;
	}

	/* Split into C and D */
	C = (permKey >> 28) & 0xFFFFFFF;
	D = permKey & 0xFFFFFFF;

	/* 16 rounds */
	for (i = 0; i < 16; i++) {
		/* Rotations for C and D following the g_des_shifts schedule */
		C = ((C << g_des_shifts[i]) | (C >> (28 - g_des_shifts[i]))) & 0xFFFFFFF;
		D = ((D << g_des_shifts[i]) | (D >> (28 - g_des_shifts[i]))) & 0xFFFFFFF;

		uint64_t CD = (C << 28) | D;

		/* PC2: 56 bits -> 48 bits
		 * Select bits from C and D to form the subkey for this round */
		subkeys[i] = 0;
		for (j = 0; j < 48; j++) {
			int bitPos = g_des_PC2[j] - 1;
			subkeys[i] <<= 1;
			subkeys[i] |= (CD >> (55 - bitPos)) & 1;
		}
	}
}

uint32_t desFeistel(uint32_t R, uint64_t subkey)
{
	uint64_t	expanded = 0;
	uint32_t	result = 0;
	int			i;

	/* Expansion E: 32 bits -> 48 bits
	 * Expand the 32-bit R to 48 bits using the g_des_E table */
	for (i = 0; i < 48; i++) {
		int bitPos = g_des_E[i] - 1;
		expanded <<= 1;
		expanded |= (R >> (31 - bitPos)) & 1;
	}

	/* XOR with subkey */
	expanded ^= subkey;

	/* S-box substitution: 48 bits -> 32 bits
	 * Divide the expanded block into 8 groups of 6 bits and apply the S-boxes */
	for (i = 0; i < 8; i++) {
		uint8_t	sextet = (expanded >> (42 - i * 6)) & 0x3F;
		uint8_t	row = ((sextet & 0x20) >> 4) | (sextet & 1);
		uint8_t	col = (sextet >> 1) & 0xF;
		uint8_t	sbox_out = g_des_S[i][row][col];
		result = (result << 4) | sbox_out;
	}

	/* Permutation P: 32 bits -> 32 bits
	 * Permute the result using the g_des_P table */
	uint32_t permuted = 0;
	for (i = 0; i < 32; i++) {
		int bitPos = g_des_P[i] - 1;
		permuted <<= 1;
		permuted |= (result >> (31 - bitPos)) & 1;
	}

	return (permuted);
}

uint64_t desEncryptBlock(uint64_t block, uint64_t subkeys[16])
{
	uint64_t	permuted = 0;
	uint32_t	L, R;
	int			i;

	/* IP */
	for (i = 0; i < 64; i++) {
		int bitPos = g_des_IP[i] - 1;
		permuted <<= 1;
		permuted |= (block >> (63 - bitPos)) & 1;
	}

	L = (permuted >> 32) & 0xFFFFFFFF;
	R = permuted & 0xFFFFFFFF;

	for (i = 0; i < 16; i++) {
		uint32_t temp = R;
		R = L ^ desFeistel(R, subkeys[i]);
		L = temp;
	}

	uint64_t combined = ((uint64_t)R << 32) | L;

	uint64_t result = 0;
	for (i = 0; i < 64; i++) {
		int bitPos = g_des_FP[i] - 1;
		result <<= 1;
		result |= (combined >> (63 - bitPos)) & 1;
	}

	return (result);
}

uint64_t desDecryptBlock(uint64_t block, uint64_t subkeys[16])
{
	uint64_t reversedKeys[16];
	for (int i = 0; i < 16; i++)
		reversedKeys[i] = subkeys[15 - i];
	return (desEncryptBlock(block, reversedKeys));
}

void desPad(uint8_t *block, size_t len, size_t blockSize)
{
	uint8_t pad = blockSize - len;
	
	for (size_t i = len; i < blockSize; i++)
		block[i] = pad;
}

int desUnpad(uint8_t *block, size_t *len, size_t blockSize)
{
	uint8_t pad = block[blockSize - 1];
	
	/* Check that the padding value is valid */
	if (pad == 0 || pad > blockSize)
		return (-1);
	
	/* Check that the padding bytes are correct */
	for (size_t i = blockSize - pad; i < blockSize; i++)
		if (block[i] != pad)
			return (-1);
	
	*len = blockSize - pad;
	return (0);
}
