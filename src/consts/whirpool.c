#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/galloisField.h"  /* Ajouter l'inclusion */

#include "../../includes/consts/consts.h"

/*
 * Whirlpool constant generator
 * 
 * This file generates all necessary constants for the Whirlpool hash function:
 * - S-box (substitution box)
 * - Round constants RC[0..9]
 * - MDS matrix (Maximum Distance Separable)
 * - Initial value (IV)
 * 
 * The constants are generated according to the Whirlpool specification:
 * - S-box: multiplicative inverse in GF(2^8) modulo polynomial 0x11D
 *		  followed by affine transformation (same matrix as AES, constant 0x1F)
 * - Round constants: first 80 bytes of S-box, grouped in 8-byte chunks (big-endian)
 * - MDS matrix: circulant matrix based on [0x01,0x01,0x04,0x01,0x08,0x05,0x02,0x09]
 * - IV: all zeros (standard for Whirlpool)
 */

/* Whirlpool polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1 (0x11D) */
#define WHIRLPOOL_POLY 0x11D

/* Affine transformation constant (same as AES, but with 0x1F instead of 0x63) */
#define WHIRLPOOL_AFFINE_CONST 0x1F

/* AES matrix for affine transformation (same for Whirlpool) */
static const uint64_t gAesMatrix[8] = {
	0x1F, 0x3E, 0x7C, 0xF8, 0xF1, 0xE3, 0xC7, 0x8F
};

/**
 * Generate the circulant MDS matrix
 * 
 * The MDS matrix is circulant: each row is the previous row rotated right by 1.
 * The base vector is [0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09]
 * which was chosen to provide optimal diffusion properties.
 * 
 * @param mds 8x8 output matrix to fill
 */
static void generateMdsMatrix(uint8_t mds[8][8])
{
	/* Base row of the circulant matrix */
	const uint8_t base[8] = {0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09};
	
	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 8; j++)
			/* Each row is the previous row shifted right by 1 */
			mds[i][j] = base[(j - i + 8) % 8];
}

/**
 * Generate Whirlpool constants header file
 * 
 * This function writes a complete C header file with all Whirlpool constants:
 * - S-box: 256 bytes (computed from GF inverse + affine transform)
 * - Round constants: 10 x 64-bit values (big-endian, from S-box bytes 0..79)
 * - MDS matrix: 8x8 byte matrix (circulant)
 * - Initial value: 8 x 64-bit zeros
 * 
 * @param fd File descriptor to write to (must be open for writing)
 * @return 0 on success
 */
int generateWhirlpoolHeader(int fd)
{
	uint8_t	S[256];		  /* S-box storage */
	uint8_t	mds[8][8];	   /* MDS matrix storage */

	ft_dprintf(fd, "#include <stdint.h>\n\n");

	/*
	 * Step 1: Generate the S-box using libgf2n functions
	 * 
	 * For each x in 0..255:
	 *   - If x = 0: S[0] = affine(0)
	 *   - Else: S[x] = affine(inverse(x) in GF(2^8))
	 * 
	 * This construction ensures the S-box has good cryptographic properties:
	 * non-linearity, low differential uniformity, etc.
	 */
	ft_dprintf(fd, "/* Whirlpool S-box */\n");
	ft_dprintf(fd, "/* Generated from GF(2^8) inverse modulo 0x11D */\n");
	ft_dprintf(fd, "/* followed by affine transformation (AES matrix, constant 0x1F) */\n");
	ft_dprintf(fd, "static const uint8_t g_whirlpool_S[256] = {\n");

	/* Compute S-box values using library functions */
	for (int x = 0; x < 256; x++) {
		if (x == 0) {
			/* S[0] = affine(0) */
			S[x] = (uint8_t)ft_gf2nAffine(0, gAesMatrix, WHIRLPOOL_AFFINE_CONST, 8);
		} else {
			/* S[x] = affine(inverse(x)) */
			uint64_t inv = ft_gf2nInv((uint64_t)x, WHIRLPOOL_POLY, 8);
			S[x] = (uint8_t)ft_gf2nAffine(inv, gAesMatrix, WHIRLPOOL_AFFINE_CONST, 8);
		}
	}

	/* Write S-box to file (8 values per line for readability) */
	for (int i = 0; i < 256; i++) {
		if (i % 8 == 0) ft_dprintf(fd, "\t");
		ft_dprintf(fd, "0x%02X", S[i]);
		if (i < 255) ft_dprintf(fd, ",");
		ft_dprintf(fd, (i % 8 == 7) ? "\n" : " ");
	}
	ft_dprintf(fd, "};\n\n");

	/*
	 * Step 2: Generate round constants RC[0..9]
	 * 
	 * Round constants are taken directly from the S-box:
	 * - RC[r] = S[8*r] || S[8*r+1] || ... || S[8*r+7] (concatenation)
	 * - Stored in big-endian order (most significant byte first)
	 * - This uses the first 80 bytes of the S-box (indices 0..79)
	 * 
	 * These constants are XORed with the state in each round
	 * to break symmetry and provide round-dependent randomness.
	 */
	ft_dprintf(fd, "/* Whirlpool round constants RC[0..9] (64-bit, big-endian) */\n");
	ft_dprintf(fd, "/* Generated from first 80 bytes of S-box (indices 0..79) */\n");
	ft_dprintf(fd, "/* Each constant: S[8*r] << 56 | S[8*r+1] << 48 | ... | S[8*r+7] */\n");

	ft_dprintf(fd, "static const uint64_t g_whirlpool_RC[10] = {\n");
	
	for (int r = 0; r < 10; r++) {
		
		uint64_t rc = 0;
		
		for (int j = 0; j < 8; j++) {
			int idx = 8 * r + j;
			uint64_t s_val = S[idx];
			int shift = 56 - 8 * j;
			uint64_t contribution = s_val << shift;
			rc |= contribution;
		}

		ft_dprintf(fd, "\t0x");
		for (int i = 0; i < 8; i++) {
			uint8_t byte = (rc >> (56 - 8 * i)) & 0xFF;
			ft_dprintf(fd, "%02X", byte);
		}
		ft_dprintf(fd, "ULL%s\n", (r == 9) ? "" : ",");
	}

	ft_dprintf(fd, "};\n\n");

	/*
	 * Step 3: Generate MDS matrix
	 * 
	 * The MDS matrix provides optimal diffusion in the linear transformation.
	 * It is circulant, meaning each row is a cyclic shift of the base row.
	 * The base row was chosen to have maximum branch number (9) in GF(2^8).
	 */
	generateMdsMatrix(mds);
	
	ft_dprintf(fd, "/* Whirlpool MDS matrix (8×8) */\n");
	ft_dprintf(fd, "/* Circulant matrix with base row [0x01,0x01,0x04,0x01,0x08,0x05,0x02,0x09] */\n");
	ft_dprintf(fd, "/* Provides optimal diffusion (branch number 9) */\n");
	ft_dprintf(fd, "static const uint8_t g_whirlpool_MDS[8][8] = {\n");
	
	/* Write matrix row by row */
	for (int i = 0; i < 8; i++) {
		ft_dprintf(fd, "\t{");
		for (int j = 0; j < 8; j++) {
			ft_dprintf(fd, "0x%02X", mds[i][j]);
			if (j < 7) ft_dprintf(fd, ", ");
		}
		ft_dprintf(fd, "}%s\n", (i == 7) ? "" : ",");
	}
	ft_dprintf(fd, "};\n\n");

	/*
	 * Step 4: Initial hash value (IV)
	 * 
	 * Whirlpool starts with an initial state of all zeros.
	 * This is standard for most hash functions (like SHA-256 uses
	 * specific non-zero values, but Whirlpool uses zeros).
	 */
	ft_dprintf(fd, "/* Whirlpool initial hash value (IV) */\n");
	ft_dprintf(fd, "/* All zeros (standard for Whirlpool) */\n");
	ft_dprintf(fd, "static const uint64_t g_whirlpool_IV[8] = {\n");
	for (int i = 0; i < 8; i++)
		ft_dprintf(fd, "\t0x0000000000000000ULL%s\n", (i == 7) ? "" : ",");
	ft_dprintf(fd, "};\n\n");

	return (0);
}
