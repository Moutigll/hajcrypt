#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../hajlib/include/galloisField.h"

#include "../../../includes/cipher/aes.h"
#include "../../../includes/consts/aes.h"

/* ---------- Key expansion ---------- */

uint32_t aesExpandKey(const uint8_t *key, size_t keyLen, uint32_t roundKeys[60])
{
	uint32_t nbRounds;
	uint32_t i;
	uint32_t temp;
	const uint32_t *rcon = g_aes_rcon;

	switch (keyLen) {
		case AES_KEY_SIZE_128:
			nbRounds = AES_ROUNDS_128; break;
		case AES_KEY_SIZE_192:
			nbRounds = AES_ROUNDS_192; break;
		case AES_KEY_SIZE_256:
			nbRounds = AES_ROUNDS_256; break;
		default:
			return 0;
	}

	for (i = 0; i < keyLen / 4; i++) {
		roundKeys[i] = ((uint32_t)key[4*i] << 24) |
					   ((uint32_t)key[4*i+1] << 16) |
					   ((uint32_t)key[4*i+2] << 8)  |
					   ((uint32_t)key[4*i+3]);
	}

	for (i = keyLen / 4; i < 4 * (nbRounds + 1); i++) {
		temp = roundKeys[i-1];
		if (i % (keyLen / 4) == 0) {
			temp = ((uint32_t)g_aes_sbox[(temp >> 16) & 0xFF] << 24) |
				   ((uint32_t)g_aes_sbox[(temp >>  8) & 0xFF] << 16) |
				   ((uint32_t)g_aes_sbox[(temp      ) & 0xFF] <<  8) |
				   ((uint32_t)g_aes_sbox[(temp >> 24) & 0xFF]);
			temp ^= rcon[i / (keyLen / 4)];
		} else if ((keyLen / 4) == 8 && i % 8 == 4) {
			temp = ((uint32_t)g_aes_sbox[(temp >> 24) & 0xFF] << 24) |
				   ((uint32_t)g_aes_sbox[(temp >> 16) & 0xFF] << 16) |
				   ((uint32_t)g_aes_sbox[(temp >>  8) & 0xFF] <<  8) |
				   ((uint32_t)g_aes_sbox[(temp      ) & 0xFF]);
		}
		roundKeys[i] = roundKeys[i - (keyLen / 4)] ^ temp;
	}
	return nbRounds;
}

void aesExpandDecryptKeys(const uint32_t *encRoundKeys, uint32_t nbRounds, uint32_t decRoundKeys[60])
{
	uint32_t i, j;

	for (i = 0; i < 4; i++) {
		decRoundKeys[i] = encRoundKeys[i];
		decRoundKeys[4*(nbRounds+1)-4+i] = encRoundKeys[4*(nbRounds+1)-4+i];
	}

	for (i = 4; i < 4 * nbRounds; i += 4) {
		for (j = 0; j < 4; j++) {
			uint32_t w = encRoundKeys[i + j];
			uint8_t a0 = (w >> 24) & 0xFF;
			uint8_t a1 = (w >> 16) & 0xFF;
			uint8_t a2 = (w >>  8) & 0xFF;
			uint8_t a3 = (w	  ) & 0xFF;

			uint32_t res = (ft_gf2nMul(a0, 0x0E, 0x11B, 8) ^
							ft_gf2nMul(a1, 0x0B, 0x11B, 8) ^
							ft_gf2nMul(a2, 0x0D, 0x11B, 8) ^
							ft_gf2nMul(a3, 0x09, 0x11B, 8)) << 24;
			res |= (ft_gf2nMul(a0, 0x09, 0x11B, 8) ^
					ft_gf2nMul(a1, 0x0E, 0x11B, 8) ^
					ft_gf2nMul(a2, 0x0B, 0x11B, 8) ^
					ft_gf2nMul(a3, 0x0D, 0x11B, 8)) << 16;
			res |= (ft_gf2nMul(a0, 0x0D, 0x11B, 8) ^
					ft_gf2nMul(a1, 0x09, 0x11B, 8) ^
					ft_gf2nMul(a2, 0x0E, 0x11B, 8) ^
					ft_gf2nMul(a3, 0x0B, 0x11B, 8)) << 8;
			res |= (ft_gf2nMul(a0, 0x0B, 0x11B, 8) ^
					ft_gf2nMul(a1, 0x0D, 0x11B, 8) ^
					ft_gf2nMul(a2, 0x09, 0x11B, 8) ^
					ft_gf2nMul(a3, 0x0E, 0x11B, 8));
			decRoundKeys[i + j] = res;
		}
	}
}


#ifdef AES_USE_REFERENCE /* REFERENCE IMPLEMENTATION (byte-oriented) */

static void addRoundKey(uint8_t state[4][4], const uint32_t *roundKey)
{
	for (int i = 0; i < 4; i++) {
		uint32_t w = roundKey[i];
		state[0][i] ^= (w >> 24) & 0xFF;
		state[1][i] ^= (w >> 16) & 0xFF;
		state[2][i] ^= (w >>  8) & 0xFF;
		state[3][i] ^= (w	  ) & 0xFF;
	}
}

/* ---------- Decryption helper functions ---------- */

static void invSubBytes(uint8_t state[4][4])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[j][i] = g_aes_inv_sbox[state[j][i]];
}

static void invShiftRows(uint8_t state[4][4])
{
	uint8_t temp;

	/* Row 1: right shift by 1 */
	temp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	/* Row 2: right shift by 2 */
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;
	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	/* Row 3: right shift by 3 (or left shift by 1) */
	temp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;
}

static void invMixColumns(uint8_t state[4][4])
{
	for (int i = 0; i < 4; i++) {
		uint8_t a0 = state[0][i];
		uint8_t a1 = state[1][i];
		uint8_t a2 = state[2][i];
		uint8_t a3 = state[3][i];

		state[0][i] = ft_gf2nMul(a0, 0x0E, 0x11B, 8) ^
					  ft_gf2nMul(a1, 0x0B, 0x11B, 8) ^
					  ft_gf2nMul(a2, 0x0D, 0x11B, 8) ^
					  ft_gf2nMul(a3, 0x09, 0x11B, 8);
		state[1][i] = ft_gf2nMul(a0, 0x09, 0x11B, 8) ^
					  ft_gf2nMul(a1, 0x0E, 0x11B, 8) ^
					  ft_gf2nMul(a2, 0x0B, 0x11B, 8) ^
					  ft_gf2nMul(a3, 0x0D, 0x11B, 8);
		state[2][i] = ft_gf2nMul(a0, 0x0D, 0x11B, 8) ^
					  ft_gf2nMul(a1, 0x09, 0x11B, 8) ^
					  ft_gf2nMul(a2, 0x0E, 0x11B, 8) ^
					  ft_gf2nMul(a3, 0x0B, 0x11B, 8);
		state[3][i] = ft_gf2nMul(a0, 0x0B, 0x11B, 8) ^
					  ft_gf2nMul(a1, 0x0D, 0x11B, 8) ^
					  ft_gf2nMul(a2, 0x09, 0x11B, 8) ^
					  ft_gf2nMul(a3, 0x0E, 0x11B, 8);
	}
}

/* ---------- Encryption helper functions ---------- */

static void subBytes(uint8_t state[4][4])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[j][i] = g_aes_sbox[state[j][i]];
}

static void shiftRows(uint8_t state[4][4])
{
	uint8_t temp;

	/* Row 1: left shift by 1 */
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	/* Row 2: left shift by 2 */
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;
	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	/* Row 3: left shift by 3 (or right shift by 1) */
	temp = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = temp;
}

static void mixColumns(uint8_t state[4][4])
{
	for (int i = 0; i < 4; i++) {
		uint8_t a0 = state[0][i];
		uint8_t a1 = state[1][i];
		uint8_t a2 = state[2][i];
		uint8_t a3 = state[3][i];

		state[0][i] = ft_gf2nMul(a0, 0x02, 0x11B, 8) ^
					  ft_gf2nMul(a1, 0x03, 0x11B, 8) ^
					  a2 ^ a3;
		state[1][i] = a0 ^
					  ft_gf2nMul(a1, 0x02, 0x11B, 8) ^
					  ft_gf2nMul(a2, 0x03, 0x11B, 8) ^
					  a3;
		state[2][i] = a0 ^ a1 ^
					  ft_gf2nMul(a2, 0x02, 0x11B, 8) ^
					  ft_gf2nMul(a3, 0x03, 0x11B, 8);
		state[3][i] = ft_gf2nMul(a0, 0x03, 0x11B, 8) ^
					  a1 ^ a2 ^
					  ft_gf2nMul(a3, 0x02, 0x11B, 8);
	}
}

void aesEncryptBlock(const uint8_t *in, uint8_t *out, const uint32_t *roundKeys, uint32_t nbRounds)
{
	uint8_t		state[4][4];
	uint32_t	i;
	
	/* Convert input block to state matrix (column-major) */
	for (i = 0; i < 4; i++) {
		state[0][i] = in[4*i];
		state[1][i] = in[4*i+1];
		state[2][i] = in[4*i+2];
		state[3][i] = in[4*i+3];
	}
	
	/* Initial round key addition */
	addRoundKey(state, roundKeys);

	/* Main rounds */
	for (i = 1; i < nbRounds; i++) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, roundKeys + i*4);
	}
	
	/* Final round (no MixColumns) */
	subBytes(state);
	shiftRows(state);
	addRoundKey(state, roundKeys + nbRounds*4);

	/* Convert state back to output block */
	for (i = 0; i < 4; i++) {
		out[4*i]   = state[0][i];
		out[4*i+1] = state[1][i];
		out[4*i+2] = state[2][i];
		out[4*i+3] = state[3][i];
	}
}

void aesDecryptBlock(const uint8_t *in, uint8_t *out,
					 const uint32_t *roundKeys, uint32_t nbRounds)
{
	uint8_t		state[4][4];
	uint32_t	i;

	/* Convert input block to state matrix (column-major) */
	for (i = 0; i < 4; i++) {
		state[0][i] = in[4*i];
		state[1][i] = in[4*i+1];
		state[2][i] = in[4*i+2];
		state[3][i] = in[4*i+3];
	}

	/* Initial round key addition (with last round key) */
	addRoundKey(state, roundKeys + nbRounds*4);

	/* Main rounds (inverse order) */
	for (i = nbRounds-1; i > 0; i--) {
		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, roundKeys + i*4);
		invMixColumns(state);
	}

	/* Final round (no InvMixColumns) */
	invShiftRows(state);
	invSubBytes(state);
	addRoundKey(state, roundKeys);

	/* Convert state back to output block */
	for (i = 0; i < 4; i++) {
		out[4*i]   = state[0][i];
		out[4*i+1] = state[1][i];
		out[4*i+2] = state[2][i];
		out[4*i+3] = state[3][i];
	}
}

/* ---------- OPTIMIZED IMPLEMENTATION (T-tables) ---------- */
#else

void aesEncryptBlock(const uint8_t *in, uint8_t *out, const uint32_t *roundKeys, uint32_t nbRounds)
{
	uint32_t		s0, s1, s2, s3, t0, t1, t2, t3;
	const uint32_t	*rk = roundKeys;

	/* Chargement column-major : chaque mot = une colonne */
	s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | 
		 ((uint32_t)in[2] << 8) | in[3];
	s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | 
		 ((uint32_t)in[6] << 8) | in[7];
	s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | 
		 ((uint32_t)in[10] << 8) | in[11];
	s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | 
		 ((uint32_t)in[14] << 8) | in[15];

	/* Initial round key addition */
	s0 ^= rk[0];
	s1 ^= rk[1];
	s2 ^= rk[2];
	s3 ^= rk[3];

	/* Main rounds */
	for (uint32_t r = 1; r < nbRounds; r++) {
		t0 = g_aes_T0[(s0 >> 24) & 0xFF] ^
			 g_aes_T1[(s1 >> 16) & 0xFF] ^
			 g_aes_T2[(s2 >>  8) & 0xFF] ^
			 g_aes_T3[(s3	  ) & 0xFF] ^ rk[4*r];
		t1 = g_aes_T0[(s1 >> 24) & 0xFF] ^
			 g_aes_T1[(s2 >> 16) & 0xFF] ^
			 g_aes_T2[(s3 >>  8) & 0xFF] ^
			 g_aes_T3[(s0	  ) & 0xFF] ^ rk[4*r+1];
		t2 = g_aes_T0[(s2 >> 24) & 0xFF] ^
			 g_aes_T1[(s3 >> 16) & 0xFF] ^
			 g_aes_T2[(s0 >>  8) & 0xFF] ^
			 g_aes_T3[(s1	  ) & 0xFF] ^ rk[4*r+2];
		t3 = g_aes_T0[(s3 >> 24) & 0xFF] ^
			 g_aes_T1[(s0 >> 16) & 0xFF] ^
			 g_aes_T2[(s1 >>  8) & 0xFF] ^
			 g_aes_T3[(s2	  ) & 0xFF] ^ rk[4*r+3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}

	/* Final round */
	t0 = (((uint32_t)g_aes_sbox[(s0 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_sbox[(s1 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_sbox[(s2 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_sbox[(s3	  ) & 0xFF])) ^ rk[4*nbRounds];
	t1 = (((uint32_t)g_aes_sbox[(s1 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_sbox[(s2 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_sbox[(s3 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_sbox[(s0	  ) & 0xFF])) ^ rk[4*nbRounds+1];
	t2 = (((uint32_t)g_aes_sbox[(s2 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_sbox[(s3 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_sbox[(s0 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_sbox[(s1	  ) & 0xFF])) ^ rk[4*nbRounds+2];
	t3 = (((uint32_t)g_aes_sbox[(s3 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_sbox[(s0 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_sbox[(s1 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_sbox[(s2	  ) & 0xFF])) ^ rk[4*nbRounds+3];

	/* Stockage column-major */
	out[0]  = (t0 >> 24) & 0xFF; out[1]  = (t0 >> 16) & 0xFF;
	out[2]  = (t0 >> 8) & 0xFF;   out[3]  = t0 & 0xFF;
	out[4]  = (t1 >> 24) & 0xFF; out[5]  = (t1 >> 16) & 0xFF;
	out[6]  = (t1 >> 8) & 0xFF;   out[7]  = t1 & 0xFF;
	out[8]  = (t2 >> 24) & 0xFF; out[9]  = (t2 >> 16) & 0xFF;
	out[10] = (t2 >> 8) & 0xFF;   out[11] = t2 & 0xFF;
	out[12] = (t3 >> 24) & 0xFF; out[13] = (t3 >> 16) & 0xFF;
	out[14] = (t3 >> 8) & 0xFF;   out[15] = t3 & 0xFF;
}

void aesDecryptBlock(const uint8_t *in, uint8_t *out,
					 const uint32_t *roundKeys,
					 uint32_t nbRounds)
{
	uint32_t		s0, s1, s2, s3, t0, t1, t2, t3;
	const uint32_t	*rk = roundKeys;
	uint32_t		lastRoundIdx = nbRounds * 4;

	/* Column-major loading */
	s0 = ((uint32_t)in[0]  << 24) | ((uint32_t)in[1]  << 16) |
		 ((uint32_t)in[2]  <<  8) | in[3];
	s1 = ((uint32_t)in[4]  << 24) | ((uint32_t)in[5]  << 16) |
		 ((uint32_t)in[6]  <<  8) | in[7];
	s2 = ((uint32_t)in[8]  << 24) | ((uint32_t)in[9]  << 16) |
		 ((uint32_t)in[10] <<  8) | in[11];
	s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) |
		 ((uint32_t)in[14] <<  8) | in[15];

	/* Initial AddRoundKey with last round key */
	s0 ^= rk[lastRoundIdx];
	s1 ^= rk[lastRoundIdx + 1];
	s2 ^= rk[lastRoundIdx + 2];
	s3 ^= rk[lastRoundIdx + 3];

	for (uint32_t r = nbRounds - 1; r > 0; r--)
	{
		uint32_t roundKeyIdx = r * 4;

		t0 = g_aes_Ti0[(s0 >> 24) & 0xFF] ^
			 g_aes_Ti1[(s3 >> 16) & 0xFF] ^
			 g_aes_Ti2[(s2 >>  8) & 0xFF] ^
			 g_aes_Ti3[(s1      ) & 0xFF] ^ rk[roundKeyIdx];
		t1 = g_aes_Ti0[(s1 >> 24) & 0xFF] ^
			 g_aes_Ti1[(s0 >> 16) & 0xFF] ^
			 g_aes_Ti2[(s3 >>  8) & 0xFF] ^
			 g_aes_Ti3[(s2      ) & 0xFF] ^ rk[roundKeyIdx + 1];
		t2 = g_aes_Ti0[(s2 >> 24) & 0xFF] ^
			 g_aes_Ti1[(s1 >> 16) & 0xFF] ^
			 g_aes_Ti2[(s0 >>  8) & 0xFF] ^
			 g_aes_Ti3[(s3      ) & 0xFF] ^ rk[roundKeyIdx + 2];
		t3 = g_aes_Ti0[(s3 >> 24) & 0xFF] ^
			 g_aes_Ti1[(s2 >> 16) & 0xFF] ^
			 g_aes_Ti2[(s1 >>  8) & 0xFF] ^
			 g_aes_Ti3[(s0      ) & 0xFF] ^ rk[roundKeyIdx + 3];

		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}

	/*
	 * Final round: only InvSubBytes and InvShiftRows (no InvMixColumns)
	 * The bytes are permuted according to InvShiftRows
	 */
	t0 = (((uint32_t)g_aes_inv_sbox[(s0 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_inv_sbox[(s3 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_inv_sbox[(s2 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_inv_sbox[(s1      ) & 0xFF])) ^ rk[0];
	t1 = (((uint32_t)g_aes_inv_sbox[(s1 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_inv_sbox[(s0 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_inv_sbox[(s3 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_inv_sbox[(s2      ) & 0xFF])) ^ rk[1];
	t2 = (((uint32_t)g_aes_inv_sbox[(s2 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_inv_sbox[(s1 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_inv_sbox[(s0 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_inv_sbox[(s3      ) & 0xFF])) ^ rk[2];
	t3 = (((uint32_t)g_aes_inv_sbox[(s3 >> 24) & 0xFF] << 24) |
		  ((uint32_t)g_aes_inv_sbox[(s2 >> 16) & 0xFF] << 16) |
		  ((uint32_t)g_aes_inv_sbox[(s1 >>  8) & 0xFF] <<  8) |
		  ((uint32_t)g_aes_inv_sbox[(s0      ) & 0xFF])) ^ rk[3];

	/* Store back column-major */
	out[0]  = (t0 >> 24) & 0xFF;
	out[1]  = (t0 >> 16) & 0xFF;
	out[2]  = (t0 >> 8)  & 0xFF;
	out[3]  = t0 & 0xFF;
	out[4]  = (t1 >> 24) & 0xFF;
	out[5]  = (t1 >> 16) & 0xFF;
	out[6]  = (t1 >> 8)  & 0xFF;
	out[7]  = t1 & 0xFF;
	out[8]  = (t2 >> 24) & 0xFF;
	out[9]  = (t2 >> 16) & 0xFF;
	out[10] = (t2 >> 8)  & 0xFF;
	out[11] = t2 & 0xFF;
	out[12] = (t3 >> 24) & 0xFF;
	out[13] = (t3 >> 16) & 0xFF;
	out[14] = (t3 >> 8)  & 0xFF;
	out[15] = t3 & 0xFF;
}
#endif /* AES_USE_REFERENCE */
