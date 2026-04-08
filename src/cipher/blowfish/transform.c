#include "../../../includes/cipher/blowfish.h"
#include "../../../includes/consts/blowfish.h"

/*
 * Fast F-function for Blowfish working directly on uint8_t arrays
 * Splits the 32-bit input into 4 bytes and applies S-boxes
 */
static inline void	blowfishFFastRaw(const uint8_t x[4], const uint32_t (*S)[256], uint8_t out[4])
{
	uint32_t	result;
	
	result = (S[0][x[0]] + S[1][x[1]]) ^ S[2][x[2]];
	result = result + S[3][x[3]];
	
	out[0] = result >> 24;
	out[1] = result >> 16;
	out[2] = result >> 8;
	out[3] = result;
}

/*
 * XOR two 4-byte arrays
 */
static inline void	xor32(const uint8_t a[4], const uint8_t b[4], uint8_t out[4])
{
	out[0] = a[0] ^ b[0];
	out[1] = a[1] ^ b[1];
	out[2] = a[2] ^ b[2];
	out[3] = a[3] ^ b[3];
}

/*
 * Copy 4 bytes
 */
static inline void	copy32(const uint8_t src[4], uint8_t dst[4])
{
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
}

void blowfishInitState(uint32_t *P, uint32_t (*S)[256])
{
    uint32_t	i;
    uint32_t	j;
 
    for (i = 0; i < 18; i++)
        P[i] = g_blowfish_P_init[i];
 
    for (i = 0; i < 4; i++)
        for (j = 0; j < 256; j++)
            S[i][j] = g_blowfish_S_init[i][j];
}

void	blowfishInitKey(uint32_t *P, uint32_t (*S)[256], const uint8_t *key, size_t keyLen)
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	data;
	uint8_t		currentBlock[8] = {0};
	uint8_t		outBlock[8];

	/* 1. Initialize P and S with standard constants */
	blowfishInitState(P, S);

	/* 2. XOR P-array with key bytes */
	j = 0;
	for (i = 0; i < 18; i++)
	{
		data = ((uint32_t)key[j % keyLen] << 24) |
			   ((uint32_t)key[(j + 1) % keyLen] << 16) |
			   ((uint32_t)key[(j + 2) % keyLen] << 8) |
			   (uint32_t)key[(j + 3) % keyLen];
		P[i] ^= data;
		j = (j + 4) % keyLen;
	}

	/* 3. Replace P-array with encrypted blocks */
	for (i = 0; i < 18; i += 2)
	{
		blowfishEncryptBlock(P, S, currentBlock, outBlock);
		
		P[i] = ((uint32_t)outBlock[0] << 24) | ((uint32_t)outBlock[1] << 16) |
			   ((uint32_t)outBlock[2] << 8) | (uint32_t)outBlock[3];
		P[i + 1] = ((uint32_t)outBlock[4] << 24) | ((uint32_t)outBlock[5] << 16) |
				   ((uint32_t)outBlock[6] << 8) | (uint32_t)outBlock[7];
		
		/* Feedback ciphertext as the next input */
		copy32(outBlock, currentBlock);
		copy32(outBlock + 4, currentBlock + 4);
	}

	/* 4. Replace S-boxes with encrypted blocks */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			blowfishEncryptBlock(P, S, currentBlock, outBlock);
			
			S[i][j] = ((uint32_t)outBlock[0] << 24) | ((uint32_t)outBlock[1] << 16) |
					  ((uint32_t)outBlock[2] << 8) | (uint32_t)outBlock[3];
			S[i][j + 1] = ((uint32_t)outBlock[4] << 24) | ((uint32_t)outBlock[5] << 16) |
						  ((uint32_t)outBlock[6] << 8) | (uint32_t)outBlock[7];
			
			/* Feedback ciphertext as the next input */
			copy32(outBlock, currentBlock);
			copy32(outBlock + 4, currentBlock + 4);
		}
	}
}

/*
 * Encrypt a single 64-bit block using Blowfish
 * Works directly on uint8_t arrays to avoid conversions
 */
void	blowfishEncryptBlock(const uint32_t *P, const uint32_t (*S)[256], const uint8_t in[8], uint8_t out[8])
{
	uint8_t	l[4];
	uint8_t	r[4];
	uint8_t	temp[4];
	uint8_t	p_word[4];
	uint8_t	ffast_out[4];
	int		i;

	/* Split 64-bit block into two 32-bit halves */
	copy32(in, l);
	copy32(in + 4, r);

	/* Convert P[0] to bytes and XOR with l */
	p_word[0] = P[0] >> 24;
	p_word[1] = P[0] >> 16;
	p_word[2] = P[0] >> 8;
	p_word[3] = P[0];
	xor32(l, p_word, l);

	/* 16 rounds of Feistel network */
	for (i = 1; i < 16; i += 2)
	{
		/* Round i: r ^= F(l) ^ P[i] */
		blowfishFFastRaw(l, S, ffast_out);
		p_word[0] = P[i] >> 24;
		p_word[1] = P[i] >> 16;
		p_word[2] = P[i] >> 8;
		p_word[3] = P[i];
		xor32(ffast_out, p_word, ffast_out);
		xor32(r, ffast_out, r);

		/* Round i+1: l ^= F(r) ^ P[i+1] */
		blowfishFFastRaw(r, S, ffast_out);
		p_word[0] = P[i + 1] >> 24;
		p_word[1] = P[i + 1] >> 16;
		p_word[2] = P[i + 1] >> 8;
		p_word[3] = P[i + 1];
		xor32(ffast_out, p_word, ffast_out);
		xor32(l, ffast_out, l);
	}

	/* XOR r with P[17] */
	p_word[0] = P[17] >> 24;
	p_word[1] = P[17] >> 16;
	p_word[2] = P[17] >> 8;
	p_word[3] = P[17];
	xor32(r, p_word, r);

	/* Final swap */
	copy32(l, temp);
	copy32(r, l);
	copy32(temp, r);

	/* Output */
	copy32(l, out);
	copy32(r, out + 4);
}

/*
 * Decrypt a single 64-bit block using Blowfish
 * Works directly on uint8_t arrays to avoid conversions
 */
void	blowfishDecryptBlock(const uint32_t *P, const uint32_t (*S)[256], const uint8_t in[8], uint8_t out[8])
{
	uint8_t	l[4];
	uint8_t	r[4];
	uint8_t	temp[4];
	uint8_t	p_word[4];
	uint8_t	ffast_out[4];
	int		i;

	/* Split 64-bit block into two 32-bit halves */
	copy32(in, l);
	copy32(in + 4, r);

	/* XOR l with P[17] */
	p_word[0] = P[17] >> 24;
	p_word[1] = P[17] >> 16;
	p_word[2] = P[17] >> 8;
	p_word[3] = P[17];
	xor32(l, p_word, l);

	/* Undo the 16 Feistel rounds (P[16] down to P[1]) */
	for (i = 16; i >= 2; i -= 2)
	{
		/* r ^= F(l) ^ P[i] */
		blowfishFFastRaw(l, S, ffast_out);
		p_word[0] = P[i] >> 24;
		p_word[1] = P[i] >> 16;
		p_word[2] = P[i] >> 8;
		p_word[3] = P[i];
		xor32(ffast_out, p_word, ffast_out);
		xor32(r, ffast_out, r);

		/* l ^= F(r) ^ P[i-1] */
		blowfishFFastRaw(r, S, ffast_out);
		p_word[0] = P[i - 1] >> 24;
		p_word[1] = P[i - 1] >> 16;
		p_word[2] = P[i - 1] >> 8;
		p_word[3] = P[i - 1];
		xor32(ffast_out, p_word, ffast_out);
		xor32(l, ffast_out, l);
	}

	/* XOR r with P[0] */
	p_word[0] = P[0] >> 24;
	p_word[1] = P[0] >> 16;
	p_word[2] = P[0] >> 8;
	p_word[3] = P[0];
	xor32(r, p_word, r);

	/* Final swap */
	copy32(l, temp);
	copy32(r, l);
	copy32(temp, r);

	/* Output */
	copy32(l, out);
	copy32(r, out + 4);
}
