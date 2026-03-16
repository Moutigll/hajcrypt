#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../includes/consts/consts.h"
#include "../../hajlib/include/galloisField.h"

/*
 * AES S-box as defined in FIPS 197.
 * It is the result of the affine transformation applied to the multiplicative inverse in GF(2^8).
 * This table is provided explicitly to guarantee correctness.
 */
static const uint8_t AES_SBOX[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* ---------- Inverse S-box generation ---------- */

/**
 * @brief Generate the inverse S-box from the given S-box.
 * @param inv_sbox Output array for the inverse S-box (size 256)
 * @param sbox Input S-box
 */
static void generateInvSbox(uint8_t inv_sbox[256], const uint8_t sbox[256])
{
	for (int i = 0; i < 256; i++) {
		inv_sbox[sbox[i]] = (uint8_t)i;
	}
}

static void writeSbox(int fd, const uint8_t sbox[256])
{
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * AES S-box (SubBytes) as defined in FIPS 197.\n");
	ft_dprintf(fd, " */\n");
	ft_dprintf(fd, "static const uint8_t g_aes_sbox[256] = {\n\t");
	for (int i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%02X", sbox[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 16 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");
}

static void writeInvSbox(int fd, const uint8_t inv_sbox[256])
{
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * Inverse AES S-box (InvSubBytes).\n");
	ft_dprintf(fd, " */\n");
	ft_dprintf(fd, "static const uint8_t g_aes_inv_sbox[256] = {\n\t");
	for (int i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%02X", inv_sbox[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 16 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");
}

/* ---------- Round constants (Rcon) ---------- */

/**
 * @brief Generate the round constants Rcon[i] for AES key expansion.
 * Rcon[i] = { x^(i-1), 0x00, 0x00, 0x00 } as a 32-bit word.
 * Multiplication uses the hajlib GF(2^8) functions with polynomial 0x11B.
 */
static void generateRcon(uint32_t rcon[11])
{
	rcon[0] = 0x00000000;  /* unused */
	uint64_t rc = 0x01;
	for (int i = 1; i <= 10; i++) {
		rcon[i] = ((uint32_t)rc) << 24;
		rc = ft_gf2nMul(rc, 0x02, 0x11B, 8);
	}
}

static void writeRcon(int fd, const uint32_t rcon[11])
{
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * Round constants (Rcon) for AES key expansion.\n");
	ft_dprintf(fd, " * Rcon[i] = { x^(i-1), 0x00, 0x00, 0x00 } with x=0x02 in GF(2^8).\n");
	ft_dprintf(fd, " */\n");
	ft_dprintf(fd, "static const uint32_t g_aes_rcon[11] = {\n\t");
	for (int i = 0; i < 11; i++) {
		ft_dprintf(fd, "0x%08X", rcon[i]);
		if (i < 10) ft_dprintf(fd, ",");
		if ((i + 1) % 4 == 0 && i < 10)
			ft_dprintf(fd, "\n\t");
		else if (i < 10)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");
}

/* ---------- MixColumns matrices ---------- */

static void writeMixColumnsMatrices(int fd)
{
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * MixColumns matrix (multiplication in GF(2^8)).\n");
	ft_dprintf(fd, " */\n");
	ft_dprintf(fd, "static const uint8_t g_aes_mixcolumns[4][4] = {\n");
	ft_dprintf(fd, "\t{0x02, 0x03, 0x01, 0x01},\n");
	ft_dprintf(fd, "\t{0x01, 0x02, 0x03, 0x01},\n");
	ft_dprintf(fd, "\t{0x01, 0x01, 0x02, 0x03},\n");
	ft_dprintf(fd, "\t{0x03, 0x01, 0x01, 0x02}\n");
	ft_dprintf(fd, "};\n\n");

	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * Inverse MixColumns matrix.\n");
	ft_dprintf(fd, " */\n");
	ft_dprintf(fd, "static const uint8_t g_aes_inv_mixcolumns[4][4] = {\n");
	ft_dprintf(fd, "\t{0x0E, 0x0B, 0x0D, 0x09},\n");
	ft_dprintf(fd, "\t{0x09, 0x0E, 0x0B, 0x0D},\n");
	ft_dprintf(fd, "\t{0x0D, 0x09, 0x0E, 0x0B},\n");
	ft_dprintf(fd, "\t{0x0B, 0x0D, 0x09, 0x0E}\n");
	ft_dprintf(fd, "};\n\n");
}

/* ---------- T-tables for optimization ---------- */

/**
 * @brief Generate the four T-tables used for fast AES encryption.
 * Each table combines SubBytes, ShiftRows, and MixColumns for one column.
 * T0[x] = (2*S[x], S[x], S[x], 3*S[x]) as a 32-bit word.
 * T1, T2, T3 are rotated versions.
 */
static void generateTtables(int fd, const uint8_t sbox[256])
{
	uint32_t T0[256], T1[256], T2[256], T3[256];
	uint32_t Ti0[256], Ti1[256], Ti2[256], Ti3[256];
	uint8_t inv_sbox[256];
	uint8_t is, is9, isB, isD, isE;
	int i;

	/* Generate inverse S-box first */
	generateInvSbox(inv_sbox, sbox);

	/* Forward T-tables (encryption) */
	for (i = 0; i < 256; i++) {
		uint8_t s = sbox[i];
		uint8_t s2 = (uint8_t)ft_gf2nMul(s, 0x02, 0x11B, 8);
		uint8_t s3 = (uint8_t)ft_gf2nMul(s, 0x03, 0x11B, 8);

		T0[i] = ((uint32_t)s2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | s3;
		T1[i] = ((uint32_t)s3 << 24) | ((uint32_t)s2 << 16) | ((uint32_t)s << 8) | s;
		T2[i] = ((uint32_t)s << 24) | ((uint32_t)s3 << 16) | ((uint32_t)s2 << 8) | s;
		T3[i] = ((uint32_t)s << 24) | ((uint32_t)s << 16) | ((uint32_t)s3 << 8) | s2;
	}

	/**
	 * @brief Generate the inverse T-tables for optimized AES decryption.
	 * These combine InvSubBytes, InvShiftRows, and InvMixColumns.
	 */
	for (i = 0; i < 256; i++) {
		is = inv_sbox[i];
		is9  = (uint8_t)ft_gf2nMul(is, 0x09, 0x11B, 8);
		isB  = (uint8_t)ft_gf2nMul(is, 0x0B, 0x11B, 8);
		isD  = (uint8_t)ft_gf2nMul(is, 0x0D, 0x11B, 8);
		isE  = (uint8_t)ft_gf2nMul(is, 0x0E, 0x11B, 8);

		Ti0[i] = ((uint32_t)isE << 24) | ((uint32_t)is9 << 16) | 
				 ((uint32_t)isD <<  8) | isB;
		Ti1[i] = ((uint32_t)isB << 24) | ((uint32_t)isE << 16) | 
				 ((uint32_t)is9 <<  8) | isD;
		Ti2[i] = ((uint32_t)isD << 24) | ((uint32_t)isB << 16) | 
				 ((uint32_t)isE <<  8) | is9;
		Ti3[i] = ((uint32_t)is9 << 24) | ((uint32_t)isD << 16) | 
				 ((uint32_t)isB <<  8) | isE;
	}

	/* Write all tables... */
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * T-tables for optimized AES encryption.\n");
	ft_dprintf(fd, " * Each table maps an input byte to a 32-bit output.\n");
	ft_dprintf(fd, " */\n");

	/* Forward tables */
	ft_dprintf(fd, "static const uint32_t g_aes_T0[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", T0[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	ft_dprintf(fd, "static const uint32_t g_aes_T1[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", T1[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	ft_dprintf(fd, "static const uint32_t g_aes_T2[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", T2[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	ft_dprintf(fd, "static const uint32_t g_aes_T3[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", T3[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	/* Inverse tables */
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * Inverse T-tables for optimized AES decryption.\n");
	ft_dprintf(fd, " * These combine InvSubBytes, InvShiftRows, and InvMixColumns.\n");
	ft_dprintf(fd, " */\n");

	ft_dprintf(fd, "static const uint32_t g_aes_Ti0[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", Ti0[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	ft_dprintf(fd, "static const uint32_t g_aes_Ti1[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", Ti1[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	ft_dprintf(fd, "static const uint32_t g_aes_Ti2[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", Ti2[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");

	ft_dprintf(fd, "static const uint32_t g_aes_Ti3[256] = {\n\t");
	for (i = 0; i < 256; i++) {
		ft_dprintf(fd, "0x%08X", Ti3[i]);
		if (i < 255) ft_dprintf(fd, ",");
		if ((i + 1) % 8 == 0 && i < 255)
			ft_dprintf(fd, "\n\t");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}
	ft_dprintf(fd, "\n};\n\n");
}

/* ---------- Main generator entry point ---------- */

int generateAesHeader(int fd)
{
	uint8_t inv_sbox[256];
	uint32_t rcon[11];

	ft_dprintf(fd, "#include <stdint.h>\n\n");

	generateInvSbox(inv_sbox, AES_SBOX);
	generateRcon(rcon);

	writeSbox(fd, AES_SBOX);
	writeInvSbox(fd, inv_sbox);
	writeRcon(fd, rcon);
	writeMixColumnsMatrices(fd);
	generateTtables(fd, AES_SBOX);

	return (0);
}
