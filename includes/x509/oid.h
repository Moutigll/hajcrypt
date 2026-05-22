#ifndef HAJCRYPT_OID_H
#define HAJCRYPT_OID_H

#include <stddef.h>
#include <stdint.h>

#define OID_MAX_LEN		16
#define MAX_CIPHER_NAME	64

typedef enum e_oidType
{
	OID_TYPE_NONE = 0,
	OID_TYPE_OID,
	OID_TYPE_OIW
}	t_oidType;

typedef struct
{
	char		name[MAX_CIPHER_NAME];
	t_oidType	type;
	uint8_t		data[OID_MAX_LEN];
	size_t		len;
}	t_algoId;

/* ---------- Macros OID ---------- */
#define OID_NONE			{ .type = OID_TYPE_NONE, .name = "", .data = {0}, .len = 0 }
#define OID_DEF(n, ...)		{ .type = OID_TYPE_OID, .name = n, .data = __VA_ARGS__, .len = sizeof((uint8_t[])__VA_ARGS__) }
#define OIW_DEF(n, ...)		{ .type = OID_TYPE_OIW, .name = n, .data = __VA_ARGS__, .len = sizeof((uint8_t[])__VA_ARGS__) }

/* ==================================================================
 * AES OIDs (NIST) - 2.16.840.1.101.3.4.1.x
 * ================================================================== */
#define AES_OID_PREFIX	0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01

/* AES-128 */
#define AES128_ECB_OID	{ AES_OID_PREFIX, 0x01 }
#define AES128_CBC_OID	{ AES_OID_PREFIX, 0x02 }
#define AES128_OFB_OID	{ AES_OID_PREFIX, 0x03 }
#define AES128_CFB_OID	{ AES_OID_PREFIX, 0x04 }
#define AES128_CTR_OID	{ AES_OID_PREFIX, 0x08 }
#define AES128_PCBC_OID	{ AES_OID_PREFIX, 0x09 }

/* AES-192 */
#define AES192_ECB_OID	{ AES_OID_PREFIX, 0x15 }
#define AES192_CBC_OID	{ AES_OID_PREFIX, 0x16 }
#define AES192_OFB_OID	{ AES_OID_PREFIX, 0x17 }
#define AES192_CFB_OID	{ AES_OID_PREFIX, 0x18 }
#define AES192_CTR_OID	{ AES_OID_PREFIX, 0x1C }
#define AES192_PCBC_OID	{ AES_OID_PREFIX, 0x1D }

/* AES-256 */
#define AES256_ECB_OID	{ AES_OID_PREFIX, 0x29 }
#define AES256_CBC_OID	{ AES_OID_PREFIX, 0x2A }
#define AES256_OFB_OID	{ AES_OID_PREFIX, 0x2B }
#define AES256_CFB_OID	{ AES_OID_PREFIX, 0x2C }
#define AES256_CTR_OID	{ AES_OID_PREFIX, 0x30 }
#define AES256_PCBC_OID	{ AES_OID_PREFIX, 0x31 }

/* ==================================================================
 * DES OIDs (NIST + OIW)
 * ================================================================== */
#define DES_NIST_PREFIX	0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03
#define DES_OIW_PREFIX	0x2B,0x0E,0x03,0x02

/* NIST */
#define DES_ECB_NIST_OID	{ DES_NIST_PREFIX, 0x06 }
#define DES_CBC_NIST_OID	{ DES_NIST_PREFIX, 0x07 }
#define DES_CFB_NIST_OID	{ DES_NIST_PREFIX, 0x08 }
#define DES_OFB_NIST_OID	{ DES_NIST_PREFIX, 0x09 }
#define DES_CTR_NIST_OID	{ DES_NIST_PREFIX, 0x0A }
#define DES_PCBC_NIST_OID	{ DES_NIST_PREFIX, 0x0B }

/* OIW (legacy) */
#define DES_ECB_OIW_OID		{ DES_OIW_PREFIX, 0x06 }
#define DES_CBC_OIW_OID		{ DES_OIW_PREFIX, 0x07 }
#define DES_CFB_OIW_OID		{ DES_OIW_PREFIX, 0x08 }
#define DES_OFB_OIW_OID		{ DES_OIW_PREFIX, 0x09 }
#define DES_CTR_OIW_OID		{ DES_OIW_PREFIX, 0x0A }
#define DES_PCBC_OIW_OID	{ DES_OIW_PREFIX, 0x0B }

/* DES3 EDE */
#define NIST_RSA_PREFIX	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03
#define OIW_PREFIX		0x2B, 0x0E, 0x03, 0x02

/* NIST / RSA */
#define DES_EDE3_ECB_NIST_OID  { NIST_RSA_PREFIX, 0x06 }
#define DES_EDE3_CBC_NIST_OID  { NIST_RSA_PREFIX, 0x07 }
#define DES_EDE3_CFB_NIST_OID  { NIST_RSA_PREFIX, 0x08 }
#define DES_EDE3_OFB_NIST_OID  { NIST_RSA_PREFIX, 0x09 }

/* OIW Legacy */
#define DES_EDE3_ECB_OIW_OID   { OIW_PREFIX, 0x0B }
#define DES_EDE3_CBC_OIW_OID   { OIW_PREFIX, 0x11 }
#define DES_EDE3_CFB_OIW_OID   { OIW_PREFIX, 0x12 }
#define DES_EDE3_OFB_OIW_OID   { OIW_PREFIX, 0x13 }

/* ==================================================================
 * Blowfish OIDs (propriétaires SSH)
 * ================================================================== */
#define BLOWFISH_OID_PREFIX	0x2B,0x06,0x01,0x04,0x01,0x8B,0x55,0x01

#define BLOWFISH_ECB_OID	{ BLOWFISH_OID_PREFIX, 0x01 }
#define BLOWFISH_CBC_OID	{ BLOWFISH_OID_PREFIX, 0x02 }
#define BLOWFISH_CFB_OID	{ BLOWFISH_OID_PREFIX, 0x03 }
#define BLOWFISH_OFB_OID	{ BLOWFISH_OID_PREFIX, 0x04 }
#define BLOWFISH_CTR_OID	{ BLOWFISH_OID_PREFIX, 0x05 }
#define BLOWFISH_PCBC_OID	{ BLOWFISH_OID_PREFIX, 0x06 }

/* ==================================================================
 * Hash OIDs
 * ================================================================== */
#define MD5_OID				{ 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05 }
#define SHA1_OID			{ 0x2B,0x0E,0x03,0x02,0x1A }
#define SHA224_OID			{ 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04 }
#define SHA256_OID			{ 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01 }
#define SHA384_OID			{ 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02 }
#define SHA512_OID			{ 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03 }
#define WHIRLPOOL_OID		{ 0x28,0xCF,0x06,0x03,0x00,0x37 }

#define BLAKE2B_BASE_OID     0x2B, 0x06, 0x01, 0x04, 0x01, 0x8E, 0xB8, 0x0C, 0x02
#define BLAKE2B_160_OID      { BLAKE2B_BASE_OID, 0x05 }
#define BLAKE2B_256_OID      { BLAKE2B_BASE_OID, 0x08 }
#define BLAKE2B_384_OID      { BLAKE2B_BASE_OID, 0x0C }
#define BLAKE2B_512_OID      { BLAKE2B_BASE_OID, 0x10 }

/* HMAC */
static const uint8_t hmacSha1Oid[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x07 };
static const uint8_t hmacSha256Oid[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x09 };

/* ==================================================================
 * PKCS#5 / PKCS#12 KDF OIDs
 * ================================================================== */
static const uint8_t pkcs5Pbkdf2Oid[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C };
static const uint8_t pkcs5Pbes2Oid[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0D };

/* ==================================================================
 * Asymmetric OIDs
 * ================================================================== */

#define RSA_OID		{ 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01 }
#define DSA_OID		{ 0x2A,0x86,0x48,0xCE,0x38,0x04,0x01 }

#endif	/* HAJCRYPT_OID_H */
