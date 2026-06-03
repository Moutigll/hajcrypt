#include "../../../../includes/hash/sha/sha256.h"
#include "../../../../includes/consts/sha.h"

const uint8_t g_sha256DigestInfoHeader[] = {
	0x30,	0x31,	0x30,	0x0D,	0x06,	0x09,
	0x60,	0x86,	0x48,	0x01,	0x65,	0x03,	0x04,	0x02,	0x01,
	0x05,	0x00,	0x04,	0x20
};

#define SHA_NAME				sha256
#define SHA_CTX					t_sha256Ctx
#define SHA_OID					SHA256_OID
#define SHA_DEPRECATED			0
#define SHA_DIGEST_SIZE			SHA256_DIGEST_SIZE
#define SHA_BLOCK_SIZE			SHA256_BLOCK_SIZE
#define SHA_STATE_WORDS			8
#define SHA_WORD				uint32_t
#define SHA_H0					SHA256_H0
#define SHA_H1					SHA256_H1
#define SHA_H2					SHA256_H2
#define SHA_H3					SHA256_H3
#define SHA_H4					SHA256_H4
#define SHA_H5					SHA256_H5
#define SHA_H6					SHA256_H6
#define SHA_H7					SHA256_H7
#define SHA_TRANSFORM			sha256Transform
#define SHA_USE_ARM64			0
#define SHA_LOAD_BE(ptr)		load32Be(ptr)
#define SHA_STORE_BE(ptr, val)	store32Be(ptr, val)
#define SHA_PAD_PARAMS			{ .blockSize = SHA256_BLOCK_SIZE, .isLittleEndian = 0, .lengthFieldSize = 8 }

#define SHA_WORD_COMPRESS		uint32_t
#define SHA_ROUNDS				64
#define SHA_K					g_sha256_K
#define SHA_CH					SHA256_CH
#define SHA_MAJ					SHA256_MAJ
#define SHA_SIGMA0				SHA256_SIGMA0
#define SHA_SIGMA1				SHA256_SIGMA1
#define SHA_sigma0				SHA256_sigma0
#define SHA_sigma1				SHA256_sigma1
#define SHA_LOAD_BE_COMPRESS	load32Be
#define SHA_STORE_BE_COMPRESS	store32Be

#include "../shaTransformTemplate.h"
#include "../shaImplTemplate.h"
