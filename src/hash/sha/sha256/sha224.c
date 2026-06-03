#include "../../../../includes/hash/sha/sha224.h"
#include "../../../../includes/consts/sha.h"

#define SHA_NAME				sha224
#define SHA_CTX					t_sha224Ctx
#define SHA_OID					SHA224_OID
#define SHA_DEPRECATED			0
#define SHA_DIGEST_SIZE			SHA224_DIGEST_SIZE
#define SHA_BLOCK_SIZE			SHA224_BLOCK_SIZE
#define SHA_STATE_WORDS			8
#define SHA_WORD				uint32_t
#define SHA_H0					SHA224_H0
#define SHA_H1					SHA224_H1
#define SHA_H2					SHA224_H2
#define SHA_H3					SHA224_H3
#define SHA_H4					SHA224_H4
#define SHA_H5					SHA224_H5
#define SHA_H6					SHA224_H6
#define SHA_H7					SHA224_H7
#define SHA_TRANSFORM			sha224Transform
#define SHA_USE_ARM64			0
#define SHA_LOAD_BE(ptr)		load32Be(ptr)
#define SHA_STORE_BE(ptr, val)	store32Be(ptr, val)
#define SHA_PAD_PARAMS			{ .blockSize = SHA224_BLOCK_SIZE, .isLittleEndian = 0, .lengthFieldSize = 8 }

#define SHA_WORD_COMPRESS		uint32_t
#define SHA_ROUNDS				64
#define SHA_K					g_sha224_K
#define SHA_CH					SHA256_CH
#define SHA_MAJ					SHA256_MAJ
#define SHA_SIGMA0				SHA256_SIGMA0
#define SHA_SIGMA1				SHA256_SIGMA1
#define SHA_sigma0				SHA256_sigma0
#define SHA_sigma1				SHA256_sigma1
#define SHA_LOAD_BE_COMPRESS	load32Be
#define SHA_STORE_BE_COMPRESS   store32Be

#include "../shaTransformTemplate.h"
#include "../shaImplTemplate.h"
