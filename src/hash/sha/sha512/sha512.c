#include "../../../../includes/hash/sha/sha512.h"
#include "../../../../includes/hash/hmac.h" /* IWYU pragma: keep */
#include "../../../../includes/consts/sha.h"

#define SHA_NAME				sha512
#define SHA_CTX					t_sha512Ctx
#define SHA_OID					SHA512_OID
#define SHA_DEPRECATED			0
#define SHA_DIGEST_SIZE			SHA512_DIGEST_SIZE
#define SHA_BLOCK_SIZE			SHA512_BLOCK_SIZE
#define SHA_STATE_WORDS			8
#define SHA_WORD				uint64_t
#define SHA_H0					SHA512_H0
#define SHA_H1					SHA512_H1
#define SHA_H2					SHA512_H2
#define SHA_H3					SHA512_H3
#define SHA_H4					SHA512_H4
#define SHA_H5					SHA512_H5
#define SHA_H6					SHA512_H6
#define SHA_H7					SHA512_H7
#define SHA_TRANSFORM			sha512Transform
#define SHA_USE_ARM64			0
#define SHA_LOAD_BE(ptr)		load64Be(ptr)
#define SHA_STORE_BE(ptr, val)	store64Be(ptr, val)
#define SHA_PAD_PARAMS			{ .blockSize = SHA512_BLOCK_SIZE, .isLittleEndian = 0, .lengthFieldSize = 16 }

#define SHA_WORD_COMPRESS		uint64_t
#define SHA_ROUNDS				80
#define SHA_K					g_sha512_K
#define SHA_CH					SHA512_CH
#define SHA_MAJ					SHA512_MAJ
#define SHA_SIGMA0				SHA512_SIGMA0
#define SHA_SIGMA1				SHA512_SIGMA1
#define SHA_sigma0				SHA512_sigma0
#define SHA_sigma1				SHA512_sigma1
#define SHA_LOAD_BE_COMPRESS	load64Be
#define SHA_STORE_BE_COMPRESS   store64Be

#include "../shaImplTemplate.h"
