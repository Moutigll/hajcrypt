#include "../../../../includes/hash/sha/sha384.h"
#include "../../../../includes/consts/sha.h"

#define SHA_NAME				sha384
#define SHA_CTX					t_sha384Ctx
#define SHA_OID					SHA384_OID
#define SHA_DEPRECATED			0
#define SHA_DIGEST_SIZE			SHA384_DIGEST_SIZE
#define SHA_BLOCK_SIZE			SHA384_BLOCK_SIZE
#define SHA_STATE_WORDS			8
#define SHA_WORD				uint64_t
#define SHA_H0					SHA384_H0
#define SHA_H1					SHA384_H1
#define SHA_H2					SHA384_H2
#define SHA_H3					SHA384_H3
#define SHA_H4					SHA384_H4
#define SHA_H5					SHA384_H5
#define SHA_H6					SHA384_H6
#define SHA_H7					SHA384_H7
#define SHA_TRANSFORM			sha512Transform
#define SHA_USE_ARM64			0
#define SHA_LOAD_BE(ptr)		load64Be(ptr)
#define SHA_STORE_BE(ptr, val)	store64Be(ptr, val)
#define SHA_PAD_PARAMS			{ .blockSize = SHA384_BLOCK_SIZE, .isLittleEndian = 0, .lengthFieldSize = 16 }

#define SHA_WORD_COMPRESS		uint64_t
#define SHA_ROUNDS				80
#define SHA_K					g_sha384_K
#define SHA_CH					SHA512_CH
#define SHA_MAJ					SHA512_MAJ
#define SHA_SIGMA0				SHA512_SIGMA0
#define SHA_SIGMA1				SHA512_SIGMA1
#define SHA_sigma0				SHA512_sigma0
#define SHA_sigma1				SHA512_sigma1
#define SHA_LOAD_BE_COMPRESS	load64Be
#define SHA_STORE_BE_COMPRESS   store64Be

#include "../shaImplTemplate.h"
