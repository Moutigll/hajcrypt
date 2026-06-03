#ifndef HAJCRYPT_SHA_COMMON_H
#define HAJCRYPT_SHA_COMMON_H

#include <stdint.h>

/* --------------- Common sizes --------------- */

#define SHA1_BLOCK_SIZE		64
#define SHA1_DIGEST_SIZE	20

#define SHA224_BLOCK_SIZE	64
#define SHA224_DIGEST_SIZE	28

#define SHA256_BLOCK_SIZE	64
#define SHA256_DIGEST_SIZE	32

#define SHA384_BLOCK_SIZE	128
#define SHA384_DIGEST_SIZE	48

#define SHA512_BLOCK_SIZE	128
#define SHA512_DIGEST_SIZE	64

#define SHA512_224_BLOCK_SIZE	128
#define SHA512_224_DIGEST_SIZE	28

#define SHA512_256_BLOCK_SIZE	128
#define SHA512_256_DIGEST_SIZE	32


/* --------------- Rotations (32‑bit and 64‑bit) --------------- */

#define ROTL32(x, n)	(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n)	(((x) >> (n)) | ((x) << (32 - (n))))

#define ROTL64(x, n)	(((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n)	(((x) >> (n)) | ((x) << (64 - (n))))


/* --------------- SHA‑1 logical functions --------------- */

#define SHA1_CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define SHA1_PARITY(x, y, z)	((x) ^ (y) ^ (z))
#define SHA1_MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))


/* --------------- SHA‑256 logical functions --------------- */

#define SHA256_CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_SIGMA0(x)	(ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define SHA256_SIGMA1(x)	(ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SHA256_sigma0(x)	(ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SHA256_sigma1(x)	(ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))


/* --------------- SHA‑384 / SHA‑512 logical functions --------------- */

#define SHA512_CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_SIGMA0(x)	(ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SHA512_SIGMA1(x)	(ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SHA512_sigma0(x)	(ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SHA512_sigma1(x)	(ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

void sha512Transform(uint64_t state[8], const uint8_t block[128]);

void	sha256TransformArm64(uint32_t *state, const uint8_t *data);

#endif /* HAJCRYPT_SHA_COMMON_H */
