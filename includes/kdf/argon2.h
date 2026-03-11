#ifndef ARGON2_H
#define ARGON2_H

#include <stddef.h>
#include <stdint.h>

/* Argon2 version */
#define ARGON2_VERSION			0x13

/* Block size in bytes */
#define ARGON2_BLOCK_SIZE		 1024
#define ARGON2_QWORDS_PER_BLOCK   (ARGON2_BLOCK_SIZE / 8)

/* Number of synchronization points per pass */
#define ARGON2_SYNC_POINTS		4

/* Pre-hash digest lengths */
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH   72

/* Default recommended parameters */
#define ARGON2_DEFAULT_MEMORY	  65536   /* 64 MiB */
#define ARGON2_DEFAULT_ITERATIONS  3
#define ARGON2_DEFAULT_PARALLELISM 4
#define ARGON2_DEFAULT_TYPE		ARGON2_ID

/* Parameter bounds */
#define ARGON2_MIN_MEMORY		  8
#define ARGON2_MAX_MEMORY		  0xFFFFFFFF
#define ARGON2_MIN_ITERATIONS	  1
#define ARGON2_MAX_ITERATIONS	  0xFFFFFFFF
#define ARGON2_MIN_PARALLELISM	 1
#define ARGON2_MAX_PARALLELISM	 0xFFFFFF

#define ARGON2_MAX_PWD_LEN		 0xFFFFFFFF
#define ARGON2_MAX_SALT_LEN		0xFFFFFFFF
#define ARGON2_MAX_SECRET		  0xFFFFFFFF
#define ARGON2_MAX_AD			  0xFFFFFFFF

#define ARGON2_MAX_PWD_LENGTH	0xFFFFFFFF

#define ARGON2_MAX_THREADS 16
#define ARGON2_MIN_MEMORY_FOR_THREADING 1024
#define ARGON2_THREADED

#define ARGON2_FLAG_THREADING 0x01
#define ARGON2_FLAG_CLEAR_MEMORY 0x02


typedef enum {
	ARGON2_D = 0,
	ARGON2_I = 1,
	ARGON2_ID = 2
} t_argon2Type;

typedef struct {
	uint64_t v[ARGON2_QWORDS_PER_BLOCK];
} t_argon2Block;

typedef struct {
	/* Core parameters */
	const uint8_t	*password;
	uint32_t		passwordLen;
	const uint8_t	*salt;
	uint32_t		saltLen;
	const uint8_t	*secret;	/* optional key */
	uint32_t		secretLen;
	const uint8_t	*ad;		/* optional associated data */
	uint32_t		adLen;

	uint32_t		memory;			/* memory in KiB */
	uint32_t		iterations;		/* number of passes */
	uint32_t		parallelism;	/* number of lanes */
	uint32_t		version;		/* 0x13 */
	t_argon2Type	type;
	uint32_t		flags;			/* ARGON2_FLAG_* */
	uint32_t		outputLen;		/* desired output length */

	/* Internal state (do not touch) */
	t_argon2Block	*memoryArray;	/* array of memory blocks */
	uint32_t		segmentLength;	/* blocks per segment */
	uint32_t		blocksPerLane;	/* blocks per lane */
	/* For secure memory management */
    size_t          memoryArraySize;  /* size of memoryArray in bytes */
} t_argon2Ctx;

/* Position within a segment (used internally) */
typedef struct s_argon2Position
{
	uint32_t pass;
	uint32_t lane;
	uint8_t  slice;
	uint32_t index;
} t_argon2Position;

typedef struct s_argon2ThreadData {
	t_argon2Ctx	*ctx;
	uint32_t	startLane;
	uint32_t	endLane;
	uint32_t	pass;
	uint32_t	slice;
} t_argon2ThreadData;

/**
 * @brief Initializes an Argon2 context with default recommended parameters.
 * @param ctx The Argon2 context to initialize.
 */
void argon2InitDefault(t_argon2Ctx *ctx);

/**
 * @brief Initializes an Argon2 context with specified parameters.
 *
 * This function initializes the Argon2 context with the provided parameters, including password, salt, memory, iterations, parallelism, and type.
 * It also sets the version to the current Argon2 version and initializes internal state variables.
 * @param ctx The Argon2 context to initialize.
 * @param password The input password for hashing.
 * @param passLen The length of the input password in bytes.
 * @param salt The input salt for hashing.
 * @param saltLen The length of the input salt in bytes.
 * @param memory The amount of memory to use (in KiB).
 * @param iterations The number of iterations (passes) to perform.
 * @param parallelism The degree of parallelism (number of lanes).
 * @param type The variant of Argon2 to use (ARGON2_D, ARGON2_I, or ARGON2_ID).
 */
void argon2Init(t_argon2Ctx		*ctx,
				const uint8_t	*password,	size_t	passLen,
				const uint8_t	*salt,		size_t	saltLen,
				uint32_t		memory,
				uint32_t		iterations,
				uint32_t		parallelism,
				t_argon2Type	type);

/**
 * @brief Sets the password for the Argon2 context.
 * @param ctx The Argon2 context.
 * @param password The input password.
 * @param len The length of the password.
 * @return 0 on success, non-zero on failure.
 */
int	argon2SetPassword(t_argon2Ctx *ctx, const uint8_t *password, size_t len);

/**
 * @brief Sets the salt for the Argon2 context.
 * @param ctx The Argon2 context.
 * @param salt The input salt.
 * @param len The length of the salt.
 * @return 0 on success, non-zero on failure.
 */
int	argon2SetSalt(t_argon2Ctx *ctx, const uint8_t *salt, size_t len);

/**
 * @brief Hashes a password using Argon2.
 * @param ctx The Argon2 context.
 * @param output The output buffer for the hash.
 * @param outputLen The length of the output buffer in bytes.
 * @return 0 on success, non-zero on failure.
 */
int argon2Hash(const t_argon2Ctx *ctx, uint8_t *output, size_t outputLen);

/**
 * @brief Hashes a password using Argon2id.
 * @param password The input password for hashing.
 * @param passLen The length of the input password in bytes.
 * @param output The output buffer for the hash.
 * @param outputLen The length of the output buffer in bytes.
 * @return 0 on success, non-zero on failure.
 */
int argon2id(const uint8_t	*password,	size_t	passLen,
			 uint8_t		*output,	size_t	outputLen);

/**
 * @brief Securely frees all memory associated with the Argon2 context.
 * This function securely wipes and frees all memory allocated for the password, salt, secret, associated data, and the memory array. It also resets all context fields to zero.
 * @param ctx The Argon2 context to free.
 */
void argon2Free(t_argon2Ctx *ctx);

/**
 * @brief Encode Argon2 context into standard string format
 * 
 * Format: $argon2<type>$v=<version>$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
 * 
 * @param ctx Argon2 context (must have been used for hashing)
 * @param hash The computed hash bytes
 * @param hashLen Length of hash
 * @param output Output buffer for encoded string
 * @param outputSize Size of output buffer
 * @return 0 on success, -1 on error
 */
int argon2Encode(const t_argon2Ctx	*ctx,
				 const uint8_t		*hash,
				 size_t				hashLen,
				 char				*output,
				 size_t				outputSize);

/**
 * @brief Decode encoded string into Argon2 context and hash
 * 
 * @param encoded Encoded string
 * @param ctx Output context (will be initialized with decoded parameters)
 * @param hash Output buffer for decoded hash
 * @param hashLen Input: max hash size, Output: actual hash length
 * @return 0 on success, -1 on error
 */
int argon2Decode(const char *encoded,
				 t_argon2Ctx *ctx,
				 uint8_t *hash,
				 size_t *hashLen);

/**
 * @brief Verify a password against an encoded Argon2 hash
 * This function decodes the encoded Argon2 hash to extract the parameters and expected hash,
 * then computes the hash of the provided password using those parameters and compares it to the expected hash.
 *
 * @param encoded The encoded Argon2 hash
 * @param password The password to verify
 * @param passLen The length of the password
 * @return 1 on match, 0 on mismatch, -1 on error
 */
int argon2Verify(const char *encoded, const uint8_t *password, size_t passLen);


/* BLAKE2 round function (used internally):
 * This is a simplified version of the BLAKE2b round function, adapted for Argon2's use.
 * It operates on 16 64-bit words and performs mixing using the fBlaMka function and bit rotations.
 */

static inline uint64_t fBlaMka(uint64_t x, uint64_t y) {
	const uint64_t m = UINT64_C(0xFFFFFFFF);
	const uint64_t xy = (x & m) * (y & m);
	return x + y + 2 * xy;
}

#define G(a, b, c, d)			\
	do {						\
		a = fBlaMka(a, b);		\
		d = rotr64(d ^ a, 32);	\
		c = fBlaMka(c, d);		\
		b = rotr64(b ^ c, 24);	\
		a = fBlaMka(a, b);		\
		d = rotr64(d ^ a, 16);	\
		c = fBlaMka(c, d);		\
		b = rotr64(b ^ c, 63);	\
	} while (0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,	\
						   v12, v13, v14, v15)	\
	do {							\
		G(v0,	v4,	v8,		v12);	\
		G(v1,	v5,	v9,		v13);	\
		G(v2,	v6,	v10,	v14);	\
		G(v3,	v7,	v11,	v15);	\
		G(v0,	v5,	v10,	v15);	\
		G(v1,	v6,	v11,	v12);	\
		G(v2,	v7,	v8,		v13);	\
		G(v3,	v4,	v9,		v14);	\
	} while (0)

#endif /* ARGON2_H */
