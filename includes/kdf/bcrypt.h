#ifndef HAJCRYPT_BCRYPT_H
#define HAJCRYPT_BCRYPT_H

#include <stddef.h>
#include <stdint.h>

#include "../cipher/blowfish.h"

#define BCRYPT_OUTPUT_SIZE	24  /* bcrypt produces 24-byte output */
#define BCRYPT_SALT_LEN		16
#define BCRYPT_HASH_LEN		24
#define BCRYPT_STRING_LEN	60
#define BCRYPT_COST_MIN		4
#define BCRYPT_COST_MAX		31
#define BCRYPT_MAX_PASSWD	72
#define BCRYPT_MAGIC_STR	"OrpheanBeholderScryDoubt" /* O_BSD :3 */

typedef struct s_bcryptCtx {
	t_blowfishEcbCtx	blowfishCtx;
	uint8_t				salt[BCRYPT_SALT_LEN];
	uint32_t			cost;
} t_bcryptCtx;

/**
 * @brief Hash a password using bcrypt
 * 
 * @param password Password to hash (null-terminated)
 * @param salt Salt (must be 16 bytes)
 * @param cost Cost factor (between 4 and 31)
 * @param output Buffer for result (must be at least BCRYPT_STRING_LEN)
 * @return 0 on success, -1 on error
 */
int	bcryptHash(const char		*password,
			   const uint8_t	salt[16],
			   uint32_t			cost,
			   char				output[BCRYPT_STRING_LEN]);

/**
 * @brief Verify a password against a bcrypt hash
 * 
 * @param password Password to verify
 * @param hash Stored bcrypt hash (format: $2b$XX$...)
 * @return 0 if match, -1 if mismatch or error
 */
int	bcryptVerify(const char *password, const char *hash);

/**
 * @brief Generate a random salt for bcrypt
 * 
 * @param salt Output buffer for salt (must be 16 bytes)
 * @return 0 on success, -1 on error
 */
int	bcryptGenSalt(uint8_t salt[16]);

/**
 * @brief One-shot bcrypt with random salt
 * 
 * @param password Password to hash
 * @param cost Cost factor
 * @param output Buffer for result (must be at least BCRYPT_STRING_LEN)
 * @return 0 on success, -1 on error
 */
int	bcryptSimple(const char *password, uint32_t cost, char output[BCRYPT_STRING_LEN ]);

/**
 * @brief Hash a password using bcrypt with a provided salt string
 * 
 * @param password Password to hash
 * @param saltStr Salt string (22 chars Base64)
 * @param cost Cost factor
 * @param output Buffer for result (must be at least BCRYPT_STRING_LEN)
 * @return 0 on success, -1 on error
 */
int bcryptHashWithSalt(const char *password, const char *saltStr, uint32_t cost, char output[BCRYPT_STRING_LEN]);

/* ---------- Internal helper functions ---------- */

/**
 * @brief Expand the Blowfish state with the password key
 * 
 * @param ctx   Blowfish context to expand
 * @param key   Key bytes
 * @param keyLen Length of key
 */
void bcryptEncodeBase64(char *dst, const uint8_t *src, size_t len);

/**
 * @brief Decode a bcrypt Base64 string to bytes
 * 
 * @param dst   output buffer for decoded bytes
 * @param src   input Base64 string (not null-terminated)
 * @param maxLen maximum number of bytes to write
 * @return number of bytes written, or -1 on error
 */
int bcryptDecodeBase64(uint8_t *dst, const char *src, size_t maxLen);

/**
 * @brief Derive a key using bcrypt's PBKDF
 * 
 * @param pass Password
 * @param passLen Length of password
 * @param salt Salt bytes
 * @param saltLen Length of salt (should be 16)
 * @param key Output buffer for derived key
 * @param keyLen Desired length of derived key
 * @param rounds Number of rounds (cost factor)
 * @return 0 on success, -1 on error
 */
int bcryptPbkdf(const char		*pass,	size_t			passLen,
				const uint8_t	*salt,	size_t			saltLen,
				uint8_t			*key,	size_t			keyLen,
				unsigned int	rounds);

/**
 * @brief Convert a 32-bit integer from/to little-endian (no-op on little-endian systems)
 *		Actually used for byte order conversion if needed.
 */
static inline uint32_t swap32(uint32_t x)
{
	return ((x >> 24) & 0xFF) |
		   ((x >> 8) & 0xFF00) |
		   ((x << 8) & 0xFF0000) |
		   ((x << 24) & 0xFF000000);
}

#endif
