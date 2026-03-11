#ifndef HAJCRYPT_PBKDF_BYTESTOKEY_H
#define HAJCRYPT_PBKDF_BYTESTOKEY_H

#include "kdf.h"

#define PBKDF_BTK_KEY_SIZE_8	8
#define PBKDF_BTK_KEY_SIZE_24	24
#define PBKDF_BTK_IV_SIZE_8		8
#define PBKDF_BTK_SALT_SIZE		8
#define PBKDF_BTK_HASH_SIZE		16	/* MD5 output size */



/**
 * @brief Derives a key and IV using the OpenSSL-compatible EVP_BytesToKey algorithm with MD5.
 * 
 * This function implements the legacy key derivation method used by OpenSSL for algorithms
 * like DES. It performs a single MD5 hash of the concatenated password and salt to produce
 * 16 bytes of key material. The first 8 bytes are used as the encryption key, and the
 * following 8 bytes are used as the initialization vector (IV).
 * 
 * @param password   The password string used for key derivation (non-NULL)
 * @param passLen    Length of the password string in bytes
 * @param salt       Pointer to 8-byte salt value. If NULL, a zero-filled salt is used
 * @param key        Output buffer for the derived key (must have at least 8 bytes capacity)
 * @param iv         Output buffer for the derived IV (must have at least 8 bytes capacity)
 * 
 * @return           0 on success, -1 on error (invalid parameters or NULL pointers)
 * 
 * @note This is a legacy key derivation method and should not be used for new applications.
 *       It is provided for compatibility with OpenSSL's historical behavior.
 * @note The password is treated as a raw byte string; no character encoding conversion
 *       is performed.
 * @warning The derived key material is only as secure as the password and salt used.
 *         For DES, the key includes parity bits that must be handled separately.
 * 
 * @see pbkdfBytesToKeyExtended for algorithms requiring longer keys (e.g., Triple DES)
 */
int	pbkdfBytesToKeySimple(const char	*password,
						  size_t		passLen,
						  const uint8_t	*salt,
						  uint8_t		*key,
						  uint8_t		*iv);

/**
 * @brief Derives a key and IV using the OpenSSL-compatible EVP_BytesToKey algorithm with MD5,
 *        supporting variable key lengths.
 * 
 * This function extends the legacy key derivation method to support longer key lengths
 * by concatenating multiple MD5 hashes. It is used by algorithms like Triple DES that
 * require more than 8 bytes of key material.
 * 
 * The number of MD5 iterations depends on the requested key length:
 * - For keyLen <= 16: 1 iteration (hash_1 provides up to 16 bytes)
 * - For keyLen <= 24: 2 iterations (hash_1 + hash_2 provides up to 24 bytes)
 * - For keyLen <= 32: 3 iterations (hash_1 + hash_2 + hash_3 provides up to 32 bytes)
 * 
 * @param password   The password string used for key derivation (non-NULL)
 * @param passLen    Length of the password string in bytes
 * @param salt       Pointer to 8-byte salt value. If NULL, a zero-filled salt is used
 * @param keyLen     Desired key length in bytes (valid values: 8, 16, or 24)
 * @param key        Output buffer for the derived key (must have at least keyLen bytes capacity)
 * @param iv         Output buffer for the derived IV (must have at least 8 bytes capacity)
 * 
 * @return           0 on success, -1 on error (invalid parameters, NULL pointers,
 *                   or unsupported keyLen)
 * 
 * @note This is a legacy key derivation method and should not be used for new applications.
 *       It is provided for compatibility with OpenSSL's historical behavior, particularly
 *       for Triple DES which requires 24-byte keys.
 * @note Supported key lengths are 8 bytes (single DES), 16 bytes (e.g., some algorithms),
 *       and 24 bytes (Triple DES). Other key lengths will return an error.
 * @warning The derived key material is only as secure as the password and salt used.
 *         For DES family algorithms, key parity bits must be handled separately.
 * 
 * @see pbkdfBytesToKeySimple for algorithms requiring exactly 8-byte keys and IVs
 */
int	pbkdfBytesToKeyExtended(const char		*password,
							size_t			passLen,
							const uint8_t	*salt,
							size_t			keyLen,
							uint8_t			*key,
							uint8_t			*iv);


/**
 * @brief Derives a key and initialization vector from a password using PBKDF.
 * 
 * Generates cryptographic key material and an initialization vector from a
 * password and hexadecimal-encoded salt using a PBKDF-based key derivation function.
 * 
 * @param password      Null-terminated string containing the password to derive from.
 * @param saltHex       Null-terminated hexadecimal string representing the salt.
 * @param keyLen        Desired length of the derived key in bytes.
 * @param key           Output buffer where the derived key will be stored.
 *                      Must be at least keyLen bytes.
 * @param iv            Output buffer where the initialization vector will be stored.
 * 
 * @return              0 on success, or an error code on failure.
 * 
 * @note                The salt should be provided as a hexadecimal string and will
 *                      be decoded internally.
 */
int	pbkdfBytesToKeyFromHex(const char	*password,
						   const char	*saltHex,
						   size_t		keyLen,
						   uint8_t		*key,
						   uint8_t		*iv);

/**
 * @brief Derives a cryptographic key and IV from a password using PBKDF with a randomly generated salt.
 *
 * This function generates a random salt, then uses the password-based key derivation function (PBKDF)
 * to produce a key and initialization vector (IV) suitable for cryptographic operations.
 *
 * @param password         The input password as a null-terminated string.
 * @param keyLen           The desired length of the derived key in bytes.
 * @param key              Pointer to a buffer where the derived key will be stored. Must be at least keyLen bytes.
 * @param iv               Pointer to a buffer where the derived IV will be stored. Size depends on the cipher used.
 * @param generatedSalt    Pointer to a buffer where the generated random salt will be stored.
 *                         The buffer must be large enough to hold the salt (implementation-defined size).
 * @return                 0 on success, non-zero on failure.
 */
int	pbkdfBytesToKeyWithRandomSalt(const char	*password,
								  size_t		keyLen,
								  uint8_t		*key,
								  uint8_t		*iv,
								  uint8_t		*generatedSalt);
#endif
