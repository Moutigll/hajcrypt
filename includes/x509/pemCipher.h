#ifndef HAJCRYPT_PEM_CIPHER_H
#define HAJCRYPT_PEM_CIPHER_H

#include "../cipher/cipher.h"
#include "../hash/hash.h"

typedef struct s_pkcs8Params {
	int				iterations;	/* Iterations for PBKDF2 (default: 10000) */
	const t_hash	*prf;		/* PRF for PBKDF2 (default: SHA256) */
	uint8_t			salt[16];	/* Salt (up to 16 bytes, depending on cipher) */
	size_t			saltLen;
	uint8_t			iv[32];		/* IV (up to 32 bytes, depending on cipher) */
	size_t			ivLen;
} t_pkcs8Params;

/**
 * @brief Derives a key from a password using PKCS#1 key derivation function.
 * 
 * This function implements the PKCS#1 key derivation function, which is used to derive a key from a password and salt.
 * @param password  Pointer to the password string
 * @param salt      Pointer to the salt bytes
 * @param key       Pointer to the output buffer for the derived key
 * @param keySize   Size of the output key buffer in bytes
 */
void pkcs1KeyDerivation(const char *password, const uint8_t *salt, uint8_t *key, size_t keySize);

/**
 * @brief Encrypts DER-encoded data using the specified cipher, key, and IV.
 * 
 * This function performs encryption of the input DER data using the provided
 * cipher context. It handles padding and returns a newly allocated buffer
 * containing the encrypted data. The caller is responsible for freeing the
 * returned buffer.
 * 
 * @param cipher    Pointer to the cipher structure defining the encryption algorithm
 * @param key       Pointer to the encryption key (must be of appropriate length for the cipher)
 * @param iv        Pointer to the initialization vector (IV) if required by the cipher, or NULL if not used
 * @param der       Pointer to the input DER-encoded data to be encrypted
 * @param derLen    Length of the input DER data in bytes
 * @param outLen    Output parameter that will receive the length of the encrypted data
 * 
 * @return           Pointer to a newly allocated buffer containing the encrypted DER data, or NULL on error
 */
uint8_t *encryptDerWithCipher(const t_cipher	*cipher,
							  const uint8_t		*key,
							  const uint8_t		*iv,
							  const uint8_t		*der,
							  size_t			derLen,
							  size_t			*outLen);

/**
 * @brief Decrypts DER-encoded data using the specified cipher, key, and IV.
 * 
 * This function performs decryption of the input encrypted DER data using the provided
 * cipher context. It handles padding and returns a newly allocated buffer containing
 * the decrypted data. The caller is responsible for freeing the returned buffer.
 * 
 * @param cipher    Pointer to the cipher structure defining the decryption algorithm
 * @param key       Pointer to the decryption key (must be of appropriate length for the cipher)
 * @param iv        Pointer to the initialization vector (IV) if required by the cipher, or NULL if not used
 * @param encDer    Pointer to the input encrypted DER-encoded data to be decrypted
 * @param encLen    Length of the input encrypted DER data in bytes
 * @param outLen    Output parameter that will receive the length of the decrypted data
 *
 * @return           Pointer to a newly allocated buffer containing the decrypted DER data, or NULL on error
 */
uint8_t *decryptDerWithCipher(const t_cipher	*cipher,
							  const uint8_t		*key,
							  const uint8_t		*iv,
							  const uint8_t		*encDer,
							  size_t			encLen,
							  size_t			*outLen);

/**
 * @brief Builds the ASN.1 structure for PBES2 encryption parameters based on the provided cipher and KDF parameters.
 * 
 * This function constructs the ASN.1 DER encoding for the PBES2 encryption scheme, which includes the KDF parameters
 * (e.g., PBKDF2) and the encryption scheme parameters (e.g., cipher OID and IV). The resulting structure is used in
 * PKCS#8 encrypted private keys to specify how the key is encrypted.
 * 
 * @param cipher    Pointer to the cipher structure defining the encryption algorithm
 * @param params    Pointer to a t_pkcs8Params structure containing the KDF parameters
 * @param outLen    Output parameter that will receive the length of the encoded ASN.1 structure
 * 
 * @return          Pointer to a newly allocated buffer containing the ASN.1 DER encoding of the PBES2 parameters, or NULL on error
 */
uint8_t *buildPbes2Algo(const t_cipher		*cipher,
						const t_pkcs8Params	*params,
						size_t				*outLen);


/**
 * @brief Parses the ASN.1 structure of PBES2 parameters from the provided DER-encoded data.
 * 
 * This function takes the DER-encoded ASN.1 structure that defines the PBES2 encryption parameters (as found in PKCS#8)
 * and extracts the cipher information and KDF parameters. It fills the provided t_pkcs8Params structure with the extracted
 * parameters and returns a pointer to the corresponding cipher structure.
 * 
 * @param algoDer   Pointer to the DER-encoded ASN.1 structure containing the PBES2 parameters
 * @param algoLen   Length of the DER-encoded data in bytes
 * @param cipher    Output parameter that will receive a pointer to the corresponding t_cipher structure based on the OID
 * @param params    Output parameter that will be filled with the extracted KDF parameters (iterations, salt, IV, etc.)
 * 
 * @return          1 on successful parsing and extraction of parameters, or 0 on error (with error details printed to stderr)
 */
int parsePbes2Params(const uint8_t	*algoDer,
					size_t			algoLen,
					const t_cipher	**cipher,
					t_pkcs8Params	*params);

#endif
