#ifndef HAJCRYPT_CIPHER_H
#define HAJCRYPT_CIPHER_H

#include <stddef.h>
#include <stdint.h>

/**
 * @enum t_cipherMode
 * @brief Enumeration of supported cipher modes for encryption and decryption operations.
 * 
 * This enumeration defines the various block cipher modes of operation available
 * in the cryptographic library. Each mode provides different security characteristics
 * and use cases.
 * 
 * @var CIPHER_MODE_NONE
 *      No cipher mode specified; represents an uninitialized or invalid state.
 * 
 * @var CIPHER_MODE_ECB
 *      Electronic Codebook mode. Each plaintext block is encrypted independently
 *      with the same key. Not recommended for most applications due to security
 *      vulnerabilities (identical plaintext blocks produce identical ciphertext blocks).
 * 
 * @var CIPHER_MODE_CBC
 *      Cipher Block Chaining mode. Each plaintext block is XORed with the previous
 *      ciphertext block before encryption. Provides better security than ECB by
 *      introducing data dependency between blocks.
 * 
 * @var CIPHER_MODE_CFB
 *      Cipher Feedback mode. A stream cipher mode that encrypts the initialization
 *      vector and XORs the result with plaintext blocks. Allows encryption of data
 *      smaller than the block size without padding.
 * 
 * @var CIPHER_MODE_OFB
 *      Output Feedback mode. A stream cipher mode that generates a keystream
 *      independent of the plaintext. The keystream is XORed with plaintext blocks.
 *      Similar to CFB but with different feedback mechanism.
 * 
 * @var CIPHER_MODE_CTR
 *      Counter mode. A stream cipher mode that encrypts successive counter values
 *      and XORs the result with plaintext blocks. Supports parallel encryption
 *      and efficient random access to encrypted data.
 */
typedef enum e_cipherMode
{
	CIPHER_MODE_NONE = 0,
	CIPHER_MODE_ECB,		/* Electronic Codebook */
	CIPHER_MODE_CBC,		/* Cipher Block Chaining */
	CIPHER_MODE_CFB,		/* Cipher Feedback */
	CIPHER_MODE_OFB,		/* Output Feedback */
	CIPHER_MODE_CTR,		/* Counter */
	CIPHER_MODE_GCM,		/* Galois/Counter Mode */
	CIPHER_MODE_CCM,		/* Counter with CBC-MAC */
	CIPHER_MODE_MAX
}	t_cipherMode;

typedef enum e_cipherDirection
{
	CIPHER_ENCRYPT,
	CIPHER_DECRYPT
}	t_cipherDirection;

/**
 * @struct s_cipher
 * @brief Structure defining a cipher algorithm with its operations and metadata.
 *
 * This structure encapsulates all necessary information and function pointers
 * for a cipher implementation, including encryption/decryption operations,
 * padding handling, and cipher-specific parameters.
 *
 * @member name
 *     Pointer to the cipher's name (e.g., "AES", "DES").
 *
 * @member mode
 *     The cipher mode of operation (e.g., ECB, CBC, CTR).
 *
 * @member isEncoder
 *     Flag indicating if the cipher supports encryption (1) or decryption only (0).
 *
 * @member blockSize
 *     Size of the cipher's block in bytes.
 *
 * @member keySize
 *     Expected key size in bytes.
 *
 * @member ivSize
 *     Size of the initialization vector in bytes (0 if not applicable).
 *
 * @member ctxSize
 *     Size of the cipher's context structure in bytes.
 *
 * @member init
 *     Function pointer to initialize the cipher context with key, IV, and direction.
 *     @param ctx Pointer to the cipher context
 *     @param key Pointer to the encryption key
 *     @param keyLen Length of the key
 *     @param iv Pointer to the initialization vector
 *     @param dir Encryption or decryption direction
 *
 * @member update
 *     Function pointer to process data blocks (encryption/decryption).
 *     @param ctx Pointer to the cipher context
 *     @param in Input data buffer
 *     @param inLen Length of input data
 *     @param out Output data buffer
 *     @param outLen Pointer to output length
 *
 * @member final
 *     Function pointer to finalize cipher operation and output remaining data.
 *     @param ctx Pointer to the cipher context
 *     @param out Output buffer for final data
 *     @param outLen Pointer to output length
 *
 * @member free
 *     Function pointer to free/cleanup cipher context resources.
 *     @param ctx Pointer to the cipher context
 *
 * @member pad
 *     Function pointer to apply padding to a block.
 *     @param block Pointer to the data block
 *     @param len Current data length in block
 *     @param blockSize Total block size
 *
 * @member unpad
 *     Function pointer to remove padding from a block.
 *     @param block Pointer to the data block
 *     @param len Pointer to data length (updated after unpadding)
 *     @param blockSize Total block size
 *     @return 0 on success, negative value on error
 *
 * @member supportsWrap
 *     Flag indicating if the cipher supports key wrapping operations.
 */
typedef struct s_cipher
{
	/* Identification */
	char			*name;
	t_cipherMode	mode;
	int				isEncoder;	/* 1 if this cipher can be used for encryption, 0 otherwise */
	
	/* Sizes */
	size_t			blockSize;
	size_t			keySize;
	size_t			ivSize;
	size_t			tagSize;	/* For AEAD modes like GCM/CCM */
	size_t			ctxSize;

	int		(*init)(void				*ctx,
					const uint8_t		*key,
					size_t				keyLen,
					const uint8_t		*iv,
					t_cipherDirection	dir);
	void	(*update)(void *ctx, const uint8_t *in, size_t inLen,
					  uint8_t *out, size_t *outLen);
	void	(*final)(void *ctx, uint8_t *out, size_t *outLen);
	void	(*free)(void *ctx);
	
	void	(*pad)(uint8_t *block, size_t len, size_t blockSize);
	int		(*unpad)(uint8_t *block, size_t *len, size_t blockSize);
	
	int		supportsWrap;
}	t_cipher;

/* ---------- Padding Functions ---------- */

/**
 * @brief Applies PKCS#7 padding to a block.
 * 
 * Fills remaining bytes in block with the padding length.
 * 
 * @param block Data block to pad
 * @param len Current data length in block
 * @param blockSize Total block size (always 8 for DES)
 */
void	pkcs7Pad(uint8_t *block, size_t len, size_t blockSize);

/**
 * @brief Verifies and removes PKCS#7 padding from a block.
 * 
 * Checks that all padding bytes have the correct value and returns
 * the original data length.
 * 
 * @param block Padded data block
 * @param len Pointer to block size, updated to original data length
 * @param blockSize Total block size (always 8 for DES)
 * @return 0 on success, -1 on invalid padding
 */
int		pkcs7Unpad(uint8_t *block, size_t *len, size_t blockSize);

#endif	/* HAJCRYPT_CIPHER_H */
