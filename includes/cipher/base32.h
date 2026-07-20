#ifndef HAJCRYPT_BASE32_H
#define HAJCRYPT_BASE32_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"

extern const t_cipher g_base32Cipher;

/**
 * @struct s_base32Ctx
 * @brief Context structure for Base32 encoding and decoding operations
 * 
 * @var s_base32Ctx::buffer
 *      Temporary buffer to accumulate bits during encoding/decoding
 * 
 * @var s_base32Ctx::bits
 *      Number of valid bits currently stored in the buffer
 * 
 * @var s_base32Ctx::dir
 *      Direction of operation (encryption for encoding, decryption for decoding)
 *
 * @var s_base32Ctx::outCount
 *      Counter for output characters processed or generated
 * 
 * @var s_base32Ctx::error
 *      Error status code (zero indicates no error)
 */
typedef struct s_base32Ctx {
	uint32_t			buffer;
	int					bits;
	t_cipherDirection	dir;
	size_t				outCount;
	int					error;
} t_base32Ctx;

/**
 * @brief Initializes the Base32 context for encoding or decoding
 * @param vctx Context pointer
 * @param key Encryption key (not used in Base32)
 * @param keyLen Length of the encryption key (not used in Base32)
 * @param iv Initialization vector (not used in Base32)
 * @param dir Direction of operation (encryption for encoding, decryption for decoding)
 * @return 0 on success, -1 on error
 */
int base32Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir);

/**
 * @brief Updates the Base32 context with input data for encoding or decoding
 * @param vctx Context pointer
 * @param in Input data buffer
 * @param inLen Length of the input data in bytes
 * @param out Output buffer for encoded or decoded data
 * @param outLen Pointer to variable that will receive the length of output data in bytes
 */
void base32Update(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);

/**
 * @brief Finalizes the Base32 encoding or decoding operation and produces any remaining output
 * @param vctx Context pointer
 * @param out Output buffer for any remaining encoded or decoded data
 * @param outLen Pointer to variable that will receive the length of remaining output data in bytes
 */
void base32Final(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees any resources associated with the Base32 context
 * @param vctx Context pointer
 */
void base32Free(void *vctx);

/* ----- one-shot Base32 encoding/decoding ----- */

/**
 * @brief Encodes binary data into Base32 string format (RFC 4648)
 * @param input Pointer to binary data to encode
 * @param inputLen Length of binary data in bytes
 * @param output Buffer to store the resulting Base32 string (must be large enough)
 * @param outputSize Size of the output buffer in bytes
 * @return The length of the resulting Base32 string (not including null terminator),
 *         or (size_t)-1 on error
 */
size_t base32Encode(const uint8_t *input, size_t inputLen, char *output, size_t outputSize);

/**
 * @brief Decodes a Base32 string back into binary data (RFC 4648)
 * @param input Null-terminated Base32 string to decode
 * @param output Buffer to store the resulting binary data (must be large enough)
 * @param outputSize Size of the output buffer in bytes
 * @return The length of the resulting binary data in bytes, or (size_t)-1 on error
 */
size_t base32Decode(const char *input, uint8_t *output, size_t outputSize);

/**
 * @brief Returns the maximum length needed for Base32 encoding
 * @param inputLen Length of the input data in bytes
 * @return Maximum length of the Base32 encoded string (including padding)
 */
size_t base32EncodedLength(size_t inputLen);

/**
 * @brief Returns the maximum length needed for Base32 decoding
 * @param input The Base32 encoded string
 * @return Maximum length of the decoded binary data
 */
size_t base32DecodedLength(const char *input);

#endif /* HAJCRYPT_BASE32_H */
