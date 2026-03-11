#ifndef HAJCRYPT_BASE64_H
#define HAJCRYPT_BASE64_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"

extern const t_cipher g_base64Cipher;

/**
 * @struct s_base64Ctx
 * @brief Context structure for Base64 encoding and decoding operations
 * 
 * @var s_base64Ctx::buffer
 *      Temporary buffer to accumulate bits during encoding/decoding
 * 
 * @var s_base64Ctx::bits
 *      Number of valid bits currently stored in the buffer
 * 
 * @var s_base64Ctx::dir
 *      Direction of operation (encryption for encoding, decryption for decoding)
 *
 * @var s_base64Ctx::outCount
 *      Counter for output characters processed or generated
 * 
 * @var s_base64Ctx::error
 *      Error status code (zero indicates no error)
 */
typedef struct s_base64Ctx {
	uint32_t			buffer;
	int					bits;
	t_cipherDirection	dir;
	size_t				outCount;
	int					error;
} t_base64Ctx;


/**
 * @brief Initializes the Base64 context for encoding or decoding
 * @param vctx Context pointer
 * @param key Encryption key (not used in Base64)
 * @param keyLen Length of the encryption key (not used in Base64)
 * @param iv Initialization vector (not used in Base64)
 * @param dir Direction of operation (encryption for encoding, decryption for decoding)
 */
void base64Init(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir);

/**
 * @brief Updates the Base64 context with input data for encoding or decoding
 * @param vctx Context pointer
 * @param in Input data buffer
 * @param inLen Length of the input data in bytes
 * @param out Output buffer for encoded or decoded data
 * @param outLen Pointer to variable that will receive the length of output data in bytes
 */
void base64Update(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen);

/**
 * @brief Finalizes the Base64 encoding or decoding operation and produces any remaining output
 * @param vctx Context pointer
 * @param out Output buffer for any remaining encoded or decoded data
 * @param outLen Pointer to variable that will receive the length of remaining output data in bytes
 */
void base64Final(void *vctx, uint8_t *out, size_t *outLen);

void base64Free(void *vctx);

/* ----- one-shot Base64 encoding/decoding ----- */

/**
 * @brief Encodes binary data into Base64 string format
 * @param input Pointer to binary data to encode
 * @param inputLen Length of binary data in bytes
 * @param output Buffer to store the resulting Base64 string (must be large enough)
 * @param outputSize Size of the output buffer in bytes
 * @return The length of the resulting Base64 string (not including null terminator)
 */
size_t base64Encode(const uint8_t *input, size_t inputLen, char *output, size_t outputSize);

/**
 * @brief Decodes a Base64 string back into binary data
 * @param input Null-terminated Base64 string to decode
 * @param output Buffer to store the resulting binary data (must be large enough)
 * @return The length of the resulting binary data in bytes, or (size_t)-1 on error
 */
size_t base64Decode(const char *input, uint8_t *output);

#endif /* HAJCRYPT_BASE64_H */
