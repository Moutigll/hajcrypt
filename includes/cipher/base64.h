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
 * @var s_base64Ctx::isDecoding
 *      Flag indicating operation mode (non-zero for decoding, zero for encoding)
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


void base64Init(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir);

#endif /* HAJCRYPT_BASE64_H */
