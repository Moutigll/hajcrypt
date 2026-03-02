#ifndef HAJCRYPT_BASE64_H
#define HAJCRYPT_BASE64_H

#include <stdint.h>
#include <stddef.h>


/**
 * @brief Encodes binary data to a Base64-encoded string.
 * 
 * @param input Pointer to the input buffer containing binary data to be encoded.
 * @param inputLen The length of the input buffer in bytes.
 * @param output Pointer to the output buffer where the Base64-encoded string will be stored.
 *			   The caller is responsible for ensuring the buffer is large enough.
 * 
 * @return The number of bytes written to the output buffer, including the null terminator if applicable.
 * 
 * @note The output buffer should be at least (inputLen * 4 / 3) + 4 bytes to accommodate
 *	   the encoded data and any padding.
 */
size_t	base64Encode(const uint8_t	*input,
					 size_t			inputLen,
					 char			*output);


/**
 * @brief Decodes a base64 encoded string into binary data.
 *
 * @param input Pointer to the base64 encoded input string.
 * @param inputLen Length of the input base64 string in bytes.
 * @param output Pointer to the output buffer where decoded binary data will be stored.
 *
 * @return The number of bytes written to the output buffer, or 0 on error.
 *
 * @note The output buffer must be large enough to hold the decoded data.
 *	   The maximum decoded size can be calculated as: (inputLen * 3) / 4
 */
size_t	base64Decode(const char	*input,
					 size_t		inputLen,
					 uint8_t	*output);

#endif /* HAJCRYPT_BASE64_H */
