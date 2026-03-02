#ifndef HAJCRYPT_BASE64_H
#define HAJCRYPT_BASE64_H

#include <stddef.h>
#include <stdint.h>


/**
 * @struct s_base64Ctx
 * @brief Context structure for Base64 encoding and decoding operations.
 *
 * This structure maintains the state information needed for streaming
 * Base64 encoding and decoding processes.
 *
 * @member buffer	Temporary buffer to store bits during encoding/decoding operations
 * @member bits	  Number of valid bits currently stored in the buffer
 * @member isDecoding Flag indicating whether the context is in decoding mode (1) or encoding mode (0)
 * @member lineLen   Current line length, typically used to track Base64 output line wrapping
 * @member outCount  Number of output bytes written so far
 */
typedef struct s_base64Ctx {
	uint32_t	buffer;
	int			bits;
	int			isDecoding;
	size_t		outCount;
	int			error;
} t_base64Ctx;


/**
 * @brief Initializes the base64 encoding/decoding context.
 * 
 * @param ctx Pointer to the base64 context structure to be initialized.
 * @param isDecoding Flag indicating the operation mode:
 *				   - Non-zero: Initialize for decoding base64 data
 *				   - Zero: Initialize for encoding data to base64
 * 
 * @return void
 */
void base64Init(void *ctx, int isDecoding);

/**
 * @brief Updates the base64 context with input data for encoding or decoding.
 * 
 * @param ctx Pointer to the base64 context structure being updated.
 * @param in Pointer to the input data buffer (raw bytes for encoding, base64 string for decoding).
 * @param inLen Length of the input data in bytes.
 * @param out Pointer to the output buffer where encoded/decoded data will be written.
 * @param outLen Pointer to a size_t variable where the number of bytes written to the output buffer will be stored.
 * 
 * @return 0 on success, -1 on error
 */
int	base64Update(void			*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen);


/**
 * @brief Finalizes the Base64 encoding process and outputs the result.
 * 
 * This function completes the Base64 encoding operation, handling any remaining
 * data and padding as required by the Base64 standard. It must be called after
 * all data has been processed with the encoding function.
 * 
 * @param ctx Pointer to the Base64 encoding context containing the state
 *			of the ongoing encoding process.
 * @param out Pointer to the output buffer where the final encoded data
 *			(including padding) will be written.
 * @param outLen Pointer to a size_t variable that specifies the maximum
 *			   capacity of the output buffer on input, and receives the
 *			   actual number of bytes written on output.
 * 
 * @note The caller is responsible for ensuring that the output buffer
 *	   has sufficient capacity to hold the finalized data.
 * @note After calling this function, the context should not be reused
 *	   without re-initialization.
 */
void base64Final(void *ctx, uint8_t *out, size_t *outLen);




/**
 * @brief Encodes binary data to Base64 format.
 * 
 * @param in Pointer to the input buffer containing binary data to be encoded.
 * @param inLen The length of the input buffer in bytes.
 * @param out Pointer to the output buffer where the Base64-encoded string will be stored.
 *			The caller must ensure this buffer is large enough to hold the encoded data
 *			plus a null terminator.
 * 
 * @return The number of characters written to the output buffer (excluding null terminator).
 * 
 * @note The output buffer should be allocated with at least ((inLen + 2) / 3) * 4 + 1 bytes
 *	   to accommodate the encoded data and null terminator.
 */
size_t base64Encode(const uint8_t *in, size_t inLen, char *out);

/**
 * @brief Decodes a Base64-encoded string back into binary data.
 * 
 * @param in Pointer to the input buffer containing the Base64-encoded string.
 * @param inLen The length of the input buffer in bytes.
 * @param out Pointer to the output buffer where the decoded binary data will be stored.
 *			The caller must ensure this buffer is large enough to hold the decoded data.
 * 
 * @return The number of bytes written to the output buffer, or (size_t)-1 if an error occurs
 *		 (e.g., invalid Base64 input).
 * 
 * @note The output buffer should be allocated with at least (inLen / 4) * 3 bytes to accommodate
 *	   the maximum possible decoded data size, considering padding.
 */
size_t base64Decode(const char *in, size_t inLen, uint8_t *out);

#endif /* HAJCRYPT_BASE64_H */
