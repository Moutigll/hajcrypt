#ifndef CIPHER_MODES_H
# define CIPHER_MODES_H

# include "cipher.h"


typedef struct s_cbcGenCtx {
	uint8_t				iv[64] __attribute__((aligned(16)));
	uint8_t				buffer[64] __attribute__((aligned(16)));
	size_t				bufferLen;
	size_t				blockSize;
	t_cipherDirection	dir;
	const void			*cipherCtx;
	void (*processBlock)(const uint8_t*, uint8_t*, const void*, int);
} t_cbcGenCtx;



/**
 * @brief Updates CBC mode encryption/decryption context with input data.
 * 
 * Processes input data using the specified CBC (Cipher Block Chaining) mode context,
 * encrypting or decrypting in blocks and storing the result in the output buffer.
 * Can be called multiple times to process data incrementally.
 * 
 * @param ctx Pointer to the CBC mode context containing cipher state and IV.
 * @param in Pointer to input data buffer to be processed.
 * @param inLen Length of input data in bytes.
 * @param out Pointer to output buffer where processed data will be written.
 * @param outLen Pointer to variable holding output buffer size; updated with 
 *               actual number of bytes written.
 * 
 * @return void
 * 
 * @note Ensure output buffer is sufficiently sized before calling.
 * @note The context must have been properly initialized before use.
 */
void cbcGenUpdate(t_cbcGenCtx	*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen);

/**
 * @brief Finalizes CBC mode encryption/decryption and outputs remaining data.
 * 
 * Processes any pending data in the CBC context and generates the final output.
 * This function should be called after all data has been processed with the
 * main CBC processing function to ensure all data is properly encrypted/decrypted
 * and padded/unpadded as necessary.
 * 
 * @param ctx Pointer to the CBC mode context containing state and configuration.
 * @param out Pointer to the output buffer where final encrypted/decrypted data
 *            will be written.
 * @param outLen Pointer to a size_t variable. On input, contains the maximum
 *               available space in the output buffer. On output, contains the
 *               number of bytes actually written.
 * 
 * @return void
 * 
 * @note The caller is responsible for ensuring that the output buffer has
 *       sufficient space and that the context is properly initialized.
 */
void cbcGenFinal(t_cbcGenCtx *ctx, uint8_t *out, size_t *outLen);



#endif /* CIPHER_MODES_H */
