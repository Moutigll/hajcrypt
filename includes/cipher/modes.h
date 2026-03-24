#ifndef CIPHER_MODES_H
# define CIPHER_MODES_H

# include "cipher.h"


typedef struct s_cbcGenCtx {
	uint8_t				iv[64]		__attribute__((aligned(16)));
	uint8_t				buffer[64]	__attribute__((aligned(16)));
	size_t				bufferLen;
	size_t				blockSize;
	t_cipherDirection	dir;
	const void			*cipherCtx;
	void (*processBlock)(const uint8_t*, uint8_t*, const void*, int);
} t_cbcGenCtx;

typedef struct s_cfbGenCtx {
	uint8_t				iv[64]				__attribute__((aligned(16)));
	uint8_t				shiftRegister[64]	__attribute__((aligned(16)));
	uint8_t				inputBuf[64]		__attribute__((aligned(16)));
	size_t				inputBufLen;
	size_t				blockSize;
	size_t				unitSize;	/* 1 for CFB1, 8 for CFB8, blockSize for CFB */
	t_cipherDirection	dir;
	const void			*cipherCtx;
	void (*processBlock)(const uint8_t*, uint8_t*, const void*);
} t_cfbGenCtx;

typedef struct s_ofbGenCtx {
	uint8_t		iv[64]			__attribute__((aligned(16)));
	uint8_t		keystream[64]	__attribute__((aligned(16)));	/* Buffer for the current keystream block */
	size_t		keystreamOff;									/* Offset in the keystream buffer for the next byte to use */
	uint8_t		inputBuf[64]	__attribute__((aligned(16)));
	size_t		inputBufLen;
	size_t		blockSize;
	const void	*cipherCtx;
	void (*processBlock)(const uint8_t*, uint8_t*, const void*);
} t_ofbGenCtx;



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
 *			   actual number of bytes written.
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
 *			will be written.
 * @param outLen Pointer to a size_t variable. On input, contains the maximum
 *			   available space in the output buffer. On output, contains the
 *			   number of bytes actually written.
 * 
 * @return void
 * 
 * @note The caller is responsible for ensuring that the output buffer has
 *	   sufficient space and that the context is properly initialized.
 */
void cbcGenFinal(t_cbcGenCtx *ctx, uint8_t *out, size_t *outLen);



/* ---------- CFB mode functions ---------- */



/**
 * @brief Updates CFB mode encryption/decryption context with input data.
 *
 * Processes input data using the specified CFB (Cipher Feedback) mode context,
 * encrypting or decrypting in blocks and storing the result in the output buffer.
 * Can be called multiple times to process data incrementally.
 *
 * @param ctx Pointer to the CFB mode context containing cipher state and IV.
 * @param in Pointer to input data buffer to be processed.
 * @param inLen Length of input data in bytes.
 * @param out Pointer to output buffer where processed data will be written.
 * @param outLen Pointer to variable holding output buffer size; updated with
 *			   actual number of bytes written.
 *
 * @return void
 *
 * @note Ensure output buffer is sufficiently sized before calling.
 * @note The context must have been properly initialized before use.
 * @note CFB mode doesn't require padding, so all input data will be processed.
 */
void cfbGenUpdate(t_cfbGenCtx	*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen);

/**
 * @brief Finalizes CFB mode encryption/decryption and outputs remaining data.
 *
 * Processes any pending data in the CFB context and generates the final output.
 * This function should be called after all data has been processed with the
 * main CFB processing function to ensure all data is properly encrypted/decrypted.
 *
 * @param ctx Pointer to the CFB mode context containing state and configuration.
 * @param out Pointer to the output buffer where final encrypted/decrypted data
 *			will be written.
 * @param outLen Pointer to a size_t variable. On input, contains the maximum
 *			   available space in the output buffer. On output, contains the
 *			   number of bytes actually written.
 *
 * @return void
 *
 * @note The caller is responsible for ensuring that the output buffer has
 *	   sufficient space and that the context is properly initialized.
 * @note Unlike CBC, CFB doesn't require a finalization step with padding,
 *	   but this function ensures all buffered data is processed.
 */
void cfbGenFinal(t_cfbGenCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Updates CFB1 mode encryption/decryption context with input data bit by bit.
 *
 * This function is specifically designed for CFB1 mode, where data is processed
 * one bit at a time. It takes the input bits, generates the keystream by
 * encrypting the shift register, and produces the output bits by XORing the
 * input bits with the keystream bits.
 *
 * @param ctx Pointer to the CFB mode context containing cipher state and IV.
 * @param in Pointer to input data buffer to be processed (bit-level).
 * @param inBits Length of input data in bits.
 * @param out Pointer to output buffer where processed data will be written (bit-level).
 * @param outBits Pointer to variable holding output buffer size in bits; updated with
 *			   actual number of bits written.
 * @return void
 * @note Ensure output buffer is sufficiently sized before calling.
 * @note The context must have been properly initialized before use.
 * @note CFB1 mode processes data bit by bit, so this function is used instead of cfbGenUpdate for CFB1 contexts.
 */
void cfb1Update(t_cfbGenCtx		*ctx,
				const uint8_t	*in,
				size_t			inBits,
				uint8_t			*out,
				size_t			*outBits);



/* ---------- OFB mode functions ---------- */


/**
 * @brief Updates the OFB (Output Feedback) cipher mode context and produces output.
 *
 * Processes input data through the OFB mode cipher, updating the internal state
 * and generating the corresponding output. This function is typically called
 * repeatedly to encrypt or decrypt data in chunks.
 *
 * @param ctx Pointer to the OFB mode context structure containing the cipher state
 *            and feedback buffer.
 * @param in Pointer to the input data buffer to be processed.
 * @param inLen Length of the input data in bytes.
 * @param out Pointer to the output buffer where encrypted/decrypted data will be written.
 * @param outLen Pointer to a size_t variable that will contain the number of bytes
 *               written to the output buffer upon function return.
 *
 * @return void
 *
 * @note The output buffer must be at least inLen bytes in length.
 * @note The outLen parameter is updated by the function to reflect actual bytes written.
 */
void ofbGenUpdate(t_ofbGenCtx	*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen);

/**
 * @brief Finalizes OFB (Output Feedback) mode generation and outputs remaining data.
 * 
 * @param ctx Pointer to the OFB generation context containing cipher state and configuration.
 * @param out Pointer to the output buffer where final ciphertext/plaintext will be written.
 * @param outLen Pointer to a size_t variable that contains the maximum output buffer size on input,
 *               and receives the actual number of bytes written on output.
 * 
 * @note This function should be called after all data has been processed with ofbGenUpdate()
 *       to finalize the cipher operation and handle any remaining buffered data.
 */
void ofbGenFinal(t_ofbGenCtx *ctx, uint8_t *out, size_t *outLen);

#endif /* CIPHER_MODES_H */
