#ifndef HAJCRYPT_ALGO_HANDLING_H
#define HAJCRYPT_ALGO_HANDLING_H

#include "parser.h"

#define CIPHER_BUFFER_SIZE (16 * 1024)

/**
 * @struct t_cipherCtx
 * @brief Structure representing the context for cipher operations.
 *
 * This structure holds all necessary information for performing cryptographic
 * operations using a specified cipher algorithm.
 *
 * @var void* ctx
 *      Pointer to the internal cipher context (implementation-specific).
 * @var const t_cipher* cipher
 *      Pointer to the cipher algorithm being used.
 * @var t_sslOptions* opts
 *      Pointer to SSL options for configuring the cipher operation.
 * @var int outFd
 *      File descriptor for output operations.
 * @var int shouldWrap
 *      Flag indicating whether output should be wrapped (e.g., for PEM formatting).
 * @var int lineLen
 *      Length of lines when wrapping output.
 */
typedef struct s_cipherCtx
{
	void				*ctx;
	const t_cipher		*cipher;
	t_sslOptions		*opts;
	int					outFd;
	int					shouldWrap;
	int					lineLen;
}	t_cipherCtx;

typedef struct s_blockData
{
	uint8_t				lastBlock[32];
	uint8_t				tempBuffer[CIPHER_BUFFER_SIZE + 32];
	size_t				lastLen;
}	t_blockData;

/**
 * @brief Processes a file descriptor using the specified hash algorithm and SSL options.
 *
 * This function reads data from the given file descriptor, applies the provided hash algorithm,
 * and processes it according to the SSL options. The filename is used for logging or error reporting.
 *
 * @param fd File descriptor to process.
 * @param hash Pointer to the hash algorithm configuration.
 * @param opts Pointer to SSL options structure.
 * @param filename Name of the file associated with the file descriptor (for logging or error reporting).
 * @return int Returns 0 on success, or a negative value on error.
 */
int processFd(int fd, const t_hash *hash, t_sslOptions *opts, const char *filename);

/**
 * @brief Processes the input string using the specified hash algorithm and SSL options.
 *
 * This function takes an input string, applies the provided hash algorithm, and utilizes
 * SSL options for additional processing as required.
 *
 * @param str The input string to be processed.
 * @param hash Pointer to the hash algorithm structure to use for processing.
 * @param opts Pointer to the SSL options structure for additional configuration.
 * @return int Returns a status code indicating success or failure of the processing.
 */
int processString(const char *str, const t_hash *hash, t_sslOptions *opts);

/**
 * @brief Executes the cipher operation based on the provided SSL options.
 *
 * This function performs encryption or decryption as specified in the
 * t_sslOptions structure. It handles the setup and execution of the cipher
 * algorithm, processing input and output as required.
 *
 * @param opts Pointer to a t_sslOptions structure containing cipher parameters.
 * @return int Returns 0 on success, or a non-zero error code on failure.
 */
int	executeCipher(t_sslOptions *opts);

/* ---------- Cipher io helpers ---------- */

/**
 * @brief Writes output data to a file descriptor, optionally wrapping lines.
 *
 * @param fd         The file descriptor to write to.
 * @param data       Pointer to the data buffer to be written.
 * @param len        Length of the data buffer.
 * @param shouldWrap If non-zero, lines will be wrapped according to lineLen.
 * @param lineLen    Pointer to an integer specifying the maximum line length; updated with the current line length.
 * @return           Returns 0 on success, or a negative value on error.
 */
int	writeOutput(int				fd,
				const uint8_t	*data,
				size_t			len,
				int				shouldWrap,
				int				*lineLen);


/**
 * @brief Prepares the key and initialization vector (IV) for the specified cipher.
 *
 * This function generates or processes the key and IV based on the provided SSL options
 * and cipher configuration. The resulting key and IV are written to the provided buffers.
 *
 * @param opts   Pointer to SSL options structure containing user parameters.
 * @param cipher Pointer to cipher configuration structure.
 * @param key    Buffer to store the generated or processed key.
 * @param iv     Buffer to store the generated or processed initialization vector (IV).
 * @return       0 on success, non-zero on failure.
 */
int	prepareKeyAndIv(t_sslOptions	*opts,
					const t_cipher	*cipher,
					uint8_t			*key,
					uint8_t			*iv);

int	openInputFile(const char *filename, const char *cipherName);
int	openOutputFile(const char *filename, const char *cipherName);

#endif /* HAJCRYPT_ALGO_HANDLING_H */
