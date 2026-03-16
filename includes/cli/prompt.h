#ifndef CLI_PROMPT_H
#define CLI_PROMPT_H

#include "parser.h"

typedef struct s_kdfParams {
	t_kdfChoice	choice;
	char		*password;
	uint8_t		salt[16];
	size_t		saltLen;
	int			iterations;		/* For PBKDF2, Bcrypt rounds, or Argon2 iterations */
	int			memory;			/* For Argon2: memory in KiB */
	int			parallelism;	/* For Argon2: number of threads */
	int			keyLen;			/* Desired key length in bytes */
} t_kdfParams;


/**
 * @brief Prompts the user to input cipher parameters and stores them in the provided options structure.
 * 
 * This function interactively requests cipher-related configuration from the user and populates
 * the given SSL options structure with the provided parameters.
 * 
 * @param opts Pointer to a t_sslOptions structure where the cipher parameters will be stored.
 *             Must not be NULL.
 * 
 * @return int Returns 0 on successful completion, or a non-zero error code if the operation fails
 *             or the user provides invalid input.
 * 
 * @note The caller is responsible for ensuring that the t_sslOptions pointer is valid and
 *       properly initialized before calling this function.
 */
int promptForCipherParams(t_sslOptions *opts);

/**
 * @brief Generates a cryptographic key from user input prompts using KDF parameters.
 *
 * @param params Pointer to a t_kdfParams structure containing key derivation function
 *               parameters (such as algorithm, salt, iterations, etc.)
 * @param key Pointer to a buffer where the generated key will be stored.
 * @param keyLen The desired length of the generated key in bytes.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int generateKeyFromPrompt(t_kdfParams *params, uint8_t *key, size_t keyLen);

/**
 * @brief Prompts the user to input an initialization vector (IV) in hexadecimal format.
 *
 * This function requests the user to enter an IV as a hexadecimal string. The input is
 * validated to ensure it matches the expected length (ivLen bytes, which corresponds to
 * ivLen*2 hex characters). If the user presses Enter without providing input, the IV will
 * be set to all zeros.
 *
 * @param iv Pointer to a buffer where the generated IV will be stored.
 * @param ivLen The expected length of the IV in bytes.
 *
 * @return 0 on success, non-zero error code on failure (e.g., invalid input, read error).
 */
int generateIvFromPrompt(uint8_t *iv, size_t ivLen);

#endif
