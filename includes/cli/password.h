#ifndef CLI_PASSWORD_H
#define CLI_PASSWORD_H

#include "parser.h"

typedef enum e_passType {
	PASSWORD_TYPE_PASS,			/* pass:secret */
	PASSWORD_TYPE_ENV,			/* env:VARNAME */
	PASSWORD_TYPE_FILE,			/* file:path/to/file */
	PASSWORD_TYPE_FD,			/* fd:3 */
	PASSWORD_TYPE_STDIN,		/* stdin */
	PASSWORD_TYPE_INTERACTIVE	/* no argument, prompt user */
} t_passType;

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
 * @brief Retrieves a password based on the specified argument and verification requirements.
 *
 * This function processes the provided argument to determine how to obtain the password. It supports
 * various methods of password retrieval, including direct input, environment variables, files, file
 * descriptors, standard input, and interactive prompts. If the `verify` flag is set, it will also
 * prompt the user to confirm the password by entering it twice.
 *
 * @param arg The argument specifying how to retrieve the password (e.g., "pass:secret", "env:VARNAME").
 * @param env An array of environment variables (in "KEY=VALUE" format) that can be used for retrieving passwords from environment variables.
 *
 * @return A dynamically allocated string containing the retrieved password on success, or NULL on failure.
 *         The caller is responsible for freeing the returned string.
 */
char *getPassword(const char *arg, char **env);

/**
 * @brief Prompts the user to input a password with an optional verification step.
 *
 * This function interactively prompts the user to enter a password. If the `verify` flag
 * is set, it will ask the user to enter the password twice and verify that both entries match.
 *
 * @param prompt The message to display when asking for the password.
 * @param verify If non-zero, the function will require the user to enter the password twice for verification.
 *
 * @return A dynamically allocated string containing the entered password on success, or NULL on failure.
 *         The caller is responsible for freeing the returned string.
 */
char *promptPassword(const char *prompt, int verify);

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

/**
 * @brief Frees any dynamically allocated memory within the t_sslOptions structure.
 *
 * This function checks for and frees any dynamically allocated fields within the provided
 * t_sslOptions structure, such as keyHex, ivHex, saltHex, and password. It is important to
 * call this function to prevent memory leaks after using a t_sslOptions instance.
 *
 * @param opts Pointer to the t_sslOptions structure to clean up. Must not be NULL.
 */
void cleanupSslOptions(t_sslOptions *opts);

#endif /* CLI_PASSWORD_H */
