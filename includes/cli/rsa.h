#ifndef CLI_RSA_H
#define CLI_RSA_H

#include "parser.h"

typedef struct s_rsaOptions
{
	const char		*inFile;		/* --in */
	const char		*outFile;		/* --out */
	int				pubin;			/* --pubin */
	int				pubout;			/* --pubout */
	const char		*pubOutFile;	/* --pubout with file argument genrsa */
	int				text;			/* --text */
	int				noout;			/* --noout */
	int				modulus;		/* --modulus */
	int				check;			/* --check */
	int				traditional;	/* --traditional */
	int				help;			/* --help */
	const char		*passin;
	const char		*passout;
	const t_cipher	*cipher;		/* Cipher for encrypting private key (if any) */
	char			*cipherName;	/* Name of the cipher specified on command line (e.g., "aes-256-cbc") */
}	t_rsaOptions;

/**
 * @brief Generates an RSA key pair based on the provided options.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to command-line argument strings.
 * @param env An array of pointers to environment variable strings.
 *
 * @return Returns 0 on successful RSA key pair generation, or a non-zero
 *         error code on failure.
 */
int cmdGenrsa(int argc, char **argv, char **env);

/**
 * @brief Executes the RSA command based on the provided command-line arguments.
 *
 * This function parses the command-line arguments specific to the RSA command,
 * performs the requested operations (e.g., key generation, key checking, output formatting),
 * and handles input/output as specified in the options.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to command-line argument strings.
 * @param env An array of pointers to environment variable strings.
 *
 * @return Returns 0 on successful execution of the RSA command, or a non-zero
 *         error code on failure (e.g., invalid arguments, file I/O errors).
 */
int	cmdRsa(int argc, char **argv, char **env);

/**
 * @brief Executes the Pkey utility command based on the provided command-line arguments.
 *
 * This function parses the command-line arguments specific to the Pkey utility command,
 * performs the requested operations (e.g., signature verification, encryption/decryption),
 * and handles input/output as specified in the options.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to command-line argument strings.
 * @param env An array of pointers to environment variable strings.
 *
 * @return Returns 0 on successful execution of the Pkey utility command, or a non-zero
 *         error code on failure (e.g., invalid arguments, file I/O errors).
 */
int	cmdPkeyutl(int argc, char **argv, char **env);

void	writeRsaOutput(const char *fileName, const char *data);
char	*readFileContent(const char *fileName);

#endif // CLI_RSA_H
