#ifndef CLI_PKEY_H
#define CLI_PKEY_H

#include "parser.h"

typedef struct s_pkeyOptions
{
	const char		*inFile;
	const char		*outFile;
	int				pubin;
	int				pubout;
	int				text;
	int				noout;
	int				modulus;	/* RSA only - silently ignored for others */
	int				check;
	int				traditional;
	int				breakIt;
	int				help;
	const char		*passin;
	const char		*passout;
	const t_cipher	*cipher;
}	t_pkeyOptions;

typedef struct s_genpkeyOpts
{
	char		*outFile;
	char		*pubOutFile;
	char		*passout;
	int			traditional;
}	t_genpkeyOpts;

typedef struct s_pkeyutlOptions
{
	const char	*inFile;
	const char	*outFile;
	const char	*keyFile;
	const char	*passin;
	const char	*sigFile;
	const char	*dgstName;
	int			paddingType;

	int			pubin;
	int			encrypt;
	int			decrypt;
	int			sign;
	int			verify;
	int			hexdump;
	int			hashInput;
	int			help;
}	t_pkeyutlOptions;

/**
 * @brief Generates an asymmetric key pair based on the specified algorithm and options.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to command-line argument strings.
 * @param env An array of pointers to environment variable strings.
 *
 * @return Returns 0 on successful asymmetric key pair generation, or a non-zero
 *         error code on failure.
 */
int	cmdGenPkey(int argc, char **argv, char **env);

/**
 * @brief Executes the `pkey` command based on the provided command-line arguments.
 *
 * This function parses the command-line arguments specific to the PKEY command,
 * performs the requested operations (e.g., key generation, key checking, output formatting),
 * and handles input/output as specified in the options.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to command-line argument strings.
 * @param env An array of pointers to environment variable strings.
 *
 * @return Returns 0 on successful execution of the PKEY command, or a non-zero
 *         error code on failure (e.g., invalid arguments, file I/O errors).
 */
int	cmdPkey(int argc, char **argv, char **env);

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

int		writePkeyOutput(const char *filename, const char *data);

#endif // CLI_PKEY_H
