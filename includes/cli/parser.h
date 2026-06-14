#ifndef HAJCRYPT_CLI_PARSER_H
#define HAJCRYPT_CLI_PARSER_H

#include <stddef.h>

#include "../x509/pemCipher.h"
#include "../utils/dispatch.h"

typedef enum e_cmdType {
	CMD_HASH,
	CMD_CIPHER,
	CMD_GENPKEY,
	CMD_PKEY,
	CMD_PKEYUTL
} t_cmdType;

typedef enum e_kdfChoice {
	KDF_BYTESTOKEY,  /* OpenSSL's legacy key derivation method (MD5-based) */
	KDF_PBKDF2,
	KDF_BCRYPT,
	KDF_ARGON2D,
	KDF_ARGON2I,
	KDF_ARGON2ID
} t_kdfChoice;

typedef struct s_sslOptions
{
	t_algo		algo;
	t_cmdType	cmdType;

/* ---------- Common options ---------- */
	int		flagP;			/* -p for hash: echo stdin to stdout */
	int		flagQ;			/* -q for hash: quiet mode, only print the hash */
	int		flagR;			/* -r for hash: reverse the format of the output */
	int		flagK;			/* -k for cipher: for HMAC (hash) and cipher key */
	int		useBase64;		/* -a for hash: base64 encode the output, for cipher: base64 encode input and output */
	int		flagB;			/* -b for hash: output binary instead of hex */

	char	*hmacKey;		/* -k for cipher: HMAC key */

/* ---------- Cipher options ---------- */
	char	*keyHex;		/* -k for cipher: key in hex */
	char	*password;		/* -p password to derive key and iv from */
	char	*saltHex;		/* -s salt in hex for key derivation */
	char	*ivHex;			/* -i iv in hex */
	char	*inputFile;		/* -i input file */
	char	*outputFile;	/* -o output file */
	int		isDecoding;		/* -d decrypt mode */
	int		wrapOutput;		/* -w wrap output */
	int		noPadding;		/* --nopad disable padding */

	char	**stringInputs;
	size_t	stringCount;
	char	**fileInputs;
	size_t	fileCount;
	size_t	maxInputs;
	int		readFromStdin;

/* ---------- Derived parameters ---------- */
	t_kdfChoice	kdfChoice;
	int			kdfIterations;
	int			kdfMemory;
	int			kdfParallelism;
}	t_sslOptions;

typedef struct {
	const char	*name;
	t_algo		algo;
} t_algoName;


/**
 * @brief Parses command-line arguments for SSL/TLS configuration options.
 * 
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to command-line argument strings.
 * @param opts A pointer to a t_sslOptions structure where parsed options will be stored.
 * 
 * @return An integer status code indicating success or failure:
 *         - 0 on success
 *         - Non-zero on error (specific error code depends on implementation)
 * 
 * @note The caller is responsible for ensuring that argv is valid and opts points
 *       to a valid t_sslOptions structure.
 */
int	parseSslArgs(int argc, char **argv, t_sslOptions *opts);

/**
 * @brief Frees the memory allocated for SSL options structure.
 * 
 * Deallocates all dynamically allocated memory within the provided SSL options
 * structure and optionally frees the structure itself.
 * 
 * @param opts Pointer to the t_sslOptions structure to be freed.
 *             If NULL, the function should handle it gracefully.
 * 
 * @return void
 * 
 * @note Ensure that opts is not used after calling this function to avoid
 *       use-after-free errors.
 */
void freeSslOptions(t_sslOptions *opts);

/**
 * @brief Prints the name of the specified algorithm to standard output.
 * 
 * @param algo The algorithm type whose name is to be printed.
 * 
 * @return void
 */
void printAlgoName(t_algo algo);


#endif /* HAJCRYPT_CLI_PARSER_H */
