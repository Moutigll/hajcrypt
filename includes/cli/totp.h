#ifndef CLI_TOTP_H
#define CLI_TOTP_H

#include "../cipher/cipher.h"

/* Default values */
#define DEFAULT_ALGO		&g_sha1Hash
#define DEFAULT_DIGITS		6
#define DEFAULT_PERIOD		30
#define DEFAULT_WINDOW		1
#define DEFAULT_USER		"Unknown"
#define DEFAULT_ISSUER		"hajcrypt"

/* Option flags */
typedef struct s_totpOpts {
	/* Input sources */
	char		**secrets;		/* multiple -s secrets (Base32), NULL‑terminated */
	int			secretCount;
	char		**inputFiles;	/* multiple -i paths (file/dir), NULL‑terminated */
	int			inputCount;
	char		**uris;		/* multiple positional URIs, NULL‑terminated */
	int			uriCount;

	/* Output */
	const char *outputFile; /* -o output file path */

	/* Passwords */
	const char	*passin;	/* -p (input password) */
	const char	*passout;	/* -P (output password) */

	/* Per‑entry defaults - will b used for input without explicit values */
	const char	*algoName;
	int			digits;
	int			period;
	int			window;
	const char	*user;
	const char	*issuer;\

	/* Flags */
	int		 generateUris;	/* -U */
	int		 live;			/* -l display a continuous stream of TOTP values */
	int		 batch;			/* -b */
	int		 showSecret;	/* -S */

	/* Cipher for encryption (e.g. --aes256‑cbc) */
	const t_cipher *cipher;
} t_totpOpts;

int cmdTotp(int argc, char **argv, char **env);

#endif /* CLI_TOTP_H */
