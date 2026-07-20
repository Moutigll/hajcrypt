#ifndef CLI_TOTP_H
#define CLI_TOTP_H

/* Default values */
#define DEFAULT_ALGO		&g_sha1Hash
#define DEFAULT_DIGITS		6
#define DEFAULT_PERIOD		30
#define DEFAULT_WINDOW		1
#define DEFAULT_USER		"blahaj"
#define DEFAULT_ISSUER		"hajcrypt"

/* Option flags */
typedef struct s_totpOpts {
	const char	*secret;		/* Base32 secret (optional) */
	const char	*algoName;		/* Algorithm name (sha1, sha256, sha512) */
	int			digits;			/* Number of digits */
	int			period;			/* Time step in seconds */
	int			window;			/* Window for verification (not used in generation) */
	const char	*user;			/* User email for URI */
	const char	*issuer;		/* Issuer name for URI */
	int			generateUri;	/* Generate URI instead of code */
	int			live;			/* Live update mode (refresh every period) */
	int			batch;			/* Non‑interactive mode (use defaults for missing) */
	int			showSecret;		/* Also output the secret when generating URI */
	const char	*uri;			/* TOTP URI (otpauth://...) to parse */
} t_totpOpts;

int cmdTotp(int argc, char **argv, char **env);

#endif /* CLI_TOTP_H */
