#ifndef CLI_CERT_H
# define CLI_CERT_H

typedef struct s_certOptions {
	const char	*inFile;
	const char	*outFile;
	const char	*inform;
	const char	*outform;
	int			text;
	int			noout;
	int			fingerprint;
	int			serial;
	int			subject;
	int			issuer;
	int			dates;
	int			startdate;
	int			enddate;
	int			pubkey;
	int			modulus;
	int			checkend;
	int			verify;
	int			noVerify;
	long		checkendSeconds;
	int			newCert;
	int			selfSigned;
	int			days;
	const char *keyFile;
	const char *passin;
	const char *subj;
	int			help;
}	t_certOptions;

/**
 * @brief Prints the help message for the cert command.
 */
int cmdCert(int argc, char **argv, char **env);

#endif /* CLI_CERT_H */
