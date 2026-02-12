#ifndef HAJCRYPT_CLI_PARSER_H
#define HAJCRYPT_CLI_PARSER_H

#include <stddef.h>

typedef enum e_algo
{
	ALGO_NONE,
	ALGO_MD5,
	ALGO_SHA256
}	t_algo;

typedef struct s_sslOptions
{
	t_algo	algo;

	int		flagP;
	int		flagQ;
	int		flagR;

	char	**stringInputs;
	size_t	stringCount;

	char	**fileInputs;
	size_t	fileCount;

	size_t	maxInputs;

	int		readFromStdin;
}	t_sslOptions;

typedef struct {
	const char *name;
	void (*setter)(t_sslOptions *);
} t_algoDispatch;


int	parseSslArgs(int argc, char **argv, t_sslOptions *opts);


#endif /* HAJCRYPT_CLI_PARSER_H */
