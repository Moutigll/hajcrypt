#ifndef HAJCRYPT_CLI_PARSER_H
#define HAJCRYPT_CLI_PARSER_H

#include <stddef.h>

#include "client.h"

typedef enum e_cmdType {
	CMD_HASH,
	CMD_ENCODE
} t_cmdType;

typedef struct s_sslOptions
{
	t_algo		algo;
	t_cmdType	cmdType;

	int		flagP;
	int		flagQ;
	int		flagR;
	int		flagK;

	char	*hmacKey;

	char	**stringInputs;
	size_t	stringCount;

	char	**fileInputs;
	size_t	fileCount;

	size_t	maxInputs;

	int		readFromStdin;

	/* Encoding */
	int		isDecoding;
	char	*inputFile;
	char	*outputFile;
	int		wrapOutput;
}	t_sslOptions;

typedef struct {
	const char	*name;
	t_algo		algo;
} t_algoName;


int	parseSslArgs(int argc, char **argv, t_sslOptions *opts);

void freeSslOptions(t_sslOptions *opts);

const char *getAlgoName(t_algo algo);

void printAlgoName(t_algo algo);



int processFd(int fd, const t_hash *hash, t_sslOptions *opts, const char *filename);

int processString(const char *str, const t_hash *hash, t_sslOptions *opts);
int	executeEncode(t_sslOptions *opts);

#endif /* HAJCRYPT_CLI_PARSER_H */
