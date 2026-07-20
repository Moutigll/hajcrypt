#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"

#include "../../includes/cli/algoHandling.h"
#include "../../includes/cli/cert.h"
#include "../../includes/cli/parser.h"
#include "../../includes/cli/pkey.h"
#include "../../includes/cli/tls.h"
#include "../../includes/cli/totp.h"

typedef int (*t_cmdFunc)(int argc, char **argv, char **env);

typedef struct s_cmdEntry {
	t_cmdType	type;
	t_cmdFunc	func;
} t_cmdEntry;

static const t_cmdEntry g_cmdTable[] = {
	{CMD_GENPKEY,	cmdGenPkey},
	{CMD_PKEY,		cmdPkey},
	{CMD_PKEYUTL,	cmdPkeyutl},
	{CMD_CERT,		cmdCert},
	{CMD_SERVER,	cmdServer},
	{CMD_TOTP,		cmdTotp}
};

static int executeSsl(t_sslOptions *opts, int argc, char **argv, char **env)
{
	const t_hash	*hash;
	size_t			i;
	int				fd;

	if (opts->cmdType == CMD_HASH) {
		hash = getHashByAlgo(opts->algo);
		if (!hash)
			return (1);

		/* -p : read from stdin */
		if (opts->flagP)
			processFd(STDIN_FILENO, hash, opts, NULL);

		/* -s : strings */
		i = 0;
		while (i < opts->stringCount)
		{
			processString(opts->stringInputs[i], hash, opts);
			i++;
		}

		/* files */
		i = 0;
		while (i < opts->fileCount)
		{
			fd = open(opts->fileInputs[i], O_RDONLY);
			if (fd < 0)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: %s: %s: No such file or directory\n",
					getAlgoName(opts->algo),
					opts->fileInputs[i]);
			}
			else
			{
				processFd(fd, hash, opts, opts->fileInputs[i]);
				close(fd);
			}
			i++;
		}

		/* default stdin */
		if (opts->readFromStdin && !opts->flagP)
			processFd(STDIN_FILENO, hash, opts, NULL);
	} else if (opts->cmdType == CMD_CIPHER)
		return (executeCipher(opts));
	else {
		for (i = 0; i < sizeof(g_cmdTable) / sizeof(g_cmdTable[0]); i++) {
			if (g_cmdTable[i].type == opts->cmdType) {
				return (g_cmdTable[i].func(argc, argv, env));
			}
		}
		ft_dprintf(STDERR_FILENO, "ft_ssl: unknown command type\n");
		return (1);
	}
	return (0);
}

int main(int argc, char **argv, char **env)
{
	t_sslOptions	opts = {0};
	int				status;

	if (parseSslArgs(argc, argv, &opts))
		return (1);

	status = executeSsl(&opts, argc, argv, env);

	freeSslOptions(&opts);
	return (status);
}
