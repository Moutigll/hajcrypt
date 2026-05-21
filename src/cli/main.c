#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"

#include "../../includes/cli/algoHandling.h"
#include "../../includes/cli/parser.h"
#include "../../includes/cli/pkey.h"


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
	else if (opts->cmdType == CMD_GENPKEY)
		return (cmdGenPkey(argc, argv, env));
	else if (opts->cmdType == CMD_RSA)
		return (cmdRsa(argc, argv, env));
	else if (opts->cmdType == CMD_PKEYUTL)
		return (cmdPkeyutl(argc, argv, env));
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
