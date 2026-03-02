#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../includes/cli/parser.h"


static int executeSsl(t_sslOptions *opts)
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
	} else if (opts->cmdType == CMD_ENCODE) {
		return executeEncode(opts);
	}

	return (0);
}

int main(int argc, char **argv)
{
	t_sslOptions	opts;
	int				status;

	if (parseSslArgs(argc, argv, &opts))
		return (1);

	status = executeSsl(&opts);

	freeSslOptions(&opts);
	return (status);
}
