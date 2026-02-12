#include <stdio.h>
#include <stdlib.h>

#include "../../hajlib/include/hajlib.h"	/* IWYU pragma: keep */
#include "../../includes/cli/parser.h"


/* -------------------------- helpers -------------------------- */

void freeSslOptions(t_sslOptions *opts)
{
	if (!opts)
		return;
	free(opts->stringInputs);
	free(opts->fileInputs);
	opts->stringInputs = NULL;
	opts->fileInputs = NULL;
	opts->stringCount = 0;
	opts->fileCount = 0;
	opts->maxInputs = 0;
}


int initSslOptions(t_sslOptions *opts, int argc)
{
	size_t cap;

	if (!opts)
		return (1);


	opts->algo = ALGO_NONE;
	opts->flagP = 0;
	opts->flagQ = 0;
	opts->flagR = 0;
	opts->readFromStdin = 0;
	opts->stringInputs = NULL;
	opts->stringCount = 0;
	opts->fileInputs = NULL;
	opts->fileCount = 0;

	cap = (argc > 0) ? (size_t)argc : 1;
	opts->maxInputs = cap;

	opts->stringInputs = malloc(sizeof(char *) * cap);
	opts->fileInputs   = malloc(sizeof(char *) * cap);
	if (!opts->stringInputs || !opts->fileInputs)
	{
		freeSslOptions(opts);
		return (1);
	}
	ft_bzero(opts->stringInputs, sizeof(char *) * cap);
	ft_bzero(opts->fileInputs, sizeof(char *) * cap);

	return (0);
}

/* ------------------------ algorithm dispatch ------------------------ */

static void setAlgoMd5(t_sslOptions *opts)    { opts->algo = ALGO_MD5; }
static void setAlgoSha256(t_sslOptions *opts) { opts->algo = ALGO_SHA256; }

static const t_algoDispatch gAlgoDispatch[] = {
	{ "md5",    setAlgoMd5    },
	{ "sha256", setAlgoSha256 },
	{ NULL,     NULL          }
};

/**
 * @brief Parse the algorithm name and set the corresponding algo in opts. *
 * @param arg - algorithm name (e.g. "md5", "sha256")
 * @param opts - options struct to set algo field in
 * @return 0 on success, 1 on failure (invalid algorithm)
 */
static int parseAlgorithm(const char *arg, t_sslOptions *opts)
{
	size_t i;

	if (!arg || !opts)
		return (1);

	i = 0;
	while (gAlgoDispatch[i].name)
	{
		if (ft_strcmp(arg, gAlgoDispatch[i].name) == 0)
		{
			gAlgoDispatch[i].setter(opts);
			return (0);
		}
		i++;
	}
	fprintf(stderr, "ft_ssl: Error: '%s' is an invalid command.\n", arg);
	return (1);
}

/**
 * @brief Parse command-line arguments for ft_ssl, populating the opts struct.
 * Expects argv[1] to be the algorithm name, followed by options and file names.
 * @param argc - argument count
 * @param argv - argument vector (argv[0] = program name, argv[1] = algorithm, argv[2...] = options/files)
 * @param opts - pointer to options struct to populate based on parsed arguments
 * @return 0 on success, 1 on failure (invalid args, memory allocation failure, etc.)
 */
int parseSslArgs(int argc, char **argv, t_sslOptions *opts)
{
	tFtGetopt st;
	tFtGetoptStatus status;
	const char *shortOpts = "pqrs:";

	/* minimal validation */
	if (argc < 2 || !argv || !opts)
	{
		/* TODO: print a list of available algorithms */
		fprintf(stderr, "ft_ssl: missing command\n");
		return (1);
	}

	if (initSslOptions(opts, argc) != 0)
	{
		fprintf(stderr, "ft_ssl: memory allocation failed\n");
		return (1);
	}

	if (parseAlgorithm(argv[1], opts) != 0)
	{
		freeSslOptions(opts);
		return (1);
	}

	if (argc <= 2)	/* if there are no further args, default to stdin */
	{
		opts->readFromStdin = 1;
		return (0);
	}

	ftGetoptInit(&st, argc - 2, argv + 2);

	/* iterate options */
	for (;;)
	{
		status = ft_getoptLong(&st, shortOpts, NULL);

		if (status == FT_GETOPT_END)
			break;

		if (status == FT_GETOPT_ERROR)
		{
			/* st.badOpt or st.status carries info; print usable message */
			fprintf(stderr, "ft_ssl: %s: illegal option -- %s\n",
				argv[1], st.badOpt ? st.badOpt : "(unknown)");
			freeSslOptions(opts);
			return (1);
		}

		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
				case 'p':
					opts->flagP = 1;
					opts->readFromStdin = 1;
					break;

				case 'q':
					opts->flagQ = 1;
					break;

				case 'r':
					opts->flagR = 1;
					break;

				case 's':
					if (st.optArg)
					{
						if (opts->stringCount < opts->maxInputs)
							opts->stringInputs[opts->stringCount++] = (char *)st.optArg;
						else
						{
							fprintf(stderr, "ft_ssl: too many inputs\n");
							freeSslOptions(opts);
							return (1);
						}
					}
					else
					{
						fprintf(stderr, "ft_ssl: %s: option requires an argument -- s\n", argv[1]);
						freeSslOptions(opts);
						return (1);
					}
					break;

				default:
					/* unknown option value (defensive) */
					fprintf(stderr, "ft_ssl: unknown option '%c'\n", (char)st.opt);
					freeSslOptions(opts);
					return (1);
			}
		}
	}

	/* remaining tokens (after options) are filenames.
	 * Note: st.argv points to argv+2; st.index is relative to that.
	 */
	while (st.index < st.argc)
	{
		if (opts->fileCount < opts->maxInputs)
			opts->fileInputs[opts->fileCount++] = st.argv[st.index];
		else
		{
			fprintf(stderr, "ft_ssl: too many inputs\n");
			freeSslOptions(opts);
			return (1);
		}
		st.index++;
	}

	/* if nothing specified -> read stdin */
	if (!opts->flagP && opts->stringCount == 0 && opts->fileCount == 0)
		opts->readFromStdin = 1;

	return (0);
}
