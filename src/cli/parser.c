#include <stdio.h>
#include <unistd.h>

#include "../../hajlib/include/hajlib.h"	/* IWYU pragma: keep */
#include "../../includes/cli/parser.h"

const char *getAlgoName(t_algo algo)
{
	for (size_t i = 0; g_hashTable[i].hash; i++)
	{
		if (g_hashTable[i].algo == algo)
			return (g_hashTable[i].hash->name);
	}

	for (size_t i = 0; g_encodeTable[i].encode; i++)
	{
		if (g_encodeTable[i].algo == algo)
			return (g_encodeTable[i].encode->name);
	}

	return (NULL);
}

void printAlgoName(t_algo algo)
{
	const char *name = getAlgoName(algo);

	if (!name)
		return;
	
	while (*name) {
		ft_putchar_fd(ft_toupper(*name), STDOUT_FILENO);
		name++;
	}
}
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

static void printUsage(void)
{
	ft_printf("Commands:\n");
	ft_printf("\tHashing:\n");
	for (size_t i = 0; g_hashTable[i].hash; i++)
		ft_printf("\t\t%s\n", g_hashTable[i].hash->name);
	ft_printf("\n\tEncoding:\n");
	for (size_t i = 0; g_encodeTable[i].encode; i++)
		ft_printf("\t\t%s\n", g_encodeTable[i].encode->name);
	ft_printf("\nFlags:\n -p -q -r -s <string> -k <key> -e (encode) -d (decode) -i <input file> -o <output file>\n");
}

static int initSslOptions(t_sslOptions *opts, int argc)
{
	size_t cap;

	if (!opts)
		return (1);


	opts->cmdType = CMD_HASH;
	opts->algo = ALGO_NONE;
	opts->isDecoding = 0;
	opts->hmacKey = NULL;
	opts->flagK = 0;
	opts->flagP = 0;
	opts->flagQ = 0;
	opts->flagR = 0;
	opts->readFromStdin = 0;
	opts->stringInputs = NULL;
	opts->stringCount = 0;
	opts->fileInputs = NULL;
	opts->fileCount = 0;
	opts->inputFile = NULL;
	opts->outputFile = NULL;

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

/**
 * @brief Parse the algorithm name and set the corresponding algo in opts. *
 * @param arg - algorithm name (e.g. "md5", "sha256")
 * @param opts - options struct to set algo field in
 * @return 0 on success, 1 on failure (invalid algorithm)
 */
static int parseAlgorithm(const char *arg, t_sslOptions *opts)
{
	for (int i = 0; g_hashTable[i].hash; i++) {
		if (ft_strcmp(arg, g_hashTable[i].hash->name) == 0) {
			opts->algo = g_hashTable[i].algo;
			opts->cmdType = CMD_HASH;
			return (0);
		}
	}

	for (int i = 0; g_encodeTable[i].encode; i++) {
		if (ft_strcmp(arg, g_encodeTable[i].encode->name) == 0) {
			opts->algo = g_encodeTable[i].algo;
			opts->cmdType = CMD_ENCODE;
			return (0);
		}
	}

	ft_dprintf(STDERR_FILENO, "ft_ssl: Error: '%s' is an invalid command.\n\n", arg);
	printUsage();
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
	const char *shortOpts = "pqrs:k:edi:o:";

	
	/* minimal validation */
	if (argc < 2 || !argv || !opts)
	{
		/* TODO: print a list of available algorithms */
		ft_dprintf(STDERR_FILENO, "usage: ft_ssl command [flags] [file/string]\n");
		return (1);
	}

	if (initSslOptions(opts, argc) != 0)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: memory allocation failed\n");
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

	ft_getoptInit(&st, argc - 2, argv + 2);
	st.index = 0; /* reset index to start of options (argv[2]) */

	/* iterate options */
	for (;;)
	{
		status = ft_getoptLong(&st, shortOpts, NULL);

		if (status == FT_GETOPT_END)
			break;

		if (status == FT_GETOPT_ERROR)
		{
			/* st.badOpt or st.status carries info; print usable message */
			ft_dprintf(STDERR_FILENO, "ft_ssl: %s: illegal option %s\n",
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

				case 'k':
					opts->flagK = 1;
					opts->hmacKey = (char *)st.optArg;
					break;

				case 'e':
					opts->isDecoding = 0;
					break;
				case 'd':
					opts->isDecoding = 1;
					break;
				case 'i':
					opts->inputFile = (char *)st.optArg;
					break;
				case 'o':
					opts->outputFile = (char *)st.optArg;
					break;


				case 's':
					if (st.optArg)
					{
						if (opts->stringCount < opts->maxInputs)
							opts->stringInputs[opts->stringCount++] = (char *)st.optArg;
						else
						{
							ft_dprintf(STDERR_FILENO, "ft_ssl: too many inputs\n");
							freeSslOptions(opts);
							return (1);
						}
					}
					else
					{
						ft_dprintf(STDERR_FILENO, "ft_ssl: %s: option requires an argument -- s\n", argv[1]);
						freeSslOptions(opts);
						return (1);
					}
					break;

				default:
					/* unknown option value (defensive) */
					ft_dprintf(STDERR_FILENO, "ft_ssl: unknown option '%c'\n", (char)st.opt);
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
			ft_dprintf(STDERR_FILENO, "ft_ssl: too many inputs\n");
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
