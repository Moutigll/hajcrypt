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

	for (size_t i = 0; g_cipherTable[i].cipher; i++)
	{
		if (g_cipherTable[i].algo == algo)
			return (g_cipherTable[i].cipher->name);
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
	ft_printf("Standard commands:\n");
	
	ft_printf("\nMessage Digest commands:\n");
	for (size_t i = 0; g_hashTable[i].hash; i++)
		ft_printf("\t%s\n", g_hashTable[i].hash->name);
	
	ft_printf("\nCipher commands:\n");
	
	size_t i = 0;
	while (g_cipherTable[i].cipher)
	{
		const char *name = g_cipherTable[i].cipher->name;
		
		/* Check if the name contains a dash, which indicates it's a specific mode rather than a base algorithm */
		int has_dash = 0;
		for (const char *p = name; *p; p++)
		{
			if (*p == '-')
			{
				has_dash = 1;
				break;
			}
		}
		
		/* If it's an alias, display it and check the following entries */
		if (!has_dash)
		{
			ft_printf("\t%s", name);
			
			/* Search for modes that start with this alias + dash */
			size_t j = i + 1;
			int first = 1;
			
			while (g_cipherTable[j].cipher)
			{
				const char *next = g_cipherTable[j].cipher->name;
				size_t k = 0;
				
				/* Check if next starts with "alias-" */
				while (name[k] && next[k] && name[k] == next[k])
					k++;
				
				if (name[k] == '\0' && next[k] == '-')
				{
					if (first)
					{
						ft_printf(", %s", next);
						first = 0;
					}
					else
						ft_printf(", %s", next);
					j++;
				}
				else
					break;
			}
			
			ft_printf("\n");
			i = j;  /* Sauter tous les modes déjà affichés */
		}
		else
		{
			/* Case of algorithms without alias (like base64 or standalone modes) */
			ft_printf("\t%s\n", name);
			i++;
		}
	}
	
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
	opts->keyHex = NULL;
	opts->password = NULL;
	opts->ivHex = NULL;
	opts->wrapOutput = 0;
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

	for (int i = 0; g_cipherTable[i].cipher; i++) {
		if (ft_strcmp(arg, g_cipherTable[i].cipher->name) == 0) {
			opts->algo = g_cipherTable[i].algo;
			opts->cmdType = CMD_CIPHER;
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
	const char *shortOpts = "pqrs:k:edi:o:v:a";

	
	/* minimal validation */
	if (argc < 2 || !argv || !opts)
	{
		printUsage();
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
	while (1)
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

		if (status == FT_GETOPT_POSITIONAL)
			break; /* stop option parsing on first non-option */

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
					if (opts->cmdType == CMD_HASH) {
						opts->hmacKey = (char *)st.optArg;
					} else {
						opts->keyHex = (char *)st.optArg;
					}
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
				case 'v':
					opts->ivHex = (char *)st.optArg;
					break;
				case 'a':
					opts->useBase64 = 1;
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
