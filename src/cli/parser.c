#include <stdio.h>
#include <unistd.h>

#include "../../hajlib/include/hajlib.h"	/* IWYU pragma: keep */

#include "../../includes/cli/parser.h"

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

static void	getRootFamily(const char *name, char *out, size_t size)
{
	size_t	i;

	i = 0;
	while (name[i] && !(name[i] >= '0' && name[i] <= '9')
		&& name[i] != '-' && i < size - 1)
	{
		out[i] = name[i];
		i++;
	}
	out[i] = '\0';
}

static int	isSameExactFamily(const char *a, const char *b)
{
	int	i;
	int	j;

	i = 0;
	j = 0;

	while (a[i] && b[j])
	{
		if (a[i] == '-')
		{
			i++;
			continue;
		}
		if (b[j] == '-')
		{
			j++;
			continue;
		}
		if (a[i] != b[j])
			return (0);
		i++;
		j++;

		/* stop à la fin du nom de base */
		if ((a[i] == '\0' || a[i] == '-') &&
			(b[j] == '\0' || b[j] == '-'))
			return (1);
	}
	return (0);
}

static int	hasDash(const char *str)
{
	while (*str)
	{
		if (*str == '-')
			return (1);
		str++;
	}
	return (0);
}

static void	printUsage(void)
{
	size_t	i;
	char	prevRoot[32];
	char	currRoot[32];

	ft_printf("Standard commands:\n\tgenrsa\n");
	
	ft_printf("\nMessage Digest commands:\n");
	i = 0;
	while (g_hashTable[i].hash)
	{
		ft_printf("\t%s\n", g_hashTable[i].hash->name);
		i++;
	}
	
	ft_printf("\nCipher commands:\n");
	
	i = 0;
	prevRoot[0] = '\0';

	while (g_cipherTable[i].cipher)
	{
		const char	*name;
		size_t		k;

		name = g_cipherTable[i].cipher->name;
		getRootFamily(name, currRoot, sizeof(currRoot));

		/* saut de ligne entre familles racines (des -> aes) */
		if (prevRoot[0] != '\0' && ft_strcmp(prevRoot, currRoot) != 0)
			ft_printf("\n");

		ft_strlcpy(prevRoot, currRoot, sizeof(prevRoot));

		if (!hasDash(name))
		{
			ft_printf("\t%s", name);

			k = i + 1;
			while (g_cipherTable[k].cipher &&
				isSameExactFamily(name, g_cipherTable[k].cipher->name))
			{
				ft_printf(",\t%s",
					g_cipherTable[k].cipher->name);
				k++;
			}
			ft_printf("\n");
			i = k;
		}
		else
		{
			ft_printf("\t%s\n", name);
			i++;
		}
	}
	
	ft_printf("\nFlags:\n"
	"\t-p <password>\n\t\tHash:\tread from stdin and print it\n\t\tCipher:\tPassword in ASCII (for key derivation)\n"
	"\t-q\t\tQuiet mode - only print the hash\n"
	"\t-r\t\tReverse output format\n"
	"\t-s <salt>\tSalt in hex (for key derivation)\n"
	"\t-k <key>\tKey in hex (direct key, no derivation)\n"
	"\t-e\t\tEncrypt mode (default)\n"
	"\t-d\t\tDecrypt mode\n"
	"\t-i <file>\tInput file\n"
	"\t-o <file>\tOutput file\n"
	"\t-a\t\tBase64 encode/decode input/output\n"
	"\t-v <iv>\t\tIV in hex (for ciphers that use IV)\n"
	);
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

	if (ft_strcmp(arg, "genrsa") == 0) {
		opts->algo = ALGO_GENRSA;
		opts->cmdType = CMD_GENRSA;
		return (0);
	}

	if (ft_strcmp(arg, "rsa") == 0) {
		opts->algo = ALGO_NONE;
		opts->cmdType = CMD_RSA;
		return (0);
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
	const char *shortOpts;

	
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

	if (opts->cmdType == CMD_RSA) /* hand options parsing to rsa-specific function */
		return (0);

	if (opts->cmdType == CMD_HASH)
		shortOpts = "pqrs:";
	else
		shortOpts = "p:qreds:k:i:o:v:a";

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
			continue;
		}

		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
				case 'p':
					if (opts->cmdType == CMD_HASH)
					{
						/* For hashes: -p means read from stdin and print it */
						opts->flagP = 1;
						opts->readFromStdin = 1;
					}
					else
					{
						/* For ciphers: -p means password provided in ASCII for key derivation */
						if (st.optArg)
							opts->password = ft_strdup((char *)st.optArg);
						else
						{
							ft_dprintf(STDERR_FILENO, "ft_ssl: %s: option requires an argument -- p\n", argv[1]);
							freeSslOptions(opts);
							return (1);
						}
						if (!opts->password) {
							ft_dprintf(STDERR_FILENO, "ft_ssl: memory allocation failed\n");
							freeSslOptions(opts);
							return (1);
						}
					}
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
						opts->keyHex = ft_strdup((char *)st.optArg);
						if (!opts->keyHex) {
							ft_dprintf(STDERR_FILENO, "ft_ssl: memory allocation failed\n");
							freeSslOptions(opts);
							return (1);
						}
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
					opts->ivHex = ft_strdup((char *)st.optArg);
					if (!opts->ivHex) {
						ft_dprintf(STDERR_FILENO, "ft_ssl: memory allocation failed\n");
						freeSslOptions(opts);
						return (1);
					}
					break;
				case 'a':
					opts->useBase64 = 1;
					break;

				case 's':
					if (st.optArg)
					{
						if (opts->cmdType == CMD_HASH)
							if (opts->stringCount < opts->maxInputs)
								opts->stringInputs[opts->stringCount++] = (char *)st.optArg;
							else
							{
								ft_dprintf(STDERR_FILENO, "ft_ssl: too many inputs\n");
								freeSslOptions(opts);
								return (1);
							}
						else
							opts->saltHex = ft_strdup((char *)st.optArg);
						if (!opts->saltHex) {
							ft_dprintf(STDERR_FILENO, "ft_ssl: memory allocation failed\n");
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
	if (((!opts->flagP && opts->cmdType == CMD_HASH) || opts->cmdType != CMD_HASH) && opts->stringCount == 0 && opts->fileCount == 0)
		opts->readFromStdin = 1;

	return (0);
}
