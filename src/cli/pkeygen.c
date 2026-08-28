#include <fcntl.h>

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/asymmetric/pkey.h"
#include "../../includes/utils/dispatch.h"
#include "../../includes/cli/password.h"
#include "../../includes/cipher/aes.h"
#include "../../includes/cli/pkey.h"

static const tFtLongOption	g_genpkeyLongOpts[] = {
	{"out",			FT_GETOPT_REQUIRED_ARGUMENT,	'o'},
	{"passout",		FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"pubout",		FT_GETOPT_REQUIRED_ARGUMENT,	'P'},
	{"traditional",	FT_GETOPT_NO_ARGUMENT,			't'},
	{"help",		FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL, 0, 0}
};

static void	printGenpkeyHelp(const t_pkeyDef *def)
{
	ft_printf(
		"Usage: ft_ssl gen%s [options] [bits]\n"
		"Options:\n"
		"  -o, --out     <file> Output file (default stdout)\n"
		"  -p, --passout <arg>  Password for encrypting the private key\n"
		"  -P, --pubout  <file> Output the public key in the specified file\n"
		"  -t, --traditional    Use traditional PEM format\n"
		"  --*                  Any supported cipher (e.g., --aes-256-cbc)\n"
		"  -h, --help           Show this help\n"
		"  bits                 Key size (default %d)\n",
		def->name,
		def->defaultBits);
}

static int	parseGenpkeyArgs(int				argc,
							 char				**argv,
							 const t_pkeyDef	*def,
							 t_genpkeyOpts		*opts,
							 const t_cipher		**cipher,
							 int				*bits)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts;
	const char		*bitsStr;

	shortOpts = "o:p:P:th";
	ft_bzero(opts, sizeof(t_genpkeyOpts));
	*cipher = NULL;
	*bits = def->defaultBits;

	ft_getoptInit(&st, argc, argv);
	st.index = 0;
	while (1)
	{
		status = ft_getoptLong(&st, shortOpts, g_genpkeyLongOpts);
		if (status == FT_GETOPT_END)
			break ;
		if (status == FT_GETOPT_POSITIONAL)
		{
			bitsStr = st.optArg;
			if (!bitsStr)
				bitsStr = argv[st.index];
			if (!bitsStr)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: %s: missing bits argument\n", def->name);
				return (0);
			}
			*bits = ft_atoi((char *)bitsStr);
			if (*bits <= 0)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: %s: invalid bits argument '%s'\n", def->name, bitsStr);
				return (0);
			}
			st.index++;
			continue ;
		}
		if (status == FT_GETOPT_ERROR)
		{
			if (st.status == FT_GETOPT_MISSING_ARG)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: %s: option '%s' requires an argument\n",
					def->name, st.badOpt);
				return (0);
			}
			if (st.status == FT_GETOPT_UNKNOWN && st.badOpt
				&& st.badOpt[0] == '-' && st.badOpt[1] == '-')
			{
				const t_cipher	*found;

				found = getCipherByName(st.badOpt + 2);
				if (found)
				{
					*cipher = found;
					st.index++;
					continue ;
				}
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: %s: unknown cipher '--%s'\n",
					def->name, st.badOpt + 2);
				return (0);
			}
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: invalid option\n", def->name);
			return (0);
		}
		if (status == FT_GETOPT_OK)
		{
			if (st.opt == 'o')
				opts->outFile = st.optArg;
			else if (st.opt == 'p')
				opts->passout = st.optArg;
			else if (st.opt == 'P')
				opts->pubOutFile = st.optArg;
			else if (st.opt == 't')
				opts->traditional = 1;
			else if (st.opt == 'h')
			{
				printGenpkeyHelp(def);
				return (-1);
			}
			continue ;
		}
	}
	while (st.index < st.argc)
	{
		bitsStr = st.argv[st.index];
		if (!bitsStr)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: missing bits argument\n", def->name);
			return (0);
		}
		*bits = ft_atoi((char *)bitsStr);
		if (*bits <= 0)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: invalid bits argument '%s'\n", def->name, bitsStr);
			return (0);
		}
		st.index++;
	}
	if (!def->validateBits(*bits))
		return (0);
	return (1);
}

int	writePkeyOutput(const char *filename, const char *data)
{
	int	fd;

	if (!filename)
	{
		ft_printf("%s", data);
		return (1);
	}
	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: cannot open '%s' for writing\n", filename);
		return (0);
	}
	ft_dprintf(fd, "%s", data);
	close(fd);
	return (1);
}

int	cmdGenPkey(int argc, char **argv, char **env)
{
	const t_pkeyDef	*def;
	t_genpkeyOpts	opts;
	const t_cipher	*cipher;
	int				bits;
	char			*password;
	t_pkey			pkey;
	char			*privPem;
	char			*pubPem;
	int				ret;
	int				offset;

	if (argc < 2)
	{
		ft_dprintf(STDERR_FILENO,
			"Usage: ft_ssl genpkey [<key_type>] [options] [bits]\n");
		return (1);
	}
	if (ft_strcmp(argv[1], "genpkey") == 0)
	{
		if (argc >= 3 && argv[2][0] != '-' && !ft_isdigit(argv[2][0]))
		{
			def = getPkeyDefByName(argv[2]);
			if (!def)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: unknown key type '%s'\n", argv[2]);
				return (1);
			}
			offset = 3;
		}
		else
		{
			if (g_pkeyTable[0].def == NULL)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: no asymmetric key algorithms available\n");
				return (1);
			}
			def = g_pkeyTable[0].def;
			offset = 2;
		}
	}
	else
	{
		def = getPkeyDefByName(argv[1] + 3);
		if (!def)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: unknown algorithm '%s'\n", argv[1]);
			return (1);
		}
		offset = 2;
	}
	if (!def->generate)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s does not support key generation\n", def->name);
		return (1);
	}
	ret = parseGenpkeyArgs(argc - offset, argv + offset, def,
			&opts, &cipher, &bits);
	if (ret <= 0)
		return (ret == -1 ? 0 : 1);

	password = NULL;
	if (opts.passout && !cipher)
		cipher = &g_aes256CbcCipher;
	if (opts.passout)
	{
		password = getPassword(opts.passout, env);
		if (!password)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: failed to get password\n", def->name);
			return (1);
		}
	}
	if (cipher && !opts.passout)
	{
		password = promptPassword("Enter pass phrase: ", 1);
		if (!password)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: failed to get password\n", def->name);
			return (1);
		}
	}

	ft_dprintf(STDERR_FILENO, "Generating %s private key, %d bits\n",
		def->name, bits);

	pkey.def = def;
	pkey.key = NULL;
	if (!pkeyGenerate(&pkey, bits))
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: key generation failed\n", def->name);
		free(password);
		return (1);
	}

	privPem = pkeyToPem(&pkey, 1, opts.traditional,
			(cipher && password) ? password : NULL,
			(cipher && password) ? cipher : NULL);
	if (!privPem)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: PEM encoding failed\n", def->name);
		pkeyFree(&pkey);
		free(password);
		return (1);
	}

	if (opts.pubOutFile)
	{
		pubPem = pkeyToPem(&pkey, 0, opts.traditional, NULL, NULL);
		if (!pubPem)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: public key PEM encoding failed\n", def->name);
			free(privPem);
			pkeyFree(&pkey);
			free(password);
			return (1);
		}
		if (!writePkeyOutput(opts.pubOutFile, pubPem))
		{
			free(pubPem);
			free(privPem);
			pkeyFree(&pkey);
			free(password);
			return (1);
		}
		free(pubPem);
	}
	if (!writePkeyOutput(opts.outFile, privPem))
	{
		free(privPem);
		pkeyFree(&pkey);
		free(password);
		return (1);
	}

	free(privPem);
	pkeyFree(&pkey);
	free(password);
	return (0);
}
