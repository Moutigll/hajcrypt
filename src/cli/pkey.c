#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/asymmetric/pkey.h"
#include "../../includes/utils/dispatch.h"
#include "../../includes/asymmetric/rsa.h"
#include "../../includes/cli/password.h"
#include "../../includes/cipher/aes.h"
#include "../../includes/utils/utils.h"

#include "../../includes/cli/pkey.h"

char	*readBinaryFile(const char *fileName)
{
	int		fd;
	char	*buf;
	char	tmp[4096];
	ssize_t	bytesRead;
	size_t	totalSize;
	size_t	capacity;

	if (fileName == NULL)
		fd = STDIN_FILENO;
	else
		fd = open(fileName, O_RDONLY);
	
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: pkey: cannot open '%s'\n",
			fileName ? fileName : "stdin");
		return (NULL);
	}

	capacity = 4096;
	buf = malloc(capacity);
	if (!buf) goto mallocError;
	
	totalSize = 0;
	while ((bytesRead = read(fd, tmp, sizeof(tmp))) > 0)
	{
		if (totalSize + bytesRead >= capacity)
		{
			while (totalSize + bytesRead >= capacity)
				capacity *= 2;
			buf = realloc(buf, capacity);
			if (!buf) goto mallocError;
		}
		ft_memcpy(buf + totalSize, tmp, bytesRead);
		totalSize += bytesRead;
	}
	
	buf[totalSize] = '\0';
	
	if (fileName)
		close(fd);
	return (buf);

mallocError:
	ft_dprintf(STDERR_FILENO, "ft_ssl: memory allocation failed\n");
	if (fileName)
		close(fd);
	return (NULL);
}


static const tFtLongOption	g_pkeyLongOpts[] = {
	{"inform",		FT_GETOPT_REQUIRED_ARGUMENT,	'I'},
	{"outform",		FT_GETOPT_REQUIRED_ARGUMENT,	'O'},
	{"in",			FT_GETOPT_REQUIRED_ARGUMENT,	'i'},
	{"out",			FT_GETOPT_REQUIRED_ARGUMENT,	'o'},
	{"passin",		FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"passout",		FT_GETOPT_REQUIRED_ARGUMENT,	'P'},
	{"text",			FT_GETOPT_NO_ARGUMENT,			't'},
	{"noout",			FT_GETOPT_NO_ARGUMENT,			'n'},
	{"modulus",		FT_GETOPT_NO_ARGUMENT,			'm'},
	{"check",			FT_GETOPT_NO_ARGUMENT,			'c'},
	{"pubin",		FT_GETOPT_NO_ARGUMENT,			'u'},
	{"pubout",		FT_GETOPT_NO_ARGUMENT,			'U'},
	{"traditional",	FT_GETOPT_NO_ARGUMENT,			'T'},
	{"breakit",		FT_GETOPT_NO_ARGUMENT,			'b'},
	{"help",			FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL,			0,								0}
};

/* ----- help ----- */
static void	printPkeyHelp(const t_pkeyDef *def)
{
	ft_printf(
		"Usage: ft_ssl %s [options]\n"
		"Options:\n"
		"  --*                  Any supported cipher (e.g., --des)\n"
		"  -I, --inform  <PEM>  Input format (only PEM supported)\n"
		"  -O, --outform <PEM>  Output format (only PEM supported)\n"
		"  -i, --in      <file> Input file (default stdin)\n"
		"  -o, --out     <file> Output file (default stdout)\n"
		"  -p, --passin  <arg>  Password for input private key\n"
		"  -P, --passout <arg>  Password for output private key\n"
		"  -t, --text           Print key components in text\n"
		"  -n, --noout          Do not output encoded key\n"
		"  -m, --modulus        Print modulus (n) in hex (RSA only)\n"
		"  -c, --check          Verify key consistency\n"
		"  -u, --pubin          Input is a public key\n"
		"  -U, --pubout         Output public key\n"
		"  -T, --traditional    Use traditional PEM format\n"
		"  -b, --breakit        Break weak small RSA keys (for testing purposes only)\n"
		"  -h, --help           Show this help\n",
		def ? def->name : "pkey"
	);
}

static int	parsePkeyArgs(int argc, char **argv, t_pkeyOptions *opt)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts = "I:O:i:o:p:P:tmncuUhTb";
	const t_cipher	*cipher;

	ft_bzero(opt, sizeof(t_pkeyOptions));
	ft_getoptInit(&st, argc, argv);
	st.index = 0;

	while (1)
	{
		status = ft_getoptLong(&st, shortOpts, g_pkeyLongOpts);
		if (status == FT_GETOPT_END)
			break;
		if (status == FT_GETOPT_POSITIONAL)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: pkey: unexpected argument '%s'\n", st.argv[st.index]);
			return (0);
		}
		if (status == FT_GETOPT_ERROR)
		{
			if (st.status == FT_GETOPT_UNKNOWN && st.badOpt
				&& st.badOpt[0] == '-' && st.badOpt[1] == '-')
			{
				cipher = getCipherByName(st.badOpt + 2);
				if (cipher)
				{
					opt->cipher = cipher;
					st.index++;
					continue;
				}
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: unknown option '%s'\n", st.badOpt);
			}
			else if (st.status == FT_GETOPT_MISSING_ARG)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: option '%c' requires an argument\n", st.opt);
			else if (st.status == FT_GETOPT_AMBIGUOUS)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: ambiguous option '%s'\n", st.badOpt);
			else
				ft_dprintf(STDERR_FILENO, "ft_ssl: invalid option\n");
			return (0);
		}
		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
			case 'I': if (ft_strcmp(st.optArg, "PEM")) {
					ft_dprintf(STDERR_FILENO,
						"ft_ssl: unsupported format '%s' (only PEM)\n",
						st.optArg); return (0); } break;
			case 'O': if (ft_strcmp(st.optArg, "PEM")) {
					ft_dprintf(STDERR_FILENO,
						"ft_ssl: unsupported format '%s' (only PEM)\n",
						st.optArg); return (0); } break;
			case 'i': opt->inFile = st.optArg; break;
			case 'o': opt->outFile = st.optArg; break;
			case 'p': opt->passin = st.optArg; break;
			case 'P': opt->passout = st.optArg; break;
			case 't': opt->text = 1; break;
			case 'n': opt->noout = 1; break;
			case 'm': opt->modulus = 1; break;
			case 'c': opt->check = 1; break;
			case 'u': opt->pubin = 1; break;
			case 'U': opt->pubout = 1; break;
			case 'T': opt->traditional = 1; break;
			case 'b': opt->breakIt = 1; break;
			case 'h': opt->help = 1; break;
			default: return (0);
			}
			continue;
		}
	}
	return (1);
}

int	cmdPkey(int argc, char **argv, char **env)
{
	const t_pkeyDef	*def = NULL;
	t_pkeyOptions	opt;
	t_pkey			pkey;
	char			*pem;
	char			*passinPass;
	char			*outPem;
	int				ret;
	int				keyRet;
	int				offset;

	/* ----- detect algorithm ----- */
	if (argc < 2)
	{
		ft_dprintf(STDERR_FILENO,
			"Usage: ft_ssl rsa|dsa [options]  or  ft_ssl pkey rsa|dsa [options]\n");
		return (1);
	}

	if (ft_strcmp(argv[1], "pkey") == 0)
	{
	    if (argc >= 3 && argv[2][0] != '-')
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
	        offset = 2;  /* Skip pkeyutl arg, pkeyFromPem will automatically try to guess which algorithm to use */
	}
	else
	{
		def = getPkeyDefByName(argv[1]);
		if (!def)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: unknown command '%s'\n", argv[1]);
			return (1);
		}
		offset = 2;
	}

	/* ----- parse remaining arguments ----- */
	if (!parsePkeyArgs(argc - offset, argv + offset, &opt))
	{
		printPkeyHelp(def);
		return (1);
	}
	if (opt.help)
	{
		printPkeyHelp(def);
		return (0);
	}

	/* ----- password for input ----- */
	passinPass = NULL;
	if (opt.passin)
	{
		passinPass = getPassword(opt.passin, env);
		if (!passinPass)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: error getting input password\n", def ? def->name : "pkey");
			return (1);
		}
	}

	/* ----- read PEM ----- */
	pem = readBinaryFile(opt.inFile);
	if (!pem)
	{
		free(passinPass);
		return (1);
	}

	/* ----- load key (generic) ----- */
	ft_bzero(&pkey, sizeof(t_pkey));
	pkey.def = def;
	keyRet = pkeyFromPem(pem, &pkey, !opt.pubin, passinPass);
	if (keyRet == 2) /* password needed */
	{
		char	*promptPass;

		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: password required for encrypted key\n", def ? def->name : "pkey");
		promptPass = promptPassword("Enter password for encrypted key: ");
		if (!promptPass)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: error getting password from prompt\n", def ? def->name : "pkey");
			free(pem);
			free(passinPass);
			return (1);
		}
		keyRet = pkeyFromPem(pem, &pkey, !opt.pubin, promptPass);
		secureZeroMemory(promptPass, ft_strlen(promptPass));
		free(promptPass);
	}
	if (keyRet != 1 || !pkey.key)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: failed to parse %s key\n",
			def ? def->name : "pkey", opt.pubin ? "public" : "private");
		free(pem);
		free(passinPass);
		return (1);
	}

	/* ----- display text / check ----- */
	if (opt.text)
	{
		if (pkey.def->printKey)
			pkey.def->printKey(pkey.key, !opt.pubin);
		else
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: text output not supported\n", pkey.def->name);
	}
	if (opt.modulus)
	{
		/* RSA specific: print modulus (n) */
		if (pkey.def->type == PKEY_TYPE_RSA)
		{
			t_rsaKey	*rsa = (t_rsaKey *)pkey.key;
			char		*hex = bigIntToHex(rsa->n);
			if (hex)
			{
				for (size_t i = 0; hex[i]; i++)
					hex[i] = ft_toupper(hex[i]);
				ft_printf("Modulus=%s\n", hex);
				free(hex);
			}
		}
		else
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: --modulus not supported\n", pkey.def->name);
	}
	if (opt.check)
	{
		int	ok;

		ok = 0;
		if (pkey.def->checkKey)
			ok = pkey.def->checkKey(pkey.key);
		ft_printf("%s key %s\n", pkey.def->name, ok ? "ok" : "check failed");
	}

	if (opt.breakIt && pkey.def == &g_rsaPkeyDef)
	{
		t_rsaKey brokenKey;
		struct timeval start, end;
		long elapsed_us;
		
		ft_dprintf(STDERR_FILENO, "Attempting to break RSA key...\n");
		gettimeofday(&start, NULL);
		
		if (!rsaAttackBreakPrivkey((t_rsaKey *)pkey.key, &brokenKey))
		{
			ft_dprintf(STDERR_FILENO, "Failed to break RSA key\n");
			ret = 1;
			goto cleanup;
		}
		
		gettimeofday(&end, NULL);
		elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
		
		if (elapsed_us < 1000)
			ft_dprintf(STDERR_FILENO, "RSA key broken successfully in %ld microseconds\n", elapsed_us);
		else if (elapsed_us < 1000000)
			ft_dprintf(STDERR_FILENO, "RSA key broken successfully in %.2f milliseconds\n", elapsed_us / 1000.0);
		else
			ft_dprintf(STDERR_FILENO, "RSA key broken successfully in %.3f seconds\n", elapsed_us / 1000000.0);
		
		rsaFreeKey((t_rsaKey *)pkey.key);
		ft_memcpy(pkey.key, &brokenKey, sizeof(t_rsaKey));
	}

	/* ----- output ----- */
	ret = 0;
	if (!opt.noout)
	{
		int			isPrivate;
		const void	*encCipher;
		char		*encPass;

		ft_dprintf(STDERR_FILENO, "writing %s key\n", pkey.def->name);

		isPrivate = opt.pubout ? 0 : 1 || opt.breakIt;
		encCipher = NULL;
		encPass = NULL;

		if (isPrivate && (opt.cipher || opt.passout))
		{
			encCipher = opt.cipher ? opt.cipher : &g_aes256CbcCipher;
			if (opt.passout)
				encPass = getPassword(opt.passout, env);
			else
				encPass = promptPassword("Enter PEM pass phrase: ");
			if (!encPass)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: %s: error getting output password\n", pkey.def->name);
				ret = 1;
				goto cleanup;
			}
		}

		outPem = pkeyToPem(&pkey, isPrivate, opt.traditional,
				encPass, encCipher);
		if (encPass)
		{
			secureZeroMemory(encPass, ft_strlen(encPass));
			free(encPass);
		}
		if (!outPem)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: failed to encode key\n", pkey.def->name);
			ret = 1;
			goto cleanup;
		}
		writePkeyOutput(opt.outFile, outPem);
		free(outPem);
	}

cleanup:
	if (passinPass)
	{
		secureZeroMemory(passinPass, ft_strlen(passinPass));
		free(passinPass);
	}
	pkeyFree(&pkey);
	free(pem);
	return (ret);
}
