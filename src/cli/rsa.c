#include <fcntl.h>

#include "../../hajlib/include/hajlib.h"	/* IWYU pragma: keep */
#include "../../includes/asymmetric/rsa.h"
#include "../../includes/cli/password.h"
#include "../../includes/cipher/aes.h"
#include "../../includes/utils/utils.h"

#include "../../includes/cli/rsa.h"

static const tFtLongOption	g_longOptions[] = {
	{"inform",		FT_GETOPT_REQUIRED_ARGUMENT,	'I'},	/* PEM only */
	{"outform",		FT_GETOPT_REQUIRED_ARGUMENT,	'O'},	/* PEM only */
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
	{"help",			FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL, 			0,								0}
};

static void	printRsaHelp(void)
{
	ft_printf(
		"Usage: ft_ssl rsa [options]\n"
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
		"  -m, --modulus        Print modulus (n) in hex\n"
		"  -c, --check          Verify key consistency\n"
		"  -u, --pubin          Input is a public key\n"
		"  -U, --pubout         Output public key\n"
		"  -T, --traditional    Use traditional PEM format (PKCS#1)\n"
		"  -h, --help           Show this help\n"
	);
}


/**
 * @brief Reads the entire content of a file into a dynamically allocated string.
 * 
 * @param fileName The path to the file to be read.
 * 
 * @return A pointer to a dynamically allocated string containing the file content,
 *		 or NULL if the file cannot be opened or read.
 */
char	*readFileContent(const char *fileName)
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
		ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: cannot open '%s'\n",
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
	ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: memory allocation failed\n");
	if (fileName)
		close(fd);
	return (NULL);
}

/**
 * @brief Writes a string to a specified file or standard output.
 * 
 * @param fileName The path to the output file, or NULL to write to standard output.
 * @param data The string data to be written.
 */
void	writeRsaOutput(const char *fileName, const char *data)
{
	int		fd;
	size_t	len;
	ssize_t	written;

	if (fileName == NULL)
		fd = STDOUT_FILENO;
	else
		fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: cannot write to '%s'\n",
			fileName ? fileName : "stdout");
		return ;
	}
	
	len = ft_strlen(data);
	written = write(fd, data, len);
	if (written < 0 || (size_t)written != len)
		ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: failed to write output\n");
	
	if (fileName)
		close(fd);
}

static int	getInputForm(const char *arg)
{
	if (ft_strcmp(arg, "PEM") == 0)
		return (1);
	ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: unsupported format '%s' (only PEM supported)\n", arg);
	return (0);
}

/**
 * @brief Parses the command-line arguments for the `ft_ssl rsa` command.
 * 
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line argument strings.
 * @param opt A pointer to the structure to store the parsed options.
 * 
 * @return 1 if the arguments were parsed successfully, 0 otherwise.
 */
static int	parseRsaArgs(int argc, char **argv, t_rsaOptions *opt)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const t_cipher	*cipher;

	ft_bzero(opt, sizeof(t_rsaOptions));
	ft_getoptInit(&st, argc - 2, argv + 2);
	const char *shortOpts = "I:O:i:o:p:P:tmncuUhT";
	st.index = 0;

	while (1)
	{
		status = ft_getoptLong(&st, shortOpts, g_longOptions);
		if (status == FT_GETOPT_END)
			break;
		if (status == FT_GETOPT_ERROR)
		{
			if (st.status == FT_GETOPT_UNKNOWN)
			{
				cipher = getCipherByName(st.badOpt + 2); /* Skip the '--' prefix */
				if (cipher)
				{
					opt->cipher = cipher;
					st.index++; /* Move past the cipher argument */
					continue;
				}
				ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: unknown option '%s'\n", st.badOpt);
			}
			else if (st.status == FT_GETOPT_MISSING_ARG)
				ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: option '%s' requires an argument\n",
					st.badOpt);
			else if (st.status == FT_GETOPT_AMBIGUOUS)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: rsa: option '%s' ambiguous (could be --%s or --%s)\n",
					st.badOpt, st.ambiguousA, st.ambiguousB);
			else
				ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: invalid option\n");
			return (0);
		}
		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
				case 'i': opt->inFile		= st.optArg; break;
				case 'o': opt->outFile		= st.optArg; break;
				case 'p': opt->passin		= st.optArg; break;
				case 'P': opt->passout		= st.optArg; break;
				case 't': opt->text			= 1; break;
				case 'n': opt->noout		= 1; break;
				case 'm': opt->modulus		= 1; break;
				case 'c': opt->check		= 1; break;
				case 'u': opt->pubin		= 1; break;
				case 'U': opt->pubout		= 1; break;
				case 'T': opt->traditional	= 1; break;
				case 'h': opt->help			= 1; break;
				case 'I': if (!getInputForm(st.optArg)) return (0); break;
				case 'O': if (!getInputForm(st.optArg)) return (0); break;
				default:
					ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: internal error\n");
					return (0);
			}
		}
	}
	return (1);
}



int cmdRsa(int argc, char **argv, char **env)
{
	t_rsaOptions	opt;
	t_rsaKey		key;
	char			*pem = NULL;
	char			*passinPas = NULL;
	char			*passoutPass = NULL;
	char			*outPem = NULL;
	int				ret = 1;

	/* 1. Parse arguments */
	if (!parseRsaArgs(argc, argv, &opt))
	{
		printRsaHelp();
		return (1);
	}
	if (opt.help)
	{
		printRsaHelp();
		return (0);
	}

	if (!opt.inFile && !opt.outFile && !opt.passin && !opt.passout)
	{
		printRsaHelp();
		return (0);
	}

	/* 2. Get input password if needed */
	if (opt.passin)
	{
		passinPas = getPassword(opt.passin, env);
		if (!passinPas)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: error getting input password\n");
			return (1);
		}
	}

	/* 3. Read the PEM file */
	pem = readFileContent(opt.inFile);
	if (!pem)
		goto cleanup;

	/* 4. Initialize and load the key */
	ft_bzero(&key, sizeof(t_rsaKey));
	int keyRet = rsaKeyFromPem(pem, &key, !opt.pubin, passinPas);
	if (keyRet == 2) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: password required for encrypted key\n");
		char *prompt_pass = promptPassword("Enter password for encrypted key: ");
		if (!prompt_pass) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: error getting password from prompt\n");
			goto cleanup;
		}
		keyRet = rsaKeyFromPem(pem, &key, !opt.pubin, prompt_pass);
		secureZeroMemory(prompt_pass, ft_strlen(prompt_pass));
		free(prompt_pass);
	}
	if (!keyRet)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: failed to parse %s key\n",
			!opt.pubin ? "private" : "public");
		goto cleanup;
	}

	/* 5. Display text options */
	if (opt.text)
		rsaPrintKey(&key, !opt.pubin);
	if (opt.modulus)
	{
		char *modHex = bigIntToHex(key.n);
		if (modHex)
		{
			for (size_t i = 0; modHex[i]; i++)
				modHex[i] = ft_toupper(modHex[i]);
			ft_printf("Modulus=%s\n", modHex);
			free(modHex);
		}
	}
	if (opt.check)
	{
		if (rsaCheckKey(&key, 64))
			ft_printf("RSA key ok\n");
		else
			ft_printf("RSA key check failed\n");
	}

	/* 6. Generation of the output (if requested) */
	if (!opt.noout)
	{
		ft_dprintf(STDERR_FILENO, "writing RSA key\n");

		if (opt.pubout) /* Public key always in clear */
			outPem = rsaKeyToPem(&key, 0, opt.traditional, NULL, NULL);
		else
		{
			int encryptOutput = (opt.cipher != NULL) || (opt.passout != NULL);
			if (encryptOutput) /* Encrypt the output if a cipher is specified or if a password is provided */
			{
				const t_cipher *encCipher = opt.cipher;
				if (!encCipher)
				{
					ft_dprintf(STDERR_FILENO, "No cipher specified for encryption, defaulting to AES-256-CBC\n");
					encCipher = &g_aes256CbcCipher;
				}

				/* Get the output password */
				if (opt.passout)
					passoutPass = getPassword(opt.passout, env);
				else
					passoutPass = promptPassword("Enter PEM pass phrase: ");

				if (!passoutPass)
				{
					ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: error getting output password\n");
					goto cleanup;
				}

				outPem = rsaKeyToPem(&key, 1, opt.traditional, passoutPass, encCipher);

				/* Clear the password from memory */
				secureZeroMemory(passoutPass, ft_strlen(passoutPass));
				free(passoutPass);
				passoutPass = NULL;
			}
			else
				outPem = rsaKeyToPem(&key, 1, opt.traditional, NULL, NULL);
		}

		if (!outPem)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: rsa: failed to encode key\n");
			goto cleanup;
		}

		writeRsaOutput(opt.outFile, outPem);
	}

	ret = 0;

cleanup:
	free(pem);
	free(outPem);
	if (passinPas)
	{
		secureZeroMemory(passinPas, ft_strlen(passinPas));
		free(passinPas);
	}
	if (passoutPass)
	{
		secureZeroMemory(passoutPass, ft_strlen(passoutPass));
		free(passoutPass);
	}
	rsaFreeKey(&key);
	return (ret);
}



/* --------------------------------------------------------------------------
 *                              genrsa command
 * -------------------------------------------------------------------------- */

#define RSA_MIN_BITS 512
#define RSA_DEFAULT_BITS 2048
#define RSA_MAX_BITS 16384

static const tFtLongOption g_genrsaLongOpts[] = {
	{"out",		FT_GETOPT_REQUIRED_ARGUMENT,	'o'},
	{"passout",	FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"pubout",	FT_GETOPT_REQUIRED_ARGUMENT,	'P'},
	{"traditional",	FT_GETOPT_NO_ARGUMENT,		't'},
	{"help",	FT_GETOPT_NO_ARGUMENT,		'h'},
	{NULL, 0, 0}
};

static void	printGenrsaHelp(void)
{
	ft_printf(
		"Usage: ft_ssl genrsa [options] [bits]\n"
		"Options:\n"
		"  -o, --out     <file> Output file (default stdout)\n"
		"  -p, --passout <arg>  Password for encrypting the private key\n"
		"  -P, --pubout  <file> Output the public key in the specified file\n"
		"  -t, --traditional    Use traditional PEM format (PKCS#1)\n"
		"  --*                  Any supported cipher for encryption (e.g., --aes-256-cbc)\n"
		"  -h, --help           Show this help\n"
		"  bits                 Key size in bits (default %d, min %d, max %d)\n",
		RSA_DEFAULT_BITS, RSA_MIN_BITS, RSA_MAX_BITS);
}

static int	parseGenrsaArgs(int				argc,
							char			**argv,
							t_rsaOptions	*opt,
							const t_cipher	**cipher,
							int				*bits)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts;
	const char		*bitsStr;

	ft_bzero(opt, sizeof(t_rsaOptions));
	*cipher = NULL;
	*bits = RSA_DEFAULT_BITS;
	shortOpts = "o:p:P:th";

	ft_getoptInit(&st, argc - 2, argv + 2);
	st.index = 0;
	while (1)
	{
		status = ft_getoptLong(&st, shortOpts, g_genrsaLongOpts);
		if (status == FT_GETOPT_END)
			break;
		if (status == FT_GETOPT_POSITIONAL)
		{
			bitsStr = st.optArg;
			if (!bitsStr)
				bitsStr = argv[2 + st.index];
			if (!bitsStr)
			{
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: genrsa: missing bits argument\n");
				return (0);
			}
			*bits = ft_atoi((char *)bitsStr);
			st.index++;
			continue;
		}
		if (status == FT_GETOPT_ERROR)
		{
			if (st.status == FT_GETOPT_MISSING_ARG)
			{
				ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: option '%s' requires an argument\n",
					st.badOpt);
				return (0);
			}
			else if (st.status == FT_GETOPT_UNKNOWN && st.badOpt
				&& st.badOpt[0] == '-' && st.badOpt[1] == '-')
			{
				const t_cipher	*found;

				found = getCipherByName(st.badOpt + 2);
				if (found)
				{
					*cipher = found;
					st.index++;
					continue;
				}
			}
			ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: invalid option\n");
			return (0);
		}
		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
				case 'o':
					opt->outFile = st.optArg;
					break;
				case 'p':
					opt->passout = st.optArg;
					break;
				case 'P':
					opt->pubOutFile = st.optArg;
					break;
				case 't':
					opt->traditional = 1;
					break;
				case 'h':
					printGenrsaHelp();
					return (-1);
			}
			continue;
		}
	}
	while (st.index < st.argc)
	{
		bitsStr = st.argv[st.index];
		if (!bitsStr)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: genrsa: missing bits argument\n");
			return (0);
		}
		*bits = ft_atoi((char *)bitsStr);
		st.index++;
	
	}
	if (*bits < RSA_MIN_BITS || *bits > RSA_MAX_BITS)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: genrsa: invalid key size %d (must be between %d and %d)\n",
			*bits, RSA_MIN_BITS, RSA_MAX_BITS);
		return (0);
	}
	return (1);
}

int	cmdGenrsa(int argc, char **argv, char **env)
{
	t_rsaKey		key;
	t_rsaOptions	options;
	char			*pem;
	int				bits;
	const t_cipher	*cipher;
	int				ret;
	char			*password;

	(void)env;

	bits = RSA_DEFAULT_BITS;
	cipher = NULL;
	password = NULL;
	ft_bzero(&options, sizeof(t_rsaOptions));

	ret = parseGenrsaArgs(argc, argv, &options, &cipher, &bits);
	if (ret <= 0)
		return (ret == -1 ? 0 : 1);

	if (options.passout && !cipher) /* If a password is provided without a cipher, default to AES-256-CBC */
		cipher = &g_aes256CbcCipher;
	if (options.passout)
	{
		password = getPassword(options.passout, env);
		if (!password)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: failed to get password\n");
			return (1);
		}
	}
	if (cipher && !options.passout) /* If a cipher is specified without a password, prompt for one */
	{
		password = promptPassword("Enter pass phrase: ");
		if (!password)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: failed to get password\n");
			return (1);
		}
	}

	ft_dprintf(STDERR_FILENO, "Generating RSA private key, %d bit modulus\n", bits);

	if (!rsaGenerateKey(&key, bits, 65537))
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: failed to generate key\n");
		return (1);
	}

	ft_dprintf(STDERR_FILENO, "e is 65537 (0x10001)\n");

	if (cipher && password)
		pem = rsaKeyToPem(&key, 1, options.traditional, password, cipher);
	else
		pem = rsaKeyToPem(&key, 1, options.traditional, NULL, NULL);

	if (!pem)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: failed to encode key\n");
		rsaFreeKey(&key);
		free(password);
		return (1);
	}

	if (options.pubOutFile)
	{
		char *pubPem = rsaKeyToPem(&key, 0, options.traditional, NULL, NULL);
		if (!pubPem)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: genrsa: failed to encode public key\n");
			free(pem);
			rsaFreeKey(&key);
			free(password);
			return (1);
		}
		writeRsaOutput(options.pubOutFile, pubPem);
		free(pubPem);
	}

	if (options.outFile)
		writeRsaOutput(options.outFile, pem);
	else
		ft_printf("%s", pem);

	free(pem);
	free(password);
	rsaFreeKey(&key);
	return (0);
}
