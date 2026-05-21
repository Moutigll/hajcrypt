#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "../../hajlib/include/hajlib.h"	/* IWYU pragma: keep */
#include "../../includes/cli/password.h"
#include "../../includes/utils/utils.h"
#include "../../includes/cli/pkey.h"
#include "../../includes/asymmetric/rsa.h"

#define FT_PKEYUTL_ERR(...) ft_dprintf(STDERR_FILENO, "ft_ssl: pkeyutl: " __VA_ARGS__)

static const tFtLongOption g_pkeyutlLongOptions[] = {
	{"in",		FT_GETOPT_REQUIRED_ARGUMENT,	'i'},
	{"out",		FT_GETOPT_REQUIRED_ARGUMENT,	'o'},
	{"inkey",		FT_GETOPT_REQUIRED_ARGUMENT,	'k'},
	{"passin",	FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"pubin",		FT_GETOPT_NO_ARGUMENT,			'u'},
	{"encrypt",	FT_GETOPT_NO_ARGUMENT,			'e'},
	{"decrypt",	FT_GETOPT_NO_ARGUMENT,			'd'},
	{"sign",		FT_GETOPT_NO_ARGUMENT,			's'},
	{"verify",	FT_GETOPT_NO_ARGUMENT,			'v'},
	{"dgst",		FT_GETOPT_REQUIRED_ARGUMENT,	'g'},
	{"sigfile",	FT_GETOPT_REQUIRED_ARGUMENT,	'S'},
	{"hexdump",	FT_GETOPT_NO_ARGUMENT,			'x'},
	{"hash",		FT_GETOPT_NO_ARGUMENT,			'H'},
	{"help",		FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL,		0,								0}
};


static void printRsautlHelp(void)
{
	ft_printf(
		"Usage: ft_ssl pkeyutl -e|-d|-s|-v [options] [input_file] [signature_file]\n"
		"Options:\n"
		"  -i, --in      <file>  Input file (default stdin)\n"
		"  -o, --out     <file>  Output file (default stdout)\n"
		"  -k, --inkey   <file>  Key file\n"
		"  -p, --passin  <arg>   Key password (e.g. pass:secret, env:VAR)\n"
		"  -u, --pubin           Input key is public\n"
		"  -e, --encrypt         Encrypt with public key\n"
		"  -d, --decrypt         Decrypt with private key\n"
		"  -s, --sign            Sign with private key\n"
		"  -v, --verify          Verify with public key\n"
		"  -g, --dgst    <alg>   Digest algorithm (default: sha256)\n"
		"  -H, --hash            Hash input with -g algo before sign/verify\n"
		"  -S, --sigfile <file>  Signature file (for --verify)\n"
		"  -x, --hexdump         Hex output\n"
		"  -h, --help            Show this help\n"
	);
}

static int readBinaryFile(const char *file, uint8_t **data, size_t *len)
{
	int		fd;
	uint8_t	tmp[4096];
	uint8_t	*buf;
	size_t	capacity;
	size_t	total;
	ssize_t	r;

	fd = file ? open(file, O_RDONLY) : STDIN_FILENO;
	if (fd < 0)
	{
		FT_PKEYUTL_ERR("cannot open '%s'\n", file ? file : "stdin");
		return (1);
	}

	capacity = 4096;
	buf = malloc(capacity);
	if (!buf)
	{
		FT_PKEYUTL_ERR("memory allocation failed\n");
		if (file)
			close(fd);
		return (1);
	}

	total = 0;
	while ((r = read(fd, tmp, sizeof(tmp))) > 0)
	{
		if (total + (size_t)r >= capacity)
		{
			while (total + (size_t)r >= capacity)
				capacity *= 2;
			buf = realloc(buf, capacity);
			if (!buf)
			{
				FT_PKEYUTL_ERR("memory allocation failed\n");
				if (file)
					close(fd);
				return (1);
			}
		}
		ft_memcpy(buf + total, tmp, r);
		total += r;
	}

	if (file)
		close(fd);

	*data = buf;
	*len = total;
	return (0);
}

static void writeBinaryOutput(const char *file, const uint8_t *data, size_t len)
{
	int fd;

	fd = file ? open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644) : STDOUT_FILENO;
	if (fd < 0)
	{
		FT_PKEYUTL_ERR("cannot write to '%s'\n", file ? file : "stdout");
		return ;
	}
	write(fd, data, len);
	if (file)
		close(fd);
}

static const t_algoId *getDigestOid(const char *name)
{
	const t_hash	*hash;

	hash = getHashByName(name ? name : "sha256");
	if (!hash)
	{
		FT_PKEYUTL_ERR("unknown digest algorithm '%s'\n", name);
		return (NULL);
	}
	return (&hash->oid);
}

static int hashDataInPlace(const char *dgstName, uint8_t **data, size_t *dataLen)
{
	const t_hash	*hash;
	uint8_t			*digest;
	void			*ctx;
	size_t			digestSize;

	hash = getHashByName(dgstName ? dgstName : "sha256");
	if (!hash)
	{
		FT_PKEYUTL_ERR("unknown digest algorithm '%s'\n", dgstName ? dgstName : "sha256");
		return (0);
	}

	digestSize = hash->digestSize;
	digest = malloc(digestSize);
	ctx = malloc(hash->ctxSize);
	if (!digest || !ctx)
	{
		free(digest);
		free(ctx);
		FT_PKEYUTL_ERR("memory allocation failed\n");
		return (0);
	}

	hash->init(ctx);
	hash->update(ctx, *data, *dataLen);
	hash->final(digest, ctx);
	free(ctx);

	free(*data);
	*data = digest;
	*dataLen = digestSize;
	return (1);
}

static int loadRsaKey(const char	*keyFile,
					  const char	*passin,
					  char			**env,
					  int			wantPriv,
					  t_rsaKey		*key)
{
	char	*pem;
	char	*password;
	int		ret;

	pem = readFileContent(keyFile);
	if (!pem)
		return (0);

	password = NULL;
	if (passin)
	{
		password = getPassword(passin, env);
		if (!password)
		{
			FT_PKEYUTL_ERR("error getting password\n");
			free(pem);
			return (0);
		}
	}

	ret = rsaKeyFromPem(pem, key, wantPriv, password);

	if (ret == 2)
	{
		FT_PKEYUTL_ERR("password required for encrypted key\n");
		if (password)
		{
			secureZeroMemory(password, ft_strlen(password));
			free(password);
			password = NULL;
		}
		password = promptPassword("Enter password for encrypted key: ");
		if (!password)
		{
			FT_PKEYUTL_ERR("failed to get password\n");
			free(pem);
			return (0);
		}
		ret = rsaKeyFromPem(pem, key, wantPriv, password);
	}

	if (password)
	{
		secureZeroMemory(password, ft_strlen(password));
		free(password);
	}
	free(pem);

	if (!ret)
	{
		FT_PKEYUTL_ERR("failed to parse %s key\n", wantPriv ? "private" : "public");
		return (0);
	}
	return (1);
}

static int parseRsautlArgs(int argc, char **argv, t_pkeyutlOptions *opt)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts;

	ft_bzero(opt, sizeof(t_pkeyutlOptions));
	shortOpts = "i:o:k:p:g:S:xhHuedsv";
	ft_getoptInit(&st, argc - 1, argv + 1);

	while (1)
	{
		status = ft_getoptLong(&st, shortOpts, g_pkeyutlLongOptions);
		if (status == FT_GETOPT_END)
			break;
		if (status == FT_GETOPT_ERROR)
		{
			if (st.status == FT_GETOPT_UNKNOWN)
				FT_PKEYUTL_ERR("unknown option '%s'\n", st.badOpt);
			else if (st.status == FT_GETOPT_MISSING_ARG)
				FT_PKEYUTL_ERR("option '%s' requires an argument\n", st.badOpt);
			else if (st.status == FT_GETOPT_AMBIGUOUS)
				FT_PKEYUTL_ERR("option '%s' ambiguous: could be either %s or %s\n",
					st.badOpt, st.ambiguousA, st.ambiguousB);
			else
				FT_PKEYUTL_ERR("invalid option\n");
			return (0);
		}
		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
				case 'i': opt->inFile	  = st.optArg; break;
				case 'o': opt->outFile	 = st.optArg; break;
				case 'k': opt->keyFile	 = st.optArg; break;
				case 'p': opt->passin	  = st.optArg; break;
				case 'g': opt->dgstName	= st.optArg; break;
				case 'S': opt->sigFile	 = st.optArg; break;
				case 'x': opt->hexdump	 = 1; break;
				case 'h': opt->help		= 1; break;
				case 'H': opt->hashInput   = 1; break;
				case 'u': opt->pubin	   = 1; break;
				case 'e': opt->encrypt	 = 1; break;
				case 'd': opt->decrypt	 = 1; break;
				case 's': opt->sign		= 1; break;
				case 'v': opt->verify	  = 1; break;
				default:
					FT_PKEYUTL_ERR("internal error (unhandled option '%c')\n", st.opt);
					return (0);
			}
		}
	}

	/* First positional -> input file (if -i not given) */
	if (!opt->inFile && st.index < st.argc)
		opt->inFile = st.argv[st.index++];

	/* Second positional -> signature file (if -S not given, for verify) */
	if (!opt->sigFile && st.index < st.argc)
		opt->sigFile = st.argv[st.index++];

	if (st.index < st.argc)
		FT_PKEYUTL_ERR("warning: extra arguments ignored\n");

	return (1);
}


static void writeHexOutput(const char *file, const uint8_t *data, size_t len)
{
	char	*hex;
	size_t	i;

	hex = malloc(len * 2 + 1);
	if (!hex)
	{
		FT_PKEYUTL_ERR("memory allocation failed\n");
		return;
	}
	i = 0;
	while (i < len)
	{
		ft_snprintf(hex + i * 2, 3, "%02x", data[i]);
		i++;
	}
	writeBinaryOutput(file, (uint8_t *)hex, len * 2);
	free(hex);
}



int cmdPkeyutl(int argc, char **argv, char **env)
{
	t_pkeyutlOptions	opt;
	t_rsaKey		key;
	uint8_t			*in;
	uint8_t			*sig;
	uint8_t			*out;
	size_t			inLen;
	size_t			sigLen;
	size_t			outLen;
	const t_algoId	*algo;
	int				wantPriv;
	int				ret;

	in		= NULL;
	sig		= NULL;
	out		= NULL;
	inLen	= 0;
	sigLen	= 0;
	outLen	= 0;
	ret		= 1;

	if (!parseRsautlArgs(argc, argv, &opt))
		return (printRsautlHelp(), 1);
	if (opt.help)
		return (printRsautlHelp(), 0);

	if (opt.encrypt + opt.decrypt + opt.sign + opt.verify != 1)
	{
		FT_PKEYUTL_ERR("must specify exactly one of --encrypt, --decrypt, --sign, --verify\n");
		return (1);
	}
	if (!opt.keyFile)
	{
		FT_PKEYUTL_ERR("key required (-k)\n");
		return (1);
	}

	/* 1. Read input data */
	if (readBinaryFile(opt.inFile, &in, &inLen))
		return (1);

	/* 2. Hash input if -H is set (only for sign/verify) */
	if ((opt.sign || opt.verify) && opt.hashInput)
	{
		if (!hashDataInPlace(opt.dgstName, &in, &inLen))
			goto cleanup;
	}

	/* 3. Load key */
	ft_bzero(&key, sizeof(t_rsaKey));
	wantPriv = (opt.decrypt || opt.sign) ? 1 : 0;
	if (opt.pubin)
		wantPriv = 0;
	if (!loadRsaKey(opt.keyFile, opt.passin, env, wantPriv, &key))
		goto cleanup;

	out = malloc(rsaModulusBytes(&key));
	if (!out)
	{
		FT_PKEYUTL_ERR("memory allocation failed\n");
		goto cleanup;
	}

	/* 4. Perform the requested operation */
	if (opt.encrypt)
	{
		if (!rsaEncrypt(in, inLen, &key, out, &outLen, PKEY_PADDING_PKCS1V15))
			{FT_PKEYUTL_ERR("RSA encryption failed\n"); ret = 1; goto cleanup;}
	}
	else if (opt.decrypt)
	{
		if (!rsaDecrypt(in, inLen, &key, out, &outLen, PKEY_PADDING_PKCS1V15))
			{FT_PKEYUTL_ERR("RSA decryption failed\n"); ret = 1; goto cleanup;}
	}
	else if (opt.sign)
	{
		algo = getDigestOid(opt.dgstName);
		if (!algo)
			algo = getDigestOid("sha256");
		if (!rsaSign(in, inLen, algo, &key, out, &outLen, PKEY_PADDING_PKCS1V15))
			{FT_PKEYUTL_ERR("RSA signing failed\n"); ret = 1; goto cleanup;}
	}
	else if (opt.verify)
	{
		if (readBinaryFile(opt.sigFile, &sig, &sigLen))
			{FT_PKEYUTL_ERR("failed to read signature file\n"); ret = 1; goto cleanup;}
		algo = getDigestOid(opt.dgstName);
		if (!algo)
			algo = getDigestOid("sha256");
		ret = 0;
		if (rsaVerify(in, inLen, algo, &key, sig, sigLen, PKEY_PADDING_PKCS1V15))
			ft_printf("Verified OK\n");
		else
		{
			ret = 1;
			ft_printf("Verification Failure\n");
		}
		goto cleanup;
	}

	/* 5. Write output */
	if (opt.hexdump)
		writeHexOutput(opt.outFile, out, outLen);
	else
		writeBinaryOutput(opt.outFile, out, outLen);

	ret = 0;

cleanup:
	free(in);
	free(sig);
	free(out);
	rsaFreeKey(&key);
	return (ret);
}
