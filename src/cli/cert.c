#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/asymmetric/pkey.h"
#include "../../includes/asymmetric/rsa.h"
#include "../../includes/x509/cert.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/x509/pem.h"
#include "../../includes/cli/password.h"
#include "../../includes/cli/pkey.h"
#include "../../includes/utils/utils.h"

#include "../../includes/cli/cert.h"

#define FT_CERT_ERR(...) ft_dprintf(STDERR_FILENO, "ft_ssl: cert: " __VA_ARGS__)

static const tFtLongOption g_certLongOpts[] = {
	{"inform",		FT_GETOPT_REQUIRED_ARGUMENT,	'I'},
	{"outform",		FT_GETOPT_REQUIRED_ARGUMENT,	'O'},
	{"in",			FT_GETOPT_REQUIRED_ARGUMENT,	'i'},
	{"out",			FT_GETOPT_REQUIRED_ARGUMENT,	'o'},
	{"text",		FT_GETOPT_NO_ARGUMENT,			't'},
	{"noout",		FT_GETOPT_NO_ARGUMENT,			'n'},
	{"fingerprint",	FT_GETOPT_NO_ARGUMENT,			'f'},
	{"serial",		FT_GETOPT_NO_ARGUMENT,			's'},
	{"subject",		FT_GETOPT_NO_ARGUMENT,			'S'},
	{"issuer",		FT_GETOPT_NO_ARGUMENT,			'u'},
	{"dates",		FT_GETOPT_NO_ARGUMENT,			'd'},
	{"startdate",	FT_GETOPT_NO_ARGUMENT,			'a'},
	{"enddate",		FT_GETOPT_NO_ARGUMENT,			'e'},
	{"pubkey",		FT_GETOPT_NO_ARGUMENT,			'p'},
	{"modulus",		FT_GETOPT_NO_ARGUMENT,			'm'},
	{"checkend",	FT_GETOPT_REQUIRED_ARGUMENT,	'c'},
	{"verify",		FT_GETOPT_NO_ARGUMENT,			'v'},
	{"no_verify",	FT_GETOPT_NO_ARGUMENT,			'V'},
	{"new",			FT_GETOPT_NO_ARGUMENT,			'w'},
	{"key",			FT_GETOPT_REQUIRED_ARGUMENT,	'K'},
	{"subj",		FT_GETOPT_REQUIRED_ARGUMENT,	'b'},
	{"days",		FT_GETOPT_REQUIRED_ARGUMENT,	'y'},
	{"self-sign",	FT_GETOPT_NO_ARGUMENT,			'U'},
	{"help",		FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL,			0,								0}
};

static void printCertHelp(void)
{
	ft_printf(
		"Usage: ft_ssl cert [options] [certificate_file]\n"
		"Options:\n"
		"  -I, --inform   <PEM|DER>  Input format (default PEM)\n"
		"  -O, --outform  <PEM|DER>  Output format (default PEM)\n"
		"  -i, --in       <file>     Input file (default stdin)\n"
		"  -o, --out      <file>     Output file (default stdout)\n"
		"  -t, --text                Print certificate in human-readable form\n"
		"  -n, --noout               Do not output the encoded certificate\n"
		"  -f, --fingerprint         Print SHA-256 fingerprint\n"
		"  -s, --serial              Print serial number\n"
		"  -S, --subject             Print subject DN\n"
		"  -u, --issuer              Print issuer DN\n"
		"  -d, --dates               Print validity period\n"
		"  -a, --startdate           Print notBefore date\n"
		"  -e, --enddate             Print notAfter date\n"
		"  -p, --pubkey              Output public key in PEM format\n"
		"  -m, --modulus             Print RSA modulus (hex)\n"
		"  -c, --checkend <sec>      Check if cert expires within <sec> seconds\n"
		"  -v, --verify              Verify certificate signature (NOT IMPLEMENTED)\n"
		"  -V, --no_verify           Skip verification (default for display)\n"
		"  -w, --new                 Generate a new certificate\n"
		"  -K, --key      <file>     Key file for new certificate\n"
		"  -b, --subj     <DN>       Subject DN (e.g. /CN=localhost)\n"
		"  -y, --days     <n>        Validity in days (default 365)\n"
		"  -U, --self-sign           Self-sign the new certificate (default)\n"
		"  -h, --help                Show this help\n"
	);
}

static int parseCertArgs(int argc, char **argv, t_certOptions *opt)
{
	tFtGetopt		st;
	const char		*shortOpts = "I:O:i:o:tnsfuSdpa:e:mc:vhwK:b:y:U";
	tFtGetoptStatus	status;

	ft_bzero(opt, sizeof(t_certOptions));
	opt->days = 365;
	opt->selfSigned = 1;

	ft_getoptInit(&st, argc, argv);
	if (st.argc < 0)
		return (0);

	while (1) {
		status = ft_getoptLong(&st, shortOpts, g_certLongOpts);
		if (status == FT_GETOPT_END)
			break;

		/* Positional argument -> input file if not already set */
		if (status == FT_GETOPT_POSITIONAL) {
			if (!opt->inFile)
				opt->inFile = st.argv[st.index];
			else
				FT_CERT_ERR("unexpected argument '%s'\n", st.argv[st.index]);
			st.index++;
			continue;
		}

		if (status == FT_GETOPT_ERROR) {
			FT_CERT_ERR("option error\n");
			return (0);
		}

		switch (st.opt) {
			case 'I': opt->inform		= st.optArg; break;
			case 'O': opt->outform		= st.optArg; break;
			case 'i': opt->inFile		= st.optArg; break;
			case 'o': opt->outFile		= st.optArg; break;
			case 't': opt->text			= 1; break;
			case 'n': opt->noout		= 1; break;
			case 'f': opt->fingerprint	= 1; break;
			case 's': opt->serial		= 1; break;
			case 'S': opt->subject		= 1; break;
			case 'u': opt->issuer		= 1; break;
			case 'd': opt->dates		= 1; break;
			case 'a': opt->startdate	= 1; break;
			case 'e': opt->enddate		= 1; break;
			case 'p': opt->pubkey		= 1; break;
			case 'm': opt->modulus		= 1; break;
			case 'c':
				opt->checkend			= 1;
				opt->checkendSeconds	= ft_atol(st.optArg);
				break;
			case 'v': opt->verify		= 1; break;
			case 'V': opt->noVerify		= 1; break;
			case 'w': opt->newCert		= 1; break;
			case 'K': opt->keyFile		= st.optArg; break;
			case 'b': opt->subj			= st.optArg; break;
			case 'y': opt->days			= ft_atoi(st.optArg); break;
			case 'U': opt->selfSigned	= 1; break;
			case 'h': opt->help			= 1; break;
			default: return (0);
		}
	}

	/* If generating a new cert, key file is mandatory */
	if (opt->newCert && !opt->keyFile) {
		FT_CERT_ERR("--new requires --key\n");
		return (0);
	}

	/* Default behaviour: if nothing specified, print text */
	if (!opt->text && !opt->fingerprint && !opt->serial && !opt->subject &&
		!opt->issuer && !opt->dates && !opt->startdate && !opt->enddate &&
		!opt->pubkey && !opt->modulus && !opt->checkend && !opt->noout &&
		!opt->newCert)
		opt->text = 1;

	return (1);
}

static void writeBinaryOutput(const char *fileName, const uint8_t *data, size_t len)
{
	int fd;
	if (!data) return;
	fd = fileName ? open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644) : STDOUT_FILENO;
	if (fd < 0) {
		FT_CERT_ERR("cannot write to '%s'\n", fileName ? fileName : "stdout");
		return;
	}
	write(fd, data, len);
	if (fileName) close(fd);
}

static int detectPemFormat(const char *data)
{
	return (data && ft_strstr(data, "-----BEGIN ") != NULL);
}

static int loadCert(const char *fileName, uint8_t **der, size_t *derLen)
{
	t_pemBlock	block;

	if (fileName) {
		*der = (uint8_t *)readBinaryFile(fileName);
		if (!*der)
			return (0);
		*derLen = ft_strlen((char *)*der);
		if (*derLen > 0 && (*der)[0] == '-') {
			char *text = (char *)*der;
			if (detectPemFormat(text)) {
				if (!pemDecode(text, &block)) {
					free(*der);
					*der = NULL;
					FT_CERT_ERR("failed to parse PEM certificate\n");
					return (0);
				}
				free(*der);
				*der	= block.der;
				*derLen	= block.derLen;
				free(block.header);
			}
		}
		return (1);
	} else {
		*der = (uint8_t *)readBinaryFile(NULL);
		if (!*der)			return (0);
		*derLen = ft_strlen((char *)*der);

		char *text = (char *)*der;
		if (detectPemFormat(text)) {
			if (!pemDecode(text, &block)) {
				free(*der);
				*der = NULL;
				FT_CERT_ERR("failed to parse PEM certificate\n");
				return (0);
			}
			free(*der);
			*der	= block.der;
			*derLen	= block.derLen;
			free(block.header);
		}
		return (1);
	}
}

static void printTime(time_t t)
{
	struct tm *tm = gmtime(&t);
	if (tm)
		ft_printf("%04d-%02d-%02d %02d:%02d:%02d GMT",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	else
		ft_printf("(invalid time)");
}

static void printHex(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++)
		ft_printf("%02X", data[i]);
}

static void printExtensionOid(const uint8_t *ext, size_t extLen)
{
	uint8_t	*oid;
	size_t	oidLen, consumed;
	if (asn1ParseSequence(ext, extLen, &oid, &oidLen, &consumed))
		printHex(oid, oidLen);
	else
		ft_printf("(invalid)");
}

static void printDN(const uint8_t *dnDer, size_t dnLen)
{
	uint8_t	*content;
	size_t	contentLen, consumed;

	if (!asn1ParseSequence(dnDer, dnLen, &content, &contentLen, &consumed))
		goto fallback;

	uint8_t	*ptr	= content;
	size_t	remain	= contentLen;
	int		first	= 1;

	while (remain > 0) {
		uint8_t	*setVal;
		size_t	setValLen, setConsumed;
		if (!asn1ParseAny(ptr, remain, &setVal, &setValLen, &setConsumed))
			break;

		uint8_t	*avaSeq;
		size_t	avaSeqLen, avaConsumed;
		if (!asn1ParseSequence(setVal, setValLen, &avaSeq, &avaSeqLen, &avaConsumed))
			break;

		uint8_t	*oid, *val;
		size_t	oidLen, valLen;

		if (!asn1ParseAny(avaSeq, avaSeqLen, &oid, &oidLen, &avaConsumed))
			break;
		avaSeq		+= avaConsumed;
		avaSeqLen	-= avaConsumed;

		if (avaSeqLen < 2)
			break;

		uint8_t valTag = avaSeq[0];

		if (!asn1ParseAny(avaSeq, avaSeqLen, &val, &valLen, &avaConsumed))
			break;

		if (!first)
			ft_printf(", ");
		first = 0;

		const char *attrName = getDnAttrName(oid, oidLen);
		if (attrName)
			ft_printf("%s=", attrName);
		else {
			ft_printf("OID.");
			printHex(oid, oidLen);
			ft_printf("=");
		}

		if (val && valLen > 0) {
			if (valTag == 0x13 || valTag == 0x0C ||
				valTag == 0x16 || valTag == 0x1A) {
				for (size_t k = 0; k < valLen; k++)
					ft_printf("%c", (char)val[k]);
			} else
				printHex(val, valLen);
		} else
			ft_printf("(empty)");

		ptr		+= setConsumed;
		remain	-= setConsumed;
	}
	return;

fallback:
	printHex(dnDer, dnLen);
}

static void printCertText(t_x509Cert *cert)
{
	ft_printf("Certificate:\n");
	ft_printf("	Serial Number: ");
	printHex(cert->serial, cert->serialLen);
	ft_printf("\n");

	ft_printf("	Validity\n");
	ft_printf("		Not Before: ");
	printTime(cert->notBefore);
	ft_printf("\n");
	ft_printf("		Not After : ");
	printTime(cert->notAfter);
	ft_printf("\n");

	ft_printf("	Issuer: ");
	printDN(cert->issuer, cert->issuerLen);
	ft_printf("\n");

	ft_printf("	Subject: ");
	printDN(cert->subject, cert->subjectLen);
	ft_printf("\n");

	ft_printf("	Subject Public Key Info: %s\n",
		cert->pubKey.def ? cert->pubKey.def->name : "unknown");

	if (cert->extCount) {
		ft_printf("	X509v3 Extensions:\n");
		for (size_t i = 0; i < cert->extCount; i++) {
			ft_printf("		");
			printExtensionOid(cert->extensions[i], cert->extLens[i]);
			ft_printf("\n");
		}
	}

	ft_printf("	SHA-256 Fingerprint: ");
	printHex(cert->sha256Fingerprint, 32);
	ft_printf("\n");

	ft_printf("	SHA-384 Fingerprint: ");
	printHex(cert->sha384Fingerprint, 48);
	ft_printf("\n");
}

static void printCertDetails(t_x509Cert *cert, t_certOptions *opt)
{
	if (opt->text)
		printCertText(cert);

	if (opt->serial) {
		ft_printf("serialNumber=");
		printHex(cert->serial, cert->serialLen);
		ft_printf("\n");
	}

	if (opt->subject) {
		ft_printf("subject=");
		printDN(cert->subject, cert->subjectLen);
		ft_printf("\n");
	}

	if (opt->issuer) {
		ft_printf("issuer=");
		printDN(cert->issuer, cert->issuerLen);
		ft_printf("\n");
	}

	if (opt->startdate) {
		ft_printf("notBefore=");
		printTime(cert->notBefore);
		ft_printf("\n");
	}

	if (opt->enddate) {
		ft_printf("notAfter=");
		printTime(cert->notAfter);
		ft_printf("\n");
	}

	if (opt->dates) {
		ft_printf("notBefore=");
		printTime(cert->notBefore);
		ft_printf("\nnotAfter=");
		printTime(cert->notAfter);
		ft_printf("\n");
	}

	if (opt->fingerprint) {
		ft_printf("SHA-256 Fingerprint=");
		printHex(cert->sha256Fingerprint, 32);
		ft_printf("\n");
	}

	if (opt->pubkey) {
		char *pem = pkeyToPem(&cert->pubKey, 0, 1, NULL, NULL);
		if (pem) {
			ft_printf("%s", pem);
			free(pem);
		}
	}

	if (opt->modulus && cert->pubKey.def &&
		cert->pubKey.def->type == PKEY_TYPE_RSA) {
		t_rsaKey *rsa = (t_rsaKey *)cert->pubKey.key;
		char *hex = bigIntToHex(rsa->n);
		if (hex) {
			for (char *p = hex; *p; p++)
				*p = ft_toupper(*p);
			ft_printf("Modulus=%s\n", hex);
			free(hex);
		}
	}

	if (opt->checkend) {
		time_t now = time(NULL);
		if (cert->notAfter - now <= opt->checkendSeconds)
			FT_CERT_ERR("Certificate will expire within %ld seconds\n",
				opt->checkendSeconds);
		else
			ft_printf("Certificate will not expire within %ld seconds\n",
				opt->checkendSeconds);
	}
}

static void outputCert(t_x509Cert *cert, t_certOptions *opt)
{
	if (opt->noout)
		return;

	if (opt->outform && ft_strcmp(opt->outform, "DER") == 0) {
		writeBinaryOutput(opt->outFile, cert->der, cert->derLen);
	} else {
		char *pem = pemEncode(cert->der, cert->derLen, "CERTIFICATE");
		if (pem) {
			writeBinaryOutput(opt->outFile, (uint8_t *)pem, ft_strlen(pem));
			free(pem);
		}
	}
}

static t_pkey *loadKeyFromFile(const char *file)
{
	char	*pem;
	t_pkey	*pkey;
	int		ret;

	pem = readBinaryFile(file);
	if (!pem)
		return (NULL);

	pkey = malloc(sizeof(t_pkey));
	if (!pkey) {
		free(pem);
		return (NULL);
	}
	ft_bzero(pkey, sizeof(t_pkey));

	ret = pkeyFromPem(pem, pkey, 1, NULL);	/* want private key, no initial password */
	if (ret == 2) {
		/* password required, prompt interactively */
		char *password = promptPassword("Enter password for encrypted key: ");
		if (password) {
			ret = pkeyFromPem(pem, pkey, 1, password);
			secureZeroMemory(password, ft_strlen(password));
			free(password);
		} else
			ret = 0;
	}

	free(pem);
	if (ret != 1 || !pkey->key) {
		free(pkey);
		return (NULL);
	}
	return (pkey);
}

static uint8_t *generateSerial(size_t *len)
{
	uint8_t *serial = malloc(20);
	if (!serial) return (NULL);
	*len = ft_snprintf((char *)serial, 20, "%lx", (unsigned long)time(NULL));
	return (serial);
}

int cmdCert(int argc, char **argv, char **env)
{
	t_certOptions	opt;
	uint8_t			*der		= NULL;
	size_t			derLen		= 0;
	t_x509Cert		*cert		= NULL;
	int				ret			= 1;

	(void)env;

	if (argc < 2 || !parseCertArgs(argc - 1, argv + 1, &opt)) {
		printCertHelp();
		return (1);
	}

	if (opt.help) {
		printCertHelp();
		return (0);
	}

	if (opt.newCert) {
		t_pkey	*key = NULL;
		time_t	now;
		size_t	serialLen;
		uint8_t	*serial;

		key = loadKeyFromFile(opt.keyFile);
		if (!key) {
			FT_CERT_ERR("failed to load private key from '%s'\n", opt.keyFile);
			return (1);
		}

		now = time(NULL);
		serial = generateSerial(&serialLen);
		if (!serial) {
			pkeyFree(key);
			free(key);
			return (1);
		}

		cert = x509CertNew(key,
			opt.subj ? opt.subj : "/CN=Generated",
			opt.subj ? opt.subj : "/CN=Generated",
			now,
			now + opt.days * 86400,
			serial, serialLen);
		free(serial);

		if (!cert) {
			FT_CERT_ERR("certificate generation failed\n");
			pkeyFree(key);
			free(key);
			return (1);
		}

		printCertDetails(cert, &opt);
		outputCert(cert, &opt);

		x509CertFree(cert);
		pkeyFree(key);
		free(key);
		return (0);
	}

	if (!loadCert(opt.inFile, &der, &derLen)) {
		FT_CERT_ERR("failed to load certificate\n");
		return (1);
	}

	cert = x509CertParse(der, derLen);
	if (!cert) {
		FT_CERT_ERR("failed to parse certificate\n");
		free(der);
		return (1);
	}

	printCertDetails(cert, &opt);
	outputCert(cert, &opt);

	ret = 0;

	free(der);
	x509CertFree(cert);
	return (ret);
}
