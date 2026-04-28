#include <fcntl.h>
#include <unistd.h>
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmath.h"
#include "../../includes/rsa/rsa.h"
#include "../../includes/cli/parser.h"

#define RSA_MIN_BITS 1
#define RSA_DEFAULT_BITS 2048

int cmdGenrsa(t_sslOptions *opts)
{
	t_rsaKey	key;
	char		*pem;
	int			fd = STDOUT_FILENO;
	int			bits = RSA_DEFAULT_BITS;
	uint64_t	e = 65537;

	if (opts->fileCount > 0 && opts->fileInputs[0])
	{
		bits = ft_atoi(opts->fileInputs[0]);
		if (bits < RSA_MIN_BITS)
		{
			ft_dprintf(STDERR_FILENO, "genrsa: RSA length must be >= %d\n", RSA_MIN_BITS);
			return (1);
		}
	}

	ft_dprintf(STDERR_FILENO, "Generating RSA private key, %d bit long modulus\n", bits);

	rsaGenerateKey(&key, bits, e);
	
	ft_dprintf(STDERR_FILENO, "e is %llu (0x%llx)\n", e, e);

	pem = rsaKeyToPem(&key, 1);
	if (!pem)
	{
		ft_dprintf(STDERR_FILENO, "genrsa: failed to encode key\n");
		rsaFreeKey(&key);
		return (1);
	}

	if (opts->outputFile)
	{
		fd = open(opts->outputFile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
		{
			ft_dprintf(STDERR_FILENO, "genrsa: cannot create %s\n", opts->outputFile);
			free(pem);
			rsaFreeKey(&key);
			return (1);
		}
	}

	write(fd, pem, ft_strlen(pem));
	if (fd != STDOUT_FILENO)
		close(fd);
	rsaFreeKey(&key);
	free(pem);
	return (0);
}
