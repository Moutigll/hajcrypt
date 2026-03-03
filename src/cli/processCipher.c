#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../includes/cli/client.h"
#include "../../includes/cli/parser.h"

#define CIPHER_BUFFER_SIZE (16 * 1024)
#define WRAP_LIMIT 64

static int	writeWrapped(int fd, const uint8_t *data, size_t len, int *lineLen)
{
	size_t	i;

	i = 0;
	while (i < len)
	{
		if (write(fd, &data[i], 1) != 1)
			return (-1);
		(*lineLen)++;
		i++;

		if (*lineLen == WRAP_LIMIT)
		{
			if (write(fd, "\n", 1) != 1)
				return (-1);
			*lineLen = 0;
		}
	}
	return (0);
}

static int	processReadLoop(int fd, void *ctx, const t_cipher *cipher,
							t_sslOptions *opts, int *lineLen)
{
	uint8_t		inBuf[CIPHER_BUFFER_SIZE];
	uint8_t		outBuf[CIPHER_BUFFER_SIZE * 2]; // Assez grand pour l'encodage
	ssize_t		bytesRead;
	size_t		outLen;
	int			shouldWrap;
	int			ret;

	if (!ctx || !cipher || !opts || !lineLen)
		return (-1);

	/* Le wrapping n'est applicable qu'en mode non-décodage (encryption/encodage) */
	shouldWrap = (!opts->isDecoding && opts->wrapOutput && cipher->supportsWrap);
	ret = 0;

	while (1)
	{
		bytesRead = read(fd, inBuf, sizeof(inBuf));
		if (bytesRead <= 0)
			break;

		cipher->update(ctx, inBuf, (size_t)bytesRead, outBuf, &outLen);
		/* Note: update ne retourne pas de code d'erreur, on suppose que l'état d'erreur est dans le contexte */

		if (outLen == 0)
			continue;

		if (shouldWrap)
		{
			if (writeWrapped(STDOUT_FILENO, outBuf, outLen, lineLen) < 0)
			{
				ret = -1;
				break;
			}
		}
		else
		{
			if (write(STDOUT_FILENO, outBuf, outLen) != (ssize_t)outLen)
			{
				ret = -1;
				break;
			}
		}
	}

	if (bytesRead < 0)
		ret = -1;
	return (ret);
}

static int	processFinalBlock(void *ctx, const t_cipher *cipher,
							  t_sslOptions *opts, int lineLen)
{
	uint8_t		finalBuf[CIPHER_BUFFER_SIZE * 2];
	size_t		finalLen;
	int			shouldWrap;

	if (!ctx || !cipher || !opts)
		return (-1);

	cipher->final(ctx, finalBuf, &finalLen);
	
	shouldWrap = (!opts->isDecoding && opts->wrapOutput && cipher->supportsWrap);
	
	if (finalLen > 0)
	{
		if (shouldWrap)
		{
			if (writeWrapped(STDOUT_FILENO, finalBuf, finalLen, &lineLen) < 0)
				return (-1);
		}
		else
		{
			if (write(STDOUT_FILENO, finalBuf, finalLen) != (ssize_t)finalLen)
				return (-1);
		}
	}

	/* Pour l'encodage (non-décodage), on ajoute un newline final si des données ont été produites */
	if (!opts->isDecoding && (finalLen > 0 || lineLen > 0))
	{
		if (write(STDOUT_FILENO, "\n", 1) != 1)
			return (-1);
	}
	
	return (0);
}

static int	processCipherFd(int fd, const t_cipher *cipher, t_sslOptions *opts)
{
	void	*ctx;
	int		lineLen;
	int		ret;

	if (!cipher || !opts)
		return (1);

	ctx = malloc(cipher->ctxSize);
	if (!ctx)
		return (1);

	/* Initialisation avec la direction appropriée */
	cipher->init(ctx, NULL, 0, NULL,
				 opts->isDecoding ? CIPHER_DECRYPT : CIPHER_ENCRYPT);
	lineLen = 0;

	ret = processReadLoop(fd, ctx, cipher, opts, &lineLen);
	if (ret == 0)
		ret = processFinalBlock(ctx, cipher, opts, lineLen);

	cipher->free(ctx);
	free(ctx);
	return (ret < 0 ? 1 : 0);
}

static int	openInputFile(const char *filename, const char *cipherName)
{
	int	fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: %s: No such file or directory\n",
			cipherName, filename);
	}
	return (fd);
}

static int	openOutputFile(const char *filename, const char *cipherName)
{
	int	fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: cannot create %s\n",
			cipherName, filename);
	}
	return (fd);
}

int	executeCipher(t_sslOptions *opts)
{
	const t_cipher	*cipher;
	int				inFd;
	int				outFd;
	int				ret;

	if (!opts)
		return (1);

	cipher = getCipherByAlgo(opts->algo);
	if (!cipher)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: unknown cipher algorithm\n");
		return (1);
	}

	inFd = STDIN_FILENO;
	outFd = STDOUT_FILENO;

	if (opts->inputFile)
	{
		inFd = openInputFile(opts->inputFile, cipher->name);
		if (inFd < 0)
			return (1);
	}

	if (opts->outputFile)
	{
		outFd = openOutputFile(opts->outputFile, cipher->name);
		if (outFd < 0)
		{
			if (inFd != STDIN_FILENO)
				close(inFd);
			return (1);
		}
		if (outFd != STDOUT_FILENO)
		{
			dup2(outFd, STDOUT_FILENO);
			close(outFd);
		}
	}

	ret = processCipherFd(inFd, cipher, opts);

	if (inFd != STDIN_FILENO)
		close(inFd);
	return (ret);
}
