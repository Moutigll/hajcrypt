#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../includes/cli/client.h"
#include "../../includes/cli/parser.h"

#define ENCODE_BUFFER_SIZE (16 * 1024)
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

static int	processReadLoop(int				fd,
							void			*ctx,
							const t_encode	*enc,
							t_sslOptions	*opts,
							int				*lineLen)
{
	uint8_t		inBuf[ENCODE_BUFFER_SIZE];
	uint8_t		outBuf[ENCODE_BUFFER_SIZE * 2];
	ssize_t		bytesRead;
	size_t		outLen;
	int			shouldWrap;
	int			ret;

	if (!ctx || !enc || !opts || !lineLen)
		return (-1);

	shouldWrap = (!opts->isDecoding && opts->wrapOutput && enc->supportsWrap);
	ret = 0;

	while (1)
	{
		bytesRead = read(fd, inBuf, sizeof(inBuf));
		if (bytesRead <= 0)
			break;

		if (enc->update(ctx, inBuf, (size_t)bytesRead, outBuf, &outLen) < 0)
		{
			ret = -1;
			break;
		}

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

static int	processFinalBlock(void				*ctx,
							  const t_encode	*enc,
							  t_sslOptions		*opts,
							  int				lineLen)
{
	uint8_t		finalBuf[ENCODE_BUFFER_SIZE * 2];
	size_t		finalLen;
	int			shouldWrap;

	if (!ctx || !enc || !opts)
		return (-1);

	enc->final(ctx, finalBuf, &finalLen);
	
	shouldWrap = (!opts->isDecoding && opts->wrapOutput && enc->supportsWrap);
	
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

	if (!opts->isDecoding && (finalLen > 0 || lineLen > 0))
	{
		if (write(STDOUT_FILENO, "\n", 1) != 1)
			return (-1);
	}
	
	return (0);
}

static int	processEncodeFd(int fd, const t_encode *enc, t_sslOptions *opts)
{
	void	*ctx;
	int		lineLen;
	int		ret;

	if (!enc || !opts)
		return (1);

	ctx = malloc(enc->ctxSize);
	if (!ctx)
		return (1);

	enc->init(ctx, opts->isDecoding ? 1 : 0);
	lineLen = 0;

	ret = processReadLoop(fd, ctx, enc, opts, &lineLen);
	if (ret == 0)
		ret = processFinalBlock(ctx, enc, opts, lineLen);

	free(ctx);
	return (ret < 0 ? 1 : 0);
}

static int	openInputFile(const char *filename, const char *encName)
{
	int	fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: %s: No such file or directory\n",
			encName, filename);
	}
	return (fd);
}

static int	openOutputFile(const char *filename, const char *encName)
{
	int	fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
	{
		ft_dprintf(STDERR_FILENO,
			"ft_ssl: %s: cannot create %s\n",
			encName, filename);
	}
	return (fd);
}

int	executeEncode(t_sslOptions *opts)
{
	const t_encode	*enc;
	int				inFd;
	int				outFd;
	int				ret;

	if (!opts)
		return (1);

	enc = getEncodeByAlgo(opts->algo);
	if (!enc)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: unknown encoding algorithm\n");
		return (1);
	}

	inFd = STDIN_FILENO;
	outFd = STDOUT_FILENO;

	if (opts->inputFile)
	{
		inFd = openInputFile(opts->inputFile, enc->name);
		if (inFd < 0)
			return (1);
	}

	if (opts->outputFile)
	{
		outFd = openOutputFile(opts->outputFile, enc->name);
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

	ret = processEncodeFd(inFd, enc, opts);

	if (inFd != STDIN_FILENO)
		close(inFd);
	return (ret);
}
