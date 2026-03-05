#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/cli/parser.h"

#define CIPHER_BUFFER_SIZE (16 * 1024)

static int	handleStreamCipher(int				fd,
							   void				*ctx,
							   const t_cipher	*cipher,
							   t_sslOptions		*opts,
							   int				shouldWrap,
							   int				*lineLen)
{
	uint8_t		inBuf[CIPHER_BUFFER_SIZE];
	uint8_t		outBuf[CIPHER_BUFFER_SIZE * 2];
	ssize_t		bytesRead;
	size_t		outLen;
	int			ret;

	ret = 0;
	while (1)
	{
		bytesRead = read(fd, inBuf, sizeof(inBuf));
		if (bytesRead <= 0)
			break ;
		cipher->update(ctx, inBuf, bytesRead, outBuf, &outLen);
		if (outLen > 0)
		{
			if (writeOutput(STDOUT_FILENO, outBuf, outLen, shouldWrap, lineLen) < 0)
			{
				ret = -1;
				break ;
			}
		}
	}
	if (ret == 0)
	{
		cipher->final(ctx, outBuf, &outLen);
		if (outLen > 0)
		{
			if (writeOutput(STDOUT_FILENO, outBuf, outLen, shouldWrap, lineLen) < 0)
				ret = -1;
		}
	}
	if (ret == 0 && !opts->isDecoding && (outLen > 0 || *lineLen > 0))
	{
		if (write(STDOUT_FILENO, "\n", 1) != 1)
			ret = -1;
	}
	return (ret < 0 ? 1 : 0);
}


static int	processLastBlock(void			*ctx,
							 const t_cipher	*cipher,
							 t_sslOptions	*opts,
							 int			shouldWrap,
							 int			*lineLen,
							 uint8_t		*lastBlock,
							 size_t			lastLen)
{
	uint8_t		outBuf[CIPHER_BUFFER_SIZE * 2];
	uint8_t		block[32];
	size_t		outLen;
	size_t		unpaddedLen;

	if (opts->isDecoding)
	{
		if (lastLen != cipher->blockSize)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: bad decrypt\n");
			return (-1);
		}
		cipher->update(ctx, lastBlock, cipher->blockSize, outBuf, &outLen);
		if (cipher->unpad && outLen > 0)
		{
			if (cipher->unpad(outBuf, &unpaddedLen, cipher->blockSize) != 0)
			{
				ft_dprintf(STDERR_FILENO, "ft_ssl: bad decrypt\n");
				return (-1);
			}
			if (unpaddedLen > 0)
			{
				if (writeOutput(STDOUT_FILENO, outBuf, unpaddedLen,
								shouldWrap, lineLen) < 0)
					return (-1);
			}
		}
	}
	else
	{
		if (lastLen > 0)
			ft_memcpy(block, lastBlock, lastLen);
		if (cipher->pad)
		{
			cipher->pad(block, lastLen, cipher->blockSize);
			cipher->update(ctx, block, cipher->blockSize, outBuf, &outLen);
			if (outLen > 0)
			{
				if (writeOutput(STDOUT_FILENO, outBuf, outLen,
								shouldWrap, lineLen) < 0)
					return (-1);
			}
		}
	}
	return (0);
}

static int	handleBlockCipher(int				fd,
							  void				*ctx,
							  const t_cipher	*cipher,
							  t_sslOptions		*opts,
							  int				shouldWrap,
							  int				*lineLen)
{
	uint8_t		inBuf[CIPHER_BUFFER_SIZE];
	uint8_t		outBuf[CIPHER_BUFFER_SIZE * 2];
	uint8_t		lastBlock[32];
	uint8_t		tempBuffer[CIPHER_BUFFER_SIZE + 32];
	size_t		lastLen;
	ssize_t		bytesRead;
	size_t		outLen = 0;
	int			ret;

	lastLen = 0;
	ret = 0;
	while (1)
	{
		bytesRead = read(fd, inBuf, sizeof(inBuf));
		if (bytesRead <= 0)
			break ;
		
		/* Combine with any leftover from previous read */
		size_t	total = lastLen + bytesRead;
		uint8_t	*temp = tempBuffer;
		
		if (lastLen > 0)
		{
			ft_memcpy(temp, lastBlock, lastLen);
			ft_memcpy(temp + lastLen, inBuf, bytesRead);
		}
		else
			ft_memcpy(temp, inBuf, bytesRead);

		size_t	fullBlocks = total / cipher->blockSize;
		lastLen = total % cipher->blockSize;
		size_t	blocksToWrite = fullBlocks;

		/* In decryption mode, keep the last full block for padding handling */
		if (opts->isDecoding && bytesRead > 0 && fullBlocks > 0)
		{
			blocksToWrite = fullBlocks - 1;
			ft_memcpy(lastBlock, temp + blocksToWrite * cipher->blockSize,
					  cipher->blockSize);
			lastLen = cipher->blockSize;
		}

		if (blocksToWrite > 0)
		{
			cipher->update(ctx, temp, blocksToWrite * cipher->blockSize,
						   outBuf, &outLen);
			if (outLen > 0)
			{
				if (writeOutput(STDOUT_FILENO, outBuf, outLen,
								shouldWrap, lineLen) < 0)
				{
					ret = -1;
					break ;
				}
			}
		}

		/* Save the remaining partial block for next iteration */
		if (lastLen > 0 && !(opts->isDecoding && blocksToWrite < fullBlocks))
			ft_memcpy(lastBlock, temp + fullBlocks * cipher->blockSize, lastLen);
	}
	if (ret == 0)
	{
		if (processLastBlock(ctx, cipher, opts, shouldWrap, lineLen,
							 lastBlock, lastLen) < 0)
			ret = -1;
	}
	if (ret == 0 && !opts->isDecoding && (outLen > 0 || *lineLen > 0))
	{
		if (write(STDOUT_FILENO, "\n", 1) != 1)
			ret = -1;
	}
	return (ret < 0 ? 1 : 0);
}

static int	processCipherFd(int fd, const t_cipher *cipher, t_sslOptions *opts)
{
	void		*ctx;
	uint8_t		key[32];
	uint8_t		iv[16];
	int			shouldWrap;
	int			lineLen;
	int			ret;

	if (!cipher || !opts)
		return (1);
	if (prepareKeyAndIv(opts, cipher, key, iv) != 0)
		return (1);
	ctx = malloc(cipher->ctxSize);
	if (!ctx)
		return (1);
	cipher->init(ctx, key, cipher->keySize,
				 cipher->ivSize > 0 ? iv : NULL,
				 opts->isDecoding ? CIPHER_DECRYPT : CIPHER_ENCRYPT);
	shouldWrap = (!opts->isDecoding && opts->wrapOutput && cipher->supportsWrap);
	lineLen = 0;

	if (cipher->blockSize == 1)
		ret = handleStreamCipher(fd, ctx, cipher, opts, shouldWrap, &lineLen);
	else
		ret = handleBlockCipher(fd, ctx, cipher, opts, shouldWrap, &lineLen);

	cipher->free(ctx);
	free(ctx);
	return (ret);
}


int	executeCipher(t_sslOptions *opts)
{
	const t_cipher	*cipher;
	int				inFd;
	int				outFd;
	int				ret;
	int				originalStdout;

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
	originalStdout = dup(STDOUT_FILENO);
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
		dup2(outFd, STDOUT_FILENO);
		close(outFd);
	}
	ret = processCipherFd(inFd, cipher, opts);
	dup2(originalStdout, STDOUT_FILENO);
	close(originalStdout);
	if (inFd != STDIN_FILENO)
		close(inFd);
	return (ret);
}
