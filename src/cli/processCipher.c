#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/cipher/base64.h"
#include "../../includes/cli/parser.h"
#include "../../includes/cli/algoHandling.h"

/* ---------- Stream cipher processing ---------- */

static int processStreamLoop(t_cipherCtx *c, int fd)
{
	uint8_t	inBuf[CIPHER_BUFFER_SIZE];
	uint8_t	outBuf[CIPHER_BUFFER_SIZE * 2];
	ssize_t	bytesRead;
	size_t	outLen;
	int		ret = 0;

	while (1)
	{
		bytesRead = read(fd, inBuf, sizeof(inBuf));
		if (bytesRead <= 0)
			break;
		c->cipher->update(c->ctx, inBuf, bytesRead, outBuf, &outLen);
		if (outLen > 0 && writeOutput(c->outFd, outBuf, outLen,
									   c->shouldWrap, &c->lineLen) < 0)
		{
			ret = -1;
			break;
		}
	}
	if (ret == 0)
	{
		c->cipher->final(c->ctx, outBuf, &outLen);
		if (outLen > 0 && writeOutput(c->outFd, outBuf, outLen,
									   c->shouldWrap, &c->lineLen) < 0)
			ret = -1;
	}
	return (ret);
}

static int handleStreamCipher(t_cipherCtx *c, int fd)
{
	int	ret = processStreamLoop(c, fd);
	if (ret == 0 && !c->opts->isDecoding && c->outFd == STDOUT_FILENO)
	{
		if (c->lineLen > 0 && write(c->outFd, "\n", 1) != 1)
			ret = -1;
	}
	return (ret < 0 ? 1 : 0);
}

/* ---------- Block cipher helpers ---------- */

static int processDecryptLast(t_cipherCtx *c, t_blockData *b, uint8_t *outBuf)
{
	size_t	outLen, unpaddedLen;

	if (b->lastLen != c->cipher->blockSize)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: bad decrypt\n");
		return (-1);
	}
	c->cipher->update(c->ctx, b->lastBlock, c->cipher->blockSize, outBuf, &outLen);
	if (c->cipher->unpad && outLen > 0)
	{
		if (c->cipher->unpad(outBuf, &unpaddedLen, c->cipher->blockSize) != 0)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: bad decrypt\n");
			return (-1);
		}
		if (unpaddedLen > 0 && writeOutput(c->outFd, outBuf,
										   unpaddedLen, c->shouldWrap, &c->lineLen) < 0)
			return (-1);
	}
	return (0);
}

static int processEncryptLast(t_cipherCtx *c, t_blockData *b, uint8_t *outBuf)
{
	uint8_t	block[32];
	size_t	outLen;

	if (b->lastLen > 0)
		ft_memcpy(block, b->lastBlock, b->lastLen);
	if (c->cipher->pad)
	{
		c->cipher->pad(block, b->lastLen, c->cipher->blockSize);
		c->cipher->update(c->ctx, block, c->cipher->blockSize, outBuf, &outLen);
		if (outLen > 0 && writeOutput(c->outFd, outBuf,
									  outLen, c->shouldWrap, &c->lineLen) < 0)
			return (-1);
	}
	return (0);
}

static int processBlockLast(t_cipherCtx *c, t_blockData *b)
{
	uint8_t outBuf[CIPHER_BUFFER_SIZE * 2];
	if (c->opts->isDecoding)
		return (processDecryptLast(c, b, outBuf));
	else
		return (processEncryptLast(c, b, outBuf));
}

static int processBlockLoop(t_cipherCtx *c, t_blockData *b, int fd, uint8_t *outBuf)
{
	uint8_t	inBuf[CIPHER_BUFFER_SIZE];
	ssize_t	bytesRead;
	size_t	outLen, total, fullBlocks, blocksToWrite;
	uint8_t	*temp;

	while (1)
	{
		bytesRead = read(fd, inBuf, sizeof(inBuf));
		if (bytesRead <= 0)
			break;
		total = b->lastLen + bytesRead;
		temp = b->tempBuffer;
		if (b->lastLen > 0)
		{
			ft_memcpy(temp, b->lastBlock, b->lastLen);
			ft_memcpy(temp + b->lastLen, inBuf, bytesRead);
		}
		else
			ft_memcpy(temp, inBuf, bytesRead);
		fullBlocks = total / c->cipher->blockSize;
		b->lastLen = total % c->cipher->blockSize;
		blocksToWrite = fullBlocks;
		if (c->opts->isDecoding && bytesRead > 0 && fullBlocks > 0)
		{
			blocksToWrite = fullBlocks - 1;
			ft_memcpy(b->lastBlock, temp + blocksToWrite * c->cipher->blockSize,
					  c->cipher->blockSize);
			b->lastLen = c->cipher->blockSize;
		}
		if (blocksToWrite > 0)
		{
			c->cipher->update(c->ctx, temp, blocksToWrite * c->cipher->blockSize,
							  outBuf, &outLen);
			if (outLen > 0 && writeOutput(c->outFd, outBuf, outLen,
										  c->shouldWrap, &c->lineLen) < 0)
				return (-1);
		}
		if (b->lastLen > 0 && !(c->opts->isDecoding && blocksToWrite < fullBlocks))
			ft_memcpy(b->lastBlock, temp + fullBlocks * c->cipher->blockSize, b->lastLen);
	}
	return (0);
}

static int handleBlockCipher(t_cipherCtx *c, int fd)
{
	t_blockData b;
	uint8_t outBuf[CIPHER_BUFFER_SIZE * 2];
	int ret;

	ft_bzero(&b, sizeof(b));
	ret = processBlockLoop(c, &b, fd, outBuf);
	if (ret == 0)
		ret = processBlockLast(c, &b);
	if (ret == 0 && !c->opts->isDecoding && c->outFd == STDOUT_FILENO)
	{
		if (c->lineLen > 0 && write(c->outFd, "\n", 1) != 1)
			ret = -1;
	}
	return (ret < 0 ? 1 : 0);
}

/* ---------- Base64 handling ---------- */

static int processBase64(int fd, int outFd, t_sslOptions *opts)
{
	t_base64Ctx b64Ctx;
	t_cipherCtx c;

	c.ctx = &b64Ctx;
	c.cipher = &g_base64Cipher;
	c.opts = opts;
	c.outFd = outFd;
	c.shouldWrap = (!opts->isDecoding && opts->wrapOutput);
	c.lineLen = 0;
	base64Init(&b64Ctx, NULL, 0, NULL,
			   opts->isDecoding ? CIPHER_DECRYPT : CIPHER_ENCRYPT);
	return (handleStreamCipher(&c, fd));
}

/* ---------- Context initialization ---------- */

static int initCipherCtx(t_cipherCtx *c, const t_cipher *cipher,
						 t_sslOptions *opts, int outFd)
{
	uint8_t key[32];
	uint8_t iv[16];
	int ret;

	if (prepareKeyAndIv(opts, cipher, key, iv) != 0)
		return (1);
	c->ctx = malloc(cipher->ctxSize);
	if (!c->ctx)
		return (1);
	c->cipher = cipher;
	c->opts = opts;
	c->outFd = outFd;
	c->shouldWrap = (!opts->isDecoding && opts->wrapOutput && cipher->supportsWrap);
	c->lineLen = 0;
	ret = cipher->init(c->ctx, key, cipher->keySize,
					   cipher->ivSize > 0 ? iv : NULL,
					   opts->isDecoding ? CIPHER_DECRYPT : CIPHER_ENCRYPT);
	if (ret != 0)
	{
		free(c->ctx);
		return (1);
	}
	return (0);
}

/* ---------- Base64 with cipher using pipe ---------- */

static int processBase64WithCipher(int inFd, int outFd, const t_cipher *cipher, t_sslOptions *opts)
{
	int		pipeFd[2];
	pid_t	pid;
	int		ret;
	int		status;

	if (pipe(pipeFd) < 0)
		return (1);

	pid = fork();
	if (pid == -1)
	{
		close(pipeFd[0]);
		close(pipeFd[1]);
		return (1);
	}

	if (pid == 0)
	{
		close(pipeFd[0]); /* Close read end in child */

		if (opts->isDecoding)
			ret = processBase64(inFd, pipeFd[1], opts);
		else
		{
			t_cipherCtx ctx;

			if (initCipherCtx(&ctx, cipher, opts, pipeFd[1]) != 0)
				exit(1);

			if (cipher->blockSize == 1)
				ret = handleStreamCipher(&ctx, inFd);
			else
				ret = handleBlockCipher(&ctx, inFd);

			ctx.cipher->free(ctx.ctx);
			free(ctx.ctx);
		}

		close(pipeFd[1]);
		exit(ret);
	}
	else
	{
		close(pipeFd[1]); /* Close write end in parent */

		if (opts->isDecoding)
		{
			t_cipherCtx ctx;

			if (initCipherCtx(&ctx, cipher, opts, outFd) != 0)
			{
				close(pipeFd[0]);
				wait(&status);
				return (1);
			}

			if (cipher->blockSize == 1)
				ret = handleStreamCipher(&ctx, pipeFd[0]);
			else
				ret = handleBlockCipher(&ctx, pipeFd[0]);

			ctx.cipher->free(ctx.ctx);
			free(ctx.ctx);
		}
		else
			ret = processBase64(pipeFd[0], outFd, opts);

		close(pipeFd[0]);
		wait(&status);
		return (ret);
	}
}

/* ---------- Main cipher dispatcher ---------- */

static int processCipherFd(int fd, int outFd, const t_cipher *cipher, t_sslOptions *opts)
{
	if (opts->algo == ALGO_BASE64)
		return (processBase64(fd, outFd, opts));

	if (opts->useBase64)
		return (processBase64WithCipher(fd, outFd, cipher, opts));
	else
	{
		t_cipherCtx	c;
		int			ret;
		if (initCipherCtx(&c, cipher, opts, outFd) != 0)
			return 1;
		if (c.cipher->blockSize == 1)
			ret = (handleStreamCipher(&c, fd));
		else
			ret = (handleBlockCipher(&c, fd));
		c.cipher->free(c.ctx);
		free(c.ctx);
		return (ret);
	}
}

/* ---------- Public API ---------- */

int executeCipher(t_sslOptions *opts)
{
	const t_cipher	*cipher;
	int				inFd = STDIN_FILENO;
	int				outFd = STDOUT_FILENO;
	int				ret;

	if (!opts || opts->cmdType != CMD_CIPHER)
		return (0);
	cipher = getCipherByAlgo(opts->algo);
	if (!cipher)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: unknown cipher algorithm\n");
		return (1);
	}
	if (opts->inputFile && (inFd = openInputFile(opts->inputFile, cipher->name)) < 0)
		return (1);
	if (opts->outputFile)
	{
		outFd = openOutputFile(opts->outputFile, cipher->name);
		if (outFd < 0)
		{
			if (inFd != STDIN_FILENO)
				close(inFd);
			return (1);
		}
	}
	ret = processCipherFd(inFd, outFd, cipher, opts);
	if (inFd != STDIN_FILENO)
		close(inFd);
	if (outFd != STDOUT_FILENO)
		close(outFd);
	return (ret);
}
