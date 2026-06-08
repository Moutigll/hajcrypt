#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/hash/hmac.h"
#include "../../includes/cli/parser.h"
#include <unistd.h>

#define BUFFER_SIZE (16 * 1024)

static void	printDigest(const t_hash *hash, uint8_t *digest, int binaryOutput)
{
	if (binaryOutput) {
		write(STDOUT_FILENO, digest, hash->digestSize);
		return;
	}

	for (size_t i = 0; i < hash->digestSize; i++)
		ft_printf("%02x", digest[i]);
	ft_printf("\n");
}

static int	allCtxDigest(const t_hash *hash, void **ctx, uint8_t **digest, int use_hmac)
{
	size_t ctx_size = hash->ctxSize;
	if (use_hmac && ctx_size < sizeof(t_hmacCtx))
		ctx_size = sizeof(t_hmacCtx);

	*ctx = malloc(ctx_size);
	*digest = malloc(hash->digestSize);

	if (!*ctx || !*digest) {
		free(*ctx);
		free(*digest);
		return (1);
	}
	return (0);
}

int			processFd(int fd, const t_hash *hash, t_sslOptions *opts, const char *filename)
{
	void	*ctx;
	uint8_t	*digest;
	uint8_t	buffer[BUFFER_SIZE];
	ssize_t	bytesRead;
	char	lastChar = 0;

	if (allCtxDigest(hash, &ctx, &digest, opts->flagK))
		return (1);


	if (!opts->flagQ) {
		if (opts->flagP && fd == STDIN_FILENO)
			ft_dprintf(STDERR_FILENO, "(\"");
		else if (fd != STDIN_FILENO) {
			if (!opts->flagR) {
				printAlgoName(opts->algo);
				ft_dprintf(STDERR_FILENO, " (%s) = ", filename);
			}
		}
	}

	if (opts->flagK) {
		t_hmacCtx *hctx = (t_hmacCtx *)ctx;
		hash->hmacInit(hctx, (const uint8_t *)opts->hmacKey, ft_strlen(opts->hmacKey));
	} else
		hash->init(ctx);

	bytesRead = read(fd, buffer, BUFFER_SIZE);
	while (bytesRead > 0) {
		if (opts->flagK) {
			t_hmacCtx *hctx = (t_hmacCtx *)ctx;
			hctx->algo->update(hctx->innerCtx, buffer, bytesRead);
		} else
			hash->update(ctx, buffer, bytesRead);

		if (opts->flagP && fd == STDIN_FILENO) {
			if (lastChar == '\n')
				write(STDOUT_FILENO, "\n", 1);
			lastChar = buffer[bytesRead - 1];
			if (lastChar == '\n')
				write(STDOUT_FILENO, buffer, bytesRead - 1);
			else
				write(STDOUT_FILENO, buffer, bytesRead);
		}

		bytesRead = read(fd, buffer, BUFFER_SIZE);
	}

	if (bytesRead < 0) {
		free(ctx);
		free(digest);
		return (1);
	}

	if (opts->flagK)
		hmacFinal((t_hmacCtx *)ctx, digest);
	else
		hash->final(digest, ctx);

	/* Affichage du résultat */
	if (!opts->flagQ) {
		if (opts->flagP && fd == STDIN_FILENO) {
			ft_dprintf(STDERR_FILENO, "\")= ");
			printDigest(hash, digest, opts->flagB);
		} else if (fd == STDIN_FILENO && !opts->flagP) {
			ft_dprintf(STDERR_FILENO, "(stdin)= ");
			printDigest(hash, digest, opts->flagB);
		} else if (fd != STDIN_FILENO && opts->flagR) {
			for (size_t i = 0; i < hash->digestSize; i++)
				ft_dprintf(STDERR_FILENO, "%02x", digest[i]);
			ft_dprintf(STDERR_FILENO, " %s\n", filename);
		} else if (fd != STDIN_FILENO)
			printDigest(hash, digest, opts->flagB);
	} else {
		if (opts->flagP && fd == STDIN_FILENO)
			ft_dprintf(STDERR_FILENO, "\n");
		printDigest(hash, digest, opts->flagB);
	}

	free(ctx);
	free(digest);
	return (0);
}

int			processString(const char *str, const t_hash *hash, t_sslOptions *opts)
{
	void	*ctx;
	uint8_t	*digest;

	if (allCtxDigest(hash, &ctx, &digest, opts->flagK))
		return (1);

	if (opts->flagK) {
		t_hmacCtx *hctx = (t_hmacCtx *)ctx;
		hash->hmacInit(hctx, (const uint8_t *)opts->hmacKey, ft_strlen(opts->hmacKey));
		hctx->algo->update(hctx->innerCtx, (const uint8_t *)str, ft_strlen(str));
		hmacFinal(hctx, digest);
	} else {
		hash->init(ctx);
		hash->update(ctx, (const uint8_t *)str, ft_strlen(str));
		hash->final(digest, ctx);
	}

	if (!opts->flagQ) {
		if (opts->flagR) {
			printDigest(hash, digest, opts->flagB);
			ft_dprintf(STDERR_FILENO, " \"%s\"\n", str);
		} else {
			printAlgoName(opts->algo);
			ft_dprintf(STDERR_FILENO, " (\"%s\") = ", str);
			printDigest(hash, digest, opts->flagB);
		}
	} else
		printDigest(hash, digest, opts->flagB);

	free(ctx);
	free(digest);
	return (0);
}
