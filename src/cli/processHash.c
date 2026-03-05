#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/hash/hmac.h"
#include "../../includes/cli/parser.h"

#define BUFFER_SIZE (16 * 1024)

static void	printDigest(const t_hash *hash, uint8_t *digest)
{
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
			ft_printf("(\"");
		else if (fd != STDIN_FILENO) {
			if (!opts->flagR) {
				printAlgoName(opts->algo);
				ft_printf(" (%s) = ", filename);
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
			hctx->algo->hashUpdate(hctx->innerCtx, buffer, bytesRead);
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
			ft_printf("\")= ");
			printDigest(hash, digest);
		} else if (fd == STDIN_FILENO && !opts->flagP) {
			ft_printf("(stdin)= ");
			printDigest(hash, digest);
		} else if (fd != STDIN_FILENO && opts->flagR) {
			for (size_t i = 0; i < hash->digestSize; i++)
				ft_printf("%02x", digest[i]);
			ft_printf(" %s\n", filename);
		} else if (fd != STDIN_FILENO)
			printDigest(hash, digest);
	} else {
		if (opts->flagP && fd == STDIN_FILENO)
			ft_printf("\n");
		printDigest(hash, digest);
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
		hctx->algo->hashUpdate(hctx->innerCtx, (const uint8_t *)str, ft_strlen(str));
		hmacFinal(hctx, digest);
	} else {
		hash->init(ctx);
		hash->update(ctx, (const uint8_t *)str, ft_strlen(str));
		hash->final(digest, ctx);
	}

	if (!opts->flagQ) {
		if (opts->flagR) {
			for (size_t i = 0; i < hash->digestSize; i++)
				ft_printf("%02x", digest[i]);
			ft_printf(" \"%s\"\n", str);   /* guillemets pour les chaînes en mode -r */
		} else {
			printAlgoName(opts->algo);
			ft_printf(" (\"%s\") = ", str);
			printDigest(hash, digest);
		}
	} else
		printDigest(hash, digest);

	free(ctx);
	free(digest);
	return (0);
}
