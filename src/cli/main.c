#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../includes/cli/parser.h"
#include "../../hajlib/include/hstring.h"

#define BUFFER_SIZE (16 * 1024)

static void printDigest(const t_hash *hash, uint8_t *digest)
{
	size_t i;
	char hex[3];

	for (i = 0; i < hash->digestSize; i++)
	{
		ft_snprintf(hex, sizeof(hex), "%02x", digest[i]);
		ft_printf("%s", hex);
	}
	ft_printf("\n");
}

static int processFd(int fd, const t_hash *hash, t_sslOptions *opts, const char *filename)
{
	void			*ctx;
	uint8_t			*digest;
	uint8_t			buffer[BUFFER_SIZE];
	ssize_t			bytesRead;
	char			lastChar = 0;
	int				isStdin = (fd == STDIN_FILENO);

	ctx = malloc(hash->ctxSize);
	digest = malloc(hash->digestSize);
	if (!ctx || !digest)
		return (1);

	if (!opts->flagQ) 
	{
		if (opts->flagP && isStdin)
			ft_printf("(\"");
		else if (!isStdin)
		{
			if (!opts->flagR)
			{
				printAlgoName(opts->algo);
				ft_printf(" (%s) = ", filename);
			}
		}
	}

	hash->init(ctx);

	bytesRead = read(fd, buffer, BUFFER_SIZE);

	while (bytesRead > 0) {
		hash->update(ctx, buffer, bytesRead);
		if (opts->flagP && isStdin)
		{
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

	hash->final(digest, ctx);

	if (!opts->flagQ) {
		if (opts->flagP && isStdin)
		{
			ft_printf("\")= ");
			printDigest(hash, digest);
		}
		else if (isStdin && !opts->flagP)
		{
			ft_printf("(stdin)= ");
			printDigest(hash, digest);
		}
		else if (!isStdin && opts->flagR) /* Reverse format: digest + space + "name" */
		{
			for (size_t i = 0; i < hash->digestSize; i++)
				ft_printf("%02x", digest[i]);
			ft_printf(" %s\n", filename);
		}
		else if (!isStdin)
			printDigest(hash, digest); /* Normal format: ALGO (filename) = digest */
	}
	else /* Quiet mode: only the digest */
	{
		if (opts->flagP && isStdin)
			ft_printf("\n"); /* Add newline after digest if -p and input is from stdin */
		printDigest(hash, digest);
	}

	free(ctx);
	free(digest);
	return (0);
}

static int processString(const char *str, const t_hash *hash, t_sslOptions *opts)
{
	void	*ctx;
	uint8_t	*digest;

	ctx = malloc(hash->ctxSize);
	digest = malloc(hash->digestSize);
	if (!ctx || !digest)
		return (1);

	hash->init(ctx);
	hash->update(ctx, (const uint8_t *)str, ft_strlen(str));
	hash->final(digest, ctx);

	if (!opts->flagQ) {
		if (opts->flagR) {
			for (size_t i = 0; i < hash->digestSize; i++)
				ft_printf("%02x", digest[i]);
			ft_printf(" \"%s\"\n", str);
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

/* --------------------- execute --------------------- */

static int executeSsl(t_sslOptions *opts)
{
	const t_hash	*hash;
	size_t			i;
	int				fd;

	hash = getHashByAlgo(opts->algo);
	if (!hash)
		return (1);

	/* -p : read from stdin */
	if (opts->flagP)
		processFd(STDIN_FILENO, hash, opts, NULL);

	/* -s : strings */
	i = 0;
	while (i < opts->stringCount)
	{
		processString(opts->stringInputs[i], hash, opts);
		i++;
	}

	/* files */
	i = 0;
	while (i < opts->fileCount)
	{
		fd = open(opts->fileInputs[i], O_RDONLY);
		if (fd < 0)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: %s: %s: No such file or directory\n",
				getAlgoName(opts->algo),
				opts->fileInputs[i]);
		}
		else
		{
			processFd(fd, hash, opts, opts->fileInputs[i]);
			close(fd);
		}
		i++;
	}

	/* default stdin */
	if (opts->readFromStdin && !opts->flagP)
		processFd(STDIN_FILENO, hash, opts, NULL);

	return (0);
}

int main(int argc, char **argv)
{
	t_sslOptions opts;
	int status;

	if (parseSslArgs(argc, argv, &opts))
		return (1);

	status = executeSsl(&opts);

	freeSslOptions(&opts);
	return (status);
}
