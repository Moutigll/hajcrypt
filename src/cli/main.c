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

static int processFd(int fd, const t_hash *hash)
{
	void			*ctx;
	uint8_t			*digest;
	uint8_t			buffer[BUFFER_SIZE];
	ssize_t			bytesRead;

	ctx = malloc(hash->ctxSize);
	digest = malloc(hash->digestSize);
	if (!ctx || !digest)
		return (1);

	hash->init(ctx);

	while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0)
		hash->update(ctx, buffer, bytesRead);

	if (bytesRead < 0)
		return (1);

	hash->final(digest, ctx);
	printDigest(hash, digest);

	free(ctx);
	free(digest);
	return (0);
}

static int processString(const char *str, const t_hash *hash)
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
		processFd(STDIN_FILENO, hash);

	/* -s : strings */
	i = 0;
	while (i < opts->stringCount)
	{
		processString(opts->stringInputs[i], hash);
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
				"ft_ssl: %s: No such file or directory\n",
				opts->fileInputs[i]);
		}
		else
		{
			processFd(fd, hash);
			close(fd);
		}
		i++;
	}

	/* default stdin */
	if (opts->readFromStdin && !opts->flagP)
		processFd(STDIN_FILENO, hash);

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
