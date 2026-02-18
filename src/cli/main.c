#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../includes/cli/parser.h"

#define BUFFER_SIZE 16 * 1024

static int executeSsl(t_sslOptions *opts)
{
	const t_hash	*hash;
	void			*ctx;
	uint8_t			*digest;
	unsigned char	buffer[BUFFER_SIZE];
	ssize_t			bytesRead;

	hash = getHashByAlgo(opts->algo);
	if (!hash)
		return (1);

	ctx = malloc(hash->ctxSize);
	digest = malloc(hash->digestSize);
	if (!ctx || !digest)
		return (1);

	hash->init(ctx);

	bytesRead = read(STDIN_FILENO, buffer, BUFFER_SIZE);
	while (bytesRead > 0)
	{
		hash->update(ctx, buffer, bytesRead);
		bytesRead = read(STDIN_FILENO, buffer, BUFFER_SIZE);
	}

	if (bytesRead < 0)
		return (1);

	hash->final(digest, ctx);

	/* print digest */
	ft_printf("\n");
	for (size_t i = 0; i < hash->digestSize; i++)
	{
		char hex[3]; // 2 caractères pour le hex + '\0'
		ft_snprintf(hex, sizeof(hex), "%02x", digest[i]);
		ft_printf("%s", hex);
	}
	ft_printf("\n");

	free(ctx);
	free(digest);

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
