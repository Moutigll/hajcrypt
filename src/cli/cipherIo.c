#include <fcntl.h>
#include <unistd.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/cli/parser.h"
#include "../../includes/kdf/kdf.h"

#define WRAP_LIMIT 64

int	writeWrapped(int fd, const uint8_t *data, size_t len, int *lineLen)
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

int	writeOutput(int fd, const uint8_t *data, size_t len,
				int shouldWrap, int *lineLen)
{
	if (shouldWrap)
		return (writeWrapped(fd, data, len, lineLen));
	if (write(fd, data, len) != (ssize_t)len)
		return (-1);
	return (0);
}


int	prepareKeyAndIv(t_sslOptions *opts, const t_cipher *cipher,
					uint8_t *key, uint8_t *iv)
{
	size_t	keyLen;
	size_t	ivLen;
	int		converted;

	keyLen = cipher->keySize;
	ivLen = cipher->ivSize;
	ft_bzero(key, keyLen);
	if (ivLen > 0)
		ft_bzero(iv, ivLen);
	if (!opts->keyHex)
		return (0);
	converted = pbkdfHexToBytes(opts->keyHex, key, keyLen);
	if (converted < 0)
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: invalid key hex format\n");
		return (-1);
	}
	if (opts->ivHex && ivLen > 0)
	{
		converted = pbkdfHexToBytes(opts->ivHex, iv, ivLen);
		if (converted < 0)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: invalid IV hex format\n");
			return (-1);
		}
	}
	return (0);
}

int	openInputFile(const char *filename, const char *cipherName)
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


int	openOutputFile(const char *filename, const char *cipherName)
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
