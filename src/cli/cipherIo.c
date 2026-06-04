#include <fcntl.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"
#include "../../includes/cli/password.h"
#include "../../includes/utils/random.h"
#include "../../includes/kdf/bytesToKey.h"
#include "../../includes/hash/sha/sha256.h"

#include "../../includes/cli/algoHandling.h"

#define WRAP_LIMIT 64

/* ---------- Write helpers ---------- */

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

int	writeOutput(int				fd,
				const uint8_t	*data,
				size_t 			len,
				int				shouldWrap,
				int				*lineLen)
{
	if (shouldWrap)
		return (writeWrapped(fd, data, len, lineLen));
	if (write(fd, data, len) != (ssize_t)len)
		return (-1);
	return (0);
}

/* ---------- File helpers ---------- */

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

/* ---------- Key/IV preparation ---------- */

int prepareKeyAndIv(t_sslOptions	*opts,
					const t_cipher	*cipher,
					uint8_t			*key,
					uint8_t			*iv)
{
	size_t	keyLen = cipher->keySize;
	size_t	ivLen  = cipher->ivSize;

	ft_bzero(key, keyLen);
	if (ivLen > 0)
		ft_bzero(iv, ivLen);

	/* Case 1 : key provided in hex (IV optional) */
	if (opts->keyHex)
	{
		if (pbkdfHexToBytes(opts->keyHex, key, keyLen) < 0)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: invalid key hex\n");
			return (-1);
		}
		/* IV hex optional, if provided it overrides the derived IV or zeros */
		if (opts->ivHex && ivLen > 0)
		{
			if (pbkdfHexToBytes(opts->ivHex, iv, ivLen) < 0)
			{
				ft_dprintf(STDERR_FILENO, "ft_ssl: invalid IV hex\n");
				return (-1);
			}
		}
		return (0);
	}

	/* Case 2 : password provided (with or without salt) */
	if (opts->password)
	{
		uint8_t salt[8];

		if (opts->saltHex)
		{
			if (pbkdfHexToBytes(opts->saltHex, salt, 8) < 0)
			{
				ft_dprintf(STDERR_FILENO, "ft_ssl: invalid salt hex\n");
				return (-1);
			}
		}
		else
		{
			/* No salt provided, generate a random one and display it (for repeatability) */
			hajSecRandBytes(salt, 8);
			ft_dprintf(STDERR_FILENO, "salt=");
			for (int i = 0; i < 8; i++)
				ft_dprintf(STDERR_FILENO, "%02X", salt[i]);
			ft_dprintf(STDERR_FILENO, "\n");
			opts->saltHex = malloc(17);
			if (opts->saltHex)
			{
				for (int i = 0; i < 8; i++)
					ft_snprintf(opts->saltHex + i*2, 3, "%02X", salt[i]);
				opts->saltHex[16] = '\0';
			}
		}

		/* Derive with bytesToKey by default for compatibility with OpenSSL, but allow other KDFs if specified */
		if (pbkdfBytesToKeyExtended(&g_sha256Hash,
									opts->password,
									ft_strlen(opts->password),
									salt, keyLen, key, iv) < 0)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: key derivation failed\n");
			return (-1);
		}

		/* IV hex optional, if provided it overrides the derived IV or zeros */
		if (opts->ivHex && ivLen > 0)
		{
			if (pbkdfHexToBytes(opts->ivHex, iv, ivLen) < 0)
			{
				ft_dprintf(STDERR_FILENO, "ft_ssl: invalid IV hex\n");
				return (-1);
			}
		}
		return (0);
	}

	/* Case 3 : interactive mode (no key or password provided) */
	if (promptForCipherParams(opts) != 0)
	{
		cleanupSslOptions(opts);
		return (-1);
	}

	/* Now we derive the key from the stored parameters */
	if (deriveKeyFromParams(opts, key, keyLen, iv) != 0) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: key derivation failed\n");
		cleanupSslOptions(opts);
		return (-1);
	}

	/* If IV hex provided, override the derived IV */
	if (ivLen > 0 && opts->ivHex)
 	{
 		if (pbkdfHexToBytes(opts->ivHex, iv, ivLen) < 0)
 		{
 			ft_dprintf(STDERR_FILENO, "ft_ssl: invalid IV hex\n");
			cleanupSslOptions(opts);
			return (-1);
 		}
 	}

	/* Display the derived key */
	ft_dprintf(STDERR_FILENO, "key=");
	for (size_t i = 0; i < keyLen; i++)
		ft_dprintf(STDERR_FILENO, "%02X", key[i]);
	ft_dprintf(STDERR_FILENO, "\n\n");

	return (0);
}
