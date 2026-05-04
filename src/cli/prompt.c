#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */

#include "../../includes/utils/random.h"
#include "../../includes/utils/utils.h"

#include "../../includes/hash/sha256.h"
#include "../../includes/kdf/bytesToKey.h"
#include "../../includes/kdf/pbkdf2.h"
#include "../../includes/kdf/bcrypt.h"
#include "../../includes/kdf/argon2.h"

#include "../../includes/cli/password.h"

/* ---------- Static helpers ---------- */

static int readInt(const char *prompt, int min, int max, int defaultValue)
{
	char	buffer[32];
	int		value;

	while (1) {
		ft_printf("%s [%d]: ", prompt, defaultValue);
		if (read(STDIN_FILENO, buffer, sizeof(buffer) - 1) <= 0)
			return (defaultValue);

		buffer[sizeof(buffer) - 1] = '\0';
		size_t len = ft_strlen(buffer);
		if (len > 0 && buffer[len-1] == '\n')
			buffer[len-1] = '\0';

		if (buffer[0] == '\0')
			return (defaultValue);

		value = ft_atoi(buffer);
		if (value >= min && value <= max)
			return (value);

		ft_printf("Invalid input. Please enter a number between %d and %d.\n", min, max);
	}
}

static int promptSalt(uint8_t *salt, size_t *saltLen)
{
	char	buffer[128];
	size_t	hexLen;
	int		i;
	ssize_t	bytesRead;

	ft_printf("Enter salt in hex (or press Enter for random): ");
	bytesRead = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
	if (bytesRead <= 0)
		return (-1);

	buffer[bytesRead] = '\0';
	hexLen = ft_strlen(buffer);
	if (hexLen > 0 && buffer[hexLen-1] == '\n')
		buffer[hexLen-1] = '\0';

	if (buffer[0] == '\0') {
		hajSecRandBytes(salt, 8);
		*saltLen = 8;
		ft_printf("Generated random salt: ");
		for (i = 0; i < 8; i++)
			ft_printf("%02X", salt[i]);
		ft_printf("\n");
		return (0);
	}

	hexLen = ft_strlen(buffer);
	if (hexLen % 2 != 0 || hexLen > 32) {
		ft_printf("Invalid salt length. Must be hex string (max 16 bytes = 32 chars).\n");
		return (-1);
	}

	*saltLen = hexLen / 2;
	for (i = 0; i < (int)hexLen; i += 2) {
		char byteStr[3] = {buffer[i], buffer[i+1], 0};
		salt[i/2] = (uint8_t)ft_strtol(byteStr, NULL, 16);
	}
	return (0);
}

/* ---------- Public functions ---------- */

void cleanupSslOptions(t_sslOptions *opts)
{
	if (opts->keyHex)
		free(opts->keyHex);
	if (opts->ivHex)
		free(opts->ivHex);
	if (opts->saltHex)
		free(opts->saltHex);
	if (opts->password)
	{
		secureZeroMemory(opts->password, ft_strlen(opts->password));
		free(opts->password);
	}
	opts->keyHex = NULL;
	opts->ivHex = NULL;
	opts->saltHex = NULL;
	opts->password = NULL;
}

char *promptPassword(const char *promptMsg)
{
	char	*pass1;
	char	*pass2;
	size_t	len1;
	size_t	len2;

	while (1) {
		pass1 = getpass(promptMsg);
		if (!pass1)
			return (NULL);

		len1 = ft_strlen(pass1);
		if (len1 == 0) {
			ft_printf("Password cannot be empty.\n");
			continue;
		}

		pass2 = getpass("confirm password: ");
		if (!pass2) {
			return (NULL);
		}

		len2 = ft_strlen(pass2);
		if (len1 == len2 && ft_memcmp(pass1, pass2, len1) == 0) {
			return (ft_strdup(pass1));
		}

		ft_printf("Passwords don't match. Try again.\n");
		secureZeroMemory(pass1, len1);
		secureZeroMemory(pass2, len2);
	}
}

t_kdfChoice promptKdfChoice(void)
{
	char	buffer[16];
	int		choice;
	ssize_t	bytesRead;

	ft_printf("\nSelect key derivation function:\n");
	ft_printf("1) EVP_BytesToKey (OpenSSL legacy - default)\n");
	ft_printf("2) PBKDF2 (RFC 2898)\n");
	ft_printf("3) bcrypt\n");
	ft_printf("4) Argon2d\n");
	ft_printf("5) Argon2i\n");
	ft_printf("6) Argon2id\n");
	ft_printf("Choice [1]: ");

	bytesRead = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
	if (bytesRead <= 0)
		return (KDF_BYTESTOKEY);

	buffer[bytesRead] = '\0';
	if (buffer[0] == '\n')
		return (KDF_BYTESTOKEY);

	choice = ft_atoi(buffer);
	if (choice >= 1 && choice <= 6)
		return ((t_kdfChoice)(choice - 1));
	
	ft_printf("Invalid choice, using EVP_BytesToKey.\n");
	return (KDF_BYTESTOKEY);
}

void promptArgon2Params(t_kdfParams *params)
{
	ft_printf("\n--- Argon2 parameters ---\n");
	params->iterations = readInt("Iterations (t)", 1, 100, 3);
	params->memory = readInt("Memory (m) in KiB", 8, 1048576, 65536);
	params->parallelism = readInt("Parallelism (p)", 1, 255, 4);
}

int generateIvFromPrompt(uint8_t *iv, size_t ivLen)
{
	char	buffer[128];
	size_t	hexLen;
	int		i;
	ssize_t	bytesRead;

	if (ivLen == 0)
		return (0);

	ft_printf("\nEnter IV in hex (or press Enter for zeros): ");
	bytesRead = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
	if (bytesRead <= 0)
		return (-1);

	buffer[bytesRead] = '\0';
	hexLen = ft_strlen(buffer);
	if (hexLen > 0 && buffer[hexLen-1] == '\n')
		buffer[hexLen-1] = '\0';

	if (buffer[0] == '\0') {
		ft_memset(iv, 0, ivLen);
		return (0);
	}

	hexLen = ft_strlen(buffer);
	if (hexLen != ivLen * 2) {
		ft_printf("IV must be exactly %zu bytes (%zu hex chars)\n", ivLen, ivLen * 2);
		return (-1);
	}

	for (i = 0; i < (int)hexLen; i += 2) {
		char byteStr[3] = {buffer[i], buffer[i+1], 0};
		iv[i/2] = (uint8_t)ft_strtol(byteStr, NULL, 16);
	}
	return (0);
}

int generateKeyFromPrompt(t_kdfParams *params, uint8_t *key, size_t keyLen)
{
	uint8_t	derived[64];
	int		ret;

	switch (params->choice) {
		case KDF_BYTESTOKEY: {
			uint8_t iv[8];
			ret = pbkdfBytesToKeyExtended(&g_sha256Hash,
										 params->password,
										 ft_strlen(params->password),
										 params->salt,
										 keyLen,
										 key,
										 iv);
			return (ret == 0 ? 0 : -1);
		}

		case KDF_PBKDF2: {
			t_pbkdf2Ctx ctx;
			pbkdf2Init(&ctx,
					  &g_sha256Hash,
					  (const uint8_t*)params->password,
					  ft_strlen(params->password),
					  params->salt,
					  params->saltLen,
					  params->iterations);
			ret = pbkdf2Derive(&ctx, key, keyLen);
			return (ret == 0 ? 0 : -1);
		}

		case KDF_BCRYPT:
			ret = bcryptHash(params->password,
						   params->salt,
						   params->iterations,
						   (char*)derived);
			if (ret != 0)
				return (-1);
			ft_memcpy(key, derived, keyLen < 24 ? keyLen : 24);
			return (0);

		case KDF_ARGON2D:
		case KDF_ARGON2I:
		case KDF_ARGON2ID: {
			t_argon2Type type;
			t_argon2Ctx ctx;

			if (params->choice == KDF_ARGON2D)
				type = ARGON2_D;
			else if (params->choice == KDF_ARGON2I)
				type = ARGON2_I;
			else
				type = ARGON2_ID;

			argon2Init(&ctx,
					  (const uint8_t*)params->password,
					  ft_strlen(params->password),
					  params->salt,
					  params->saltLen,
					  params->memory,
					  params->iterations,
					  params->parallelism,
					  type);
			ctx.outputLen = keyLen;
			ret = argon2Hash(&ctx, key, keyLen);
			argon2Free(&ctx);
			return (ret == 0 ? 0 : -1);
		}

		default:
			return (-1);
	}
}

int promptForCipherParams(t_sslOptions *opts)
{
	t_kdfParams	 params;
	const t_cipher *cipher = getCipherByAlgo(opts->algo);
	int			 i;
	
	if (!cipher) return (-1);
	
	ft_printf("\n=== Missing parameters for %s ===\n", cipher->name);

	ft_bzero(&params, sizeof(params));

	params.password = promptPassword("enter encryption password: ");
	if (!params.password) return (-1);

	if (promptSalt(params.salt, &params.saltLen) != 0) {
		free(params.password);
		return (-1);
	}

	params.choice = promptKdfChoice();

	switch (params.choice) {
		case KDF_PBKDF2:
			params.iterations = readInt("Iterations", 1, 1000000, 10000);
			break;
		case KDF_BCRYPT:
			params.iterations = readInt("Cost factor", 4, 31, 10);
			break;
		case KDF_ARGON2D:
		case KDF_ARGON2I:
		case KDF_ARGON2ID:
			promptArgon2Params(&params);
			break;
		default:
			break;
	}

	ft_printf("\nsalt=");
	for (i = 0; i < (int)params.saltLen; i++)
		ft_printf("%02X", params.salt[i]);

	if (cipher->ivSize > 0) {
		uint8_t iv[16];
		if (generateIvFromPrompt(iv, cipher->ivSize) != 0) {
			free(params.password);
			return (-1);
		}
		ft_printf("\niv=");
		for (i = 0; i < (int)cipher->ivSize; i++)
			ft_printf("%02X", iv[i]);

		opts->ivHex = malloc(cipher->ivSize * 2 + 1);
		if (opts->ivHex) {
			for (i = 0; i < (int)cipher->ivSize; i++)
				ft_snprintf(opts->ivHex + i*2, 3, "%02X", iv[i]);
			opts->ivHex[cipher->ivSize * 2] = '\0';
		}
	}
	ft_printf("\n");

	opts->password = params.password;
	opts->saltHex = malloc(params.saltLen * 2 + 1);
	if (opts->saltHex) {
		for (i = 0; i < (int)params.saltLen; i++)
			ft_snprintf(opts->saltHex + i*2, 3, "%02X", params.salt[i]);
		opts->saltHex[params.saltLen * 2] = '\0';
	}
	
	opts->kdfChoice = params.choice;
	opts->kdfIterations = params.iterations;
	opts->kdfMemory = params.memory;
	opts->kdfParallelism = params.parallelism;

	opts->keyHex = NULL;
	
	return (0);
}
