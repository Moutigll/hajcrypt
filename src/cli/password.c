#include <fcntl.h>

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/utils/utils.h"

#include "../../includes/cli/password.h"

/* ---------- Static helpers (password retrieval) ---------- */

static char *readFromFd(int fd)
{
	char	buffer[256];
	char	*password = NULL;
	ssize_t	n;

	ft_memset(buffer, 0, sizeof(buffer));
	n = read(fd, buffer, sizeof(buffer) - 1);
	if (n > 0) {
		if (n > 0 && buffer[n - 1] == '\n')
			buffer[n - 1] = '\0';
		password = ft_strdup(buffer);
		secureZeroMemory(buffer, sizeof(buffer));
	}
	return (password);
}

static char *readFromFile(const char *filename)
{
	int		fd;
	char	*password;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return (NULL);

	password = readFromFd(fd);
	close(fd);
	return (password);
}

static char *readFromEnv(const char *var, char **env)
{
	for (int i = 0; env[i]; i++) {
		if (ft_strncmp(env[i], var, ft_strlen(var)) == 0 && env[i][ft_strlen(var)] == '=') {
			return (ft_strdup(env[i] + ft_strlen(var) + 1));
		}
	}
	ft_dprintf(STDERR_FILENO, "Environment variable '%s' not found\n", var);
	return (NULL);
}

static char *getPasswordSpec(const char *arg, t_passType *type_out)
{
	t_passType	type;
	char		*value = NULL;

	if (!arg) {
		type = PASSWORD_TYPE_INTERACTIVE;
		value = NULL;
	}
	else if (ft_strncmp(arg, "pass:", 5) == 0) {
		type = PASSWORD_TYPE_PASS;
		value = ft_strdup(arg + 5);
	}
	else if (ft_strncmp(arg, "env:", 4) == 0) {
		type = PASSWORD_TYPE_ENV;
		value = ft_strdup(arg + 4);
	}
	else if (ft_strncmp(arg, "file:", 5) == 0) {
		type = PASSWORD_TYPE_FILE;
		value = ft_strdup(arg + 5);
	}
	else if (ft_strncmp(arg, "fd:", 3) == 0) {
		type = PASSWORD_TYPE_FD;
		value = ft_strdup(arg + 3);
	}
	else if (ft_strcmp(arg, "stdin") == 0) {
		type = PASSWORD_TYPE_STDIN;
		value = NULL;
	}
	else if (ft_strchr(arg, ':') && (ft_strchr(arg, ':') - arg) <= 5) {
		ft_dprintf(STDERR_FILENO, "Invalid password argument, missing ':' within the first 5 chars\n");
		return (NULL);
	}
	else {
		type = PASSWORD_TYPE_PASS;
		value = ft_strdup(arg);
	}

	if (type_out)
		*type_out = type;
	return (value);
}

/* ---------- Public password retrieval ---------- */

char *getPassword(const char *arg, char **env)
{
	t_passType	type = PASSWORD_TYPE_INTERACTIVE;
	char		*value;
	char		*password = NULL;

	value = getPasswordSpec(arg, &type);
	if (!value && type != PASSWORD_TYPE_INTERACTIVE && type != PASSWORD_TYPE_STDIN)
		return (NULL);

	switch (type) {
		case PASSWORD_TYPE_PASS:
			password = value;
			break;
		case PASSWORD_TYPE_ENV:
			password = readFromEnv(value, env);
			free(value);
			break;
		case PASSWORD_TYPE_FILE:
			password = readFromFile(value);
			free(value);
			if (!password)
				ft_dprintf(STDERR_FILENO, "Cannot read password from file\n");
			break;
		case PASSWORD_TYPE_FD: {
			int fd = ft_atoi(value);
			password = readFromFd(fd);
			free(value);
			if (!password)
				ft_dprintf(STDERR_FILENO, "Cannot read password from fd %d\n", fd);
			break;
		}
		case PASSWORD_TYPE_STDIN:
			password = readFromFd(STDIN_FILENO);
			if (!password)
				ft_dprintf(STDERR_FILENO, "Cannot read password from stdin\n");
			break;
		case PASSWORD_TYPE_INTERACTIVE:
			password = promptPassword("enter password: ", 1);
			break;
	}
	return (password);
}
