#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../hajlib/include/hchar.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/consts/consts.h"

const static t_header headers[] = {
	{ "md5", generateMd5Header },
};



static void buildPath(char *dst, const char *dir, const char *file)
{
	char	fileHeader[256];
	size_t len = ft_strlen(dir);

	ft_strlcpy(dst, dir, 1024);

	if (dir[len - 1] != '/')
		dst[len++] = '/';

	ft_strlcpy(fileHeader, file, 256);
	ft_strlcat(fileHeader, ".h", 256);
	ft_strlcpy(dst + len, fileHeader, 1024 - len);
}

static int openHeader(const char *dir, const char *file, const char * upperFile)
{
	char	path[1024];
	int		fd;

	buildPath(path, dir, file);
	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		ft_dprintf(2, "Error: could not open file '%s' for writing\n", path);
		return (-1);
	}

	ft_dprintf(fd, "#ifndef HAJCRYPT_%s_CONSTS_H\n#define HAJCRYPT_%s_CONSTS_H\n\n", upperFile, upperFile);
	return fd;
}



int main(void)
{
	const char		*outdir = "includes/consts";
	char			upperFile[256];
	unsigned long	i;
	int				j;


	for (i = 0; i < sizeof(headers)/sizeof(headers[0]); i++)
	{
		j = 0;
		while (headers[i].name[j])
		{
			upperFile[j] = ft_toupper(headers[i].name[j]);
			j++;
		}
		upperFile[j] = '\0';

		int fd = openHeader(outdir, headers[i].name, upperFile);
		if (fd < 0)
			return (1);

		if (headers[i].generate(fd) != 0)
		{
			close(fd);
			ft_dprintf(2, "Error: failed to generate header %s\n", headers[i].name);
			return (1);
		}

		ft_dprintf(fd, "\n#endif /* HAJCRYPT_%s_CONSTS_H */\n", upperFile);
		close(fd);
	}

	return (0);
}
