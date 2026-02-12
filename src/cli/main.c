#include "../../includes/cli/parser.h"

int	main(int argc, char **argv)
{
	t_sslOptions	opts;
	int				status;

	status = 0;
	if (parseSslArgs(argc, argv, &opts))
		return (1);
	/* status = executeSsl(&opts);
	freeSslOptions(&opts); */
	return (status);
}
