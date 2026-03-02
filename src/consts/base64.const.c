#include "../../hajlib/include/hprintf.h"

#include "../../includes/consts/consts.h"

int generateBase64Header(int fd)
{
	ft_dprintf(fd, "#include <stdint.h>\n\n");

	/* Encoding table */
	ft_dprintf(fd, "static const char g_base64_enc[64] = {\n");
	ft_dprintf(fd, "\t'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',\n");
	ft_dprintf(fd, "\t'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',\n");
	ft_dprintf(fd, "\t'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',\n");
	ft_dprintf(fd, "\t'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'\n");
	ft_dprintf(fd, "};\n\n");

	/* Decoding table */
	ft_dprintf(fd, "/*\n");
	ft_dprintf(fd, " * Base64 decoding table\n");
	ft_dprintf(fd, " * Maps ASCII characters to 6-bit values (0-63)\n");
	ft_dprintf(fd, " * Invalid characters map to 0xFF\n");
	ft_dprintf(fd, " */\n");
	ft_dprintf(fd, "static const uint8_t g_base64_dec[256] = {\n");

	for (int i = 0; i < 256; i++) {
		uint8_t val = 0xFF;  /* Default to invalid */	
		
		/* A-Z */
		if (i >= 'A' && i <= 'Z')
			val = i - 'A';
		/* a-z */
		else if (i >= 'a' && i <= 'z')
			val = 26 + (i - 'a');
		/* 0-9 */
		else if (i >= '0' && i <= '9')
			val = 52 + (i - '0');
		/* + et / */
		else if (i == '+')
			val = 62;
		else if (i == '/')
			val = 63;
		
		ft_dprintf(fd, "\t0x%02X", val);
		if (i < 255)
			ft_dprintf(fd, ",");

		if ((i + 1) % 8 == 0)
			ft_dprintf(fd, "\n");
		else if (i < 255)
			ft_dprintf(fd, " ");
	}

	ft_dprintf(fd, "};\n\n");
	
	return (0);
}
