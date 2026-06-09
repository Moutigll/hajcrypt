#include <stdlib.h>

#include "../../../../hajlib/include/hmemory.h"

#include "../../../includes/hello.h"


void tlsHelloInit(t_tlsHello *hello)
{
	if (!hello)
		return;
	ft_bzero(hello, sizeof(t_tlsHello));
	hello->legacyVersion = 0x0303;
}

void tlsHelloFree(t_tlsHello *hello)
{
	if (!hello)
		return;

	free(hello->sessionId);
	free(hello->cipherSuites);
	free(hello->compressionMethods);
	free(hello->rawExtensions);
	tlsFreeParsedExtensions(&hello->extensions);
	ft_bzero(hello, sizeof(t_tlsHello));
}
