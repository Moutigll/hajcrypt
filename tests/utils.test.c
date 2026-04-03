#include "../hajlib/include/hprintf.h"
#include "../hajlib/include/hstring.h"

#include "test.h"

void printSuccess(const char *msg) {
	ft_printf(COLOR_GREEN "[✓] %s" COLOR_RESET "\n", msg);
}

void printFailure(const char *msg) {
	ft_printf(COLOR_RED "[✗] %s" COLOR_RESET "\n", msg);
}

void printInfo(const char *msg) {
	ft_printf(COLOR_BLUE "[i] %s" COLOR_RESET "\n", msg);
}

void hexDump(const uint8_t *data, size_t len) {
	for (size_t i = 0; i < len; i++) {
		ft_printf("%02x", data[i]);
		if ((i + 1) % 16 == 0 && i + 1 < len)
			ft_printf("\n");
		else if (i + 1 < len)
			ft_printf(" ");
	}
	ft_printf("\n");
}

int compareHex(const char *expected, const uint8_t *actual, size_t len) {
	size_t expected_len = ft_strlen(expected);
	if (expected_len != len * 2)
		return (0); // Length mismatch

	for (size_t i = 0; i < len; i++) {
		char byte_str[3];
		ft_snprintf(byte_str, sizeof(byte_str), "%02x", actual[i]);
		if (ft_strncmp(expected + i * 2, byte_str, 2) != 0)
			return (0); // Mismatch at this byte
	}
	return (1); // All bytes match
}

int isZeroed(const void *ptr, size_t len) {
	const uint8_t	*p = (const uint8_t *)ptr;
	for (size_t i = 0; i < len; i++) {
		if (p[i] != 0) return (0);
	}
	return (1);
}
