#include "../hajlib/include/hprintf.h"
#include "../hajlib/include/hstring.h"

#include "test.h"

static testEntry_t all_tests[] = {
	{"MD5 basic", testMd5Basic},
	{"MD5 update", testMd5Update},
	{"SHA-256 basic", testSha256Basic},
	{"SHA-256 update", testSha256Update},
	{"SHA-256 large", testSha256Large},
	{"Whirlpool basic", testWhirlpoolBasic},
	{NULL, NULL}
};

int main(int argc, char **argv) {
	int	passed = 0;
	int	total = 0;
	
	ft_printf(COLOR_CYAN "\n=== HAJCRYPT TEST SUITE ===\n" COLOR_RESET "\n");
	
	/* If specific test names are provided as command-line arguments, run only those tests */
	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			int found = 0;
			for (int j = 0; all_tests[j].name != NULL; j++) {
				if (ft_strcmp(argv[i], all_tests[j].name) == 0) {
					ft_printf(COLOR_YELLOW "\n--- %s ---\n" COLOR_RESET, all_tests[j].name);
					if (all_tests[j].func())
						passed++;
					total++;
					found = 1;
					break;
				}
			}
			if (!found) {
				ft_printf(COLOR_RED "Test not found: %s\n" COLOR_RESET, argv[i]);
			}
		}
	} else { /* Run all tests if no specific test names are provided */
		for (int i = 0; all_tests[i].name != NULL; i++) {
			ft_printf(COLOR_YELLOW "\n--- %s ---\n" COLOR_RESET, all_tests[i].name);
			if (all_tests[i].func())
				passed++;
			total++;
		}
	}
	
	/* Summary */
	ft_printf(COLOR_CYAN "\n=== SUMMARY ===\n" COLOR_RESET);
	ft_printf("Tests passed: %d/%d\n", passed, total);
	
	if (passed == total) {
		ft_printf(COLOR_GREEN "\n✓ ALL TESTS PASSED\n" COLOR_RESET);
		return (0);
	} else {
		ft_printf(COLOR_RED "\n✗ SOME TESTS FAILED\n" COLOR_RESET);
		return (1);
	}
}
