#include "../hajlib/include/hprintf.h"
#include "../hajlib/include/hstring.h"

#include "test.h"

int g_totalTests = 0;
int g_passedTests = 0;

static testEntry_t all_tests[] = {
	{"MD5 basic", testMd5Basic},
	{"MD5 update", testMd5Update},
	{"SHA-256 basic", testSha256Basic},
	{"SHA-256 update", testSha256Update},
	{"SHA-256 large", testSha256Large},
	{"Whirlpool basic", testWhirlpoolBasic},
	{"AES-128 ECB", testAes128Ecb},
	{"AES-128 CBC", testAes128Cbc},
	{"AES-128 CFB", testAes128Cfb},
	{"AES-128 CFB8", testAes128Cfb8},
	{"AES-128 CFB1", testAes128Cfb1},
	{"AES-128 OFB", testAes128Ofb},
	{"AES-128 CTR", testAes128Ctr},
	{"AES-128 GCM", testAes128Gcm},
	{"AES-128 PCBC", testAes128Pcbc},
	{"DES ECB", testDesEcb},
	{"DES CBC", testDesCbc},
	{"DES Multi-block", testDesMultiBlock},
	{"DES CFB", testDesCfb},
	{"DES CFB8", testDesCfb8},
	{"DES CFB1", testDesCfb1},
	{"DES OFB", testDesOfb},
	{"DES CTR", testDesCtr},
	{"DES PCBC", testDesPcbc},
	{"3DES ECB", testDes3Ecb},
	{"3DES CBC", testDes3Cbc},
	{"Blowfish ECB", testBlowfishEcb},
	{"Blowfish CBC", testBlowfishCbc},
	{"Blowfish CFB", testBlowfishCfb},
	{"Blowfish CFB8", testBlowfishCfb8},
	{"Blowfish CFB1", testBlowfishCfb1},
	{"Blowfish OFB", testBlowfishOfb},
	{"Blowfish CTR", testBlowfishCtr},
	{"Blowfish PCBC", testBlowfishPcbc},
	{"Base64", testBase64},
	{"BLAKE2b unkeyed", testBlake2bUnkeyed},
	{"BLAKE2b incremental", testBlake2bIncremental},
	{"BLAKE2b keyed", testBlake2bKeyed},
	{"BLAKE2b long output", testBlake2bLong},
	{"PBKDF2-HMAC-SHA256", testPbkdf2Sha256},
	{"PBKDF2-HMAC-MD5", testPbkdf2Md5},
	{"PBKDF2 derive key", testPbkdf2DeriveKeyIv},
	{"PBKDF2 edge cases", testPbkdf2EdgeCases},
	{"Argon2d", testArgon2d},
	{"Argon2i", testArgon2i},
	{"Argon2id", testArgon2id},
	{"Argon2id one-shot", testArgon2idOneShot},
	{"Argon2 encode/decode", testArgon2EncodeDecode},
	{"Argon2 edge cases", testArgon2EdgeCases},
	{"Bcrypt hash", testBcryptHash},
	{"Bcrypt verify", testBcryptVerify},
	{"Bcrypt gen salt", testBcryptGenSalt},
	{"Bcrypt edge cases", testBcryptEdgeCases},
	{"Bcrypt hash with salt string", testBcryptHashWithSaltStr},
	{"BigInt odd/even", testBigIntIsOddEven},
	{"BigInt addition", testBigIntAdd},
	{"BigInt subtraction", testBigIntSub},
	{"BigInt multiplication", testBigIntMul},
	{"BigInt division and modulus", testBigIntDivMod},
	{"BigInt modular arithmetic", testModularArithmetic},
	{"ChaCha20 keystream", testChacha20Keystream},
	{"ChaCha20 encrypt", testChacha20Encrypt},
	{"ChaCha20 roundtrip", testChacha20Roundtrip},
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
	ft_printf("Sections passed: %d/%d\n", passed, total);
	double passRate = (g_totalTests > 0) ? ((double)g_passedTests / g_totalTests) * 100 : 0.0;
	ft_printf("Assertions passed: %d/%d (%.2f%%)\n", g_passedTests, g_totalTests, passRate);
	
	if (passed == total) {
		ft_printf(COLOR_GREEN "\n✓ ALL TESTS PASSED\n" COLOR_RESET);
		return (0);
	} else {
		ft_printf(COLOR_RED "\n✗ SOME TESTS FAILED\n" COLOR_RESET);
		return (1);
	}
}
