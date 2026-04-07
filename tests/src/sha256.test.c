#include "../../hajlib/include/hprintf.h"
#include "../../includes/hash/sha256.h"

#include "../test.h"

/* Vecteurs de test SHA-256 (FIPS 180-2) */
static testVector_t sha256_vectors[] = {
	{"", 0,
	 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"a", 1,
	 "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
	{"abc", 3,
	 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
	{NULL, 0, NULL}
};

int testSha256Basic(void) {
	int passed = 0;
	int total = 0;
	
	printInfo("Testing SHA-256 basic vectors...");
	
	for (int i = 0; sha256_vectors[i].input != NULL; i++) {
		uint8_t digest[32];
		t_sha256Ctx ctx;
		
		sha256Init(&ctx);
		sha256Update(&ctx, (const uint8_t*)sha256_vectors[i].input,
					 sha256_vectors[i].input_len);
		sha256Final(digest, &ctx);
		
		total++;
		if (compareHex(sha256_vectors[i].expected, digest, 32)) {
			passed++;
			printSuccess(sha256_vectors[i].input);
		} else
			printFailure(sha256_vectors[i].input);
	}
	
	ft_printf("SHA-256 basic: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testSha256Update(void) {
	int passed = 0;
	int total = 0;
	
	printInfo("Testing SHA-256 update vectors...");
	
	for (int i = 0; sha256_vectors[i].input != NULL; i++) {
		uint8_t digest[32];
		t_sha256Ctx ctx;
		
		sha256Init(&ctx);
		for (size_t j = 0; j < sha256_vectors[i].input_len; j++) {
			sha256Update(&ctx, (const uint8_t*)&sha256_vectors[i].input[j], 1);
		}
		sha256Final(digest, &ctx);
		
		total++;
		if (compareHex(sha256_vectors[i].expected, digest, 32)) {
			passed++;
			printSuccess(sha256_vectors[i].input);
		} else
			printFailure(sha256_vectors[i].input);
	}
	
	ft_printf("SHA-256 update: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testSha256Large(void) {
	int passed = 0;
	int total = 0;
	
	printInfo("Testing SHA-256 large vector...");
	
	const char *input = "a";
	size_t input_len = 1000000; // 1 million 'a's
	const char *expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
	
	uint8_t digest[32];
	t_sha256Ctx ctx;
	
	sha256Init(&ctx);
	for (size_t i = 0; i < input_len; i++) {
		sha256Update(&ctx, (const uint8_t*)input, 1);
	}
	sha256Final(digest, &ctx);
	
	total++;
	if (compareHex(expected, digest, 32)) {
		passed++;
		printSuccess("1 million 'a's");
	} else
		printFailure("1 million 'a's");
	
	ft_printf("SHA-256 large: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
