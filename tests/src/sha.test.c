#include "../../hajlib/include/hprintf.h"
#include "../../includes/hash/sha.h" /* IWYU pragma: keep */
#include "../test.h"

/* ---------- Vecteurs de test pour chaque algorithme ---------- */

/* SHA-1 vectors (RFC 3174) */
static testVector_t sha1_vectors[] = {
	{"", 0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"a", 1, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"},
	{"abc", 3, "a9993e364706816aba3e25717850c26c9cd0d89d"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
	{NULL, 0, NULL}
};

/* SHA-224 vectors (RFC 3874) */
static testVector_t sha224_vectors[] = {
	{"", 0, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
	{"a", 1, "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"},
	{"abc", 3, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
	{NULL, 0, NULL}
};

/* SHA-256 vectors (FIPS 180-2) */
static testVector_t sha256_vectors[] = {
	{"", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"a", 1, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
	{"abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
	{NULL, 0, NULL}
};

/* SHA-384 vectors (FIPS 180-2) */
static testVector_t sha384_vectors[] = {
	{"", 0, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
	{"a", 1, "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"},
	{"abc", 3, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"},
	{NULL, 0, NULL}
};

/* SHA-512 vectors (FIPS 180-2) */
static testVector_t sha512_vectors[] = {
	{"", 0, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
	{"a", 1, "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"},
	{"abc", 3, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"},
	{NULL, 0, NULL}
};

/* SHA-512/224 vectors (FIPS 180-4) */
static testVector_t sha512_224_vectors[] = {
	{"", 0, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"},
	{"a", 1, "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327"},
	{"abc", 3, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174"},
	{NULL, 0, NULL}
};

/* SHA-512/256 vectors (FIPS 180-4) */
static testVector_t sha512_256_vectors[] = {
	{"", 0, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
	{"a", 1, "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8"},
	{"abc", 3, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	 "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"},
	{NULL, 0, NULL}
};

/* ---------- Macros de génération de tests ---------- */

/* Test incrémental (init/update/final) */
#define DEFINE_TEST_BASIC(NAME, CTX_TYPE, DIGEST_SIZE) \
int test_##NAME##Basic(void) { \
	int passed = 0, total = 0; \
	printInfo("Testing " #NAME " basic vectors..."); \
	for (int i = 0; NAME##_vectors[i].input != NULL; i++) { \
		uint8_t digest[DIGEST_SIZE]; \
		CTX_TYPE ctx; \
		NAME##Init(&ctx); \
		NAME##Update(&ctx, (const uint8_t*)NAME##_vectors[i].input, \
		             NAME##_vectors[i].input_len); \
		NAME##Final(digest, &ctx); \
		total++; \
		if (compareHex(NAME##_vectors[i].expected, digest, DIGEST_SIZE)) { \
			passed++; \
			printSuccess(NAME##_vectors[i].input); \
		} else {\
			ft_printf("Expected: %s\n", NAME##_vectors[i].expected); \
			ft_printf("Got:      "); hexDump(digest, DIGEST_SIZE); \
			printFailure(NAME##_vectors[i].input); \
		} \
	} \
	ft_printf(#NAME " basic: %d/%d passed\n", passed, total); \
	g_totalTests += total; g_passedTests += passed; \
	return (passed == total); \
}

/* Test one‑shot (Hash) */
#define DEFINE_TEST_ONESHOT(NAME, DIGEST_SIZE) \
int test_##NAME##Oneshot(void) { \
	int passed = 0, total = 0; \
	printInfo("Testing " #NAME " one‑shot vectors..."); \
	for (int i = 0; NAME##_vectors[i].input != NULL; i++) { \
		uint8_t digest[DIGEST_SIZE]; \
		NAME##Hash((const uint8_t*)NAME##_vectors[i].input, \
		           NAME##_vectors[i].input_len, digest); \
		total++; \
		if (compareHex(NAME##_vectors[i].expected, digest, DIGEST_SIZE)) { \
			passed++; \
			printSuccess(NAME##_vectors[i].input); \
		} else \
			printFailure(NAME##_vectors[i].input); \
	} \
	ft_printf(#NAME " one‑shot: %d/%d passed\n", passed, total); \
	g_totalTests += total; g_passedTests += passed; \
	return (passed == total); \
}

/* Test incrémental caractère par caractère */
#define DEFINE_TEST_UPDATE(NAME, CTX_TYPE, DIGEST_SIZE) \
int test_##NAME##Update(void) { \
	int passed = 0, total = 0; \
	printInfo("Testing " #NAME " update vectors..."); \
	for (int i = 0; NAME##_vectors[i].input != NULL; i++) { \
		uint8_t digest[DIGEST_SIZE]; \
		CTX_TYPE ctx; \
		NAME##Init(&ctx); \
		for (size_t j = 0; j < NAME##_vectors[i].input_len; j++) { \
			NAME##Update(&ctx, (const uint8_t*)&NAME##_vectors[i].input[j], 1); \
		} \
		NAME##Final(digest, &ctx); \
		total++; \
		if (compareHex(NAME##_vectors[i].expected, digest, DIGEST_SIZE)) { \
			passed++; \
			printSuccess(NAME##_vectors[i].input); \
		} else \
			printFailure(NAME##_vectors[i].input); \
	} \
	ft_printf(#NAME " update: %d/%d passed\n", passed, total); \
	g_totalTests += total; g_passedTests += passed; \
	return (passed == total); \
}

/* Test large (1 million caractères) pour SHA-1, SHA-256, SHA-512 */
#define DEFINE_TEST_LARGE(NAME, CTX_TYPE, DIGEST_SIZE, EXPECTED) \
int test_##NAME##Large(void) { \
	int passed = 0, total = 0; \
	printInfo("Testing " #NAME " large vector..."); \
	const char *input = "a"; \
	size_t input_len = 1000000; \
	uint8_t digest[DIGEST_SIZE]; \
	CTX_TYPE ctx; \
	NAME##Init(&ctx); \
	for (size_t i = 0; i < input_len; i++) { \
		NAME##Update(&ctx, (const uint8_t*)input, 1); \
	} \
	NAME##Final(digest, &ctx); \
	total++; \
	if (compareHex(EXPECTED, digest, DIGEST_SIZE)) { \
		passed++; \
		printSuccess("1 million 'a's"); \
	} else \
		printFailure("1 million 'a's"); \
	ft_printf(#NAME " large: %d/%d passed\n", passed, total); \
	g_totalTests += total; g_passedTests += passed; \
	return (passed == total); \
}

/* ---------- Instanciation des tests pour chaque algorithme ---------- */

/* SHA-1 */
DEFINE_TEST_BASIC(sha1, t_sha1Ctx, 20)
DEFINE_TEST_ONESHOT(sha1, 20)
DEFINE_TEST_UPDATE(sha1, t_sha1Ctx, 20)
DEFINE_TEST_LARGE(sha1, t_sha1Ctx, 20,
	"34aa973cd4c4daa4f61eeb2bdbad27316534016f")

/* SHA-224 */
DEFINE_TEST_BASIC(sha224, t_sha224Ctx, 28)
DEFINE_TEST_ONESHOT(sha224, 28)
DEFINE_TEST_UPDATE(sha224, t_sha224Ctx, 28)
/* Pas de vecteur large officiel pour SHA-224, on peut omettre ou utiliser SHA-256 */

/* SHA-256 */
DEFINE_TEST_BASIC(sha256, t_sha256Ctx, 32)
DEFINE_TEST_ONESHOT(sha256, 32)
DEFINE_TEST_UPDATE(sha256, t_sha256Ctx, 32)
DEFINE_TEST_LARGE(sha256, t_sha256Ctx, 32,
	"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

/* SHA-384 */
DEFINE_TEST_BASIC(sha384, t_sha384Ctx, 48)
DEFINE_TEST_ONESHOT(sha384, 48)
DEFINE_TEST_UPDATE(sha384, t_sha384Ctx, 48)
/* 1 million 'a' pour SHA-384 */
DEFINE_TEST_LARGE(sha384, t_sha384Ctx, 48,
	"9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")

/* SHA-512 */
DEFINE_TEST_BASIC(sha512, t_sha512Ctx, 64)
DEFINE_TEST_ONESHOT(sha512, 64)
DEFINE_TEST_UPDATE(sha512, t_sha512Ctx, 64)
DEFINE_TEST_LARGE(sha512, t_sha512Ctx, 64,
	"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")

/* SHA-512/224 */
DEFINE_TEST_BASIC(sha512_224, t_sha512_224Ctx, 28)
DEFINE_TEST_ONESHOT(sha512_224, 28)
DEFINE_TEST_UPDATE(sha512_224, t_sha512_224Ctx, 28)

/* SHA-512/256 */
DEFINE_TEST_BASIC(sha512_256, t_sha512_256Ctx, 32)
DEFINE_TEST_ONESHOT(sha512_256, 32)
DEFINE_TEST_UPDATE(sha512_256, t_sha512_256Ctx, 32)

int	testSha1(void) {
	return test_sha1Basic() && test_sha1Oneshot() && test_sha1Update() && test_sha1Large();
}

int	testSha224(void) {
	return test_sha224Basic() && test_sha224Oneshot() && test_sha224Update();
}

int	testSha256(void) {
	return test_sha256Basic() && test_sha256Oneshot() && test_sha256Update() && test_sha256Large();
}

int	testSha384(void) {
	return test_sha384Basic() && test_sha384Oneshot() && test_sha384Update() && test_sha384Large();
}

int	testSha512(void) {
	return test_sha512Basic() && test_sha512Oneshot() && test_sha512Update() && test_sha512Large();
}

int	testSha512_224(void) {
	return test_sha512_224Basic() && test_sha512_224Oneshot() && test_sha512_224Update();
}

int	testSha512_256(void) {
	return test_sha512_256Basic() && test_sha512_256Oneshot() && test_sha512_256Update();
}
